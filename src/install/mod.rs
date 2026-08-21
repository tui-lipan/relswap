//! Managed installation, activation, and crash recovery.
//!
//! The release modules own the signed wire formats and archive trust boundary.  This module owns
//! only the local lifecycle: private state, immutable version directories, an authoritative
//! platform selector, and the small activation journal needed to recover a crash at any point in
//! the selector switch.

mod activation;
mod journal;
mod recovery;

use crate::App;
use crate::fs::{executable, security as fs_security};
use crate::release::{self, Downloader, UreqDownloader};
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use url::Url;

const STATE_SCHEMA_VERSION: u32 = 1;
const VERSIONS_DIR: &str = "versions";
const STAGING_DIR: &str = ".staging";
const LOCK_FILE: &str = ".lock";
const INSTALL_FILE: &str = "install.json";
const PENDING_FILE: &str = "pending-activation.json";
#[cfg(windows)]
const ACTIVE_FILE: &str = "active";
#[cfg(windows)]
const BIN_DIR: &str = "bin";
const MANIFEST_FILE: &str = "release.json";
const SIGNATURE_FILE: &str = "release.signatures.json";
const VERSION_FILE: &str = "version.json";
#[cfg(windows)]
const LAUNCHER_CREATED_MARKER: &str = ".launcher-created";

/// A point after which a durable activation boundary has completed.
///
/// The names are intentionally about observable filesystem boundaries rather than implementation
/// helper calls.  A fault injector can therefore model a process dying immediately after any
/// journal step without knowing how a particular platform performs that step.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultPoint {
    LockAcquired,
    StagingCreated,
    PayloadWritten,
    Verified,
    StagingSynced,
    VersionRenamed,
    SelfTested,
    PendingWritten,
    PointerSwitched,
    InstallWritten,
    PendingRemoved,
    ParentsSynced,
}

/// Descriptive alias for [`FaultPoint`].
pub type ActivationBoundary = FaultPoint;

/// Injectable failure boundary used by deterministic activation and recovery tests.
pub trait FaultInjector: Send + Sync {
    /// Called after the named boundary has completed.  Returning an error simulates a process
    /// failure observed by the caller; the filesystem is deliberately left at that boundary.
    fn after(&self, point: FaultPoint) -> io::Result<()> {
        self.inject(point)
    }

    /// Alternate spelling useful for small test injectors.  Implement either this method or
    /// [`Self::after`]; the default implementation is a no-op.
    fn inject(&self, _point: FaultPoint) -> io::Result<()> {
        Ok(())
    }
}

impl<T: FaultInjector + ?Sized> FaultInjector for Arc<T> {
    fn after(&self, point: FaultPoint) -> io::Result<()> {
        (**self).after(point)
    }
}

impl<F> FaultInjector for F
where
    F: Fn(FaultPoint) -> io::Result<()> + Send + Sync,
{
    fn after(&self, point: FaultPoint) -> io::Result<()> {
        self(point)
    }
}

/// The production fault injector.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaultInjector;

impl FaultInjector for NoFaultInjector {}

/// Errors raised by local managed-installation policy or by the signed release layer.
#[derive(Debug)]
pub enum InstallError {
    Io(io::Error),
    Release(release::ReleaseError),
    Json(serde_json::Error),
    Invalid(String),
    Unmanaged,
    Downgrade {
        current: Version,
        requested: Version,
    },
    Fault {
        point: FaultPoint,
        source: io::Error,
    },
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "managed installation I/O error: {error}"),
            Self::Release(error) => write!(f, "release verification error: {error}"),
            Self::Json(error) => write!(f, "managed installation state JSON error: {error}"),
            Self::Invalid(message) => f.write_str(message),
            Self::Unmanaged => f.write_str("managed installation is not present"),
            Self::Downgrade { current, requested } => {
                write!(
                    f,
                    "refusing to downgrade managed install from {current} to {requested}"
                )
            }
            Self::Fault { point, source } => write!(f, "fault injector at {point:?}: {source}"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Release(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Fault { source, .. } => Some(source),
            Self::Invalid(_) | Self::Unmanaged | Self::Downgrade { .. } => None,
        }
    }
}

impl From<io::Error> for InstallError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<release::ReleaseError> for InstallError {
    fn from(error: release::ReleaseError) -> Self {
        Self::Release(error)
    }
}

impl From<serde_json::Error> for InstallError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub type Result<T> = std::result::Result<T, InstallError>;

/// The state recorded beside one immutable payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionState {
    pub schema_version: u32,
    #[serde(deserialize_with = "deserialize_canonical_version")]
    pub version: Version,
    pub target: release::ReleaseTarget,
    pub binary_sha256: String,
    pub size: u64,
    pub installation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<LauncherMetadata>,
}

/// Signed launcher metadata copied into `version.json` on Windows.  The stable launcher itself is
/// recorded separately in [`LauncherOwnership`] because updates never replace it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherMetadata {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub protocol: u32,
}

/// Descriptive launcher ownership state stored in `install.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherOwnership {
    pub owned: bool,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub protocol: u32,
}

/// Descriptive installation state.  The platform selector, not this document, is authoritative.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallState {
    pub schema_version: u32,
    #[serde(deserialize_with = "deserialize_optional_canonical_version")]
    pub active: Option<Version>,
    #[serde(deserialize_with = "deserialize_optional_canonical_version")]
    pub previous: Option<Version>,
    pub installation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<LauncherOwnership>,
}

/// The activation journal.  `from: null` is the first-install transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActivation {
    pub schema_version: u32,
    #[serde(deserialize_with = "deserialize_optional_canonical_version")]
    pub from: Option<Version>,
    #[serde(deserialize_with = "deserialize_canonical_version")]
    pub to: Version,
    pub transaction_id: String,
}

/// Result of checking signed latest metadata.  No archive is fetched by this operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub current: Option<Version>,
    pub latest: Version,
    pub managed: bool,
}

/// Result of an install/update/rollback activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationResult {
    pub version: Version,
    pub changed: bool,
}

/// High-level managed installation manager.
pub struct Installation<D = UreqDownloader> {
    app: &'static App,
    root: PathBuf,
    command_path: PathBuf,
    downloader: D,
    fault: Arc<dyn FaultInjector>,
    /// `None` means production verification through the caller's compiled trust anchor.  `Some`
    /// exists only as an explicit test/tooling seam and is never read from process environment.
    trusted_keys: Option<Vec<release::TrustedKey>>,
}

/// Short name suitable for callers that think in terms of a manager rather than an installation.
pub type Manager<D = UreqDownloader> = Installation<D>;

impl<D: Downloader> Installation<D> {
    /// Construct an installation with explicit identity, paths, downloader, and fault injector.
    pub fn new<F>(
        app: &'static App,
        root: impl Into<PathBuf>,
        command_path: impl Into<PathBuf>,
        downloader: D,
        fault: F,
    ) -> Self
    where
        F: FaultInjector + 'static,
    {
        Self {
            app,
            root: absolute_path(root.into()),
            command_path: absolute_path(command_path.into()),
            downloader,
            fault: Arc::new(fault),
            trusted_keys: None,
        }
    }

    /// Construct with the production no-fault behavior.
    pub fn without_faults(
        app: &'static App,
        root: impl Into<PathBuf>,
        command_path: impl Into<PathBuf>,
        downloader: D,
    ) -> Self {
        Self::new(app, root, command_path, downloader, NoFaultInjector)
    }

    /// Replace trust-anchor verification with an explicit in-memory key set for deterministic
    /// tests.  Production constructors never call this method.
    pub fn with_trusted_keys(mut self, keys: Vec<release::TrustedKey>) -> Self {
        self.trusted_keys = Some(keys);
        self
    }

    pub fn app(&self) -> &'static App {
        self.app
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn command_path(&self) -> &Path {
        &self.command_path
    }

    fn validate_configuration(&self) -> Result<()> {
        if !executable::is_safe_basename(self.app.name, cfg!(windows)) {
            return Err(InstallError::Invalid(
                "application name must be a plain platform-safe basename".into(),
            ));
        }
        #[cfg(windows)]
        let launcher_name = {
            if self.app.launcher_protocol() != Some(1) {
                return Err(InstallError::Invalid(
                    "Windows installations require launcher protocol 1".into(),
                ));
            }
            Some(self.app.launcher_name().ok_or_else(|| {
                InstallError::Invalid("Windows installations require launcher activation".into())
            })?)
        };
        #[cfg(not(windows))]
        let launcher_name = None;
        validate_command_path(&self.root, &self.command_path, launcher_name)
    }

    fn read_pointer_unlocked(&self) -> Result<Option<Version>> {
        #[cfg(unix)]
        {
            let Some(target) = executable::read_symlink(&self.command_path)? else {
                return Ok(None);
            };
            if !target.is_absolute() {
                return Err(InstallError::Invalid(
                    "managed command symlink must contain an absolute payload path".into(),
                ));
            }
            let version =
                parse_pointer_version(&self.root, &target, &self.app.host_payload_name())?;
            if !same_path(&target, &self.payload_path(&version)) {
                return Err(InstallError::Invalid(
                    "managed command symlink points outside the current installation".into(),
                ));
            }
            Ok(Some(version))
        }
        #[cfg(windows)]
        {
            let path = self.active_path();
            match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.file_type().is_symlink()
                        || executable::is_reparse_point(&path)?
                        || !metadata.is_file() =>
                {
                    Err(InstallError::Invalid(
                        "active selector is not a regular file".into(),
                    ))
                }
                Ok(_) => {
                    let bytes = read_regular_limited(&path, 128)?;
                    let raw = std::str::from_utf8(&bytes).map_err(|_| {
                        InstallError::Invalid("active selector is not UTF-8".into())
                    })?;
                    let version = parse_canonical_version(raw)?;
                    Ok(Some(version))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        }
    }

    fn pointer_path_exists(&self) -> Result<bool> {
        #[cfg(unix)]
        {
            match fs::symlink_metadata(&self.command_path) {
                Ok(metadata) => Ok(metadata.file_type().is_symlink()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
        #[cfg(windows)]
        {
            Ok(lexists(&self.active_path())?)
        }
    }

    fn lock_existing(&self) -> Result<InstallLock> {
        self.open_lock(false)
    }

    fn lock_for_mutation(&self) -> Result<InstallLock> {
        self.ensure_root()?;
        self.open_lock(true)
    }

    fn open_lock(&self, create: bool) -> Result<InstallLock> {
        if create {
            fs_security::ensure_private_dir(&self.root)?;
        }
        let path = self.root.join(LOCK_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || executable::is_reparse_point(&path)? =>
            {
                return Err(InstallError::Invalid(
                    "managed lock path is not a regular file".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Do not follow a symlink planted after the metadata preflight and before open.
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            // Open a reparse point itself so the post-open metadata check cannot be redirected.
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        if create {
            options.create(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        fs4::FileExt::lock(&file)?;
        self.fault(FaultPoint::LockAcquired)?;
        Ok(InstallLock { file })
    }

    fn ensure_root(&self) -> Result<()> {
        if lexists(&self.root)? {
            fs_security::ensure_private_dir(&self.root)?;
            return Ok(());
        }
        fs_security::ensure_private_dir(&self.root)?;
        Ok(())
    }

    fn ensure_private_layout(&self) -> Result<()> {
        fs_security::ensure_private_dir(&self.root)?;
        fs_security::ensure_private_dir(&self.versions_dir())?;
        fs_security::ensure_private_dir(&self.staging_dir())?;
        #[cfg(windows)]
        {
            fs_security::ensure_private_dir(&self.bin_dir())?;
            if let Some(parent) = self.command_path.parent()
                && lexists(parent)?
            {
                self.validate_windows_command_parent(parent)?;
            }
        }
        Ok(())
    }

    fn ensure_command_parent(&self) -> Result<()> {
        let parent = self.command_path.parent().ok_or_else(|| {
            InstallError::Invalid(format!(
                "managed command has no parent directory: {}",
                self.command_path.display()
            ))
        })?;
        #[cfg(windows)]
        {
            fs_security::ensure_private_dir(parent)?;
            fs_security::ensure_private_dir(&self.bin_dir())?;
            self.validate_windows_command_parent(parent)?;
        }
        #[cfg(unix)]
        {
            fs::create_dir_all(parent)?;
            let metadata = fs::symlink_metadata(parent)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || executable::is_reparse_point(parent)?
            {
                return Err(InstallError::Invalid(format!(
                    "managed command parent is not a real directory: {}",
                    parent.display()
                )));
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_windows_command_parent(&self, parent: &Path) -> Result<()> {
        if !executable::same_directory_object(parent, &self.bin_dir())? {
            return Err(InstallError::Invalid(
                "Windows launcher parent is not the managed bin directory".into(),
            ));
        }
        let launcher_name = self.app.launcher_name().ok_or_else(|| {
            InstallError::Invalid("Windows installations require launcher activation".into())
        })?;
        if executable::directory_is_case_sensitive(parent)?
            && self.command_path.file_name() != Some(std::ffi::OsStr::new(launcher_name))
        {
            return Err(InstallError::Invalid(
                "Windows launcher filename casing is noncanonical in a case-sensitive directory"
                    .into(),
            ));
        }
        Ok(())
    }

    fn sync_affected_parents(&self) -> Result<()> {
        executable::sync_dir(&self.root)?;
        if lexists(&self.versions_dir())? {
            executable::sync_dir(&self.versions_dir())?;
        }
        if let Some(parent) = self.command_path.parent()
            && lexists(parent)?
        {
            executable::sync_dir(parent)?;
        }
        Ok(())
    }

    fn fault(&self, point: FaultPoint) -> Result<()> {
        self.fault
            .after(point)
            .map_err(|source| InstallError::Fault { point, source })
    }

    fn repository_url(&self) -> Result<Url> {
        Url::parse(self.app.repository_url).map_err(|error| {
            InstallError::Invalid(format!("invalid release repository URL: {error}"))
        })
    }

    fn versions_dir(&self) -> PathBuf {
        self.root.join(VERSIONS_DIR)
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }

    fn version_dir(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    fn payload_path(&self, version: &Version) -> PathBuf {
        self.version_dir(version).join(self.app.host_payload_name())
    }

    fn version_manifest_path(&self, version: &Version) -> PathBuf {
        self.version_dir(version).join(MANIFEST_FILE)
    }

    fn version_signature_path(&self, version: &Version) -> PathBuf {
        self.version_dir(version).join(SIGNATURE_FILE)
    }

    fn install_state_path(&self) -> PathBuf {
        self.root.join(INSTALL_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.root.join(PENDING_FILE)
    }

    #[cfg(windows)]
    fn active_path(&self) -> PathBuf {
        self.root.join(ACTIVE_FILE)
    }

    #[cfg(windows)]
    fn bin_dir(&self) -> PathBuf {
        self.root.join(BIN_DIR)
    }
}

struct InstallLock {
    file: File,
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

#[derive(Clone, Debug)]
struct Transaction {
    id: String,
    dir: PathBuf,
    version_dir: PathBuf,
}

fn current_target() -> Result<release::ReleaseTarget> {
    release::ReleaseTarget::current().ok_or_else(|| {
        InstallError::Invalid("this host has no supported signed release target".to_string())
    })
}

fn absolute_path(path: PathBuf) -> PathBuf {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    };
    lexical_normalize(&absolute)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn validate_command_path(
    root: &Path,
    command_path: &Path,
    launcher_name: Option<&str>,
) -> Result<()> {
    if same_path(root, command_path) || path_starts_with(root, command_path) {
        return Err(InstallError::Invalid(
            "managed command path collides with the installation root".into(),
        ));
    }
    for reserved in [
        root.join(ACTIVE_PATH_NAME),
        root.join(LOCK_FILE),
        root.join(STAGING_DIR),
        root.join(VERSIONS_DIR),
        root.join(INSTALL_FILE),
        root.join(PENDING_FILE),
    ] {
        if path_starts_with(command_path, &reserved) {
            return Err(InstallError::Invalid(format!(
                "managed command path collides with internal path {}",
                reserved.display()
            )));
        }
    }
    if let Some(launcher_name) = launcher_name {
        if !executable::is_safe_basename(launcher_name, true)
            || Path::new(launcher_name)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(launcher_name)
        {
            return Err(InstallError::Invalid(
                "Windows launcher name must be a plain basename".into(),
            ));
        }
        let expected = root.join("bin").join(launcher_name);
        if !same_path(command_path, &expected) {
            return Err(InstallError::Invalid(format!(
                "Windows launcher path must be exactly {}",
                expected.display()
            )));
        }
    }
    Ok(())
}

const ACTIVE_PATH_NAME: &str = "active";

fn path_starts_with(path: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut path = path.components();
        let mut base = base.components();
        loop {
            match base.next() {
                None => return true,
                Some(expected) => match path.next() {
                    Some(actual)
                        if windows_component_eq(actual.as_os_str(), expected.as_os_str()) => {}
                    _ => return false,
                },
            }
        }
    }
    #[cfg(not(windows))]
    {
        path.starts_with(base)
    }
}

fn lexists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn read_regular_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = executable::open_regular_file_secure(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > limit as u64 {
        return Err(InstallError::Invalid(format!(
            "file is larger than its limit: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(InstallError::Invalid(format!(
            "file is larger than its limit: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn verify_file_digest(
    path: &Path,
    expected_size: u64,
    expected_hash: &str,
    label: &str,
) -> Result<()> {
    let mut file = executable::open_regular_file_secure(path)?;
    let metadata = file.metadata()?;
    if metadata.len() != expected_size {
        return Err(InstallError::Invalid(format!(
            "{label} size mismatch: expected {expected_size}, got {}",
            metadata.len()
        )));
    }
    let actual = release::sha256_reader(&mut file)?;
    if actual != expected_hash {
        return Err(InstallError::Invalid(format!(
            "{label} SHA-256 mismatch: expected {expected_hash}, got {actual}"
        )));
    }
    Ok(())
}

/// Flush one staged file's contents to disk.
///
/// `sync_all` is `fsync` on Unix, which is happy with a read-only descriptor, but it is
/// `FlushFileBuffers` on Windows, which requires a handle carrying write access and fails with
/// `ERROR_ACCESS_DENIED` otherwise.  The staged payload is ours and still writable at this point in
/// the pipeline, so asking for write access is free; the Unix open stays read-only so the durability
/// behaviour there is unchanged.
fn sync_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?
            .sync_all()
    }
    #[cfg(not(windows))]
    {
        File::open(path)?.sync_all()
    }
}

fn sync_regular_files(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || executable::is_reparse_point(&path)? {
            return Err(InstallError::Invalid(format!(
                "staging contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            sync_regular_files(&path)?;
            executable::sync_dir(&path)?;
        } else if metadata.is_file() {
            sync_file(&path)?;
        } else {
            return Err(InstallError::Invalid(format!(
                "staging contains a special file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_id(label: &str) -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        InstallError::Invalid(format!(
            "OS randomness failed while creating {label}: {error}"
        ))
    })?;
    Ok(hex::encode(bytes))
}

fn parse_canonical_version(value: &str) -> Result<Version> {
    let version = Version::parse(value)
        .map_err(|error| InstallError::Invalid(format!("invalid managed version: {error}")))?;
    if version.to_string() != value {
        return Err(InstallError::Invalid(
            "managed version is not canonical".into(),
        ));
    }
    Ok(version)
}

fn deserialize_canonical_version<'de, D>(deserializer: D) -> std::result::Result<Version, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    let version = Version::parse(&raw).map_err(serde::de::Error::custom)?;
    if version.to_string() != raw {
        return Err(serde::de::Error::custom("version is not canonical"));
    }
    Ok(version)
}

fn deserialize_optional_canonical_version<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Version>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    raw.map(|raw| {
        let version = Version::parse(&raw).map_err(serde::de::Error::custom)?;
        if version.to_string() != raw {
            return Err(serde::de::Error::custom("version is not canonical"));
        }
        Ok(version)
    })
    .transpose()
}

#[allow(dead_code)]
fn parse_pointer_version(root: &Path, pointer: &Path, payload_name: &str) -> Result<Version> {
    let versions = root.join(VERSIONS_DIR);
    let relative = pointer.strip_prefix(&versions).map_err(|_| {
        InstallError::Invalid("managed command pointer is outside versions directory".into())
    })?;
    let mut components = relative.components();
    let Some(Component::Normal(version)) = components.next() else {
        return Err(InstallError::Invalid(
            "managed command pointer has no version".into(),
        ));
    };
    let Some(Component::Normal(payload)) = components.next() else {
        return Err(InstallError::Invalid(
            "managed command pointer has no payload".into(),
        ));
    };
    if components.next().is_some() || payload != payload_name {
        return Err(InstallError::Invalid(
            "managed command pointer has a noncanonical payload".into(),
        ));
    }
    let version = version.to_str().ok_or_else(|| {
        InstallError::Invalid("managed command pointer version is not UTF-8".into())
    })?;
    parse_canonical_version(version)
}

#[allow(dead_code)]
fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut left = left.components();
        let mut right = right.components();
        loop {
            match (left.next(), right.next()) {
                (None, None) => return true,
                (Some(left), Some(right))
                    if windows_component_eq(left.as_os_str(), right.as_os_str()) => {}
                _ => return false,
            }
        }
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(windows)]
fn windows_component_eq(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(test)]
mod tests {
    use super::journal::validate_launcher_metadata;
    use super::*;
    use crate::app::ActivationStrategy;
    use crate::release::signature::{TrustedKey, sign_manifest_bytes};
    use crate::release::{ReleaseAsset, ReleaseManifest, ReleaseMetadata, Target};
    use flate2::{Compression, write::GzEncoder};
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;
    use std::sync::Mutex;

    fn test_temp_dir() -> PathBuf {
        std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
    }

    static TEST_APP: App = App {
        name: "hyprmux",
        version: "1.2.3",
        repository_url: "https://github.com/Razuer/hyprmux/",
        trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
        activation: ActivationStrategy::WindowsLauncher {
            launcher_name: "hyprmux-launcher.exe",
            protocol: 1,
        },
        self_test: None,
    };

    #[test]
    fn launcher_protocol_validation_is_strict_and_platform_neutral() {
        let good = LauncherMetadata {
            path: "hyprmux-1.2.3-x86_64-pc-windows-msvc/hyprmux-launcher.exe".into(),
            sha256: "a".repeat(64),
            size: 1,
            protocol: 1,
        };
        assert!(validate_launcher_metadata(&TEST_APP, &good).is_ok());
        let mut bad = good.clone();
        bad.protocol = 2;
        assert!(validate_launcher_metadata(&TEST_APP, &bad).is_err());
        bad = good.clone();
        bad.sha256 = "A".repeat(64);
        assert!(validate_launcher_metadata(&TEST_APP, &bad).is_err());
    }

    #[test]
    fn pointer_parser_requires_an_absolute_canonical_payload_shape() {
        let payload = TEST_APP.payload_name(false);
        let root = PathBuf::from("/tmp/hyprmux-managed");
        let pointer = root.join("versions/1.2.3/hyprmux");
        assert_eq!(
            parse_pointer_version(&root, &pointer, &payload).unwrap(),
            Version::parse("1.2.3").unwrap()
        );
        assert!(parse_pointer_version(&root, &root.join("other/1.2.3/hyprmux"), &payload).is_err());
        assert!(
            parse_pointer_version(&root, &root.join("versions/1.2.3/hyprmux.exe"), &payload)
                .is_err()
        );
    }

    #[test]
    fn command_path_validation_rejects_internal_collisions() {
        let root = Path::new("/managed/relswap");
        assert!(validate_command_path(root, Path::new("/usr/local/bin/hyprmux"), None).is_ok());
        for command in [
            root.to_path_buf(),
            root.join("active"),
            root.join(".lock"),
            root.join(".staging"),
            root.join(".staging/transaction/payload"),
            root.join("versions"),
            root.join("versions/1.2.3/hyprmux"),
            root.join("install.json"),
            root.join("pending-activation.json"),
        ] {
            assert!(
                validate_command_path(root, &command, None).is_err(),
                "{}",
                command.display()
            );
        }
    }

    #[test]
    fn launcher_path_validation_requires_the_exact_root_bin_child() {
        let root = Path::new("/managed/relswap");
        let expected = root.join("bin/hyprmux-launcher.exe");
        assert!(validate_command_path(root, &expected, Some("hyprmux-launcher.exe")).is_ok());
        for command in [
            root.join("hyprmux-launcher.exe"),
            root.join("other/hyprmux-launcher.exe"),
            root.join("bin/nested/hyprmux-launcher.exe"),
            root.join("bin/other.exe"),
            root.join("bin/../active"),
        ] {
            let command = lexical_normalize(&command);
            assert!(
                validate_command_path(root, &command, Some("hyprmux-launcher.exe")).is_err(),
                "{}",
                command.display()
            );
        }
        for invalid_name in ["../launcher.exe", "name:stream", "CON.exe", "launcher.exe."] {
            assert!(validate_command_path(root, &expected, Some(invalid_name)).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_comparison_matches_case_insensitive_filesystem_semantics() {
        let root = PathBuf::from(r"C:\Users\Example\App");
        let command = PathBuf::from(r"c:\users\example\app\BIN\HYPRMUX-LAUNCHER.EXE");
        assert!(validate_command_path(&root, &command, Some("hyprmux-launcher.exe")).is_ok());
        assert!(same_path(
            Path::new(r"C:\Temp\File"),
            Path::new(r"c:\TEMP\file")
        ));
    }

    // Keep the fixture helpers local to this file: the production path always uses the caller's
    // trust anchor, while these tests inject a deterministic key set through the explicit
    // verifier seam.
    /// A `.tar.gz` in the canonical Unix shape: a root directory and one payload member.
    fn unix_fixture_archive(target: Target, version: &Version, payload: &[u8]) -> Vec<u8> {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut compressed);
            let root = target.root_name(&TEST_APP, version);
            let mut root_header = tar::Header::new_gnu();
            root_header.set_entry_type(tar::EntryType::Directory);
            root_header.set_size(0);
            root_header.set_mode(0o755);
            root_header.set_cksum();
            builder
                .append_data(
                    &mut root_header,
                    format!("{root}/"),
                    Cursor::new(Vec::<u8>::new()),
                )
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    target.payload_path(&TEST_APP, version),
                    Cursor::new(payload),
                )
                .unwrap();
            builder.finish().unwrap();
        }
        compressed.finish().unwrap()
    }

    /// A `.zip` in the canonical Windows shape: a root directory, the payload, and the launcher a
    /// Windows asset is required to carry.
    fn windows_fixture_archive(
        target: Target,
        version: &Version,
        payload: &[u8],
        launcher: &[u8],
    ) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::{CompressionMethod, ZipWriter};

        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            writer
                .add_directory(
                    format!("{}/", target.root_name(&TEST_APP, version)),
                    options,
                )
                .unwrap();
            writer
                .start_file(target.payload_path(&TEST_APP, version), options)
                .unwrap();
            writer.write_all(payload).unwrap();
            writer
                .start_file(target.launcher_path(&TEST_APP, version).unwrap(), options)
                .unwrap();
            writer.write_all(launcher).unwrap();
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    /// A signed single-target release for the host platform.
    ///
    /// The archive format and member set are per-target: a Windows asset is a zip that must carry a
    /// protocol-1 launcher beside the payload, and validation rejects one that does not. Building
    /// only the Unix shape would leave the Windows install path with no passing coverage at all.
    #[allow(dead_code)]
    fn signed_fixture(version: &Version) -> (ReleaseMetadata, TrustedKey, Vec<u8>) {
        let target = Target::current().unwrap();
        let payload = b"fixture payload";
        let launcher = b"fixture launcher";
        let archive = if target.is_windows() {
            windows_fixture_archive(target, version, payload, launcher)
        } else {
            unix_fixture_archive(target, version, payload)
        };
        let asset = ReleaseAsset::new(
            &TEST_APP,
            version,
            target,
            archive.len() as u64,
            release::sha256_bytes(&archive),
            payload.len() as u64,
            release::sha256_bytes(payload),
        );
        let asset = if target.is_windows() {
            asset.with_launcher(
                &TEST_APP,
                version,
                target,
                TEST_APP.launcher_protocol().unwrap(),
                launcher.len() as u64,
                release::sha256_bytes(launcher),
            )
        } else {
            asset
        };
        let manifest = ReleaseManifest::new(
            &TEST_APP,
            version.clone(),
            "2026-08-02T12:00:00Z",
            "2099-08-02T12:00:00Z",
            BTreeMap::from([(target, asset.clone())]),
        )
        .unwrap();
        let manifest_bytes = manifest.to_bytes(&TEST_APP).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let trusted = TrustedKey::ed25519("test", signing.verifying_key().to_bytes());
        let signature_bytes = sign_manifest_bytes(&manifest_bytes, "test", &signing).unwrap();
        let signature = release::SignatureEnvelope::from_bytes(&signature_bytes).unwrap();
        let verified_signature = release::verify_manifest_with_keys(
            &manifest_bytes,
            &signature_bytes,
            std::slice::from_ref(&trusted),
        )
        .unwrap();
        let repository = Url::parse(&format!(
            "https://github.com/Razuer/hyprmux/releases/download/v{version}/"
        ))
        .unwrap();
        (
            ReleaseMetadata {
                version: version.clone(),
                manifest_bytes,
                manifest,
                signature_bytes,
                signature,
                verified_signature,
                release_base: repository,
            },
            trusted,
            archive,
        )
    }

    #[derive(Default)]
    struct FixtureDownloader {
        responses: Mutex<HashMap<String, release::DownloadResponse>>,
    }

    impl Downloader for FixtureDownloader {
        fn fetch(
            &self,
            url: &Url,
            _max_bytes: usize,
        ) -> release::Result<release::DownloadResponse> {
            self.responses
                .lock()
                .unwrap()
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| release::ReleaseError::Download(format!("missing fixture {url}")))
        }
    }

    #[cfg(unix)]
    struct FailOnce {
        point: FaultPoint,
        fired: Mutex<bool>,
    }

    #[cfg(unix)]
    impl FaultInjector for FailOnce {
        fn after(&self, point: FaultPoint) -> io::Result<()> {
            let mut fired = self.fired.lock().unwrap();
            if point == self.point && !*fired {
                *fired = true;
                Err(io::Error::other("injected activation failure"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    fn fixture_manager(
        version: &Version,
        root: &Path,
        fault: impl FaultInjector + 'static,
    ) -> Installation<FixtureDownloader> {
        fixture_manager_with_command(version, root, root.join("command-dir/hyprmux"), fault)
    }

    #[cfg(unix)]
    fn fixture_manager_with_command(
        version: &Version,
        root: &Path,
        command: PathBuf,
        fault: impl FaultInjector + 'static,
    ) -> Installation<FixtureDownloader> {
        let (metadata, trusted, archive) = signed_fixture(version);
        let exact = release::download::exact_metadata_url(
            &TEST_APP,
            &Url::parse(TEST_APP.repository_url).unwrap(),
            version,
        )
        .unwrap();
        let signature = exact.join(&TEST_APP.signature_filename()).unwrap();
        let target = Target::current().unwrap();
        let archive_url = metadata
            .release_base
            .join(
                &metadata
                    .manifest
                    .asset_for(&TEST_APP, target)
                    .unwrap()
                    .archive,
            )
            .unwrap();
        let downloader = FixtureDownloader::default();
        downloader.responses.lock().unwrap().extend([
            (
                exact.to_string(),
                release::DownloadResponse::new(
                    exact.clone(),
                    exact.clone(),
                    vec![exact],
                    metadata.manifest_bytes.clone(),
                ),
            ),
            (
                signature.to_string(),
                release::DownloadResponse::new(
                    signature.clone(),
                    signature.clone(),
                    vec![signature],
                    metadata.signature_bytes.clone(),
                ),
            ),
            (
                archive_url.to_string(),
                release::DownloadResponse::new(
                    archive_url.clone(),
                    archive_url,
                    Vec::new(),
                    archive,
                ),
            ),
        ]);
        Installation::new(&TEST_APP, root, command, downloader, fault)
            .with_trusted_keys(vec![trusted])
    }

    #[test]
    fn state_models_reject_unknown_fields() {
        let result = serde_json::from_slice::<VersionState>(
            br#"{"schema_version":1,"version":"1.2.3","target":"x86_64-unknown-linux-gnu","binary_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"installation_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","launcher":null,"extra":true}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn signed_install_creates_the_pointer_and_immutable_state() {
        let version = Version::parse("1.2.3").unwrap();
        let (metadata, trusted, archive) = signed_fixture(&version);
        let exact = release::download::exact_metadata_url(
            &TEST_APP,
            &Url::parse(TEST_APP.repository_url).unwrap(),
            &version,
        )
        .unwrap();
        let signature = exact.join(&TEST_APP.signature_filename()).unwrap();
        let archive_url = metadata
            .release_base
            .join(
                &metadata
                    .manifest
                    .asset_for(&TEST_APP, Target::current().unwrap())
                    .unwrap()
                    .archive,
            )
            .unwrap();
        let downloader = FixtureDownloader::default();
        downloader.responses.lock().unwrap().extend([
            (
                exact.to_string(),
                release::DownloadResponse::new(
                    exact.clone(),
                    exact.clone(),
                    vec![exact.clone()],
                    metadata.manifest_bytes.clone(),
                ),
            ),
            (
                signature.to_string(),
                release::DownloadResponse::new(
                    signature.clone(),
                    signature.clone(),
                    vec![signature.clone()],
                    metadata.signature_bytes.clone(),
                ),
            ),
            (
                archive_url.to_string(),
                release::DownloadResponse::new(
                    archive_url.clone(),
                    archive_url.clone(),
                    vec![archive_url],
                    archive,
                ),
            ),
        ]);
        let root = test_temp_dir().join(format!(
            "relswap-install-test-{}-{}",
            std::process::id(),
            version
        ));
        let _ = fs::remove_dir_all(&root);
        #[cfg(unix)]
        let command = root.join("command-dir/hyprmux");
        #[cfg(windows)]
        let command = root.join("bin/hyprmux-launcher.exe");
        let manager = Installation::new(&TEST_APP, &root, &command, downloader, NoFaultInjector)
            .with_trusted_keys(vec![trusted]);
        let result = manager.install_version(version.clone()).unwrap();
        assert_eq!(result.version, version);
        assert!(result.changed);
        assert_eq!(
            manager.read_pointer_unlocked().unwrap(),
            Some(version.clone())
        );
        assert!(manager.install_state_path().is_file());
        assert!(!manager.pending_path().exists());
        assert!(manager.version_dir(&version).join(MANIFEST_FILE).is_file());
        assert!(manager.version_dir(&version).join(VERSION_FILE).is_file());
        // Activation is per-platform: Unix repoints an absolute symlink at the payload, Windows
        // rewrites the selector file the launcher reads.  Assert whichever this host actually uses.
        #[cfg(unix)]
        {
            let target = fs::read_link(&command).unwrap();
            assert!(target.is_absolute());
        }
        #[cfg(windows)]
        {
            let active = fs::read_to_string(manager.active_path()).unwrap();
            assert_eq!(active.trim(), version.to_string());
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_version_is_reused_only_while_fully_verified() {
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-reuse-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = fixture_manager(&version, &root, NoFaultInjector);
        assert!(manager.install_version(version.clone()).unwrap().changed);
        assert!(!manager.install_version(version.clone()).unwrap().changed);
        fs::write(manager.payload_path(&version), b"corrupt").unwrap();
        assert!(manager.install_version(version).is_err());
        let _ = fs::remove_dir_all(root);
    }

    /// Name which Windows filesystem primitive fails, rather than surfacing a bare "Access is
    /// denied" from somewhere inside a whole install.
    ///
    /// `InstallError::Io` carries no path, so a failure in the install pipeline is
    /// indistinguishable between the private-directory DACL, the no-replace directory rename, and
    /// the selector write. Each stage here is asserted separately and in pipeline order.
    #[cfg(windows)]
    #[test]
    fn windows_layout_rename_and_selector_primitives_work() {
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-win-primitives-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let command = root.join("bin").join("hyprmux-launcher.exe");
        let manager = Installation::new(
            &TEST_APP,
            &root,
            &command,
            FixtureDownloader::default(),
            NoFaultInjector,
        );

        manager
            .ensure_private_layout()
            .expect("stage: ensure_private_layout");
        manager
            .ensure_command_parent()
            .expect("stage: ensure_command_parent");

        let staging = manager.staging_dir().join("transaction");
        fs_security::ensure_private_dir(&staging).expect("stage: private staging dir");
        let source = staging.join("version");
        fs_security::ensure_private_dir(&source).expect("stage: private version dir");
        fs::write(source.join("hyprmux.exe"), b"payload").expect("stage: write payload");

        // Regressed once: sync_all is FlushFileBuffers here and needs a writable handle, so a
        // read-only open fails the whole install with a bare ERROR_ACCESS_DENIED.
        sync_regular_files(&source).expect("stage: sync_regular_files");

        executable::rename_new(&source, &manager.version_dir(&version))
            .expect("stage: rename_new version directory");
        executable::atomic_replace_file(&manager.active_path(), version.to_string().as_bytes())
            .expect("stage: atomic_replace_file selector");

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn invalid_windows_launcher_path_is_rejected_before_root_creation() {
        let root = test_temp_dir().join(format!("relswap-invalid-win-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = Installation::new(
            &TEST_APP,
            &root,
            root.join("elsewhere/hyprmux-launcher.exe"),
            FixtureDownloader::default(),
            NoFaultInjector,
        );
        let error = manager.recover().unwrap_err();
        assert!(error.to_string().contains("must be exactly"));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn every_activation_boundary_recovers_to_a_valid_install() {
        let version = Version::parse("1.2.3").unwrap();
        let points = [
            FaultPoint::LockAcquired,
            FaultPoint::StagingCreated,
            FaultPoint::PayloadWritten,
            FaultPoint::Verified,
            FaultPoint::StagingSynced,
            FaultPoint::VersionRenamed,
            FaultPoint::SelfTested,
            FaultPoint::PendingWritten,
            FaultPoint::PointerSwitched,
            FaultPoint::InstallWritten,
            FaultPoint::PendingRemoved,
            FaultPoint::ParentsSynced,
        ];
        for point in points {
            let root = test_temp_dir().join(format!(
                "relswap-fault-test-{}-{point:?}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            let manager = fixture_manager(
                &version,
                &root,
                FailOnce {
                    point,
                    fired: Mutex::new(false),
                },
            );
            assert!(
                manager.install_version(version.clone()).is_err(),
                "{point:?}"
            );
            manager.recover_if_managed().unwrap();
            if manager.read_pointer_unlocked().unwrap().is_none() {
                manager.install_version(version.clone()).unwrap();
            }
            assert_eq!(
                manager.read_pointer_unlocked().unwrap(),
                Some(version.clone())
            );
            assert!(manager.read_install_state().unwrap().is_some());
            assert!(!manager.pending_path().exists());
            let _ = fs::remove_dir_all(root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn valid_pointer_repairs_disagreeing_descriptive_metadata_without_switching_it() {
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-repair-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = fixture_manager(&version, &root, NoFaultInjector);
        manager.install_version(version.clone()).unwrap();
        let pointer_before = fs::read_link(&manager.command_path).unwrap();
        let mut state = manager.read_install_state().unwrap().unwrap();
        state.active = None;
        fs::write(
            manager.install_state_path(),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert!(manager.recover_if_managed().unwrap());
        assert_eq!(
            fs::read_link(&manager.command_path).unwrap(),
            pointer_before
        );
        assert_eq!(
            manager.read_install_state().unwrap().unwrap().active,
            Some(version)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn initial_install_refuses_an_existing_unmanaged_command_without_creating_root_state() {
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-ownership-root-{}", std::process::id()));
        let command =
            test_temp_dir().join(format!("relswap-ownership-command-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&command);
        fs::write(&command, b"user executable").unwrap();
        let manager =
            fixture_manager_with_command(&version, &root, command.clone(), NoFaultInjector);
        assert!(manager.install_version(version).is_err());
        assert!(!root.exists());
        assert_eq!(fs::read(&command).unwrap(), b"user executable");
        let _ = fs::remove_file(command);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_revalidates_the_retained_target_before_switching_pointer() {
        let first = Version::parse("1.2.3").unwrap();
        let second = Version::parse("1.3.0").unwrap();
        let root = test_temp_dir().join(format!("relswap-rollback-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let first_manager = fixture_manager(&first, &root, NoFaultInjector);
        first_manager.install_version(first.clone()).unwrap();
        let second_manager = fixture_manager(&second, &root, NoFaultInjector);
        second_manager.install_version(second.clone()).unwrap();
        let first_payload = second_manager.payload_path(&first);
        fs::write(&first_payload, b"tampered retained payload").unwrap();
        assert!(second_manager.rollback().is_err());
        assert_eq!(
            second_manager.read_pointer_unlocked().unwrap(),
            Some(second)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn self_test_manager(app: &'static App, root: &Path) -> Installation<FixtureDownloader> {
        Installation::new(
            app,
            root,
            root.join("command-dir/hyprmux"),
            FixtureDownloader::default(),
            NoFaultInjector,
        )
    }

    /// Write a staged payload that reports `reports` the way a real binary reports `--version`.
    ///
    /// `reports` is deliberately independent of the directory the payload is staged in, so a test
    /// can stage a correct version whose binary lies about which release it is.
    #[cfg(unix)]
    fn write_self_test_payload(
        manager: &Installation<FixtureDownloader>,
        version: &Version,
        reports: &str,
    ) {
        use std::os::unix::fs::PermissionsExt;

        let payload = manager.payload_path(version);
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::create_dir_all(manager.command_path().parent().unwrap()).unwrap();
        fs::write(
            &payload,
            format!("#!/bin/sh\nprintf 'hyprmux {reports}\\n'\n"),
        )
        .unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn write_self_test_script(
        manager: &Installation<FixtureDownloader>,
        version: &Version,
        script: &str,
    ) {
        use std::os::unix::fs::PermissionsExt;

        let payload = manager.payload_path(version);
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::create_dir_all(manager.command_path().parent().unwrap()).unwrap();
        fs::write(&payload, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    const SELF_TEST: Option<crate::SelfTest> = Some(crate::SelfTest {
        args: &["--version"],
        timeout: std::time::Duration::from_secs(5),
    });

    #[cfg(unix)]
    #[test]
    fn configured_self_test_allows_activation_when_output_matches() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: SELF_TEST,
        };
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-self-test-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_payload(&manager, &version, "1.2.3");
        manager
            .activate_pointer_and_state(None, version.clone(), "a".repeat(64), None, None, None)
            .expect("activation");
        assert_eq!(manager.read_pointer_unlocked().unwrap(), Some(version));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn configured_self_test_rejects_activation_when_output_mismatches() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: SELF_TEST,
        };
        let version = Version::parse("1.2.3").unwrap();
        let root =
            test_temp_dir().join(format!("relswap-self-test-mismatch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_payload(&manager, &version, "9.9.9");
        let error = manager
            .activate_pointer_and_state(None, version, "a".repeat(64), None, None, None)
            .unwrap_err();
        assert!(error.to_string().contains("output mismatch"));
        assert!(!manager.command_path().exists());
        assert!(!manager.pending_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn self_test_rejects_excessive_combined_output() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: SELF_TEST,
        };
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!("relswap-self-test-output-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_script(
            &manager,
            &version,
            "dd if=/dev/zero bs=4096 count=300 2>/dev/null",
        );

        let error = manager
            .activate_pointer_and_state(None, version, "a".repeat(64), None, None, None)
            .unwrap_err();

        assert!(error.to_string().contains("output exceeds"));
        assert!(!manager.command_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn self_test_timeout_bounds_process_and_output_collection() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: Some(crate::SelfTest {
                args: &[],
                timeout: std::time::Duration::from_millis(150),
            }),
        };
        let version = Version::parse("1.2.3").unwrap();
        let root =
            test_temp_dir().join(format!("relswap-self-test-timeout-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_script(&manager, &version, "sleep 10");
        let started = std::time::Instant::now();

        let error = manager
            .activate_pointer_and_state(None, version, "a".repeat(64), None, None, None)
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert!(!manager.command_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn self_test_timeout_handles_descendant_retaining_output_pipes() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: Some(crate::SelfTest {
                args: &[],
                timeout: std::time::Duration::from_millis(250),
            }),
        };
        let version = Version::parse("1.2.3").unwrap();
        let root = test_temp_dir().join(format!(
            "relswap-self-test-descendant-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_script(&manager, &version, "sleep 10 & printf 'hyprmux 1.2.3\\n'");
        let started = std::time::Instant::now();

        let error = manager
            .activate_pointer_and_state(None, version, "a".repeat(64), None, None, None)
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert!(!manager.command_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    /// The update case: the staged payload is a different release than the running binary.
    ///
    /// A probe expectation taken from `App::version` would reject every update while still letting
    /// a first install pass, so this activates a version deliberately unequal to `App::version`.
    #[cfg(unix)]
    #[test]
    fn self_test_expects_the_activated_version_not_the_running_binary() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: SELF_TEST,
        };
        let version = Version::parse("2.0.0").unwrap();
        let root = test_temp_dir().join(format!("relswap-self-test-update-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_payload(&manager, &version, "2.0.0");
        manager
            .activate_pointer_and_state(
                Some(Version::parse("1.2.3").unwrap()),
                version.clone(),
                "a".repeat(64),
                None,
                None,
                None,
            )
            .expect("activation");
        assert_eq!(manager.read_pointer_unlocked().unwrap(), Some(version));
        let _ = fs::remove_dir_all(root);
    }

    /// The inverse guard: a staged payload reporting the *running* version must be rejected, so the
    /// expectation can never quietly drift back to `App::version`.
    #[cfg(unix)]
    #[test]
    fn self_test_rejects_a_payload_reporting_the_running_binary_version() {
        static APP: App = App {
            name: "hyprmux",
            version: "1.2.3",
            repository_url: "https://example.test/",
            trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
            activation: ActivationStrategy::UnixSymlink,
            self_test: SELF_TEST,
        };
        let version = Version::parse("2.0.0").unwrap();
        let root = test_temp_dir().join(format!("relswap-self-test-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let manager = self_test_manager(&APP, &root);
        write_self_test_payload(&manager, &version, "1.2.3");
        let error = manager
            .activate_pointer_and_state(
                Some(Version::parse("1.2.3").unwrap()),
                version,
                "a".repeat(64),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(error.to_string().contains("output mismatch"));
        assert!(!manager.command_path().exists());
        assert!(!manager.pending_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fault_points_are_ordered_and_complete() {
        let points = [
            FaultPoint::LockAcquired,
            FaultPoint::StagingCreated,
            FaultPoint::PayloadWritten,
            FaultPoint::Verified,
            FaultPoint::StagingSynced,
            FaultPoint::VersionRenamed,
            FaultPoint::SelfTested,
            FaultPoint::PendingWritten,
            FaultPoint::PointerSwitched,
            FaultPoint::InstallWritten,
            FaultPoint::PendingRemoved,
            FaultPoint::ParentsSynced,
        ];
        assert_eq!(points.len(), 12);
        assert_ne!(points[0], points[11]);
    }
}
