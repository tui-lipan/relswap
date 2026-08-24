//! Durable executable and selector operations used by managed installations.
//!
//! This module is deliberately small.  It owns the operations whose correctness depends on the
//! host filesystem (temporary files, durable replacement, executable permissions, and Unix
//! symlinks); the installation module owns the policy about which paths may be changed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Return the executable that started the current process, after resolving a launcher symlink when
/// the platform can do so.  A regular file is required: an installer must never copy a directory,
/// FIFO, or another indirection as its own payload.
pub fn current_exe() -> io::Result<PathBuf> {
    let path = std::env::current_exe()?;
    let path = fs::canonicalize(path)?;
    ensure_regular_file(&path)?;
    Ok(path)
}

/// Descriptive alias for [`current_exe`].
pub fn current_executable() -> io::Result<PathBuf> {
    current_exe()
}

/// Resolve the launcher-v1 payload from the launcher's own location and an `active` file value.
///
/// This parser is platform-neutral so the path and semantic-version contract is unit tested on
/// every host. The launcher accepts no path from state: the only inputs are a canonical semantic
/// version and the product payload basename, so the payload path is always derived as
/// `versions/<version>/<payload_name>`.
pub fn resolve_launcher_v1_payload(
    launcher: &Path,
    active: &[u8],
    payload_name: &str,
) -> io::Result<PathBuf> {
    let bin = launcher.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher has no parent directory",
        )
    })?;
    if !bin
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher must be installed directly under the managed bin directory",
        ));
    }
    let root = bin.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher bin directory has no install root",
        )
    })?;
    let raw = std::str::from_utf8(active)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "active is not UTF-8"))?;
    if raw.is_empty() || raw.len() > 128 || raw.trim() != raw {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active must contain only a canonical semantic version",
        ));
    }
    let version = semver::Version::parse(raw).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("active does not contain a semantic version: {error}"),
        )
    })?;
    if version.to_string() != raw {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active version is not canonical",
        ));
    }
    if !is_safe_basename(payload_name, true) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed payload name must be a plain basename",
        ));
    }
    Ok(root
        .join("versions")
        .join(version.to_string())
        .join(payload_name))
}

/// Execute the immutable Windows launcher-v1 protocol and return the payload exit code.
#[cfg(windows)]
pub fn run_windows_launcher(payload_name: &str) -> io::Result<i32> {
    use std::io::Read;

    let launcher = std::env::current_exe()?;
    let bin = launcher.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher has no parent directory",
        )
    })?;
    if windows_handle::directory_is_case_sensitive(&windows_handle::open_directory(bin, false)?)?
        && bin.file_name() != Some(std::ffi::OsStr::new("bin"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher bin directory casing is noncanonical",
        ));
    }
    let root = launcher
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid launcher location"))?;
    let active_path = root.join("active");
    let mut active_lock = windows_handle::lock_regular(&active_path)?;
    let mut active = Vec::new();
    Read::take(&mut active_lock.file, 129).read_to_end(&mut active)?;
    if active.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active selector is too large",
        ));
    }
    let payload = resolve_launcher_v1_payload(&launcher, &active, payload_name)?;
    let payload_lock = windows_handle::lock_regular(&payload)?;

    // Command inherits the exact environment, working directory, standard handles, and attached
    // console. Only argv[0] changes from the stable launcher to the selected payload.
    let mut child = std::process::Command::new(payload)
        .args(std::env::args_os().skip(1))
        .spawn()?;
    drop(payload_lock);
    drop(active_lock);
    let status = child.wait()?;
    status.code().ok_or_else(|| {
        io::Error::other("managed payload exited without a Windows process exit code")
    })
}

/// The launcher artifact is Windows-only; keeping a stub lets all-target checks build the named
/// binary without pretending it can launch on another platform.
#[cfg(not(windows))]
pub fn run_windows_launcher(payload_name: &str) -> io::Result<i32> {
    let _ = payload_name;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "relswap launcher is only supported on Windows",
    ))
}

/// Reject a path which is not a regular, non-link file.
pub fn ensure_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || is_reparse_point(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(())
}

/// Open a regular file without following a final symlink or Windows reparse point.
///
/// Callers must validate untrusted ancestor directories separately. This closes the common
/// `metadata`-then-`open` race for files in an already trusted directory.
pub fn open_regular_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is a reparse point", path.display()),
            ));
        }
    }
    Ok(file)
}

/// Open a regular file while refusing symlink/reparse-point ancestors.
pub fn open_regular_file_secure(path: &Path) -> io::Result<File> {
    #[cfg(not(windows))]
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    #[cfg(not(windows))]
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let directory = open_directory_tree(parent, false)?;
        let filename = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file path has no basename")
        })?;
        let filename = CString::new(filename.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename contains NUL"))?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not a regular file", path.display()),
            ));
        }
        Ok(file)
    }
    #[cfg(windows)]
    {
        windows_handle::open_regular(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        ensure_directory_tree_by_path(parent, false)?;
        open_regular_file(path)
    }
}

/// Create or validate every component of a directory path without traversing a Unix symlink.
///
/// Unix uses `openat(O_NOFOLLOW)` and Windows uses root-directory handles with `NtCreateFile`.
pub fn ensure_directory_tree(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        open_directory_tree(path, true).map(drop)
    }
    #[cfg(windows)]
    {
        windows_handle::open_directory(path, true).map(drop)
    }
    #[cfg(not(any(unix, windows)))]
    {
        ensure_directory_tree_by_path(path, true)
    }
}

#[cfg(windows)]
pub(crate) fn open_directory_handle(path: &Path) -> io::Result<File> {
    windows_handle::open_directory(path, false)
}

#[cfg(windows)]
pub(crate) fn create_private_directory_handle(
    path: &Path,
    security_descriptor: *mut core::ffi::c_void,
) -> io::Result<File> {
    windows_handle::create_private_directory(path, security_descriptor)
}

#[cfg(windows)]
pub(crate) fn same_directory_object(left: &Path, right: &Path) -> io::Result<bool> {
    let left = windows_handle::open_directory(left, false)?;
    let right = windows_handle::open_directory(right, false)?;
    windows_handle::same_object(&left, &right)
}

#[cfg(windows)]
pub(crate) fn same_regular_file_object(left: &Path, right: &Path) -> io::Result<bool> {
    let left = windows_handle::lock_regular(left)?;
    let right = windows_handle::lock_regular(right)?;
    windows_handle::same_object(&left.file, &right.file)
}

pub(crate) struct OpenDirectory {
    handle: File,
    path: PathBuf,
}

impl OpenDirectory {
    pub(crate) fn create_new_file(
        &self,
        filename: &str,
        bytes: &[u8],
        mode: Option<u32>,
    ) -> io::Result<PathBuf> {
        create_new_file_at(&self.handle, &self.path, filename, bytes, mode)
    }

    pub(crate) fn remove_file(&self, filename: &str) -> io::Result<()> {
        remove_file_at(&self.handle, filename)
    }

    pub(crate) fn path_still_identifies_directory(&self) -> io::Result<bool> {
        let reopened = open_output_directory(&self.path, false)?;
        same_directory_handle(&self.handle, &reopened.handle)
    }
}

fn same_directory_handle(left: &File, right: &File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(windows)]
    {
        windows_handle::same_object(left, right)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (left, right);
        Ok(true)
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn open_private_directory(path: &Path) -> io::Result<OpenDirectory> {
    crate::fs::security::ensure_private_dir(path)?;
    let directory = open_output_directory(path, false)?;
    #[cfg(unix)]
    crate::fs::security::validate_private_dir(path, &directory.handle.metadata()?)?;
    #[cfg(windows)]
    crate::fs::security::validate_private_dir_handle(&directory.handle)?;
    Ok(directory)
}

pub(crate) fn open_extraction_directory(path: &Path) -> io::Result<OpenDirectory> {
    #[cfg(windows)]
    {
        open_private_directory(path)
    }
    #[cfg(not(windows))]
    {
        open_output_directory(path, false)
    }
}

fn open_output_directory(path: &Path, create: bool) -> io::Result<OpenDirectory> {
    #[cfg(unix)]
    let handle = open_directory_tree(path, create)?;
    #[cfg(windows)]
    let handle = windows_handle::open_directory(path, create)?;
    #[cfg(not(any(unix, windows)))]
    let handle = {
        ensure_directory_tree_by_path(path, create)?;
        File::open(path)?
    };
    Ok(OpenDirectory {
        handle,
        path: path.to_path_buf(),
    })
}

/// Create one new file in `directory`, without replacing an existing name or following links.
///
/// On Unix both the create and cleanup are relative to an open directory handle. Permissions,
/// size, and bytes are checked through the opened file handle.
pub fn create_new_file_in_directory(
    directory: &Path,
    filename: &str,
    bytes: &[u8],
    mode: Option<u32>,
) -> io::Result<PathBuf> {
    #[cfg(windows)]
    let directory = open_private_directory(directory)?;
    #[cfg(not(windows))]
    let directory = open_output_directory(directory, true)?;
    directory.create_new_file(filename, bytes, mode)
}

pub(crate) fn is_safe_basename(value: &str, windows_semantics: bool) -> bool {
    if value.is_empty() || matches!(value, "." | "..") || value.contains(['/', '\\', '\0', ':']) {
        return false;
    }
    if !windows_semantics {
        return true;
    }
    if value.ends_with([' ', '.'])
        || value.bytes().any(|byte| byte < b' ')
        || value.contains(['"', '<', '>', '|', '?', '*'])
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or_default();
    !matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
            | "CONIN$"
            | "CONOUT$"
    )
}

/// Whether `path` is a Windows reparse point.  Unix has no equivalent indirection bit; symlink
/// checks use `symlink_metadata` at every policy boundary instead.
pub fn is_reparse_point(path: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        Ok(fs::symlink_metadata(path)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(false)
    }
}

/// Read a Unix selector symlink without following it.  On Windows this returns `None`; managed
/// installations use the UTF-8 `active` file instead.
#[cfg(unix)]
pub fn read_symlink(path: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::read_link(path).map(Some),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a symbolic link", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The non-Unix selector shape is intentionally represented by an absent symlink.
#[cfg(not(unix))]
pub fn read_symlink(path: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a symbolic link on this platform", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Replace a regular file atomically and durably.  The temporary file is created beside the
/// destination, written and synced before the final replace, so a crash exposes either the old
/// complete file or the new complete file.
pub fn atomic_replace_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_file_with_mode(path, bytes, None)
}

/// [`atomic_replace_file`] with an optional Unix mode for the newly-created file.
pub fn atomic_replace_file_with_mode(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    ensure_directory(parent)?;
    reject_reparse(path)?;

    let temporary = create_temporary_file(path, mode)?;
    let result = (|| {
        let mut file = temporary.file;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        replace_existing(&temporary.path, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary.path);
    }
    result
}

/// Create a regular file without replacing an existing path, write it fully, and sync it.  This
/// is used for the Windows launcher, whose ownership contract forbids self-updating an existing
/// launcher.
pub fn create_new_file(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    ensure_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("destination already exists: {}", path.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = create_temporary_file(path, mode)?;
    let result = (|| {
        let mut file = temporary.file;
        file.write_all(bytes)?;
        file.flush()?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            set_mode(&file, mode)?;
        }
        file.sync_all()?;
        drop(file);
        rename_new(&temporary.path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary.path);
    }
    result
}

/// Change a payload into an executable without following a link.
pub fn set_executable(path: &Path) -> io::Result<()> {
    ensure_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        if metadata.nlink() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to change a hard-linked executable {}",
                    path.display()
                ),
            ));
        }
        let mode = metadata.mode() | 0o755;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Atomically switch a Unix selector symlink to an absolute target.  This is not available on
/// Windows because the managed selector there is a regular UTF-8 file.
#[cfg(unix)]
pub fn atomic_switch_symlink(path: &Path, target: &Path) -> io::Result<()> {
    if !target.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed selector targets must be absolute",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    ensure_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not an existing selector symlink", path.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let temporary = temporary_path(path, "symlink");
    std::os::unix::fs::symlink(target, &temporary)?;
    let result = (|| {
        replace_existing(&temporary, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Sync a directory after a rename or replacement.  Directory fsync is available on Unix; Windows
/// does not provide a portable directory handle contract, while `MOVEFILE_WRITE_THROUGH` and the
/// synced file cover the supported atomic-replacement path.
pub fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        // Windows does not expose a portable directory-fsync operation.  The file itself is
        // flushed before replacement and MoveFileExW uses MOVEFILE_WRITE_THROUGH for the rename;
        // attempting FlushFileBuffers on a directory handle would fail on supported filesystems.
        let _ = path;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Rename a newly-created directory without intentionally replacing a prior version.  Callers
/// still check for existence first; the platform-specific no-replace operation prevents ordinary
/// races from silently merging or overwriting a retained version.
pub fn rename_new(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", destination.display()),
        )
    })?;
    ensure_directory(parent)?;
    reject_reparse(source)?;
    reject_reparse(destination)?;
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        let source_wide = wide_path(source);
        let destination_wide = wide_path(destination);
        let ok = unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        return sync_dir(parent);
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
        let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
        })?;
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source_c.as_ptr(),
                libc::AT_FDCWD,
                destination_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EINVAL)
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("atomic no-replace rename is unavailable: {error}"),
                ));
            }
            return Err(error);
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
        let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
        })?;
        let result = unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                source_c.as_ptr(),
                libc::AT_FDCWD,
                destination_c.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this Unix target has no supported atomic no-replace rename",
    ));
    #[cfg(unix)]
    {
        sync_dir(parent)?;
        if let Some(source_parent) = source.parent()
            && source_parent != parent
        {
            sync_dir(source_parent)?;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (source, destination, parent);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this target has no supported atomic no-replace rename",
        ))
    }
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a real directory", path.display()),
        ));
    }
    Ok(())
}

fn reject_reparse(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(path)? => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing to replace indirection {}", path.display()),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
mod windows_handle {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileCaseSensitiveInfo,
        FileDispositionInfo, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL,
        SYNCHRONIZE, SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    pub(super) struct LockedRegularFile {
        pub(super) file: File,
        _directories: Vec<File>,
    }

    pub(super) fn open_directory(path: &Path, create: bool) -> io::Result<File> {
        let path = absolute_normalized(path)?;
        let (root, components) = split_root(&path)?;
        let mut directory = open_root(&root, SHARE_ALL)?;
        for component in components {
            directory = open_relative(
                &directory,
                &component,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                SHARE_ALL,
                if create { FILE_OPEN_IF } else { FILE_OPEN },
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null_mut(),
            )?;
            validate_directory(&directory)?;
        }
        Ok(directory)
    }

    pub(super) fn create_private_directory(
        path: &Path,
        security_descriptor: *mut core::ffi::c_void,
    ) -> io::Result<File> {
        let path = absolute_normalized(path)?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "directory path has no parent")
        })?;
        let filename = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory path has no basename",
            )
        })?;
        let parent = open_directory(parent, true)?;
        let directory = open_relative(
            &parent,
            filename,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            SHARE_ALL,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            security_descriptor,
        )?;
        validate_directory(&directory)?;
        Ok(directory)
    }

    pub(super) fn open_regular(path: &Path) -> io::Result<File> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let filename = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file path has no basename")
        })?;
        let directory = open_directory(parent, false)?;
        let file = open_relative(
            &directory,
            filename,
            FILE_GENERIC_READ | SYNCHRONIZE,
            SHARE_ALL,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
        )?;
        validate_regular(&file)?;
        Ok(file)
    }

    pub(super) fn create_file(directory: &File, filename: &str) -> io::Result<File> {
        let file = open_relative(
            directory,
            OsStr::new(filename),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
            SHARE_ALL,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
        )?;
        validate_regular(&file)?;
        Ok(file)
    }

    pub(super) fn remove_file(directory: &File, filename: &str) -> io::Result<()> {
        let file = open_relative(
            directory,
            OsStr::new(filename),
            DELETE | SYNCHRONIZE,
            SHARE_ALL,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
        )?;
        validate_regular(&file)?;
        delete_open_file(&file)
    }

    pub(super) fn delete_open_file(file: &File) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn lock_regular(path: &Path) -> io::Result<LockedRegularFile> {
        let path = absolute_normalized(path)?;
        let (root, mut components) = split_root(&path)?;
        let filename = components.pop().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file path has no basename")
        })?;
        let mut directories = vec![open_root(&root, FILE_SHARE_READ | FILE_SHARE_WRITE)?];
        for component in components {
            let parent = directories.last().expect("root directory handle exists");
            let directory = open_relative(
                parent,
                &component,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null_mut(),
            )?;
            validate_directory(&directory)?;
            directories.push(directory);
        }
        let parent = directories.last().expect("root directory handle exists");
        let file = open_relative(
            parent,
            &filename,
            FILE_GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
        )?;
        validate_regular(&file)?;
        Ok(LockedRegularFile {
            file,
            _directories: directories,
        })
    }

    pub(super) fn same_object(left: &File, right: &File) -> io::Result<bool> {
        fn identity(file: &File) -> io::Result<FILE_ID_INFO> {
            let mut info: FILE_ID_INFO = unsafe { zeroed() };
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle() as HANDLE,
                    FileIdInfo,
                    (&raw mut info).cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(info)
            }
        }

        let left = identity(left)?;
        let right = identity(right)?;
        Ok(left.VolumeSerialNumber == right.VolumeSerialNumber
            && left.FileId.Identifier == right.FileId.Identifier)
    }

    pub(super) fn directory_is_case_sensitive(directory: &File) -> io::Result<bool> {
        #[repr(C)]
        struct CaseSensitiveInfo {
            flags: u32,
        }

        let mut info = CaseSensitiveInfo { flags: 0 };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                FileCaseSensitiveInfo,
                (&raw mut info).cast(),
                size_of::<CaseSensitiveInfo>() as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(50) | Some(87)) {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(info.flags & 1 != 0)
    }

    fn open_relative(
        directory: &File,
        name: &OsStr,
        access: u32,
        share: u32,
        disposition: u32,
        options: u32,
        security_descriptor: *mut core::ffi::c_void,
    ) -> io::Result<File> {
        let mut name = name.encode_wide().collect::<Vec<_>>();
        let byte_len = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "path component is too long")
            })?;
        let unicode = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len,
            Buffer: name.as_mut_ptr(),
        };
        let object_flags = if directory_is_case_sensitive(directory)? {
            0
        } else {
            OBJ_CASE_INSENSITIVE
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: directory.as_raw_handle() as HANDLE,
            ObjectName: &raw const unicode,
            Attributes: object_flags,
            SecurityDescriptor: security_descriptor,
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        let mut handle: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                disposition,
                options,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    fn open_root(root: &Path, share: u32) -> io::Result<File> {
        let wide = root
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle as _) };
        validate_directory(&file)?;
        Ok(file)
    }

    fn validate_directory(file: &File) -> io::Result<()> {
        use std::os::windows::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path component is not a real directory",
            ));
        }
        Ok(())
    }

    fn validate_regular(file: &File) -> io::Result<()> {
        use std::os::windows::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is not a regular non-reparse file",
            ));
        }
        Ok(())
    }

    fn absolute_normalized(path: &Path) -> io::Result<PathBuf> {
        use std::path::Component;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
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
        Ok(normalized)
    }

    fn split_root(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
        use std::path::Component;
        let mut root = PathBuf::new();
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir if components.is_empty() => {
                    root.push(component.as_os_str());
                }
                Component::Normal(name) => components.push(name.to_os_string()),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "path must not contain '..'",
                    ));
                }
                Component::Prefix(_) | Component::RootDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid rooted path",
                    ));
                }
            }
        }
        if root.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path has no filesystem root",
            ));
        }
        Ok((root, components))
    }

    fn nt_error(status: i32) -> io::Error {
        let code = unsafe { RtlNtStatusToDosError(status) };
        io::Error::from_raw_os_error(code as i32)
    }
}

#[cfg(unix)]
fn open_directory_tree(path: &Path, create: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(start)?;
    for component in path.components() {
        use std::path::Component;
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path must not contain '..'",
                ));
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported directory path prefix",
                ));
            }
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory component contains NUL",
            )
        })?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            if !create || error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if created != 0 {
                let create_error = io::Error::last_os_error();
                if create_error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(create_error);
                }
            }
            descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        directory = unsafe { File::from_raw_fd(descriptor) };
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory component is not a directory",
            ));
        }
    }
    Ok(directory)
}

#[cfg(not(any(unix, windows)))]
fn ensure_directory_tree_by_path(path: &Path, create: bool) -> io::Result<()> {
    use std::path::Component;

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                current.push(component.as_os_str());
                continue;
            }
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path must not contain '..'",
                ));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && !is_reparse_point(&current)? => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is not a real directory", current.display()),
                ));
            }
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                ensure_directory(&current)?;
            }
            Err(error) => return Err(error),
        }
    }
    ensure_directory(path)
}

fn create_new_file_at(
    directory_handle: &File,
    directory: &Path,
    filename: &str,
    bytes: &[u8],
    mode: Option<u32>,
) -> io::Result<PathBuf> {
    if !is_safe_basename(filename, cfg!(windows)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output filename must be a plain basename",
        ));
    }
    #[cfg(unix)]
    {
        create_new_file_at_unix(directory_handle, directory, filename, bytes, mode)
    }
    #[cfg(windows)]
    {
        let _ = mode;
        let output = directory.join(filename);
        let mut file = windows_handle::create_file(directory_handle, filename)?;
        let result = verify_new_file_contents(&mut file, bytes, None);
        if let Err(error) = result {
            let cleanup = windows_handle::delete_open_file(&file);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; cleanup failed: {cleanup}"),
                )),
            };
        }
        Ok(output)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory_handle, mode);
        let output = directory.join(filename);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&output)?;
        verify_new_file_contents(&mut file, bytes, None)?;
        Ok(output)
    }
}

fn remove_file_at(directory: &File, filename: &str) -> io::Result<()> {
    if !is_safe_basename(filename, cfg!(windows)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output filename must be a plain basename",
        ));
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;

        let filename = CString::new(filename)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename contains NUL"))?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        directory.sync_all()
    }
    #[cfg(windows)]
    {
        windows_handle::remove_file(directory, filename)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-relative removal is not supported",
        ))
    }
}

#[cfg(unix)]
fn create_new_file_at_unix(
    directory_handle: &File,
    directory: &Path,
    filename: &str,
    bytes: &[u8],
    mode: Option<u32>,
) -> io::Result<PathBuf> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let filename_c = CString::new(filename)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename contains NUL"))?;
    let descriptor = unsafe {
        libc::openat(
            directory_handle.as_raw_fd(),
            filename_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode.unwrap_or(0o600),
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "new output is not a singly linked regular file",
            ));
        }
        if let Some(mode) = mode {
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        verify_new_file_contents(&mut file, bytes, None)?;
        directory_handle.sync_all()
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory_handle.as_raw_fd(), filename_c.as_ptr(), 0);
        }
    }
    result.map(|()| directory.join(filename))
}

fn verify_new_file_contents(file: &mut File, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        set_mode(file, mode)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    file.sync_all()?;
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(io::Error::other("written file size mismatch"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let end = offset + read;
        if bytes.get(offset..end) != Some(&buffer[..read]) {
            return Err(io::Error::other("written file content mismatch"));
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err(io::Error::other("written file content mismatch"));
    }
    Ok(())
}

struct TemporaryFile {
    path: PathBuf,
    file: File,
}

fn create_temporary_file(path: &Path, mode: Option<u32>) -> io::Result<TemporaryFile> {
    #[cfg(not(unix))]
    let _ = mode;
    let mut last_error = None;
    for _ in 0..32 {
        let temporary = temporary_path(path, "file");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match options.open(&temporary) {
            Ok(file) => {
                return Ok(TemporaryFile {
                    path: temporary,
                    file,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not allocate a temporary path beside {}",
                path.display()
            ),
        )
    }))
}

fn temporary_path(path: &Path, kind: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    path.with_file_name(format!(".{name}.{kind}.{pid}.{counter}.tmp"))
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn replace_existing(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    if unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_existing(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_temp_dir() -> PathBuf {
        std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
    }

    #[test]
    fn atomic_replacement_is_durable_and_replaces_only_regular_files() {
        let root = test_temp_dir().join(format!(
            "hyprmux-executable-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("state.json");
        atomic_replace_file(&path, b"one").unwrap();
        atomic_replace_file(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn create_new_file_never_replaces_an_existing_path() {
        let root = test_temp_dir().join(format!(
            "hyprmux-executable-create-new-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("launcher");
        fs::write(&path, b"original").unwrap();

        let error = create_new_file(&path, b"replacement", None).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"original");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rename_new_never_replaces_an_existing_destination() {
        let root = test_temp_dir().join(format!(
            "relswap-executable-rename-new-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"original").unwrap();

        let error = rename_new(&source, &destination).unwrap_err();

        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        assert_ne!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::AlreadyExists
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::Unsupported
            ),
            "{error}"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read(&source).unwrap(), b"new");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn handle_relative_create_rejects_symlink_ancestors_and_outputs() {
        use std::os::unix::fs::symlink;

        let root = test_temp_dir().join(format!(
            "relswap-executable-openat-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        assert!(
            create_new_file_in_directory(&root.join("link"), "payload", b"new", Some(0o755))
                .is_err()
        );
        assert!(!root.join("real/payload").exists());

        fs::write(root.join("victim"), b"original").unwrap();
        symlink(root.join("victim"), root.join("real/payload")).unwrap();
        assert!(
            create_new_file_in_directory(&root.join("real"), "payload", b"new", Some(0o755))
                .is_err()
        );
        assert_eq!(fs::read(root.join("victim")).unwrap(), b"original");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_detects_path_replacement_and_cleans_original() {
        let root = test_temp_dir().join(format!(
            "relswap-directory-identity-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let destination = root.join("destination");
        let moved = root.join("moved");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&destination).unwrap();
        let directory = open_output_directory(&destination, false).unwrap();
        fs::rename(&destination, &moved).unwrap();
        fs::create_dir(&destination).unwrap();

        directory
            .create_new_file("payload", b"data", Some(0o755))
            .unwrap();
        assert!(!directory.path_still_identifies_directory().unwrap());
        assert!(moved.join("payload").exists());
        assert!(!destination.join("payload").exists());
        directory.remove_file("payload").unwrap();
        assert!(!moved.join("payload").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn launcher_v1_derives_only_a_canonical_versioned_payload() {
        let launcher = Path::new("/managed/hyprmux/bin/hyprmux.exe");
        assert_eq!(
            resolve_launcher_v1_payload(launcher, b"0.2.0", "hyprmux.exe").unwrap(),
            PathBuf::from("/managed/hyprmux/versions/0.2.0/hyprmux.exe")
        );
        assert!(
            resolve_launcher_v1_payload(
                Path::new("/managed/hyprmux/BIN/hyprmux.exe"),
                b"0.2.0",
                "hyprmux.exe"
            )
            .is_ok()
        );
        for invalid in [
            b"v0.2.0".as_slice(),
            b"0.2.0\n".as_slice(),
            b"../payload".as_slice(),
            b"0.2".as_slice(),
            b"".as_slice(),
        ] {
            assert!(resolve_launcher_v1_payload(launcher, invalid, "hyprmux.exe").is_err());
        }
        assert!(
            resolve_launcher_v1_payload(Path::new("/managed/hyprmux.exe"), b"0.2.0", "hyprmux.exe")
                .is_err()
        );
        assert!(resolve_launcher_v1_payload(launcher, b"0.2.0", "../escape").is_err());
    }

    #[test]
    fn windows_basename_validation_rejects_devices_and_invalid_characters() {
        assert!(is_safe_basename("hyprmux-launcher.exe", true));
        for invalid in [
            "CON.exe",
            "com1",
            "LPT².txt",
            "name:stream",
            "bad?.exe",
            "trailing.",
            "../escape",
        ] {
            assert!(!is_safe_basename(invalid, true), "{invalid}");
        }
    }

    #[test]
    fn secure_open_accepts_a_relative_basename() {
        let file = open_regular_file_secure(Path::new("Cargo.toml")).unwrap();
        assert!(file.metadata().unwrap().is_file());
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = test_temp_dir().join(format!(
            "relswap-executable-fifo-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();

        assert!(open_regular_file_secure(&path).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_switch_is_absolute_and_atomic() {
        let root = test_temp_dir().join(format!(
            "hyprmux-executable-link-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let target = root.join("payload");
        fs::write(&target, b"payload").unwrap();
        let pointer = root.join("hyprmux");
        atomic_switch_symlink(&pointer, &target).unwrap();
        assert_eq!(read_symlink(&pointer).unwrap(), Some(target));
        let _ = fs::remove_dir_all(root);
    }
}
