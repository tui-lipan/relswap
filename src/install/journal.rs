//! Reading, writing, and validating the descriptive state documents and the activation journal.

use super::*;

impl<D: Downloader> Installation<D> {
    pub(super) fn read_install_state(&self) -> Result<Option<InstallState>> {
        read_json(&self.install_state_path())
    }

    pub(super) fn read_pending(&self) -> Result<Option<PendingActivation>> {
        read_json(&self.pending_path())
    }

    pub(super) fn write_pending(&self, pending: &PendingActivation) -> Result<()> {
        validate_pending(pending)?;
        let bytes = serde_json::to_vec(pending)?;
        executable::atomic_replace_file_with_mode(&self.pending_path(), &bytes, Some(0o600))?;
        Ok(())
    }

    pub(super) fn remove_pending(&self) -> Result<()> {
        match fs::symlink_metadata(self.pending_path()) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
                InstallError::Invalid("pending activation is not a regular file".into()),
            ),
            Ok(_) => {
                fs::remove_file(self.pending_path())?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn write_install_state(&self, state: &InstallState) -> Result<()> {
        validate_install_state(state)?;
        let bytes = serde_json::to_vec(state)?;
        executable::atomic_replace_file_with_mode(&self.install_state_path(), &bytes, Some(0o600))?;
        Ok(())
    }

    pub(super) fn write_version_state(&self, dir: &Path, state: &VersionState) -> Result<()> {
        validate_version_state(self.app, state)?;
        let bytes = serde_json::to_vec(state)?;
        executable::atomic_replace_file_with_mode(&dir.join(VERSION_FILE), &bytes, Some(0o600))?;
        Ok(())
    }
}

pub(super) fn read_json<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || executable::is_reparse_point(path)? =>
        {
            Err(InstallError::Invalid(format!(
                "state path is not a regular file: {}",
                path.display()
            )))
        }
        Ok(metadata) => {
            if metadata.len() > release::MAX_METADATA_SIZE as u64 {
                return Err(InstallError::Invalid(format!(
                    "state file is too large: {}",
                    path.display()
                )));
            }
            Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn validate_version_state(app: &App, state: &VersionState) -> Result<()> {
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(InstallError::Invalid(format!(
            "unsupported version state schema {}",
            state.schema_version
        )));
    }
    if state.version.to_string().is_empty()
        || !valid_id(&state.installation_id)
        || state.size == 0
        || !lower_sha256(&state.binary_sha256)
    {
        return Err(InstallError::Invalid("invalid version state fields".into()));
    }
    if state.target.is_windows() {
        let launcher = state.launcher.as_ref().ok_or_else(|| {
            InstallError::Invalid("Windows version state lacks launcher metadata".into())
        })?;
        validate_launcher_metadata(app, launcher)?;
    } else if state.launcher.is_some() {
        return Err(InstallError::Invalid(
            "Unix version state contains launcher metadata".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_install_state(state: &InstallState) -> Result<()> {
    if state.schema_version != STATE_SCHEMA_VERSION || !valid_id(&state.installation_id) {
        return Err(InstallError::Invalid(
            "invalid install state schema or installation id".into(),
        ));
    }
    if state.active.is_none() && state.previous.is_some() {
        return Err(InstallError::Invalid(
            "install state has previous without active".into(),
        ));
    }
    if state.active == state.previous && state.active.is_some() {
        return Err(InstallError::Invalid(
            "install state active and previous are equal".into(),
        ));
    }
    #[cfg(windows)]
    {
        let launcher = state.launcher.as_ref().ok_or_else(|| {
            InstallError::Invalid("Windows install state lacks launcher ownership".into())
        })?;
        validate_launcher_ownership(launcher)?;
    }
    #[cfg(not(windows))]
    if state.launcher.is_some() {
        return Err(InstallError::Invalid(
            "Unix install state contains launcher ownership".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_pending(pending: &PendingActivation) -> Result<()> {
    if pending.schema_version != STATE_SCHEMA_VERSION || !valid_id(&pending.transaction_id) {
        return Err(InstallError::Invalid(
            "invalid pending activation schema".into(),
        ));
    }
    if pending.from.as_ref() == Some(&pending.to) {
        return Err(InstallError::Invalid(
            "pending activation from and to are equal".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_launcher_metadata(app: &App, launcher: &LauncherMetadata) -> Result<()> {
    if launcher.protocol != 1
        || launcher.size == 0
        || !lower_sha256(&launcher.sha256)
        || !canonical_launcher_path(app, &launcher.path)
    {
        return Err(InstallError::Invalid(
            "invalid signed launcher metadata".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_signed_launcher(app: &App, launcher: &release::LauncherInfo) -> Result<()> {
    if launcher.protocol != 1
        || launcher.size == 0
        || !lower_sha256(&launcher.sha256)
        || !canonical_launcher_path(app, &launcher.path)
    {
        return Err(InstallError::Invalid(
            "invalid signed launcher metadata".into(),
        ));
    }
    Ok(())
}

/// A signed launcher member is always `<archive root>/<launcher name>`.
fn canonical_launcher_path(app: &App, path: &str) -> bool {
    let Some(launcher_name) = app.launcher_name() else {
        return false;
    };
    let mut components = path.split('/');
    let Some(root) = components.next() else {
        return false;
    };
    let Some(name) = components.next() else {
        return false;
    };
    components.next().is_none()
        && !root.is_empty()
        && root.starts_with(&app.archive_prefix())
        && name == launcher_name
        && !path.contains('\\')
        && !path.contains('\0')
}

#[cfg(windows)]
pub(super) fn validate_launcher_ownership(launcher: &LauncherOwnership) -> Result<()> {
    if !launcher.owned
        || launcher.protocol != 1
        || launcher.path.is_empty()
        || launcher.path.contains('\0')
        || launcher.size == 0
        || !lower_sha256(&launcher.sha256)
    {
        return Err(InstallError::Invalid(
            "invalid launcher ownership state".into(),
        ));
    }
    Ok(())
}

pub(super) fn launcher_metadata(launcher: &release::LauncherInfo) -> LauncherMetadata {
    LauncherMetadata {
        path: launcher.path.clone(),
        sha256: launcher.sha256.clone(),
        size: launcher.size,
        protocol: launcher.protocol,
    }
}
