//! Crash recovery, journal reconciliation, and staging cleanup.

#[cfg(windows)]
use super::journal::read_json;
use super::journal::validate_install_state;
use super::journal::validate_pending;
use super::*;

impl<D: Downloader> Installation<D> {
    /// Recover an interrupted activation if the installation root already exists.  An absent root
    /// is the normal unmanaged state and returns `false` without creating any files.
    pub fn recover_if_managed(&self) -> Result<bool> {
        self.validate_configuration()?;
        if !lexists(&self.root)? {
            return Ok(false);
        }
        fs_security::ensure_private_dir(&self.root)?;
        let has_install = lexists(&self.install_state_path())?;
        let has_pending = lexists(&self.pending_path())?;
        let has_pointer = self.pointer_path_exists()?;
        #[cfg(windows)]
        let has_staging_recovery = self.staging_has_launcher_marker()?;
        #[cfg(not(windows))]
        let has_staging_recovery = false;
        if !has_install && !has_pending && !has_pointer && !has_staging_recovery {
            return Ok(false);
        }
        #[cfg(unix)]
        if has_pointer && !has_install && !has_pending {
            // A command symlink is also a perfectly ordinary unmanaged user command.  Only a
            // canonical pointer into this private root is installation evidence; an unrelated
            // symlink must remain untouched and must not make an unmanaged check fail.
            if self.read_pointer_unlocked().is_err() {
                return Ok(false);
            }
        }
        let _lock = self.lock_existing()?;
        self.recover_locked()
    }

    /// Recover an interrupted activation, returning whether managed state was found.
    pub fn recover(&self) -> Result<bool> {
        self.recover_if_managed()
    }

    fn recover_locked(&self) -> Result<bool> {
        self.ensure_private_layout()?;
        let pending = self.read_pending()?;
        let install = self.read_install_state()?;
        if let Some(install) = &install {
            validate_install_state(install)?;
        }
        let pointer = self.read_pointer_unlocked()?;
        if let Some(pending) = pending {
            validate_pending(&pending)?;
            match pointer {
                Some(pointer) if pointer == pending.to => {
                    let state = self.verify_final_version(
                        &pending.to,
                        install.as_ref().map(|state| state.installation_id.as_str()),
                    )?;
                    if let Some(install) = &install {
                        if install.installation_id != state.installation_id {
                            return Err(InstallError::Invalid(
                                "pending target installation id differs from install.json"
                                    .to_string(),
                            ));
                        }
                        self.verify_installed_launcher(install)?;
                    }
                    let launcher = self.launcher_ownership_for(&pending.to, install.as_ref())?;
                    let repaired = InstallState {
                        schema_version: STATE_SCHEMA_VERSION,
                        active: Some(pending.to.clone()),
                        previous: pending.from.clone(),
                        installation_id: state.installation_id,
                        launcher,
                    };
                    self.write_install_state(&repaired)?;
                    self.fault(FaultPoint::InstallWritten)?;
                    self.remove_pending()?;
                    self.fault(FaultPoint::PendingRemoved)?;
                    self.sync_affected_parents()?;
                    self.fault(FaultPoint::ParentsSynced)?;
                    self.cleanup_staging()?;
                    return Ok(true);
                }
                Some(pointer) if Some(pointer.clone()) == pending.from => {
                    self.remove_pending()?;
                    self.fault(FaultPoint::PendingRemoved)?;
                    self.sync_affected_parents()?;
                    self.fault(FaultPoint::ParentsSynced)?;
                    self.cleanup_staging()?;
                    return Ok(install.is_some());
                }
                Some(pointer) => {
                    return Err(InstallError::Invalid(format!(
                        "pending activation pointer is neither from nor to: {pointer}"
                    )));
                }
                None if pending.from.is_none() => {
                    self.remove_pending()?;
                    self.fault(FaultPoint::PendingRemoved)?;
                    self.sync_affected_parents()?;
                    self.fault(FaultPoint::ParentsSynced)?;
                    self.cleanup_staging()?;
                    return Ok(install.is_some());
                }
                None => {
                    return Err(InstallError::Invalid(
                        "pending activation lost its prior pointer".to_string(),
                    ));
                }
            }
        }

        let Some(pointer) = pointer else {
            if install.as_ref().is_some_and(|state| state.active.is_some()) {
                return Err(InstallError::Invalid(
                    "install.json claims an active version but the authoritative pointer is missing"
                    .to_string(),
                ));
            }
            #[cfg(windows)]
            if self.staging_has_launcher_marker()? {
                self.cleanup_staging()?;
            }
            return Ok(false);
        };
        // The pointer is authoritative during reconciliation.  In particular, do not reject a
        // valid pointer merely because a descriptive installation id is stale; regenerate the
        // descriptive document from the pointer below.
        let state = self.verify_final_version(&pointer, None)?;
        let metadata_matches = install.as_ref().is_some_and(|install| {
            state.schema_version == STATE_SCHEMA_VERSION
                && install.active.as_ref() == Some(&pointer)
                && install.installation_id == state.installation_id
        });
        let needs_repair = match &install {
            Some(install) => {
                install.schema_version != STATE_SCHEMA_VERSION
                    || install.active.as_ref() != Some(&pointer)
                    || install.installation_id != state.installation_id
                    || self.launcher_state_disagrees(install, state.launcher.as_ref())
            }
            None => true,
        } || !metadata_matches;
        if needs_repair {
            let previous = install
                .as_ref()
                .and_then(|state| state.previous.clone())
                .filter(|previous| previous != &pointer)
                .filter(|previous| {
                    self.verify_final_version(previous, Some(&state.installation_id))
                        .is_ok()
                });
            let launcher = self.launcher_ownership_for(&pointer, install.as_ref())?;
            let repaired = InstallState {
                schema_version: STATE_SCHEMA_VERSION,
                active: Some(pointer),
                previous,
                installation_id: state.installation_id,
                launcher,
            };
            // Reconciliation is intentionally metadata-only: never switch the authoritative
            // pointer while repairing a descriptive document.
            self.write_install_state(&repaired)?;
            self.sync_affected_parents()?;
        }
        self.cleanup_staging()?;
        Ok(true)
    }

    fn launcher_state_disagrees(
        &self,
        install: &InstallState,
        signed: Option<&LauncherMetadata>,
    ) -> bool {
        #[cfg(unix)]
        {
            let _ = signed;
            install.launcher.is_some()
        }
        #[cfg(windows)]
        {
            let Some(launcher) = install.launcher.as_ref() else {
                return true;
            };
            signed.is_none()
                || !launcher.owned
                || launcher.protocol != 1
                || self.verify_installed_launcher_record(launcher).is_err()
        }
    }

    pub(super) fn cleanup_staging(&self) -> Result<()> {
        let staging = self.staging_dir();
        if !lexists(&staging)? {
            return Ok(());
        }
        fs_security::ensure_private_dir(&staging)?;
        #[cfg(windows)]
        let remove_orphan_launcher =
            self.read_pointer_unlocked()?.is_none() && self.read_install_state()?.is_none();
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || executable::is_reparse_point(&path)?
            {
                return Err(InstallError::Invalid(
                    "staging contains a non-directory entry".into(),
                ));
            }
            #[cfg(windows)]
            if remove_orphan_launcher {
                let marker = path.join(LAUNCHER_CREATED_MARKER);
                if lexists(&marker)? {
                    let expected = std::str::from_utf8(&read_regular_limited(&marker, 128)?)
                        .map_err(|_| {
                            InstallError::Invalid("staging launcher marker is not UTF-8".into())
                        })?
                        .to_string();
                    if !lower_sha256(&expected) {
                        return Err(InstallError::Invalid(
                            "staging launcher marker has an invalid digest".into(),
                        ));
                    }
                    if lexists(&self.command_path)? {
                        executable::ensure_regular_file(&self.command_path)?;
                        let actual = release::sha256_file(&self.command_path)?;
                        if actual != expected {
                            return Err(InstallError::Invalid(
                                "orphaned launcher differs from its transaction marker".into(),
                            ));
                        }
                        if !self.retained_launcher_matches(&expected)? {
                            fs::remove_file(&self.command_path)?;
                        }
                    }
                }
            }
            fs::remove_dir_all(path)?;
        }
        executable::sync_dir(&staging)?;
        Ok(())
    }

    #[cfg(windows)]
    fn retained_launcher_matches(&self, expected: &str) -> Result<bool> {
        let versions = self.versions_dir();
        if !lexists(&versions)? {
            return Ok(false);
        }
        for entry in fs::read_dir(versions)? {
            let path = entry?.path();
            if !fs::symlink_metadata(&path)?.is_dir() {
                continue;
            }
            let Some(state) = read_json::<VersionState>(&path.join(VERSION_FILE))? else {
                continue;
            };
            if state
                .launcher
                .as_ref()
                .is_some_and(|launcher| launcher.sha256 == expected)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(windows)]
    fn staging_has_launcher_marker(&self) -> Result<bool> {
        let staging = self.staging_dir();
        if !lexists(&staging)? {
            return Ok(false);
        }
        for entry in fs::read_dir(staging)? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir()
                && lexists(&path.join(LAUNCHER_CREATED_MARKER))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(windows)]
    pub(super) fn prove_retained_launcher_ownership(&self) -> Result<bool> {
        Ok(self.retained_launcher_ownership()?.is_some())
    }

    #[cfg(windows)]
    pub(super) fn retained_launcher_ownership(&self) -> Result<Option<LauncherOwnership>> {
        let versions = self.versions_dir();
        if !lexists(&versions)? {
            return Ok(None);
        }
        for entry in fs::read_dir(versions)? {
            let path = entry?.path();
            if !fs::symlink_metadata(&path)?.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let version = parse_canonical_version(name)?;
            let state = self.verify_final_version(&version, None)?;
            if let Some(launcher) = state.launcher
                && lexists(&self.command_path)?
            {
                executable::ensure_regular_file(&self.command_path)?;
                if verify_file_digest(
                    &self.command_path,
                    launcher.size,
                    &launcher.sha256,
                    "installed launcher",
                )
                .is_ok()
                {
                    return Ok(Some(LauncherOwnership {
                        owned: true,
                        path: self.command_path.to_string_lossy().into_owned(),
                        sha256: launcher.sha256,
                        size: launcher.size,
                        protocol: launcher.protocol,
                    }));
                }
            }
        }
        Ok(None)
    }
}
