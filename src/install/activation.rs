//! Install, update, rollback, and the durable activation pipeline.

use super::journal::{launcher_metadata, validate_install_state, validate_version_state};
use super::*;
use crate::release::{ReleaseMetadata, ReleaseTarget};
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Backoff between self-test spawn attempts rejected with `ETXTBSY`.
const SELF_TEST_BUSY_RETRY_DELAY: Duration = Duration::from_millis(25);

impl<D: Downloader> Installation<D> {
    /// Install the exact package version supplied by [`App::version`].
    pub fn install(&self) -> Result<ActivationResult> {
        let version = Version::parse(self.app.version)
            .map_err(|error| InstallError::Invalid(format!("invalid package version: {error}")))?;
        self.install_version(version)
    }

    /// Descriptive alias for [`Self::install`].
    pub fn install_current(&self) -> Result<ActivationResult> {
        self.install()
    }

    /// Fetch and install one exact signed release version.
    pub fn install_version(&self, version: Version) -> Result<ActivationResult> {
        self.recover_if_managed()?;
        let metadata = self.fetch_exact_metadata(&version)?;
        let target = current_target()?;
        let archive = release::download_archive(self.app, &self.downloader, &metadata, target)?;
        self.activate_download(metadata, archive, version)
    }

    /// Explicit-version spelling for callers that expose an `install --version` command.
    pub fn install_exact(&self, version: Version) -> Result<ActivationResult> {
        self.install_version(version)
    }

    /// Fetch only signed latest metadata and report the authoritative current pointer.
    pub fn check_latest(&self) -> Result<CheckResult> {
        let _ = self.recover_if_managed()?;
        let latest = self.fetch_latest_metadata()?.version;
        let current = if lexists(&self.root)?
            && (self.read_install_state()?.is_some() || self.pointer_path_exists()?)
        {
            self.read_pointer_unlocked()?
        } else {
            None
        };
        let managed = current.is_some() && self.install_state_path().exists();
        Ok(CheckResult {
            current,
            latest,
            managed,
        })
    }

    /// Descriptive alias for [`Self::check_latest`].
    pub fn check(&self) -> Result<CheckResult> {
        self.check_latest()
    }

    /// Update a managed installation to the signed latest release.  Unmanaged installations are
    /// rejected before any download or filesystem mutation.
    pub fn update(&self) -> Result<ActivationResult> {
        self.recover_if_managed()?;
        let current = self.require_managed_current()?;
        let metadata = self.fetch_latest_metadata()?;
        if metadata.version < current {
            return Err(InstallError::Downgrade {
                current,
                requested: metadata.version,
            });
        }
        if metadata.version == current {
            return Ok(ActivationResult {
                version: current,
                changed: false,
            });
        }
        let archive =
            release::download_archive(self.app, &self.downloader, &metadata, current_target()?)?;
        let version = metadata.version.clone();
        self.activate_download(metadata, archive, version)
    }

    /// Explicit latest-update spelling for CLI integrations.
    pub fn update_latest(&self) -> Result<ActivationResult> {
        self.update()
    }

    /// Roll back to `install.json.previous` using the same pending/pointer/install sequence as an
    /// update.  The retained target is fully reverified before a pending journal is written.
    pub fn rollback(&self) -> Result<ActivationResult> {
        self.recover_if_managed()?;
        let current = self.require_managed_current()?;
        let install = self.read_install_state()?.ok_or(InstallError::Unmanaged)?;
        let target = install.previous.clone().ok_or_else(|| {
            InstallError::Invalid("managed installation has no previous version".to_string())
        })?;
        if target >= current {
            return Err(InstallError::Invalid(
                "managed installation previous version is not older than active".to_string(),
            ));
        }
        self.activate_existing(target)
    }

    /// Explicit previous-version spelling for CLI integrations.
    pub fn rollback_previous(&self) -> Result<ActivationResult> {
        self.rollback()
    }

    /// Roll back to a specific retained version.  The normal CLI-facing operation is
    /// [`Self::rollback`], which targets the descriptive previous field.
    pub fn rollback_to(&self, target: Version) -> Result<ActivationResult> {
        self.recover_if_managed()?;
        let current = self.require_managed_current()?;
        if target >= current {
            return Err(InstallError::Invalid(
                "rollback target must be older than active version".to_string(),
            ));
        }
        self.activate_existing(target)
    }

    fn fetch_exact_metadata(&self, version: &Version) -> Result<ReleaseMetadata> {
        let repository = self.repository_url()?;
        Ok(match &self.trusted_keys {
            Some(keys) => release::fetch_version_metadata_with_keys(
                self.app,
                &self.downloader,
                &repository,
                version,
                keys,
            )?,
            None => {
                release::fetch_exact_metadata(self.app, &self.downloader, &repository, version)?
            }
        })
    }

    fn fetch_latest_metadata(&self) -> Result<ReleaseMetadata> {
        let repository = self.repository_url()?;
        Ok(match &self.trusted_keys {
            Some(keys) => release::fetch_latest_metadata_with_keys(
                self.app,
                &self.downloader,
                &repository,
                keys,
            )?,
            None => release::fetch_latest_metadata(self.app, &self.downloader, &repository)?,
        })
    }

    fn activate_download(
        &self,
        metadata: ReleaseMetadata,
        archive: release::DownloadedArchive,
        version: Version,
    ) -> Result<ActivationResult> {
        let _ = self.recover_if_managed()?;
        if lexists(&self.command_path)? && !lexists(&self.install_state_path())? {
            #[cfg(windows)]
            let proven = self.prove_retained_launcher_ownership()?;
            #[cfg(not(windows))]
            let proven = false;
            if !proven {
                return Err(InstallError::Invalid(format!(
                    "refusing to replace existing unmanaged command {}",
                    self.command_path.display()
                )));
            }
        }
        let lock = self.lock_for_mutation()?;
        let result = self.activate_download_locked(&lock, metadata, archive, version);
        drop(lock);
        result
    }

    fn activate_download_locked(
        &self,
        _lock: &InstallLock,
        metadata: ReleaseMetadata,
        archive: release::DownloadedArchive,
        version: Version,
    ) -> Result<ActivationResult> {
        let target = current_target()?;
        if archive.target != target {
            return Err(InstallError::Invalid(format!(
                "downloaded archive target {} differs from current target {target}",
                archive.target
            )));
        }
        if metadata.version != version {
            return Err(InstallError::Invalid(
                "downloaded metadata version differs from requested version".to_string(),
            ));
        }
        self.verify_metadata(&metadata, target)?;
        let install = self.read_install_state()?;
        if let Some(install) = &install {
            validate_install_state(install)?;
        }
        let from = self.read_pointer_unlocked()?;
        #[cfg(windows)]
        let retained_launcher = if install.is_none() {
            self.retained_launcher_ownership()?
        } else {
            None
        };
        #[cfg(not(windows))]
        let retained_launcher: Option<LauncherOwnership> = None;
        let managed = install.is_some() && from.is_some();
        if managed {
            let active = from.as_ref().expect("managed pointer is present");
            if version <= *active {
                if version == *active {
                    let state = self.verify_final_version(
                        active,
                        install.as_ref().map(|s| s.installation_id.as_str()),
                    )?;
                    if fs::read(self.version_manifest_path(active))? != metadata.manifest_bytes
                        || fs::read(self.version_signature_path(active))?
                            != metadata.signature_bytes
                    {
                        return Err(InstallError::Invalid(
                            "existing final version has different signed metadata".to_string(),
                        ));
                    }
                    self.ensure_command_owned(Some(active), install.as_ref())?;
                    let _ = state;
                    return Ok(ActivationResult {
                        version: active.clone(),
                        changed: false,
                    });
                }
                return Err(InstallError::Downgrade {
                    current: active.clone(),
                    requested: version.clone(),
                });
            }
        }

        self.ensure_private_layout()?;
        let installation_id = self.choose_installation_id(&version, install.as_ref())?;
        if from.is_some() || !lexists(&self.command_path)? {
            self.cleanup_staging()?;
        }
        #[cfg(windows)]
        if from.is_none() && install.is_none() {
            self.cleanup_staging()?;
        }
        self.ensure_command_owned(from.as_ref(), install.as_ref())?;
        let already_managed = install.is_some() || retained_launcher.is_some();

        let final_dir = self.version_dir(&version);
        let existing = lexists(&final_dir)?;
        let mut transaction = None;
        if existing {
            let _state = self.verify_final_version(&version, Some(&installation_id))?;
            if fs::read(self.version_manifest_path(&version))? != metadata.manifest_bytes
                || fs::read(self.version_signature_path(&version))? != metadata.signature_bytes
            {
                return Err(InstallError::Invalid(
                    "existing final version has different signed metadata".to_string(),
                ));
            }
            if let Some(install) = &install {
                self.verify_installed_launcher(install)?;
            } else {
                #[cfg(windows)]
                {
                    let (launcher_size, launcher_sha256) =
                        if let Some(launcher) = retained_launcher.as_ref() {
                            (launcher.size, launcher.sha256.as_str())
                        } else {
                            let launcher = _state.launcher.as_ref().ok_or_else(|| {
                                InstallError::Invalid(
                                    "Windows version state lacks launcher metadata".into(),
                                )
                            })?;
                            (launcher.size, launcher.sha256.as_str())
                        };
                    executable::ensure_regular_file(&self.command_path)?;
                    verify_file_digest(
                        &self.command_path,
                        launcher_size,
                        launcher_sha256,
                        "installed launcher",
                    )?;
                }
            }
        } else {
            let tx = self.create_transaction()?;
            transaction = Some(tx.clone());
            self.write_downloaded_version(
                &tx,
                &metadata,
                &archive,
                &installation_id,
                target,
                already_managed,
            )?;
            self.fault(FaultPoint::PayloadWritten)?;
            self.verify_staged_version(&tx, &version, &installation_id)?;
            self.fault(FaultPoint::Verified)?;
            self.sync_staging_transaction(&tx)?;
            self.fault(FaultPoint::StagingSynced)?;

            if lexists(&final_dir)? {
                return Err(InstallError::Invalid(format!(
                    "retained version directory appeared during installation: {}",
                    final_dir.display()
                )));
            }
            executable::rename_new(&tx.version_dir, &final_dir)?;
            self.fault(FaultPoint::VersionRenamed)?;
        }

        self.ensure_command_parent()?;
        let prior_install = match (install, retained_launcher) {
            (Some(install), _) => Some(install),
            (None, Some(launcher)) => Some(InstallState {
                schema_version: STATE_SCHEMA_VERSION,
                active: None,
                previous: None,
                installation_id: installation_id.clone(),
                launcher: Some(launcher),
            }),
            (None, None) => None,
        };
        self.activate_pointer_and_state(
            from,
            version.clone(),
            installation_id,
            prior_install,
            transaction
                .as_ref()
                .map(|transaction| transaction.id.clone()),
            transaction.as_ref(),
        )?;
        Ok(ActivationResult {
            version,
            changed: true,
        })
    }

    fn activate_existing(&self, target: Version) -> Result<ActivationResult> {
        let lock = self.lock_for_mutation()?;
        let result = self.activate_existing_locked(&lock, target);
        drop(lock);
        result
    }

    fn activate_existing_locked(
        &self,
        _lock: &InstallLock,
        target: Version,
    ) -> Result<ActivationResult> {
        let install = self.read_install_state()?.ok_or(InstallError::Unmanaged)?;
        let from = self
            .read_pointer_unlocked()?
            .ok_or(InstallError::Unmanaged)?;
        if target >= from {
            return Err(InstallError::Invalid(
                "retained activation target must be older than active pointer".to_string(),
            ));
        }
        self.ensure_command_owned(Some(&from), Some(&install))?;
        self.verify_final_version(&target, Some(&install.installation_id))?;
        self.verify_installed_launcher(&install)?;
        self.fault(FaultPoint::Verified)?;
        self.ensure_command_parent()?;
        self.activate_pointer_and_state(
            Some(from),
            target,
            install.installation_id.clone(),
            Some(install),
            None,
            None,
        )
    }

    pub(super) fn activate_pointer_and_state(
        &self,
        from: Option<Version>,
        to: Version,
        installation_id: String,
        prior_install: Option<InstallState>,
        transaction_id: Option<String>,
        transaction: Option<&Transaction>,
    ) -> Result<ActivationResult> {
        if let Some(config) = self.app.self_test {
            self.run_self_test(&to, config)?;
        }
        self.fault(FaultPoint::SelfTested)?;
        let pending = PendingActivation {
            schema_version: STATE_SCHEMA_VERSION,
            from: from.clone(),
            to: to.clone(),
            transaction_id: transaction_id.unwrap_or(random_id("transaction")?),
        };
        self.write_pending(&pending)?;
        self.fault(FaultPoint::PendingWritten)?;
        self.switch_pointer(&to)?;
        self.fault(FaultPoint::PointerSwitched)?;

        let launcher = self.launcher_ownership_for(&to, prior_install.as_ref())?;
        let install = InstallState {
            schema_version: STATE_SCHEMA_VERSION,
            active: Some(to.clone()),
            previous: from,
            installation_id,
            launcher,
        };
        self.write_install_state(&install)?;
        self.fault(FaultPoint::InstallWritten)?;
        self.remove_pending()?;
        self.fault(FaultPoint::PendingRemoved)?;
        if let Some(transaction) = transaction {
            self.remove_transaction_after_rename(transaction)?;
        }
        self.sync_affected_parents()?;
        self.fault(FaultPoint::ParentsSynced)?;
        Ok(ActivationResult {
            version: to,
            changed: true,
        })
    }

    /// Run the configured probe against the staged payload for `version`.
    ///
    /// The expected output is derived from `version` - the release about to be activated - so the
    /// check is correct for updates, where the staged payload differs from the running binary.
    fn run_self_test(&self, version: &Version, config: crate::SelfTest) -> Result<()> {
        let started = Instant::now();
        // ETXTBSY is a race, not a verdict on the payload.  A `fork` in any thread of the host
        // process briefly inherits every open descriptor, so a payload we have only just finished
        // writing can be reported busy because an unrelated thread spawned a child in that window -
        // routine in a threaded application, which is exactly what this crate is embedded in.
        // Retry within the caller's timeout budget.
        //
        // Every other spawn failure is reported with its cause: the probe exists to diagnose a
        // payload that cannot run, and a bare "self-test failed" would hide precisely the
        // ENOENT/EACCES/loader errors it was added to surface.
        let mut child = loop {
            match Command::new(self.payload_path(version))
                .args(config.args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(child) => break child,
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy
                        && started.elapsed() + SELF_TEST_BUSY_RETRY_DELAY < config.timeout =>
                {
                    thread::sleep(SELF_TEST_BUSY_RETRY_DELAY);
                }
                Err(error) => {
                    return Err(InstallError::Invalid(format!(
                        "self-test could not run staged payload: {error}"
                    )));
                }
            }
        };
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| InstallError::Invalid("self-test failed".into()))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| InstallError::Invalid("self-test failed".into()))?;
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        // `started` is deliberately not reset: `config.timeout` bounds the whole probe, spawn
        // retries included, so a payload that is busy for the full budget cannot also get a fresh
        // budget to run in.
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| InstallError::Invalid("self-test failed".into()))?
            {
                break status;
            }
            if started.elapsed() >= config.timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(InstallError::Invalid("self-test timed out".into()));
            }
            thread::sleep(std::time::Duration::from_millis(10));
        };
        let mut output = stdout_reader
            .join()
            .map_err(|_| InstallError::Invalid("self-test failed".into()))?
            .map_err(|_| InstallError::Invalid("self-test failed".into()))?;
        output.extend(
            stderr_reader
                .join()
                .map_err(|_| InstallError::Invalid("self-test failed".into()))?
                .map_err(|_| InstallError::Invalid("self-test failed".into()))?,
        );
        if !status.success() {
            return Err(InstallError::Invalid("self-test failed".into()));
        }
        if !String::from_utf8_lossy(&output).contains(&version.to_string()) {
            return Err(InstallError::Invalid("self-test output mismatch".into()));
        }
        Ok(())
    }

    fn switch_pointer(&self, version: &Version) -> Result<()> {
        let payload = self.payload_path(version);
        executable::ensure_regular_file(&payload)?;
        #[cfg(unix)]
        {
            executable::atomic_switch_symlink(&self.command_path, &payload)?;
        }
        #[cfg(windows)]
        {
            executable::atomic_replace_file(&self.active_path(), version.to_string().as_bytes())?;
        }
        Ok(())
    }

    fn create_transaction(&self) -> Result<Transaction> {
        self.ensure_private_layout()?;
        let transaction_id = random_id("transaction")?;
        let transaction_dir = self.staging_dir().join(&transaction_id);
        fs_security::ensure_private_dir(&transaction_dir)?;
        let version_dir = transaction_dir.join("version");
        fs_security::ensure_private_dir(&version_dir)?;
        self.fault(FaultPoint::StagingCreated)?;
        Ok(Transaction {
            id: transaction_id,
            dir: transaction_dir,
            version_dir,
        })
    }

    fn write_downloaded_version(
        &self,
        transaction: &Transaction,
        metadata: &ReleaseMetadata,
        archive: &release::DownloadedArchive,
        installation_id: &str,
        target: ReleaseTarget,
        already_managed: bool,
    ) -> Result<()> {
        #[cfg(not(windows))]
        let _ = already_managed;
        let selected = self.verify_metadata(metadata, target)?;
        let archive_path = transaction.dir.join(&selected.asset.archive);
        executable::create_new_file(&archive_path, &archive.bytes, Some(0o600))?;
        release::extract_archive_file(
            self.app,
            &archive_path,
            selected.asset,
            &transaction.version_dir,
        )?;
        executable::atomic_replace_file_with_mode(
            &transaction.version_dir.join(MANIFEST_FILE),
            &metadata.manifest_bytes,
            Some(0o600),
        )?;
        executable::atomic_replace_file_with_mode(
            &transaction.version_dir.join(SIGNATURE_FILE),
            &metadata.signature_bytes,
            Some(0o600),
        )?;
        let payload = transaction.version_dir.join(target.payload_name(self.app));
        executable::set_executable(&payload)?;
        let state = VersionState {
            schema_version: STATE_SCHEMA_VERSION,
            version: metadata.version.clone(),
            target,
            binary_sha256: selected.asset.payload.sha256.clone(),
            size: selected.asset.payload.size,
            installation_id: installation_id.to_string(),
            launcher: selected.launcher().map(launcher_metadata),
        };
        self.write_version_state(&transaction.version_dir, &state)?;

        #[cfg(windows)]
        {
            let launcher = selected.launcher().ok_or_else(|| {
                InstallError::Invalid("Windows release is missing signed launcher metadata".into())
            })?;
            if launcher.protocol != 1 {
                return Err(InstallError::Invalid(
                    "managed Windows installations require launcher protocol 1".into(),
                ));
            }
            let launcher_name = self.app.launcher_name().ok_or_else(|| {
                InstallError::Invalid(
                    "managed Windows installations require a configured launcher name".into(),
                )
            })?;
            let staged_launcher = transaction.version_dir.join(launcher_name);
            executable::ensure_regular_file(&staged_launcher)?;
            verify_file_digest(
                &staged_launcher,
                launcher.size,
                &launcher.sha256,
                "launcher",
            )?;
            if !lexists(&self.command_path)? {
                if already_managed {
                    return Err(InstallError::Invalid(
                        "managed Windows launcher is missing and cannot be recreated by an update"
                            .into(),
                    ));
                }
                self.ensure_command_parent()?;
                executable::atomic_replace_file_with_mode(
                    &transaction.dir.join(LAUNCHER_CREATED_MARKER),
                    launcher.sha256.as_bytes(),
                    Some(0o600),
                )?;
                executable::create_new_file(
                    &self.command_path,
                    &fs::read(&staged_launcher)?,
                    None,
                )?;
            } else if !already_managed {
                return Err(InstallError::Invalid(
                    "existing Windows launcher requires a proven managed owner".into(),
                ));
            } else if let Some(install) = self.read_install_state()? {
                self.verify_installed_launcher(&install)?;
            } else if !self.prove_retained_launcher_ownership()? {
                return Err(InstallError::Invalid(
                    "existing Windows launcher ownership could not be re-established".into(),
                ));
            }
            fs::remove_file(staged_launcher)?;
        }
        Ok(())
    }

    fn verify_metadata<'a>(
        &self,
        metadata: &'a ReleaseMetadata,
        target: ReleaseTarget,
    ) -> Result<release::SelectedAsset<'a>> {
        if metadata.version != metadata.manifest.version {
            return Err(InstallError::Invalid(
                "release metadata version does not match its manifest".to_string(),
            ));
        }
        if metadata.manifest.version.to_string() != metadata.version.to_string() {
            return Err(InstallError::Invalid(
                "release metadata version is not canonical".to_string(),
            ));
        }
        let verified = match &self.trusted_keys {
            Some(keys) => release::verify_manifest_with_keys(
                &metadata.manifest_bytes,
                &metadata.signature_bytes,
                keys,
            )?,
            None => release::verify_manifest(
                self.app,
                &metadata.manifest_bytes,
                &metadata.signature_bytes,
            )?,
        };
        if verified.key_id != metadata.verified_signature.key_id {
            return Err(InstallError::Invalid(
                "release signature result differs from downloaded metadata".into(),
            ));
        }
        let parsed = release::ReleaseManifest::from_bytes(self.app, &metadata.manifest_bytes)?;
        parsed.ensure_not_expired(chrono::Utc::now())?;
        if parsed != metadata.manifest {
            return Err(InstallError::Invalid(
                "downloaded release metadata changed after verification".into(),
            ));
        }
        Ok(metadata.manifest.asset_for(self.app, target)?)
    }

    fn verify_staged_version(
        &self,
        transaction: &Transaction,
        version: &Version,
        installation_id: &str,
    ) -> Result<VersionState> {
        let state =
            self.verify_version_dir_inner(&transaction.version_dir, Some(installation_id))?;
        if &state.version != version {
            return Err(InstallError::Invalid(
                "staged version state differs from transaction version".to_string(),
            ));
        }
        Ok(state)
    }

    pub(super) fn verify_final_version(
        &self,
        version: &Version,
        installation_id: Option<&str>,
    ) -> Result<VersionState> {
        let state = self.verify_version_dir_inner(&self.version_dir(version), installation_id)?;
        if state.version != *version {
            return Err(InstallError::Invalid(
                "version.json does not match its immutable directory name".into(),
            ));
        }
        Ok(state)
    }

    fn verify_version_dir_inner(
        &self,
        dir: &Path,
        installation_id: Option<&str>,
    ) -> Result<VersionState> {
        fs_security::ensure_private_dir(dir)?;
        let state = super::journal::read_json::<VersionState>(&dir.join(VERSION_FILE))?
            .ok_or_else(|| InstallError::Invalid("version.json is missing".into()))?;
        validate_version_state(self.app, &state)?;
        if let Some(expected) = installation_id
            && state.installation_id != expected
        {
            return Err(InstallError::Invalid(
                "version installation id differs from managed installation".into(),
            ));
        }
        let target = current_target()?;
        if state.target != target {
            return Err(InstallError::Invalid(
                "version target differs from current host target".into(),
            ));
        }
        let manifest_bytes =
            read_regular_limited(&dir.join(MANIFEST_FILE), release::MAX_METADATA_SIZE)?;
        let signature_bytes =
            read_regular_limited(&dir.join(SIGNATURE_FILE), release::MAX_METADATA_SIZE)?;
        let verified = match &self.trusted_keys {
            Some(keys) => {
                release::verify_manifest_with_keys(&manifest_bytes, &signature_bytes, keys)?
            }
            None => release::verify_manifest(self.app, &manifest_bytes, &signature_bytes)?,
        };
        let manifest = release::ReleaseManifest::from_bytes(self.app, &manifest_bytes)?;
        if manifest.version != state.version {
            return Err(InstallError::Invalid(
                "version state does not match signed release version".into(),
            ));
        }
        let selected = manifest.asset_for(self.app, target)?;
        if selected.asset.payload.path
            != format!(
                "{}/{}",
                target.root_name(self.app, &state.version),
                target.payload_name(self.app)
            )
        {
            return Err(InstallError::Invalid(
                "signed payload path is not canonical".into(),
            ));
        }
        if verified.key_id.is_empty() {
            return Err(InstallError::Invalid(
                "release signature key id is empty".into(),
            ));
        }
        if state.binary_sha256 != selected.asset.payload.sha256
            || state.size != selected.asset.payload.size
        {
            return Err(InstallError::Invalid(
                "version state payload digest does not match signed manifest".into(),
            ));
        }
        let payload = dir.join(target.payload_name(self.app));
        executable::ensure_regular_file(&payload)?;
        verify_file_digest(&payload, state.size, &state.binary_sha256, "payload")?;
        if target.is_windows() {
            let launcher = selected.launcher().ok_or_else(|| {
                InstallError::Invalid("Windows release is missing launcher metadata".into())
            })?;
            super::journal::validate_signed_launcher(self.app, launcher)?;
            if state.launcher.as_ref() != Some(&launcher_metadata(launcher)) {
                return Err(InstallError::Invalid(
                    "version state launcher metadata does not match signed manifest".into(),
                ));
            }
        } else if state.launcher.is_some() || selected.launcher().is_some() {
            return Err(InstallError::Invalid(
                "Unix version contains Windows launcher metadata".into(),
            ));
        }
        validate_exact_version_members(self.app, dir, target)?;
        Ok(state)
    }

    fn sync_staging_transaction(&self, transaction: &Transaction) -> Result<()> {
        sync_regular_files(&transaction.version_dir)?;
        sync_regular_files(&transaction.dir)?;
        executable::sync_dir(&self.staging_dir())?;
        Ok(())
    }

    fn remove_transaction_after_rename(&self, transaction: &Transaction) -> Result<()> {
        if lexists(&transaction.dir)? {
            fs::remove_dir_all(&transaction.dir)?;
            executable::sync_dir(&self.staging_dir())?;
        }
        Ok(())
    }

    fn require_managed_current(&self) -> Result<Version> {
        let current = self
            .read_pointer_unlocked()?
            .ok_or(InstallError::Unmanaged)?;
        let install = self.read_install_state()?.ok_or(InstallError::Unmanaged)?;
        validate_install_state(&install)?;
        if install.active.as_ref() != Some(&current) {
            return Err(InstallError::Invalid(
                "managed install metadata does not describe the authoritative pointer".into(),
            ));
        }
        self.verify_final_version(&current, Some(&install.installation_id))?;
        self.ensure_command_owned(Some(&current), Some(&install))?;
        Ok(current)
    }

    fn choose_installation_id(
        &self,
        version: &Version,
        install: Option<&InstallState>,
    ) -> Result<String> {
        if let Some(install) = install {
            validate_install_state(install)?;
            return Ok(install.installation_id.clone());
        }
        let final_dir = self.version_dir(version);
        if lexists(&final_dir)? {
            return Ok(self.verify_final_version(version, None)?.installation_id);
        }
        if lexists(&self.versions_dir())? {
            let mut existing_id = None;
            for entry in fs::read_dir(self.versions_dir())? {
                let path = entry?.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(InstallError::Invalid(
                        "versions contains a non-directory entry".into(),
                    ));
                }
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        InstallError::Invalid("version directory is not UTF-8".into())
                    })?;
                let retained = parse_canonical_version(name)?;
                let state = self.verify_final_version(&retained, None)?;
                if let Some(existing) = &existing_id {
                    if existing != &state.installation_id {
                        return Err(InstallError::Invalid(
                            "retained versions belong to different installations".into(),
                        ));
                    }
                } else {
                    existing_id = Some(state.installation_id);
                }
            }
            if let Some(existing_id) = existing_id {
                return Ok(existing_id);
            }
        }
        random_id("installation")
    }

    pub(super) fn ensure_command_owned(
        &self,
        active: Option<&Version>,
        install: Option<&InstallState>,
    ) -> Result<()> {
        let exists = lexists(&self.command_path)?;
        if !exists {
            #[cfg(windows)]
            if active.is_some() && install.is_some() {
                return Err(InstallError::Invalid(
                    "managed Windows launcher is missing and cannot be recreated by an update"
                        .into(),
                ));
            }
            return Ok(());
        }
        let Some(active) = active else {
            #[cfg(windows)]
            if install.is_none() && self.prove_retained_launcher_ownership()? {
                // A first install can create the stable launcher before its version directory is
                // renamed into place.  If the process dies at that boundary, the marker and the
                // retained version prove that this launcher is ours even though install.json and
                // active do not exist yet.
                return Ok(());
            }
            return Err(InstallError::Invalid(format!(
                "refusing to replace existing unmanaged command {}",
                self.command_path.display()
            )));
        };
        let Some(install) = install else {
            return Err(InstallError::Invalid(
                "existing command has no installation ownership record".into(),
            ));
        };
        if install.active.as_ref() != Some(active) {
            return Err(InstallError::Invalid(
                "existing command ownership does not match the active pointer".into(),
            ));
        }
        let version_state = self.verify_final_version(active, Some(&install.installation_id))?;
        #[cfg(unix)]
        {
            let Some(pointer) = executable::read_symlink(&self.command_path)? else {
                return Err(InstallError::Invalid(
                    "managed Unix command is missing its symlink".into(),
                ));
            };
            if !pointer.is_absolute() || !same_path(&pointer, &self.payload_path(active)) {
                return Err(InstallError::Invalid(
                    "existing command symlink is not owned by this installation".into(),
                ));
            }
            let _ = version_state;
        }
        #[cfg(windows)]
        {
            self.verify_installed_launcher(install)?;
            let _ = version_state;
        }
        Ok(())
    }

    pub(super) fn launcher_ownership_for(
        &self,
        version: &Version,
        prior: Option<&InstallState>,
    ) -> Result<Option<LauncherOwnership>> {
        #[cfg(unix)]
        {
            let _ = (version, prior);
            Ok(None)
        }
        #[cfg(windows)]
        {
            if let Some(prior) = prior {
                self.verify_installed_launcher(prior)?;
                return Ok(prior.launcher.clone());
            }
            let state = self.verify_final_version(version, None)?;
            let launcher = state.launcher.ok_or_else(|| {
                InstallError::Invalid("Windows version has no signed launcher metadata".into())
            })?;
            let ownership = LauncherOwnership {
                owned: true,
                path: self.command_path.to_string_lossy().into_owned(),
                sha256: launcher.sha256,
                size: launcher.size,
                protocol: launcher.protocol,
            };
            self.verify_installed_launcher_record(&ownership)?;
            Ok(Some(ownership))
        }
    }

    pub(super) fn verify_installed_launcher(&self, install: &InstallState) -> Result<()> {
        #[cfg(unix)]
        {
            let _ = install;
            Ok(())
        }
        #[cfg(windows)]
        {
            let launcher = install.launcher.as_ref().ok_or_else(|| {
                InstallError::Invalid(
                    "managed Windows installation lacks launcher ownership".into(),
                )
            })?;
            self.verify_installed_launcher_record(launcher)
        }
    }

    #[cfg(windows)]
    pub(super) fn verify_installed_launcher_record(
        &self,
        launcher: &LauncherOwnership,
    ) -> Result<()> {
        if !launcher.owned
            || launcher.protocol != 1
            || launcher.path != self.command_path.to_string_lossy()
        {
            return Err(InstallError::Invalid(
                "Windows launcher ownership/protocol metadata is invalid".into(),
            ));
        }
        executable::ensure_regular_file(&self.command_path)?;
        verify_file_digest(
            &self.command_path,
            launcher.size,
            &launcher.sha256,
            "installed launcher",
        )
    }
}

/// An immutable version directory contains exactly the signed payload, its signed metadata, and
/// the local version state.
fn validate_exact_version_members(app: &App, dir: &Path, target: ReleaseTarget) -> Result<()> {
    let payload_unix = app.payload_name(false);
    let payload_windows = app.payload_name(true);
    let metadata_members = [MANIFEST_FILE, SIGNATURE_FILE, VERSION_FILE];
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| InstallError::Invalid("version member is not UTF-8".into()))?;
        let allowed = if target.is_windows() {
            name == payload_windows || metadata_members.contains(&name)
        } else {
            name == payload_unix || metadata_members.contains(&name)
        };
        if !allowed {
            return Err(InstallError::Invalid(format!(
                "unexpected immutable version member: {name}"
            )));
        }
    }
    let payload = if target.is_windows() {
        payload_windows.as_str()
    } else {
        payload_unix.as_str()
    };
    for name in [payload, MANIFEST_FILE, SIGNATURE_FILE, VERSION_FILE] {
        if !lexists(&dir.join(name))? {
            return Err(InstallError::Invalid(format!(
                "missing immutable version member: {name}"
            )));
        }
    }
    Ok(())
}
