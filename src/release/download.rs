//! HTTPS release metadata resolution and bounded archive downloads.

use super::archive::verify_archive_bytes;
use super::manifest::ReleaseManifest;
use super::signature::{
    SignatureEnvelope, TrustedKey, VerifiedSignature, verify_manifest, verify_manifest_with_keys,
};
use super::target::Target;
use super::{MAX_ARCHIVE_SIZE, MAX_METADATA_SIZE, ReleaseError, Result};
use crate::App;
use chrono::Utc;
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use ureq::ResponseExt;
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;

pub const MAX_REDIRECTS: u32 = 8;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The result returned by an injected or production downloader.
#[derive(Clone, Debug)]
pub struct DownloadResponse {
    pub requested_url: Url,
    pub final_url: Url,
    /// Includes whatever redirect history the transport observed. The requested and final URLs
    /// are also considered by the release resolver even when a test seam supplies an empty list.
    pub redirect_history: Vec<Url>,
    pub bytes: Vec<u8>,
}

impl DownloadResponse {
    pub fn new(
        requested_url: Url,
        final_url: Url,
        redirect_history: Vec<Url>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            requested_url,
            final_url,
            redirect_history,
            bytes,
        }
    }
}

/// Injectable network boundary used by metadata and archive operations.
///
/// Deliberately free of progress plumbing: this is the seam tests inject a fake through, and a
/// fake has no transfer to report on. Progress belongs to the real transport, so it lives on
/// [`UreqDownloader`] instead - which also means an [`Installation`] gains a meter by being handed
/// a differently configured downloader, not by growing a parameter.
///
/// [`Installation`]: crate::Installation
pub trait Downloader {
    fn fetch(&self, url: &Url, max_bytes: usize) -> Result<DownloadResponse>;
}

/// Notified as a response body arrives.
///
/// `total` is the `Content-Length` when the server sent one. A chunked response has none, so an
/// observer must be able to represent an unknown total rather than assuming a fraction exists.
///
/// Called once with `downloaded == 0` before any body is read, so an observer can show a started
/// transfer rather than appearing only once the first chunk lands on a slow link. Implementations
/// are called from the thread driving the download and should return promptly; throttle redraws in
/// the observer rather than slowing the transfer.
pub trait ProgressObserver: Send + Sync {
    fn advance(&self, downloaded: u64, total: Option<u64>);
}

/// How much body to accumulate between observer calls.
///
/// Small enough that a slow link still animates, large enough that a fast one does not spend its
/// time in the observer: at 64 KiB an 18 MB archive reports about 290 times.
const PROGRESS_CHUNK: usize = 64 * 1024;

/// A configured ureq/rustls downloader for production operations.
#[derive(Clone)]
pub struct UreqDownloader {
    agent: ureq::Agent,
    /// Notified as bodies arrive. `None` reads the body in one call, exactly as before.
    observer: Option<Arc<dyn ProgressObserver>>,
}

impl UreqDownloader {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_config(production_config()),
            observer: None,
        }
    }

    /// A downloader that reports body progress to `observer`.
    ///
    /// The transport is otherwise identical, which is the point: a consumer that wants a progress
    /// meter should not have to reimplement `Downloader` and with it this module's TLS, redirect,
    /// and timeout policy. Getting `RootCerts::PlatformVerifier` wrong in a reimplementation is
    /// what made every managed install fail with `UnknownIssuer` in rozi 0.0.3.
    pub fn with_progress(observer: Arc<dyn ProgressObserver>) -> Self {
        Self {
            observer: Some(observer),
            ..Self::new()
        }
    }
}

fn production_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        // The bootstrap scripts and package managers use the host trust store. The managed
        // downloader must agree with them so a machine with an administrator-installed CA
        // (for example a corporate HTTPS inspection root) does not bootstrap successfully
        // and then fail while fetching the signed manifest. Signature verification remains
        // an independent requirement after TLS succeeds.
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .https_only(true)
        .max_redirects(MAX_REDIRECTS)
        .max_redirects_will_error(true)
        .save_redirect_history(true)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .timeout_connect(Some(REQUEST_TIMEOUT))
        .timeout_recv_response(Some(REQUEST_TIMEOUT))
        .timeout_recv_body(Some(REQUEST_TIMEOUT))
        .build()
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(u64, Option<u64>)>>);

    impl ProgressObserver for Recorder {
        fn advance(&self, downloaded: u64, total: Option<u64>) {
            self.0
                .lock()
                .expect("recorder lock")
                .push((downloaded, total));
        }
    }

    /// Drive the chunked reader over an in-memory body, which is what a `Body` wraps anyway.
    fn read_observed(
        payload: &[u8],
        max_bytes: usize,
        observer: &dyn ProgressObserver,
    ) -> Result<Vec<u8>> {
        let total = Some(payload.len() as u64);
        let mut body = ureq::Body::builder()
            .limit(progress_read_limit(max_bytes).expect("limit"))
            .reader(std::io::Cursor::new(payload.to_vec()));
        read_response_body_observed(max_bytes, &mut body, total, observer)
    }

    #[test]
    fn a_body_is_delivered_intact_and_reported_from_zero() {
        let payload = vec![7u8; PROGRESS_CHUNK * 2 + 11];
        let recorder = Recorder::default();
        let bytes = read_observed(&payload, payload.len(), &recorder).expect("read");
        assert_eq!(bytes, payload, "streaming must not alter the body");

        let seen = recorder.0.lock().expect("lock");
        // The leading zero is what lets a meter appear before the first chunk lands on a slow link.
        assert_eq!(seen.first(), Some(&(0, Some(payload.len() as u64))));
        assert_eq!(
            seen.last(),
            Some(&(payload.len() as u64, Some(payload.len() as u64)))
        );
        assert!(
            seen.len() > 2,
            "a multi-chunk body reports more than its endpoints"
        );
        // Progress only ever moves forward, which a meter relies on.
        assert!(seen.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    #[test]
    fn an_oversized_body_is_refused_rather_than_truncated() {
        // The ceiling is the reason this path reads one byte past `max_bytes`. Truncating instead
        // would surface later as a checksum failure and name the wrong cause.
        //
        // Which of the two guards fires is an implementation detail: the reader's own limit trips
        // first and reports "larger than request limit", and the explicit length check behind it
        // catches anything that limit ever stopped enforcing. What must hold is that the body is
        // refused, and refused the same way the unobserved path refuses it.
        let payload = vec![0u8; 4096];
        let recorder = Recorder::default();
        let observed = read_observed(&payload, 1024, &recorder).expect_err("must refuse");

        let plain = read_response_body(1024, |limit| {
            ureq::Body::builder()
                .limit(limit)
                .reader(std::io::Cursor::new(payload.clone()))
                .with_config()
                .limit(limit)
                .read_to_vec()
        })
        .expect_err("the unobserved path must refuse it too");
        assert_eq!(observed.to_string(), plain.to_string());
    }

    #[test]
    fn a_body_exactly_at_the_ceiling_is_accepted() {
        let payload = vec![3u8; 2048];
        let recorder = Recorder::default();
        let bytes = read_observed(&payload, 2048, &recorder).expect("exactly at the limit is fine");
        assert_eq!(bytes.len(), 2048);
    }

    #[test]
    fn an_empty_body_still_reports_its_start() {
        let recorder = Recorder::default();
        let bytes = read_observed(&[], 1024, &recorder).expect("read");
        assert!(bytes.is_empty());
        assert_eq!(recorder.0.lock().expect("lock").as_slice(), &[(0, Some(0))]);
    }

    #[test]
    fn the_observed_and_unobserved_paths_share_one_ceiling() {
        // Both readers must reject the same bodies; a divergence here would mean the progress
        // downloader quietly accepted archives the plain one refuses.
        assert_eq!(progress_read_limit(1024).expect("limit"), 1025);
        assert!(progress_read_limit(usize::MAX).is_err());
    }

    #[test]
    fn a_downloader_without_an_observer_is_the_default() {
        assert!(UreqDownloader::new().observer.is_none());
        let observer: Arc<dyn ProgressObserver> = Arc::new(Recorder::default());
        assert!(UreqDownloader::with_progress(observer).observer.is_some());
    }

    #[test]
    fn a_progress_downloader_keeps_the_production_transport() {
        // The whole reason `with_progress` exists rather than consumers reimplementing
        // `Downloader`: reimplementing it is how the platform verifier gets dropped by accident.
        let observer: Arc<dyn ProgressObserver> = Arc::new(Recorder::default());
        let downloader = UreqDownloader::with_progress(observer);
        assert!(matches!(
            downloader.agent.config().tls_config().root_certs(),
            RootCerts::PlatformVerifier
        ));
        assert!(downloader.agent.config().https_only());
    }
}

#[cfg(test)]
mod production_tls_tests {
    use super::*;

    #[test]
    fn production_downloads_use_the_platform_certificate_verifier() {
        let config = production_config();

        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::PlatformVerifier
        ));
    }
}

impl Default for UreqDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl Downloader for UreqDownloader {
    fn fetch(&self, url: &Url, max_bytes: usize) -> Result<DownloadResponse> {
        require_https(url)?;
        let mut response = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|error| ReleaseError::download(error.to_string()))?;
        let final_url = Url::parse(response.get_uri().to_string().as_str()).map_err(|error| {
            ReleaseError::download(format!("invalid final response URL: {error}"))
        })?;
        require_https(&final_url)?;
        let redirect_history = response
            .get_redirect_history()
            .unwrap_or(&[])
            .iter()
            .map(|uri| {
                Url::parse(uri.to_string().as_str()).map_err(|error| {
                    ReleaseError::download(format!("invalid redirect URL: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let body = response.body_mut();
        let total = body.content_length();
        let bytes = match self.observer.as_deref() {
            None => read_response_body(max_bytes, |limit| {
                body.with_config().limit(limit).read_to_vec()
            })?,
            Some(observer) => read_response_body_observed(max_bytes, body, total, observer)?,
        };
        Ok(DownloadResponse::new(
            url.clone(),
            final_url,
            redirect_history,
            bytes,
        ))
    }
}

/// Read a body in chunks, notifying `observer` as it arrives.
///
/// Enforces the same ceiling as [`read_response_body`] by the same means - reading one byte past it
/// so an oversized body is caught rather than silently truncated to exactly the limit, which would
/// surface later as a checksum failure and name the wrong cause.
fn read_response_body_observed(
    max_bytes: usize,
    body: &mut ureq::Body,
    total: Option<u64>,
    observer: &dyn ProgressObserver,
) -> Result<Vec<u8>> {
    let read_limit = progress_read_limit(max_bytes)?;
    let mut reader = body.with_config().limit(read_limit).reader();
    // Trust the declared length only as far as the ceiling: a server claiming gigabytes must not
    // get them preallocated on the strength of a header.
    let mut bytes = Vec::with_capacity(
        total
            .and_then(|total| usize::try_from(total).ok())
            .unwrap_or(PROGRESS_CHUNK)
            .min(max_bytes),
    );
    let mut chunk = vec![0u8; PROGRESS_CHUNK];

    observer.advance(0, total);
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| ReleaseError::download(error.to_string()))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        observer.advance(bytes.len() as u64, total);
    }

    if bytes.len() > max_bytes {
        return Err(ReleaseError::download(format!(
            "response body exceeds maximum size {max_bytes}"
        )));
    }
    Ok(bytes)
}

/// The read ceiling shared by both body readers: one byte past `max_bytes`, as a `u64`.
fn progress_read_limit(max_bytes: usize) -> Result<u64> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| ReleaseError::download("download size limit overflow"))?;
    u64::try_from(read_limit).map_err(|_| ReleaseError::download("download size limit exceeds u64"))
}

fn read_response_body<F, E>(max_bytes: usize, read: F) -> Result<Vec<u8>>
where
    F: FnOnce(u64) -> std::result::Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    let read_limit = progress_read_limit(max_bytes)?;
    let bytes = read(read_limit).map_err(|error| ReleaseError::download(error.to_string()))?;
    if bytes.len() > max_bytes {
        return Err(ReleaseError::download(format!(
            "response body exceeds maximum size {max_bytes}"
        )));
    }
    Ok(bytes)
}

/// Metadata whose manifest bytes have been signature-checked and parsed.
#[derive(Clone, Debug)]
pub struct ReleaseMetadata {
    pub version: semver::Version,
    pub manifest_bytes: Vec<u8>,
    pub manifest: ReleaseManifest,
    pub signature_bytes: Vec<u8>,
    pub signature: SignatureEnvelope,
    pub verified_signature: VerifiedSignature,
    /// Exact version-specific GitHub release download base, including its trailing slash.
    pub release_base: Url,
}

/// An archive whose bytes have been checked against the selected manifest asset.
#[derive(Clone, Debug)]
pub struct DownloadedArchive {
    pub target: Target,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Fetch and verify the latest release metadata. This never downloads an archive.
pub fn fetch_latest_metadata<D: Downloader>(
    app: &App,
    downloader: &D,
    repository: &Url,
) -> Result<ReleaseMetadata> {
    let response = downloader.fetch(&latest_metadata_url(app, repository)?, MAX_METADATA_SIZE)?;
    resolve_latest_response(app, downloader, repository, response, None)
}

/// Inject trusted keys while resolving latest metadata. This is the deterministic test/tooling seam.
pub fn fetch_latest_metadata_with_keys<D: Downloader>(
    app: &App,
    downloader: &D,
    repository: &Url,
    trusted_keys: &[TrustedKey],
) -> Result<ReleaseMetadata> {
    let response = downloader.fetch(&latest_metadata_url(app, repository)?, MAX_METADATA_SIZE)?;
    resolve_latest_response(app, downloader, repository, response, Some(trusted_keys))
}

/// Fetch and verify a specific release version without consulting the moving `latest` endpoint.
pub fn fetch_exact_metadata<D: Downloader>(
    app: &App,
    downloader: &D,
    repository: &Url,
    version: &semver::Version,
) -> Result<ReleaseMetadata> {
    let response = downloader.fetch(
        &exact_metadata_url(app, repository, version)?,
        MAX_METADATA_SIZE,
    )?;
    fetch_version_metadata_response(app, downloader, repository, response, version, None)
}

pub fn fetch_version_metadata_with_keys<D: Downloader>(
    app: &App,
    downloader: &D,
    repository: &Url,
    version: &semver::Version,
    trusted_keys: &[TrustedKey],
) -> Result<ReleaseMetadata> {
    let response = downloader.fetch(
        &exact_metadata_url(app, repository, version)?,
        MAX_METADATA_SIZE,
    )?;
    fetch_version_metadata_response(
        app,
        downloader,
        repository,
        response,
        version,
        Some(trusted_keys),
    )
}

/// Download and verify one selected target archive after metadata resolution.
pub fn download_archive<D: Downloader>(
    app: &App,
    downloader: &D,
    metadata: &ReleaseMetadata,
    target: Target,
) -> Result<DownloadedArchive> {
    let selected = metadata.manifest.asset_for(app, target)?;
    let asset = selected.asset;
    let url = metadata
        .release_base
        .join(&asset.archive)
        .map_err(|error| ReleaseError::download(format!("invalid archive URL: {error}")))?;
    let response = downloader.fetch(&url, MAX_ARCHIVE_SIZE as usize)?;
    validate_response_transport(&response)?;
    reject_cross_release_redirects(app, &response, &metadata.version)?;
    verify_archive_bytes(app, &response.bytes, asset)?;
    Ok(DownloadedArchive {
        target,
        name: asset.archive.clone(),
        bytes: response.bytes,
    })
}

pub fn latest_metadata_url(app: &App, repository: &Url) -> Result<Url> {
    repository_base(repository)?
        .join(&format!(
            "releases/latest/download/{}",
            app.metadata_filename()
        ))
        .map_err(|error| ReleaseError::download(format!("invalid latest metadata URL: {error}")))
}

pub fn exact_metadata_url(app: &App, repository: &Url, version: &semver::Version) -> Result<Url> {
    let base = repository_base(repository)?;
    base.join(format!("releases/download/v{version}/{}", app.metadata_filename()).as_str())
        .map_err(|error| ReleaseError::download(format!("invalid release metadata URL: {error}")))
}

fn resolve_latest_response<D: Downloader>(
    app: &App,
    downloader: &D,
    _repository: &Url,
    response: DownloadResponse,
    trusted_keys: Option<&[TrustedKey]>,
) -> Result<ReleaseMetadata> {
    validate_response_transport(&response)?;
    let candidates = versioned_manifest_candidates(app, &response)?;
    let mut versions = BTreeSet::new();
    for (version, _) in &candidates {
        versions.insert(version.to_string());
    }
    if versions.len() != 1 {
        return Err(ReleaseError::download(
            "latest metadata redirect history names multiple release versions",
        ));
    }
    let (version, release_url) = candidates.into_iter().next().ok_or_else(|| {
        ReleaseError::download("latest metadata did not resolve to a versioned release URL")
    })?;
    let release_base = release_base_from_manifest_url(app, &release_url)?;
    fetch_verified_metadata(
        app,
        downloader,
        response.bytes,
        release_base,
        version,
        trusted_keys,
    )
}

fn fetch_version_metadata_response<D: Downloader>(
    app: &App,
    downloader: &D,
    repository: &Url,
    response: DownloadResponse,
    version: &semver::Version,
    trusted_keys: Option<&[TrustedKey]>,
) -> Result<ReleaseMetadata> {
    validate_response_transport(&response)?;
    reject_cross_release_redirects(app, &response, version)?;
    let release_base = repository_base(repository)?
        .join(format!("releases/download/v{version}/").as_str())
        .map_err(|error| ReleaseError::download(format!("invalid release base URL: {error}")))?;
    fetch_verified_metadata(
        app,
        downloader,
        response.bytes,
        release_base,
        version.clone(),
        trusted_keys,
    )
}

fn fetch_verified_metadata<D: Downloader>(
    app: &App,
    downloader: &D,
    manifest_bytes: Vec<u8>,
    release_base: Url,
    version: semver::Version,
    trusted_keys: Option<&[TrustedKey]>,
) -> Result<ReleaseMetadata> {
    if manifest_bytes.len() > MAX_METADATA_SIZE {
        return Err(ReleaseError::download(
            "release manifest exceeds metadata limit",
        ));
    }
    let signature_url = release_base
        .join(app.signature_filename().as_str())
        .map_err(|error| ReleaseError::download(format!("invalid signature URL: {error}")))?;
    let signature_response = downloader.fetch(&signature_url, MAX_METADATA_SIZE)?;
    validate_response_transport(&signature_response)?;
    reject_cross_release_redirects(app, &signature_response, &version)?;
    let verified_signature = match trusted_keys {
        Some(keys) => verify_manifest_with_keys(&manifest_bytes, &signature_response.bytes, keys)?,
        None => verify_manifest(app, &manifest_bytes, &signature_response.bytes)?,
    };
    let signature = SignatureEnvelope::from_bytes(&signature_response.bytes)?;
    let manifest = ReleaseManifest::from_bytes(app, &manifest_bytes)?;
    manifest.ensure_not_expired(Utc::now())?;
    if manifest.version != version {
        return Err(ReleaseError::download(format!(
            "release manifest version {} differs from resolved version {version}",
            manifest.version
        )));
    }
    Ok(ReleaseMetadata {
        version,
        manifest_bytes,
        manifest,
        signature_bytes: signature_response.bytes,
        signature,
        verified_signature,
        release_base,
    })
}

fn repository_base(repository: &Url) -> Result<Url> {
    require_https(repository)?;
    if repository.query().is_some() || repository.fragment().is_some() {
        return Err(ReleaseError::download(
            "repository URL must not contain a query or fragment",
        ));
    }
    let mut base = repository.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    Ok(base)
}

fn release_base_from_manifest_url(app: &App, url: &Url) -> Result<Url> {
    let (version, _) = versioned_manifest_url(app, url)?
        .ok_or_else(|| ReleaseError::download("URL is not a version-specific release manifest"))?;
    let suffix = format!("/releases/download/v{version}/{}", app.metadata_filename());
    let path = url.path();
    let base_path = path
        .strip_suffix(&suffix)
        .map(|prefix| format!("{prefix}/releases/download/v{version}/"))
        .ok_or_else(|| ReleaseError::download("cannot derive exact release base URL"))?;
    let mut base = url.clone();
    base.set_query(None);
    base.set_fragment(None);
    base.set_path(&base_path);
    Ok(base)
}

fn validate_response_transport(response: &DownloadResponse) -> Result<()> {
    require_https(&response.requested_url)?;
    require_https(&response.final_url)?;
    for url in &response.redirect_history {
        require_https(url)?;
    }
    Ok(())
}

fn reject_cross_release_redirects(
    app: &App,
    response: &DownloadResponse,
    expected: &semver::Version,
) -> Result<()> {
    for url in response_history(response) {
        if let Some((version, _)) = versioned_manifest_url(app, url)? {
            if version != *expected {
                return Err(ReleaseError::download(format!(
                    "redirect history points at release {version}, expected {expected}"
                )));
            }
        } else if let Some(version) = versioned_release_version(url)?
            && version != *expected
        {
            return Err(ReleaseError::download(format!(
                "redirect history points at release {version}, expected {expected}"
            )));
        }
    }
    Ok(())
}

fn versioned_manifest_candidates(
    app: &App,
    response: &DownloadResponse,
) -> Result<Vec<(semver::Version, Url)>> {
    let mut output = Vec::new();
    for url in response_history(response) {
        if let Some((version, _)) = versioned_manifest_url(app, url)? {
            output.push((version, url.clone()));
        }
    }
    Ok(output)
}

fn response_history(response: &DownloadResponse) -> Vec<&Url> {
    let mut output = Vec::with_capacity(response.redirect_history.len() + 2);
    output.extend(response.redirect_history.iter());
    output.push(&response.requested_url);
    output.push(&response.final_url);
    output
}

fn versioned_manifest_url(app: &App, url: &Url) -> Result<Option<(semver::Version, Url)>> {
    let metadata_filename = app.metadata_filename();
    let segments = url
        .path_segments()
        .ok_or_else(|| ReleaseError::download("release URL has no path segments"))?
        .collect::<Vec<_>>();
    for index in 0..segments.len().saturating_sub(3) {
        if segments[index] != "releases"
            || segments[index + 1] != "download"
            || segments[index + 3] != metadata_filename
            || index + 4 != segments.len()
        {
            continue;
        }
        let tag = segments[index + 2];
        let raw = tag
            .strip_prefix('v')
            .ok_or_else(|| ReleaseError::download("versioned release URL is missing v prefix"))?;
        let version = semver::Version::parse(raw).map_err(|error| {
            ReleaseError::download(format!("invalid release URL version: {error}"))
        })?;
        if version.to_string() != raw || url.query().is_some() || url.fragment().is_some() {
            return Err(ReleaseError::download(
                "release manifest redirect URL is not canonical",
            ));
        }
        return Ok(Some((version, url.clone())));
    }
    Ok(None)
}

fn versioned_release_version(url: &Url) -> Result<Option<semver::Version>> {
    let Some(segments) = url.path_segments() else {
        return Ok(None);
    };
    let segments = segments.collect::<Vec<_>>();
    for index in 0..segments.len().saturating_sub(2) {
        if segments[index] == "releases" && segments[index + 1] == "download" {
            let Some(tag) = segments[index + 2].strip_prefix('v') else {
                return Err(ReleaseError::download(
                    "versioned release redirect is missing v prefix",
                ));
            };
            let version = semver::Version::parse(tag).map_err(|error| {
                ReleaseError::download(format!("invalid release redirect version: {error}"))
            })?;
            if version.to_string() != tag {
                return Err(ReleaseError::download(
                    "release redirect version is not canonical",
                ));
            }
            return Ok(Some(version));
        }
    }
    Ok(None)
}

fn require_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(ReleaseError::download(format!(
            "release downloads require HTTPS, got {}",
            url.scheme()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActivationStrategy;
    use crate::release::signature::{TrustedKey, sign_manifest_bytes};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    const TEST_APP: App = App {
        name: "hyprmux",
        version: "1.2.3",
        repository_url: "https://example.test/hyprmux/",
        trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
        activation: ActivationStrategy::UnixSymlink,
        self_test: None,
    };

    struct MockDownloader {
        responses: Mutex<HashMap<String, DownloadResponse>>,
    }

    impl MockDownloader {
        fn new(responses: HashMap<String, DownloadResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl Downloader for MockDownloader {
        fn fetch(&self, url: &Url, max_bytes: usize) -> Result<DownloadResponse> {
            let response = self
                .responses
                .lock()
                .unwrap()
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| ReleaseError::download(format!("unexpected URL {url}")))?;
            if response.bytes.len() > max_bytes {
                return Err(ReleaseError::download(
                    "mock response exceeded requested limit",
                ));
            }
            Ok(response)
        }
    }

    fn fixture() -> (Url, semver::Version, Vec<u8>, Vec<u8>, TrustedKey, String) {
        let repository = Url::parse("https://example.test/hyprmux/").unwrap();
        let version = semver::Version::parse("1.2.3").unwrap();
        let archive = b"archive bytes".to_vec();
        let asset = crate::release::manifest::ReleaseAsset::new(
            &TEST_APP,
            &version,
            Target::X86_64UnknownLinuxGnu,
            archive.len() as u64,
            crate::release::sha256_bytes(&archive),
            3,
            crate::release::sha256_bytes(b"bin"),
        );
        let target = Target::X86_64UnknownLinuxGnu;
        let manifest = ReleaseManifest::new(
            &TEST_APP,
            version.clone(),
            "2026-08-02T12:00:00Z",
            "2099-08-02T12:00:00Z",
            BTreeMap::from([(target, asset.clone())]),
        )
        .unwrap();
        let manifest_bytes = manifest.to_bytes(&TEST_APP).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let trusted = TrustedKey::ed25519("stable", signing.verifying_key().to_bytes());
        let signature = sign_manifest_bytes(&manifest_bytes, "stable", &signing).unwrap();
        (
            repository,
            version,
            manifest_bytes,
            signature,
            trusted,
            asset.archive,
        )
    }

    fn response(
        requested: &str,
        final_url: &str,
        history: &[&str],
        bytes: Vec<u8>,
    ) -> DownloadResponse {
        DownloadResponse::new(
            Url::parse(requested).unwrap(),
            Url::parse(final_url).unwrap(),
            history.iter().map(|url| Url::parse(url).unwrap()).collect(),
            bytes,
        )
    }

    #[test]
    fn response_body_limit_accepts_exact_size_and_rejects_one_extra() {
        let exact = read_response_body(4, |limit| {
            assert_eq!(limit, 5);
            Ok::<_, &'static str>(vec![0; 4])
        })
        .unwrap();
        assert_eq!(exact.len(), 4);

        let too_large = read_response_body(4, |limit| {
            assert_eq!(limit, 5);
            Ok::<_, &'static str>(vec![0; 5])
        });
        assert!(
            matches!(too_large, Err(ReleaseError::Download(message)) if message.contains("exceeds maximum size 4"))
        );
    }

    #[test]
    fn latest_resolution_uses_exact_redirected_release_base() {
        let (repository, version, manifest, signature, trusted, archive_name) = fixture();
        let latest = latest_metadata_url(&TEST_APP, &repository).unwrap();
        let metadata_filename = TEST_APP.metadata_filename();
        let signature_filename = TEST_APP.signature_filename();
        let exact = format!(
            "https://example.test/hyprmux/releases/download/v{version}/{metadata_filename}"
        );
        let signature_url = format!(
            "https://example.test/hyprmux/releases/download/v{version}/{signature_filename}"
        );
        let archive_url =
            format!("https://example.test/hyprmux/releases/download/v{version}/{archive_name}");
        let archive = b"archive bytes".to_vec();
        let mut responses = HashMap::new();
        responses.insert(
            latest.to_string(),
            response(
                latest.as_str(),
                &exact,
                &[latest.as_str(), &exact],
                manifest,
            ),
        );
        responses.insert(
            signature_url.clone(),
            response(&signature_url, &signature_url, &[&signature_url], signature),
        );
        responses.insert(
            archive_url.clone(),
            response(&archive_url, &archive_url, &[&archive_url], archive),
        );
        let downloader = MockDownloader::new(responses);
        let metadata =
            fetch_latest_metadata_with_keys(&TEST_APP, &downloader, &repository, &[trusted])
                .unwrap();
        assert_eq!(metadata.version, version);
        let downloaded = download_archive(
            &TEST_APP,
            &downloader,
            &metadata,
            Target::X86_64UnknownLinuxGnu,
        );
        assert!(downloaded.is_ok());
    }

    #[test]
    fn latest_cross_release_redirect_is_rejected() {
        let (repository, version, manifest, _signature, _trusted, _archive_name) = fixture();
        let latest = latest_metadata_url(&TEST_APP, &repository).unwrap();
        let metadata_filename = TEST_APP.metadata_filename();
        let other =
            format!("https://example.test/hyprmux/releases/download/v2.0.0/{metadata_filename}");
        let exact = format!(
            "https://example.test/hyprmux/releases/download/v{version}/{metadata_filename}"
        );
        let mut responses = HashMap::new();
        responses.insert(
            latest.to_string(),
            response(
                latest.as_str(),
                &exact,
                &[latest.as_str(), &other, &exact],
                manifest,
            ),
        );
        let downloader = MockDownloader::new(responses);
        assert!(fetch_latest_metadata_with_keys(&TEST_APP, &downloader, &repository, &[]).is_err());
    }
}
