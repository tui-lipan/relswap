//! Signed-release install/update engine with durable activation and crash recovery.
//!
//! Consumers supply an [`App`] identity. This crate never embeds a product trust anchor or
//! package version of its own.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod app;
pub mod fs;
pub mod install;
pub mod release;

pub use app::{ActivationStrategy, App, SelfTest};
pub use install::{
    ActivationBoundary, ActivationResult, CheckResult, FaultInjector, FaultPoint, InstallError,
    InstallState, Installation, LauncherMetadata, LauncherOwnership, Manager, NoFaultInjector,
    PendingActivation, Result as InstallResult, VersionState,
};
pub use release::{
    Asset, DownloadResponse, DownloadedArchive, Downloader, ExtractedFiles, ExtractedPaths,
    ExtractedRelease, FileDigest, LauncherInfo, MAX_ARCHIVE_SIZE, MAX_MEMBER_SIZE,
    MAX_METADATA_SIZE, MAX_UNCOMPRESSED_SIZE, Manifest, PayloadInfo, ReleaseAsset, ReleaseError,
    ReleaseManifest, ReleaseMetadata, ReleaseTarget, Result as ReleaseResult, SelectedAsset,
    SignatureEntry, SignatureEnvelope, Target, TrustedKey, TrustedKeySet, UreqDownloader,
    VerifiedArchive, VerifiedMember, VerifiedSignature, extract_archive, extract_archive_file,
    fetch_exact_metadata, fetch_latest_metadata, fetch_latest_metadata_with_keys,
    fetch_version_metadata_with_keys, inspect_archive, sha256_bytes, sha256_file, sign_manifest,
    sign_manifest_bytes, sign_manifest_multi, verify_archive_bytes, verify_archive_file,
    verify_manifest, verify_manifest_with_keys,
};

/// Windows launcher entry point used by consumer shim binaries.
pub mod launcher {
    pub use crate::fs::executable::run_windows_launcher as run;
}
