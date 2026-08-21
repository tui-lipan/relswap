//! Bounded, non-following release archive inspection and extraction.

use super::manifest::ReleaseAsset;
use super::target::Target;
use super::{
    MAX_ARCHIVE_MEMBER_NAME, MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_METADATA_SIZE, MAX_ARCHIVE_SIZE,
    MAX_MEMBER_SIZE, MAX_TAR_DECOMPRESSED_SIZE, MAX_TAR_METADATA_SIZE, MAX_UNCOMPRESSED_SIZE,
    ReleaseError, Result, path_is_safe_directory, read_limited, verify_bytes,
};
use crate::App;
use crate::fs::executable;
use flate2::read::GzDecoder;
use std::collections::HashSet;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use zip::CompressionMethod;

/// A member that matched one of the manifest's exact expected paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMember {
    pub path: String,
    pub data: Vec<u8>,
}

/// All expected members after an archive has been completely inspected and hashed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedRelease {
    pub payload: VerifiedMember,
    pub launcher: Option<VerifiedMember>,
}

pub type VerifiedArchive = ExtractedRelease;

/// Verify the published archive bytes before handing them to tar or ZIP parsing.
pub fn verify_archive_bytes(app: &App, bytes: &[u8], asset: &ReleaseAsset) -> Result<()> {
    let target = target_from_asset(app, asset)?;
    asset.validate(
        app,
        &canonical_version_from_asset(app, asset, target),
        target,
    )?;
    if bytes.len() as u64 > MAX_ARCHIVE_SIZE {
        return Err(ReleaseError::archive(format!(
            "archive exceeds maximum size {MAX_ARCHIVE_SIZE}"
        )));
    }
    verify_bytes(
        bytes,
        asset.archive_size,
        &asset.archive_sha256,
        "release archive",
    )
}

/// Read and verify an archive file before parsing it.
pub fn verify_archive_file(app: &App, path: &Path, asset: &ReleaseAsset) -> Result<()> {
    let mut file = executable::open_regular_file_secure(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ReleaseError::archive(format!(
            "release archive is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_ARCHIVE_SIZE {
        return Err(ReleaseError::archive(format!(
            "archive exceeds maximum size {MAX_ARCHIVE_SIZE}"
        )));
    }
    let bytes = read_limited(&mut file, MAX_ARCHIVE_SIZE)?;
    verify_archive_bytes(app, &bytes, asset)
}

/// Inspect every archive member, verify the selected payload and optional launcher, and return
/// their bytes without writing any unrelated member to disk.
pub fn inspect_archive(app: &App, bytes: &[u8], asset: &ReleaseAsset) -> Result<ExtractedRelease> {
    validate_asset_against_manifest_shape(app, asset)?;
    verify_archive_bytes(app, bytes, asset)?;
    if target_from_asset(app, asset)?.is_windows() {
        inspect_zip(app, bytes, asset)
    } else {
        inspect_tar_gz(app, bytes, asset)
    }
}

/// Inspect an archive and write only its exact expected executable members into `destination`.
/// The destination is the install directory; the canonical archive root is not recreated.
pub fn extract_archive(
    app: &App,
    bytes: &[u8],
    asset: &ReleaseAsset,
    destination: &Path,
) -> Result<ExtractedPaths> {
    let release = inspect_archive(app, bytes, asset)?;
    let target = target_from_asset(app, asset)?;
    path_is_safe_directory(destination)?;
    let destination_handle =
        executable::open_extraction_directory(destination).map_err(|error| {
            ReleaseError::archive(format!(
                "could not open extraction destination {}: {error}",
                destination.display()
            ))
        })?;
    let payload_name = target.payload_name(app);
    let launcher_name = if release.launcher.is_some() {
        Some(
            target
                .launcher_name(app)
                .ok_or_else(|| ReleaseError::archive("app does not configure a launcher"))?,
        )
    } else {
        None
    };
    let payload_path = write_member(&destination_handle, &release.payload, &payload_name)?;
    let launcher_path = match &release.launcher {
        Some(launcher) => {
            let name = launcher_name.expect("launcher name checked before payload creation");
            match write_member(&destination_handle, launcher, name) {
                Ok(path) => Some(path),
                Err(error) => {
                    if let Err(cleanup) = destination_handle.remove_file(&payload_name) {
                        return Err(ReleaseError::archive(format!(
                            "{error}; payload rollback failed: {cleanup}"
                        )));
                    }
                    return Err(error);
                }
            }
        }
        None => None,
    };
    let destination_identity = destination_handle.path_still_identifies_directory();
    if !matches!(destination_identity, Ok(true)) {
        let mut cleanup_errors = Vec::new();
        if let Some(name) = launcher_name
            && let Err(error) = destination_handle.remove_file(name)
        {
            cleanup_errors.push(format!("launcher cleanup failed: {error}"));
        }
        if let Err(error) = destination_handle.remove_file(&payload_name) {
            cleanup_errors.push(format!("payload cleanup failed: {error}"));
        }
        let reason = match destination_identity {
            Ok(false) => "extraction destination pathname changed during extraction".to_string(),
            Err(error) => format!("could not revalidate extraction destination: {error}"),
            Ok(true) => unreachable!(),
        };
        if cleanup_errors.is_empty() {
            return Err(ReleaseError::archive(reason));
        }
        return Err(ReleaseError::archive(format!(
            "{reason}; {}",
            cleanup_errors.join("; ")
        )));
    }
    Ok(ExtractedPaths {
        payload: payload_path,
        launcher: launcher_path,
    })
}

/// Verify and extract an archive file.
pub fn extract_archive_file(
    app: &App,
    archive_path: &Path,
    asset: &ReleaseAsset,
    destination: &Path,
) -> Result<ExtractedPaths> {
    let mut file = executable::open_regular_file_secure(archive_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ARCHIVE_SIZE {
        return Err(ReleaseError::archive(format!(
            "invalid or oversized release archive: {}",
            archive_path.display()
        )));
    }
    let bytes = read_limited(&mut file, MAX_ARCHIVE_SIZE)?;
    extract_archive(app, &bytes, asset, destination)
}

/// Paths written by [`extract_archive`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedPaths {
    pub payload: PathBuf,
    pub launcher: Option<PathBuf>,
}

pub type ExtractedFiles = ExtractedPaths;

fn inspect_tar_gz(app: &App, bytes: &[u8], asset: &ReleaseAsset) -> Result<ExtractedRelease> {
    let target = target_from_asset(app, asset)?;
    let version = canonical_version_from_asset(app, asset, target);
    let root = target.root_name(app, &version);
    let mut archive = DecompressedLimit::new(
        GzDecoder::new(Cursor::new(bytes)),
        MAX_TAR_DECOMPRESSED_SIZE,
    );
    let mut names = HashSet::new();
    let mut total_uncompressed = 0u64;
    let mut payload = None;
    let mut launcher = None;
    let mut root_seen = false;
    let expected_launcher = target.launcher_path(app, &version);
    let mut pending_long_name: Option<Vec<u8>> = None;
    let mut pending_long_link: Option<Vec<u8>> = None;
    let mut pending_pax: Option<Vec<u8>> = None;
    let mut global_pax = OwnedPaxOverrides::default();
    let mut index = 0usize;
    loop {
        let mut block = [0u8; 512];
        archive.read_exact(&mut block).map_err(|error| {
            ReleaseError::archive(format!("invalid tar header at index {index}: {error}"))
        })?;
        if block.iter().all(|byte| *byte == 0) {
            if pending_long_name.is_some() || pending_long_link.is_some() || pending_pax.is_some() {
                return Err(ReleaseError::archive(
                    "tar metadata record has no following member",
                ));
            }
            let mut trailing = [0u8; 8192];
            loop {
                let read = archive.read(&mut trailing).map_err(|error| {
                    ReleaseError::archive(format!("invalid trailing tar data: {error}"))
                })?;
                if read == 0 {
                    break;
                }
                if trailing[..read].iter().any(|byte| *byte != 0) {
                    return Err(ReleaseError::archive(
                        "tar archive has nonzero data after its end marker",
                    ));
                }
            }
            break;
        }
        if index >= MAX_ARCHIVE_MEMBERS {
            return Err(ReleaseError::archive(format!(
                "tar archive exceeds maximum member count {MAX_ARCHIVE_MEMBERS}"
            )));
        }
        validate_tar_checksum(&block, index)?;
        let mut header = tar::Header::new_old();
        header.as_mut_bytes().copy_from_slice(&block);
        let entry_type = header.entry_type();
        let header_size = header.size().map_err(|error| {
            ReleaseError::archive(format!("invalid tar member size at index {index}: {error}"))
        })?;
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_pax_global_extensions()
        {
            if header_size > MAX_TAR_METADATA_SIZE {
                return Err(ReleaseError::archive(format!(
                    "tar metadata at index {index} exceeds {MAX_TAR_METADATA_SIZE} bytes"
                )));
            }
            let data = read_tar_record(&mut archive, header_size, index)?;
            if entry_type.is_gnu_longname() {
                if pending_long_name.replace(data).is_some() {
                    return Err(ReleaseError::archive(
                        "duplicate GNU long-name metadata for one tar member",
                    ));
                }
            } else if entry_type.is_gnu_longlink() {
                if pending_long_link.replace(data).is_some() {
                    return Err(ReleaseError::archive(
                        "duplicate GNU long-link metadata for one tar member",
                    ));
                }
            } else if entry_type.is_pax_local_extensions() {
                pax_overrides(&data, index)?;
                if pending_pax.replace(data).is_some() {
                    return Err(ReleaseError::archive(
                        "duplicate local PAX metadata for one tar member",
                    ));
                }
            } else {
                global_pax.update(pax_overrides(&data, index)?);
            }
            index += 1;
            continue;
        }
        let pax = match pending_pax.as_deref() {
            Some(data) => pax_overrides(data, index)?,
            None => PaxOverrides::default(),
        };
        let declared_size = match pax.size {
            Some(size) => size,
            None => global_pax.size,
        }
        .unwrap_or(header_size);
        let pax_path = match pax.path {
            Some(path) => path,
            None => global_pax.path.as_deref(),
        };
        let header_path = header.path_bytes();
        let raw_path = pending_long_name
            .as_deref()
            .map(trim_tar_nul)
            .or(pax_path)
            .unwrap_or(header_path.as_ref())
            .to_vec();
        let path = validate_member_name(&raw_path, &root, index)?;
        pending_long_name = None;
        pending_long_link = None;
        pending_pax = None;
        if !names.insert(path.clone()) {
            return Err(ReleaseError::archive(format!(
                "duplicate archive member: {path}"
            )));
        }

        if entry_type.is_symlink()
            || entry_type.is_hard_link()
            || entry_type.is_character_special()
            || entry_type.is_block_special()
            || entry_type.is_fifo()
            || entry_type.is_contiguous()
            || !entry_type.is_file() && !entry_type.is_dir()
        {
            return Err(ReleaseError::archive(format!(
                "unsupported or unsafe tar entry type for {path}"
            )));
        }

        if raw_path.last() == Some(&b'/') && entry_type.is_file() {
            return Err(ReleaseError::archive(format!(
                "regular tar member has a directory name: {path}"
            )));
        }

        if declared_size > MAX_MEMBER_SIZE {
            return Err(ReleaseError::archive(format!(
                "tar member {path} exceeds maximum size {MAX_MEMBER_SIZE}"
            )));
        }
        if entry_type.is_dir() {
            if declared_size != 0 {
                return Err(ReleaseError::archive(format!(
                    "directory member {path} has nonzero size"
                )));
            }
            if path == root {
                root_seen = true;
            }
            index += 1;
            continue;
        }
        if path == root {
            return Err(ReleaseError::archive(
                "canonical archive root must be a directory".to_string(),
            ));
        }

        total_uncompressed = total_uncompressed
            .checked_add(declared_size)
            .ok_or_else(|| ReleaseError::archive("tar uncompressed size overflow"))?;
        if total_uncompressed > MAX_UNCOMPRESSED_SIZE {
            return Err(ReleaseError::archive(format!(
                "tar contents exceed maximum uncompressed size {MAX_UNCOMPRESSED_SIZE}"
            )));
        }
        let expected = if path == asset.payload.path {
            Some((&asset.payload.size, &asset.payload.sha256, true))
        } else if expected_launcher.as_deref() == Some(path.as_str()) {
            let launcher = asset
                .launcher
                .as_ref()
                .expect("validated Windows launcher path cannot be selected for tar");
            Some((&launcher.size, &launcher.sha256, false))
        } else {
            None
        };
        let mut member_reader = archive.by_ref().take(declared_size);
        let data = read_member_data(&mut member_reader, declared_size, expected.is_some(), &path)?;
        let padding = (512 - declared_size % 512) % 512;
        if padding != 0 {
            let mut padding_bytes = [0u8; 512];
            archive
                .read_exact(&mut padding_bytes[..padding as usize])
                .map_err(|error| {
                    ReleaseError::archive(format!("truncated tar padding after {path}: {error}"))
                })?;
            if padding_bytes[..padding as usize]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ReleaseError::archive(format!(
                    "nonzero tar padding after {path}"
                )));
            }
        }
        if let Some((expected_size, expected_hash, is_payload)) = expected {
            if header.mode().unwrap_or_default() & 0o111 == 0 {
                return Err(ReleaseError::archive(format!(
                    "expected executable member is not executable: {path}"
                )));
            }
            verify_bytes(&data, *expected_size, expected_hash, &path)?;
            let member = VerifiedMember { path, data };
            if is_payload {
                payload = Some(member);
            } else {
                launcher = Some(member);
            }
        }
        index += 1;
    }
    if !root_seen {
        return Err(ReleaseError::archive(format!(
            "archive has no canonical root directory {root}"
        )));
    }
    finish_members(app, payload, launcher, asset)
}

fn inspect_zip(app: &App, bytes: &[u8], asset: &ReleaseAsset) -> Result<ExtractedRelease> {
    let target = target_from_asset(app, asset)?;
    let version = canonical_version_from_asset(app, asset, target);
    let root = target.root_name(app, &version);
    preflight_zip_member_count(bytes)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| ReleaseError::archive(format!("invalid ZIP archive: {error}")))?;
    if archive.len() > MAX_ARCHIVE_MEMBERS {
        return Err(ReleaseError::archive(format!(
            "ZIP archive exceeds maximum member count {MAX_ARCHIVE_MEMBERS}"
        )));
    }
    let mut names = HashSet::new();
    let mut total_uncompressed = 0u64;
    let mut payload = None;
    let mut launcher = None;
    let mut root_seen = false;
    let expected_launcher = target.launcher_path(app, &version);

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            ReleaseError::archive(format!("invalid ZIP entry {index}: {error}"))
        })?;
        let raw_path = entry.name_raw().to_vec();
        let path = validate_member_name(&raw_path, &root, index)?;
        if !names.insert(path.clone()) {
            return Err(ReleaseError::archive(format!(
                "duplicate archive member: {path}"
            )));
        }
        if entry.encrypted() {
            return Err(ReleaseError::archive(format!(
                "encrypted ZIP member is not supported: {path}"
            )));
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(ReleaseError::archive(format!(
                "unsupported ZIP compression for {path}"
            )));
        }
        if entry.is_symlink() {
            return Err(ReleaseError::archive(format!(
                "symbolic-link ZIP member is not supported: {path}"
            )));
        }
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & 0o170000;
            if file_type != 0 && file_type != 0o100000 && file_type != 0o040000 {
                return Err(ReleaseError::archive(format!(
                    "special ZIP member is not supported: {path}"
                )));
            }
            if file_type == 0o040000 && !entry.is_dir() {
                return Err(ReleaseError::archive(format!(
                    "ZIP directory mode disagrees with name: {path}"
                )));
            }
        }

        let declared_size = entry.size();
        if declared_size > MAX_MEMBER_SIZE {
            return Err(ReleaseError::archive(format!(
                "ZIP member {path} exceeds maximum size {MAX_MEMBER_SIZE}"
            )));
        }
        if entry.is_dir() {
            if declared_size != 0 {
                return Err(ReleaseError::archive(format!(
                    "directory member {path} has nonzero size"
                )));
            }
            if path == root {
                root_seen = true;
            }
            continue;
        }
        if path == root {
            return Err(ReleaseError::archive(
                "canonical archive root must be a directory".to_string(),
            ));
        }
        total_uncompressed = total_uncompressed
            .checked_add(declared_size)
            .ok_or_else(|| ReleaseError::archive("ZIP uncompressed size overflow"))?;
        if total_uncompressed > MAX_UNCOMPRESSED_SIZE {
            return Err(ReleaseError::archive(format!(
                "ZIP contents exceed maximum uncompressed size {MAX_UNCOMPRESSED_SIZE}"
            )));
        }

        let expected = if path == asset.payload.path {
            Some((&asset.payload.size, &asset.payload.sha256, true))
        } else if expected_launcher.as_deref() == Some(path.as_str()) {
            let launcher = asset
                .launcher
                .as_ref()
                .expect("validated Windows launcher path always has metadata");
            Some((&launcher.size, &launcher.sha256, false))
        } else {
            None
        };
        let data = read_member_data(&mut entry, declared_size, expected.is_some(), &path)?;
        if let Some((expected_size, expected_hash, is_payload)) = expected {
            verify_bytes(&data, *expected_size, expected_hash, &path)?;
            let member = VerifiedMember { path, data };
            if is_payload {
                payload = Some(member);
            } else {
                launcher = Some(member);
            }
        }
    }
    if !root_seen {
        return Err(ReleaseError::archive(format!(
            "archive has no canonical root directory {root}"
        )));
    }
    finish_members(app, payload, launcher, asset)
}

fn read_member_data<R: Read>(
    reader: &mut R,
    declared_size: u64,
    collect: bool,
    path: &str,
) -> Result<Vec<u8>> {
    let mut data = if collect {
        Vec::with_capacity(declared_size as usize)
    } else {
        Vec::new()
    };
    let mut buffer = [0u8; 64 * 1024];
    let mut actual = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        actual = actual
            .checked_add(read as u64)
            .ok_or_else(|| ReleaseError::archive(format!("member {path} size overflow")))?;
        if actual > MAX_MEMBER_SIZE || actual > declared_size {
            return Err(ReleaseError::archive(format!(
                "member {path} actual size exceeds its declared size"
            )));
        }
        if collect {
            data.extend_from_slice(&buffer[..read]);
        }
    }
    if actual != declared_size {
        return Err(ReleaseError::archive(format!(
            "member {path} actual size {actual} differs from declared size {declared_size}"
        )));
    }
    Ok(data)
}

fn finish_members(
    app: &App,
    payload: Option<VerifiedMember>,
    launcher: Option<VerifiedMember>,
    asset: &ReleaseAsset,
) -> Result<ExtractedRelease> {
    let payload = payload.ok_or_else(|| {
        ReleaseError::archive(format!(
            "archive did not contain exact payload {}",
            asset.payload.path
        ))
    })?;
    let target = target_from_asset(app, asset)?;
    if target.is_windows() && launcher.is_none() {
        return Err(ReleaseError::archive(
            "archive did not contain the exact Windows launcher".to_string(),
        ));
    }
    if !target.is_windows() && launcher.is_some() {
        return Err(ReleaseError::archive(
            "non-Windows archive contained an unexpected launcher".to_string(),
        ));
    }
    Ok(ExtractedRelease { payload, launcher })
}

fn validate_member_name(raw: &[u8], root: &str, index: usize) -> Result<String> {
    if raw.is_empty()
        || raw.len() > MAX_ARCHIVE_MEMBER_NAME
        || raw.contains(&0)
        || raw.contains(&b'\\')
    {
        return Err(ReleaseError::archive(format!(
            "malformed archive member name at index {index}"
        )));
    }
    let raw = std::str::from_utf8(raw).map_err(|_| {
        ReleaseError::archive(format!("non-UTF-8 archive member name at index {index}"))
    })?;
    if raw.starts_with('/') || raw.starts_with("//") {
        return Err(ReleaseError::archive(format!(
            "absolute archive member name: {raw:?}"
        )));
    }
    let without_trailing_slash = raw.strip_suffix('/').unwrap_or(raw);
    if without_trailing_slash.is_empty()
        || without_trailing_slash.contains("//")
        || without_trailing_slash
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ReleaseError::archive(format!(
            "malformed archive member name: {raw:?}"
        )));
    }
    let mut components = without_trailing_slash.split('/');
    let first = components.next().unwrap_or_default();
    if first.contains(':')
        || first != root
        || without_trailing_slash
            .split('/')
            .any(|component| component.contains(':'))
    {
        return Err(ReleaseError::archive(format!(
            "archive member is outside canonical root {root:?}: {raw:?}"
        )));
    }
    Ok(without_trailing_slash.to_string())
}

fn write_member(
    destination: &executable::OpenDirectory,
    member: &VerifiedMember,
    filename: &str,
) -> Result<PathBuf> {
    destination
        .create_new_file(filename, &member.data, Some(0o755))
        .map_err(|error| {
            ReleaseError::archive(format!(
                "could not create extracted member {filename}: {error}"
            ))
        })
}

fn validate_tar_checksum(block: &[u8; 512], index: usize) -> Result<()> {
    let mut header = tar::Header::new_old();
    header.as_mut_bytes().copy_from_slice(block);
    let expected = header.cksum().map_err(|error| {
        ReleaseError::archive(format!("invalid tar checksum at index {index}: {error}"))
    })?;
    let actual = block
        .iter()
        .enumerate()
        .map(|(offset, byte)| {
            if (148..156).contains(&offset) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            }
        })
        .sum::<u32>();
    if actual != expected {
        return Err(ReleaseError::archive(format!(
            "tar checksum mismatch at index {index}"
        )));
    }
    Ok(())
}

fn read_tar_record<R: Read>(reader: &mut R, size: u64, index: usize) -> Result<Vec<u8>> {
    let mut record = reader.by_ref().take(size);
    let data = read_member_data(
        &mut record,
        size,
        true,
        &format!("tar metadata at index {index}"),
    )?;
    let padding = (512 - size % 512) % 512;
    if padding != 0 {
        let mut bytes = [0u8; 512];
        reader
            .read_exact(&mut bytes[..padding as usize])
            .map_err(|error| {
                ReleaseError::archive(format!(
                    "truncated tar metadata padding at index {index}: {error}"
                ))
            })?;
        if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
            return Err(ReleaseError::archive(format!(
                "nonzero tar metadata padding at index {index}"
            )));
        }
    }
    Ok(data)
}

fn trim_tar_nul(value: &[u8]) -> &[u8] {
    value.strip_suffix(&[0]).unwrap_or(value)
}

#[derive(Default)]
struct PaxOverrides<'a> {
    path: Option<Option<&'a [u8]>>,
    size: Option<Option<u64>>,
}

#[derive(Default)]
struct OwnedPaxOverrides {
    path: Option<Vec<u8>>,
    size: Option<u64>,
}

impl OwnedPaxOverrides {
    fn update(&mut self, overrides: PaxOverrides<'_>) {
        if let Some(path) = overrides.path {
            self.path = path.map(<[u8]>::to_vec);
        }
        if let Some(size) = overrides.size {
            self.size = size;
        }
    }
}

fn pax_overrides(data: &[u8], index: usize) -> Result<PaxOverrides<'_>> {
    let mut cursor = 0usize;
    let mut overrides = PaxOverrides::default();
    while cursor < data.len() {
        let relative_space = data[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| {
                ReleaseError::archive(format!("malformed PAX record at tar index {index}"))
            })?;
        let space = cursor + relative_space;
        let length = std::str::from_utf8(&data[cursor..space])
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                ReleaseError::archive(format!("invalid PAX length at tar index {index}"))
            })?;
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                ReleaseError::archive(format!("oversized PAX record at tar index {index}"))
            })?;
        if end <= space + 1 || data[end - 1] != b'\n' {
            return Err(ReleaseError::archive(format!(
                "malformed PAX record at tar index {index}"
            )));
        }
        let field = &data[space + 1..end - 1];
        let equals = field.iter().position(|byte| *byte == b'=').ok_or_else(|| {
            ReleaseError::archive(format!("malformed PAX field at tar index {index}"))
        })?;
        let key = &field[..equals];
        let value = &field[equals + 1..];
        if key == b"path" {
            overrides.path = Some((!value.is_empty()).then_some(value));
        }
        if key == b"size" {
            overrides.size = Some(if value.is_empty() {
                None
            } else {
                Some(
                    std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or_else(|| {
                            ReleaseError::archive(format!("invalid PAX size at tar index {index}"))
                        })?,
                )
            });
        }
        cursor = end;
    }
    Ok(overrides)
}

fn preflight_zip_member_count(bytes: &[u8]) -> Result<()> {
    const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
    const EOCD_SIZE: usize = 22;
    const MAX_COMMENT: usize = u16::MAX as usize;

    let search_start = bytes.len().saturating_sub(EOCD_SIZE + MAX_COMMENT);
    for (relative, window) in bytes[search_start..]
        .windows(EOCD_SIGNATURE.len())
        .enumerate()
        .rev()
    {
        if window != EOCD_SIGNATURE {
            continue;
        }
        let offset = search_start + relative;
        let Some(record) = bytes.get(offset..offset + EOCD_SIZE) else {
            continue;
        };
        let short = |start: usize| u16::from_le_bytes([record[start], record[start + 1]]);
        let long = |start: usize| {
            u32::from_le_bytes([
                record[start],
                record[start + 1],
                record[start + 2],
                record[start + 3],
            ])
        };
        if offset + EOCD_SIZE + short(20) as usize != bytes.len()
            || short(4) != 0
            || short(6) != 0
            || short(8) != short(10)
        {
            continue;
        }
        if short(10) == u16::MAX || long(12) == u32::MAX || long(16) == u32::MAX {
            return Err(ReleaseError::archive(
                "ZIP64 archives are not supported for release assets",
            ));
        }
        let central_start = long(16) as usize;
        let Some(central_end) = central_start.checked_add(long(12) as usize) else {
            continue;
        };
        if central_end != offset {
            continue;
        }
        let Some(actual_members) = zip_central_member_count(bytes, central_start, central_end)?
        else {
            continue;
        };
        if actual_members != usize::from(short(10)) {
            continue;
        }
        if actual_members > MAX_ARCHIVE_MEMBERS {
            return Err(ReleaseError::archive(format!(
                "ZIP archive exceeds maximum member count {MAX_ARCHIVE_MEMBERS}"
            )));
        }
        return Ok(());
    }
    Err(ReleaseError::archive(
        "ZIP archive has no valid end-of-directory record",
    ))
}

fn zip_central_member_count(bytes: &[u8], start: usize, end: usize) -> Result<Option<usize>> {
    const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
    const CENTRAL_HEADER_SIZE: usize = 46;

    let mut cursor = start;
    let mut members = 0usize;
    let mut metadata_size = 0usize;
    while cursor < end {
        let Some(header) = bytes.get(cursor..cursor + CENTRAL_HEADER_SIZE) else {
            return Ok(None);
        };
        if &header[..4] != CENTRAL_SIGNATURE {
            return Ok(None);
        }
        let short = |offset: usize| u16::from_le_bytes([header[offset], header[offset + 1]]);
        let name_size = usize::from(short(28));
        if name_size > MAX_ARCHIVE_MEMBER_NAME {
            return Err(ReleaseError::archive(format!(
                "ZIP member name exceeds {MAX_ARCHIVE_MEMBER_NAME} bytes"
            )));
        }
        let variable = name_size
            .checked_add(usize::from(short(30)))
            .and_then(|size| size.checked_add(usize::from(short(32))))
            .ok_or_else(|| ReleaseError::archive("ZIP central metadata size overflow"))?;
        metadata_size = metadata_size
            .checked_add(variable)
            .ok_or_else(|| ReleaseError::archive("ZIP central metadata size overflow"))?;
        if metadata_size > MAX_ARCHIVE_METADATA_SIZE {
            return Err(ReleaseError::archive(format!(
                "ZIP central metadata exceeds {MAX_ARCHIVE_METADATA_SIZE} bytes"
            )));
        }
        let Some(next) = cursor.checked_add(CENTRAL_HEADER_SIZE + variable) else {
            return Ok(None);
        };
        cursor = next;
        if cursor > end {
            return Ok(None);
        }
        members += 1;
        if members > MAX_ARCHIVE_MEMBERS {
            return Ok(Some(members));
        }
    }
    Ok((cursor == end).then_some(members))
}

struct DecompressedLimit<R> {
    inner: R,
    remaining: u64,
}

impl<R> DecompressedLimit<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for DecompressedLimit<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut excess = [0u8; 1];
            return match self.inner.read(&mut excess)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decompressed tar exceeds processing limit",
                )),
            };
        }
        let allowed =
            usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn validate_asset_against_manifest_shape(app: &App, asset: &ReleaseAsset) -> Result<()> {
    // The asset API intentionally does not accept an independent version. The version embedded in
    // its canonical paths is therefore checked by the caller's manifest before this function is
    // reached. This catches malformed manually constructed assets without trusting archive names.
    if asset.archive_size == 0
        || asset.archive_size > MAX_ARCHIVE_SIZE
        || asset.payload.size == 0
        || asset.payload.size > MAX_MEMBER_SIZE
    {
        return Err(ReleaseError::archive("invalid release asset size"));
    }
    if asset.archive_sha256.len() != 64 || asset.payload.sha256.len() != 64 {
        return Err(ReleaseError::archive("invalid release asset hash"));
    }
    if target_from_asset(app, asset)?.is_windows() {
        let launcher = asset
            .launcher
            .as_ref()
            .ok_or_else(|| ReleaseError::archive("Windows asset has no launcher metadata"))?;
        if Some(launcher.protocol) != app.launcher_protocol()
            || launcher.size == 0
            || launcher.size > MAX_MEMBER_SIZE
        {
            return Err(ReleaseError::archive("invalid Windows launcher metadata"));
        }
    } else if asset.launcher.is_some() {
        return Err(ReleaseError::archive("unexpected launcher metadata"));
    }
    Ok(())
}

fn canonical_version_from_asset(
    app: &App,
    asset: &ReleaseAsset,
    target: Target,
) -> semver::Version {
    // Archive entry names are compared with the manifest's paths. This fallback is only used by
    // public byte-level helpers that receive an asset rather than its parent manifest; parse the
    // version component from the canonical root instead of accepting arbitrary caller input.
    let suffix = format!("-{}", target.as_str());
    let root = asset
        .payload
        .path
        .split('/')
        .next()
        .and_then(|root| root.strip_prefix(app.archive_prefix().as_str()))
        .and_then(|rest| rest.strip_suffix(&suffix))
        .unwrap_or("0.0.0");
    semver::Version::parse(root).unwrap_or_else(|_| semver::Version::new(0, 0, 0))
}

fn target_from_asset(app: &App, asset: &ReleaseAsset) -> Result<Target> {
    Target::ALL
        .into_iter()
        .find(|target| {
            asset.archive
                == target.archive_name(
                    app,
                    &canonical_version_from_archive_name(app, &asset.archive, *target),
                )
        })
        .ok_or_else(|| ReleaseError::archive("release asset has no supported target"))
}

fn canonical_version_from_archive_name(app: &App, name: &str, target: Target) -> semver::Version {
    let suffix = target.archive_suffix();
    let stem = name.strip_suffix(suffix).unwrap_or_default();
    let prefix = app.archive_prefix();
    let version = stem
        .strip_prefix(prefix.as_str())
        .and_then(|value| value.strip_suffix(&format!("-{}", target.as_str())))
        .unwrap_or("0.0.0");
    semver::Version::parse(version).unwrap_or_else(|_| semver::Version::new(0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActivationStrategy;
    use crate::release::{Target, sha256_bytes};
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Cursor, Write};
    use tar::Builder;
    use zip::write::{SimpleFileOptions, ZipWriter};

    const ARCHIVE_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PAYLOAD_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    const TEST_APP: App = App {
        name: "hyprmux",
        version: "0.2.0",
        repository_url: "https://example.test/hyprmux/",
        trust_anchor: br#"{"schema_version":1,"keys":[]}"#,
        activation: ActivationStrategy::WindowsLauncher {
            launcher_name: "hyprmux-launcher.exe",
            protocol: 1,
        },
        self_test: None,
    };

    fn append_test_root<W: Write>(builder: &mut Builder<W>, root: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{root}/"),
                Cursor::new(Vec::<u8>::new()),
            )
            .unwrap();
    }

    fn append_test_payload<W: Write>(builder: &mut Builder<W>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(b"bin"))
            .unwrap();
    }

    fn tar_archive(_version: &semver::Version, path: &str, data: &[u8]) -> Vec<u8> {
        let root = path.split('/').next().unwrap_or(path);
        let builder_path = if path.contains("..") {
            format!("{root}/placeholder")
        } else {
            path.to_string()
        };
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut compressed);
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
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, builder_path, Cursor::new(data))
                .unwrap();
            builder.finish().unwrap();
        }
        let compressed = compressed.finish().unwrap();
        if path.contains("..") {
            rewrite_tar_member_path(&compressed, path)
        } else {
            compressed
        }
    }

    fn rewrite_tar_member_path(compressed: &[u8], path: &str) -> Vec<u8> {
        let mut decoded = Vec::new();
        GzDecoder::new(Cursor::new(compressed))
            .read_to_end(&mut decoded)
            .unwrap();
        assert!(path.len() < 100);
        let header = &mut decoded[512..1024];
        header[..100].fill(0);
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let checksum_field = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_field.as_bytes());

        let mut output = GzEncoder::new(Vec::new(), Compression::default());
        output.write_all(&decoded).unwrap();
        output.finish().unwrap()
    }

    fn zip_archive(path: &str, data: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            if let Some((root, _)) = path.split_once('/') {
                writer.add_directory(format!("{root}/"), options).unwrap();
            }
            writer.start_file(path, options).unwrap();
            writer.write_all(data).unwrap();
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    fn zip_windows_archive(root: &str) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            writer.add_directory(format!("{root}/"), options).unwrap();
            writer
                .start_file(format!("{root}/hyprmux.exe"), options)
                .unwrap();
            writer.write_all(b"bin").unwrap();
            writer
                .start_file(format!("{root}/hyprmux-launcher.exe"), options)
                .unwrap();
            writer.write_all(b"run").unwrap();
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    fn unix_asset(version: &semver::Version, archive: &[u8]) -> ReleaseAsset {
        let mut asset = ReleaseAsset::new(
            &TEST_APP,
            version,
            Target::X86_64UnknownLinuxGnu,
            archive.len() as u64,
            sha256_bytes(archive),
            3,
            sha256_bytes(b"bin"),
        );
        asset.payload.path = Target::X86_64UnknownLinuxGnu.payload_path(&TEST_APP, version);
        asset
    }

    #[test]
    fn tar_payload_hash_and_archive_hash_are_checked() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let root = Target::X86_64UnknownLinuxGnu.root_name(&TEST_APP, &version);
        let archive = tar_archive(&version, &format!("{root}/hyprmux"), b"bin");
        let asset = unix_asset(&version, &archive);
        assert_eq!(
            inspect_archive(&TEST_APP, &archive, &asset)
                .unwrap()
                .payload
                .data,
            b"bin"
        );

        let mut bad_archive = asset.clone();
        bad_archive.archive_sha256 = ARCHIVE_HASH.to_string();
        assert!(inspect_archive(&TEST_APP, &archive, &bad_archive).is_err());
        let mut bad_payload = asset;
        bad_payload.payload.sha256 = PAYLOAD_HASH.to_string();
        assert!(inspect_archive(&TEST_APP, &archive, &bad_payload).is_err());
    }

    #[test]
    fn decompression_limit_is_inclusive_at_exact_boundary() {
        let mut exact = DecompressedLimit::new(Cursor::new(b"abc"), 3);
        let mut output = Vec::new();
        exact.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"abc");

        let mut excessive = DecompressedLimit::new(Cursor::new(b"abcd"), 3);
        let mut output = Vec::new();
        assert!(excessive.read_to_end(&mut output).is_err());
    }

    #[test]
    fn gnu_long_names_and_local_pax_paths_remain_supported() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let target = Target::X86_64UnknownLinuxGnu;
        let root = target.root_name(&TEST_APP, &version);

        let mut gnu = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gnu);
            append_test_root(&mut builder, &root);
            let mut extra = tar::Header::new_gnu();
            extra.set_size(0);
            extra.set_mode(0o644);
            extra.set_cksum();
            let long_path = format!("{root}/{}", "long-name-".repeat(20));
            builder
                .append_data(&mut extra, long_path, Cursor::new(Vec::<u8>::new()))
                .unwrap();
            append_test_payload(&mut builder, &format!("{root}/hyprmux"));
            builder.finish().unwrap();
        }
        let gnu = gnu.finish().unwrap();
        let asset = unix_asset(&version, &gnu);
        assert!(inspect_archive(&TEST_APP, &gnu, &asset).is_ok());

        let pax_record = |key: &str, value: &str| {
            let body = format!("{key}={value}\n");
            let mut length = body.len() + 2;
            loop {
                let record = format!("{length} {body}");
                if record.len() == length {
                    break record;
                }
                length = record.len();
            }
        };
        let global_metadata = format!(
            "{}{}{}{}{}",
            pax_record("path", "outside"),
            pax_record("path", ""),
            pax_record("size", "1"),
            pax_record("size", ""),
            pax_record("mtime", "0")
        );
        let mut global = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut global);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::XGlobalHeader);
            header.set_size(global_metadata.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "GlobalHead",
                    Cursor::new(global_metadata.as_bytes()),
                )
                .unwrap();
            append_test_root(&mut builder, &root);
            append_test_payload(&mut builder, &format!("{root}/hyprmux"));
            builder.finish().unwrap();
        }
        let global = global.finish().unwrap();
        let asset = unix_asset(&version, &global);
        assert!(inspect_archive(&TEST_APP, &global, &asset).is_ok());

        let metadata = format!(
            "{}{}",
            pax_record("path", &format!("{root}/hyprmux")),
            pax_record("size", "3")
        );
        let mut raw = Vec::new();
        {
            let mut append_raw = |header: &tar::Header, data: &[u8]| {
                raw.extend_from_slice(header.as_bytes());
                raw.extend_from_slice(data);
                raw.resize(raw.len() + (512 - data.len() % 512) % 512, 0);
            };
            let mut root_header = tar::Header::new_gnu();
            root_header.set_path(&root).unwrap();
            root_header.set_entry_type(tar::EntryType::Directory);
            root_header.set_size(0);
            root_header.set_mode(0o755);
            root_header.set_cksum();
            append_raw(&root_header, &[]);
            let mut pax_header = tar::Header::new_gnu();
            pax_header.set_path("PaxHeaders/entry").unwrap();
            pax_header.set_entry_type(tar::EntryType::XHeader);
            pax_header.set_size(metadata.len() as u64);
            pax_header.set_mode(0o644);
            pax_header.set_cksum();
            append_raw(&pax_header, metadata.as_bytes());
            let mut payload_header = tar::Header::new_gnu();
            payload_header.set_path(format!("{root}/hyprmux")).unwrap();
            payload_header.set_size(0);
            payload_header.set_mode(0o755);
            payload_header.set_cksum();
            append_raw(&payload_header, b"bin");
        }
        raw.resize(raw.len() + 1024, 0);
        let mut pax = GzEncoder::new(Vec::new(), Compression::default());
        pax.write_all(&raw).unwrap();
        let pax = pax.finish().unwrap();
        let asset = unix_asset(&version, &pax);
        assert!(inspect_archive(&TEST_APP, &pax, &asset).is_ok());
    }

    #[test]
    fn tar_and_zip_member_counts_are_bounded() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let unix_target = Target::X86_64UnknownLinuxGnu;
        let unix_root = unix_target.root_name(&TEST_APP, &version);
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut compressed);
            for index in 0..=MAX_ARCHIVE_MEMBERS {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_cksum();
                builder
                    .append_data(
                        &mut header,
                        format!("{unix_root}/empty-{index}/"),
                        Cursor::new(Vec::<u8>::new()),
                    )
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let tar = compressed.finish().unwrap();
        let tar_asset = unix_asset(&version, &tar);
        let error = inspect_archive(&TEST_APP, &tar, &tar_asset).unwrap_err();
        assert!(error.to_string().contains("member count"));

        let windows_target = Target::X86_64PcWindowsMsvc;
        let windows_root = windows_target.root_name(&TEST_APP, &version);
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for index in 0..=MAX_ARCHIVE_MEMBERS {
                writer
                    .add_directory(format!("{windows_root}/empty-{index}/"), options)
                    .unwrap();
            }
            writer.finish().unwrap();
        }
        let zip = output.into_inner();
        let zip_asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            windows_target,
            zip.len() as u64,
            sha256_bytes(&zip),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(
            &TEST_APP,
            &version,
            windows_target,
            1,
            3,
            sha256_bytes(b"run"),
        );
        let error = inspect_archive(&TEST_APP, &zip, &zip_asset).unwrap_err();
        assert!(error.to_string().contains("member count"));
    }

    #[test]
    fn zip_central_directory_allocations_are_bounded_before_parsing() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let target = Target::X86_64PcWindowsMsvc;
        let root = target.root_name(&TEST_APP, &version);

        let mut long_name_output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut long_name_output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer
                .start_file(
                    format!("{root}/{}", "n".repeat(MAX_ARCHIVE_MEMBER_NAME + 1)),
                    options,
                )
                .unwrap();
            writer.finish().unwrap();
        }
        let long_name = long_name_output.into_inner();
        let asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            long_name.len() as u64,
            sha256_bytes(&long_name),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        let error = inspect_archive(&TEST_APP, &long_name, &asset).unwrap_err();
        assert!(error.to_string().contains("member name"));

        let mut metadata_output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut metadata_output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for index in 0..2100 {
                let prefix = format!("{root}/{index}-");
                writer
                    .start_file(
                        format!("{prefix}{}", "m".repeat(4000 - prefix.len())),
                        options,
                    )
                    .unwrap();
            }
            writer.finish().unwrap();
        }
        let metadata = metadata_output.into_inner();
        let asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            metadata.len() as u64,
            sha256_bytes(&metadata),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        let error = inspect_archive(&TEST_APP, &metadata, &asset).unwrap_err();
        assert!(error.to_string().contains("central metadata"));
    }

    #[test]
    fn extraction_never_replaces_an_existing_output() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let root_name = Target::X86_64UnknownLinuxGnu.root_name(&TEST_APP, &version);
        let archive = tar_archive(&version, &format!("{root_name}/hyprmux"), b"bin");
        let asset = unix_asset(&version, &archive);
        let destination =
            std::env::temp_dir().join(format!("relswap-extract-existing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&destination);
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("hyprmux"), b"original").unwrap();

        assert!(extract_archive(&TEST_APP, &archive, &asset, &destination).is_err());
        assert_eq!(
            std::fs::read(destination.join("hyprmux")).unwrap(),
            b"original"
        );
        let _ = std::fs::remove_dir_all(destination);
    }

    #[test]
    fn extraction_rolls_back_payload_when_launcher_creation_fails() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let target = Target::X86_64PcWindowsMsvc;
        let root_name = target.root_name(&TEST_APP, &version);
        let archive = zip_windows_archive(&root_name);
        let asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            archive.len() as u64,
            sha256_bytes(&archive),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        let destination =
            std::env::temp_dir().join(format!("relswap-extract-rollback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&destination);
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("hyprmux-launcher.exe"), b"original").unwrap();

        assert!(extract_archive(&TEST_APP, &archive, &asset, &destination).is_err());
        assert!(!destination.join("hyprmux.exe").exists());
        assert_eq!(
            std::fs::read(destination.join("hyprmux-launcher.exe")).unwrap(),
            b"original"
        );
        let _ = std::fs::remove_dir_all(destination);
    }

    #[cfg(unix)]
    #[test]
    fn extraction_rejects_symlink_destinations_ancestors_and_outputs() {
        use std::os::unix::fs::symlink;

        let version = semver::Version::parse("1.2.3").unwrap();
        let root_name = Target::X86_64UnknownLinuxGnu.root_name(&TEST_APP, &version);
        let archive = tar_archive(&version, &format!("{root_name}/hyprmux"), b"bin");
        let asset = unix_asset(&version, &archive);
        let root =
            std::env::temp_dir().join(format!("relswap-extract-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();

        symlink(root.join("real"), root.join("destination-link")).unwrap();
        assert!(
            extract_archive(&TEST_APP, &archive, &asset, &root.join("destination-link")).is_err()
        );
        assert!(!root.join("real/hyprmux").exists());

        symlink(root.join("outside"), root.join("ancestor-link")).unwrap();
        assert!(
            extract_archive(
                &TEST_APP,
                &archive,
                &asset,
                &root.join("ancestor-link/nested"),
            )
            .is_err()
        );
        assert!(!root.join("outside/nested/hyprmux").exists());

        std::fs::write(root.join("victim"), b"original").unwrap();
        symlink(root.join("victim"), root.join("real/hyprmux")).unwrap();
        assert!(extract_archive(&TEST_APP, &archive, &asset, &root.join("real")).is_err());
        assert_eq!(std::fs::read(root.join("victim")).unwrap(), b"original");

        let archive_path = root.join("archive.tar.gz");
        std::fs::write(&archive_path, &archive).unwrap();
        symlink(&archive_path, root.join("archive-link.tar.gz")).unwrap();
        assert!(verify_archive_file(&TEST_APP, &root.join("archive-link.tar.gz"), &asset).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tar_traversal_symlink_and_duplicate_members_are_rejected() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let root = Target::X86_64UnknownLinuxGnu.root_name(&TEST_APP, &version);
        let archive = tar_archive(&version, &format!("{root}/../hyprmux"), b"bin");
        let asset = unix_asset(&version, &archive);
        assert!(inspect_archive(&TEST_APP, &archive, &asset).is_err());

        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut compressed);
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
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("somewhere").unwrap();
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!("{root}/hyprmux"),
                    Cursor::new(Vec::<u8>::new()),
                )
                .unwrap();
            builder.finish().unwrap();
        }
        let symlink = compressed.finish().unwrap();
        let symlink_asset = unix_asset(&version, &symlink);
        assert!(inspect_archive(&TEST_APP, &symlink, &symlink_asset).is_err());

        // The single-member helper cannot create a duplicate, but an archive with a second
        // identical header must be rejected before either payload is selected.
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut compressed);
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
            for _ in 0..2 {
                let mut header = tar::Header::new_gnu();
                header.set_size(3);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{root}/hyprmux"), Cursor::new(b"bin"))
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let duplicate = compressed.finish().unwrap();
        let duplicate_asset = unix_asset(&version, &duplicate);
        assert!(inspect_archive(&TEST_APP, &duplicate, &duplicate_asset).is_err());
    }

    #[test]
    fn zip_payload_is_checked_and_traversal_is_rejected() {
        let version = semver::Version::parse("1.2.3").unwrap();
        let target = Target::X86_64PcWindowsMsvc;
        let root = target.root_name(&TEST_APP, &version);
        let complete = zip_windows_archive(&root);
        let complete_asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            complete.len() as u64,
            sha256_bytes(&complete),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        let complete_release = inspect_archive(&TEST_APP, &complete, &complete_asset).unwrap();
        assert_eq!(complete_release.payload.data, b"bin");
        assert_eq!(complete_release.launcher.unwrap().data, b"run");

        let mut commented = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut commented);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer.set_comment("comment containing PK\u{5}\u{6} marker");
            writer.add_directory(format!("{root}/"), options).unwrap();
            writer
                .start_file(format!("{root}/hyprmux.exe"), options)
                .unwrap();
            writer.write_all(b"bin").unwrap();
            writer
                .start_file(format!("{root}/hyprmux-launcher.exe"), options)
                .unwrap();
            writer.write_all(b"run").unwrap();
            writer.finish().unwrap();
        }
        let commented = commented.into_inner();
        let commented_asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            commented.len() as u64,
            sha256_bytes(&commented),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        assert!(inspect_archive(&TEST_APP, &commented, &commented_asset).is_ok());

        let payload = zip_archive(&format!("{root}/hyprmux.exe"), b"bin");
        let mut asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            payload.len() as u64,
            sha256_bytes(&payload),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        // The launcher is required for Windows, so a payload-only archive must fail.
        assert!(inspect_archive(&TEST_APP, &payload, &asset).is_err());
        asset.launcher = None;
        assert!(inspect_archive(&TEST_APP, &payload, &asset).is_err());

        let traversal = zip_archive("../hyprmux.exe", b"bin");
        let mut traversal_asset = ReleaseAsset::new(
            &TEST_APP,
            &version,
            target,
            traversal.len() as u64,
            sha256_bytes(&traversal),
            3,
            sha256_bytes(b"bin"),
        )
        .with_launcher(&TEST_APP, &version, target, 1, 3, sha256_bytes(b"run"));
        traversal_asset.archive_size = traversal.len() as u64;
        assert!(inspect_archive(&TEST_APP, &traversal, &traversal_asset).is_err());
    }
}
