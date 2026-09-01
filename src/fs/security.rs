//! Cross-platform "private directory" security policy (cross-platform plan Phase 3/5).
//!
//! On Unix (Linux/macOS) this enforces a directory that is a real directory (never a symlink,
//! checked via `symlink_metadata` rather than `metadata`), owned by the current uid, with no
//! group/other access bits set (`mode & 0o077 == 0`) - the same policy `control::runtime_dir`
//! enforced inline before this module existed.
//!
//! On Windows the equivalent is a directory created with an explicit, non-inherited DACL granting
//! full control to the current user's SID and nobody else. Validation of an existing directory
//! also rejects a reparse point (junction/symlink) standing in for it, the Windows counterpart of
//! the Unix `symlink_metadata` check. An attacker-planted junction could otherwise redirect a
//! private directory somewhere world-readable.
//!
//! The Windows half type-checks under `cargo check --target x86_64-pc-windows-gnu` but is
//! **unverified at runtime** - no Windows host is available in this workspace.

use std::fs;
use std::io;
use std::path::Path;

/// Current user id, used to assign ownership expectations and per-user fallback paths.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

/// Create (if missing) or validate an existing directory as private to the current user.
#[cfg(unix)]
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    match fs::symlink_metadata(dir) {
        Ok(metadata) => validate_private_dir(dir, &metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            validate_private_dir(dir, &fs::symlink_metadata(dir)?)
        }
        Err(err) => Err(err),
    }
}

/// Write `bytes` to a new file with mode `0600` (Unix) / inherited private ACL (Windows).
///
/// Creates parent directories as private when missing. Uses `create_new` so an existing path
/// is never truncated through a re-resolved path race; callers that need unique names
/// (for example scrollback dumps) should generate them before calling.
#[cfg(unix)]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // Reinforce mode on the open handle (not via path) in case the create mode was masked.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Validate that `dir` (with pre-fetched `metadata` from `symlink_metadata`, never `metadata`, so
/// a symlink cannot substitute for the real directory) is private to the current user.
#[cfg(unix)]
pub fn validate_private_dir(dir: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if metadata.uid() != current_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", dir.display()),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} permissions must not allow group/other access",
                dir.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use super::{Path, fs, io};

    use windows_sys::Win32::Foundation::{GENERIC_ALL, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetTokenInformation, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// An owned `SECURITY_DESCRIPTOR` allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    ///
    /// Wrapping it in a type with a `Drop` is the whole point: the raw pointer must be released with
    /// `LocalFree`, and every user of it (directory creation, named-pipe creation) would otherwise
    /// have to remember to do that on each of its several error paths.
    pub struct PrivateSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl PrivateSecurityDescriptor {
        /// A `SECURITY_ATTRIBUTES` pointing at this descriptor, with non-inheritable handles.
        ///
        /// Borrowed, not owned: the returned struct is only valid while `self` is alive, which the
        /// lifetime here enforces.
        pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }
    }

    impl Drop for PrivateSecurityDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// The current process token's user SID, as a string (`S-1-5-21-...`).
    pub fn current_user_sid() -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = OwnedHandle(token);

            // Two-call idiom: the first call fails with ERROR_INSUFFICIENT_BUFFER but reports the
            // size a TOKEN_USER plus its variable-length SID actually needs.
            let mut needed: u32 = 0;
            GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }

            let token_user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut sid_string: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) == 0 {
                return Err(io::Error::last_os_error());
            }
            let sid = wide_to_string(sid_string);
            LocalFree(sid_string as HLOCAL);
            Ok(sid)
        }
    }

    /// A security descriptor granting full control to the current user and to nobody else.
    ///
    /// `D:P` makes the DACL *protected*: inheritable ACEs from the parent container (which for a
    /// directory under `%LOCALAPPDATA%` would normally include SYSTEM and Administrators) are not
    /// merged in. `(A;OICI;GA;;;<sid>)` grants that one SID `GENERIC_ALL`, inheritable by child
    /// objects and containers so files created inside a private directory stay private.
    pub fn private_security_descriptor() -> io::Result<PrivateSecurityDescriptor> {
        let sid = current_user_sid()?;
        let sddl = format!("O:{sid}D:P(A;OICI;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PrivateSecurityDescriptor(descriptor))
    }

    pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
        match crate::fs::executable::open_directory_handle(dir) {
            Ok(directory) => validate_found_dir(dir, &directory),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let descriptor = private_security_descriptor()?;
                match crate::fs::executable::create_private_directory_handle(dir, descriptor.0) {
                    Ok(directory) => validate_private_dir_handle(&directory),
                    // Someone else created the directory between the open above and this create.
                    // The leaf is created with `FILE_CREATE` rather than `FILE_OPEN_IF` on purpose
                    // - the descriptor only applies on create, so opening-if-exists would silently
                    // adopt whatever DACL a directory already at the path happens to carry - which
                    // means a lost race surfaces as `ERROR_ALREADY_EXISTS` instead of the
                    // now-existing directory. Adopt the winner's directory the only way that keeps
                    // the guarantee: re-open it and put it through the same validation any
                    // pre-existing directory gets.
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                        let directory = crate::fs::executable::open_directory_handle(dir)?;
                        validate_found_dir(dir, &directory)
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Validate a directory this call found rather than created.
    ///
    /// Names the directory in the failure. A bare "does not have a protected private DACL"
    /// describes a Windows ACL invariant most people have no reason to know, says nothing about
    /// which path is at fault, and gives no way forward - while the fix is usually just removing a
    /// folder something else left at the managed path.
    fn validate_found_dir(dir: &Path, directory: &fs::File) -> io::Result<()> {
        validate_private_dir_handle(directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{}: {error}. This directory was not created by the managed installer; \
                     remove it and run the install again.",
                    dir.display()
                ),
            )
        })
    }

    /// Write `bytes` into a private parent directory. Child files inherit the protected DACL.
    ///
    /// Uses `create_new` so an existing path is never truncated through a re-resolved path race.
    pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent")
        })?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private filename must be Unicode",
                )
            })?;
        let directory = crate::fs::executable::open_private_directory(parent)?;
        directory.create_new_file(filename, bytes, None).map(drop)
    }

    /// Validate type, reparse attributes, and DACL through one non-following directory handle.
    pub(crate) fn validate_private_dir_handle(directory: &fs::File) -> io::Result<()> {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

        let metadata = directory.metadata()?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private path is not a directory",
            ));
        }
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory handle refers to a reparse point",
            ));
        }
        validate_private_dacl(directory.as_raw_handle() as HANDLE)
    }

    fn validate_private_dacl(directory: HANDLE) -> io::Result<()> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                directory,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = PrivateSecurityDescriptor(descriptor);
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory does not have a protected private DACL",
            ));
        }
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        if unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if info.AceCount != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory DACL grants access to more than one identity",
            ));
        }
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let required_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if ace.Header.AceType != 0
            || u32::from(ace.Header.AceFlags) & required_flags != required_flags
            || (ace.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
                && ace.Mask & GENERIC_ALL != GENERIC_ALL)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory DACL is not a private full-control ACL",
            ));
        }

        let sid_string = current_user_sid()?;
        let sid_wide = sid_string
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut expected_sid: PSID = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut expected_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let actual_sid = (&raw const ace.SidStart).cast_mut().cast();
        let ace_matches = unsafe { EqualSid(actual_sid, expected_sid) } != 0;
        let owner_matches = !owner.is_null() && unsafe { EqualSid(owner, expected_sid) } != 0;
        unsafe {
            LocalFree(expected_sid);
        }
        if !ace_matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory DACL belongs to a different identity",
            ));
        }
        if !owner_matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is owned by a different identity",
            ));
        }
        Ok(())
    }

    unsafe fn wide_to_string(ptr: *const u16) -> String {
        let mut len = 0;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Closes its `HANDLE` on drop, so the several `?` early-returns above cannot leak it.
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
pub(crate) use windows_impl::validate_private_dir_handle;
#[cfg(windows)]
pub use windows_impl::{
    current_user_sid, ensure_private_dir, private_security_descriptor, write_private_file,
};

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_base(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hyprmux-fs-security-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn creates_missing_directory_with_private_mode() {
        let dir = temp_base("create");
        let _ = fs::remove_dir_all(&dir);

        ensure_private_dir(&dir).expect("create");
        let mode = fs::symlink_metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_private_file_creates_0600_file() {
        let dir = temp_base("private-file");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("dump.txt");

        write_private_file(&path, b"scrollback\n").expect("write");
        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "scrollback\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_group_or_other_accessible_directory() {
        let dir = temp_base("perms");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let err = ensure_private_dir(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_symlink_standing_in_for_the_directory() {
        let dir = temp_base("symlink");
        let target = temp_base("symlink-target");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &dir).unwrap();

        let err = ensure_private_dir(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&target);
    }
}

/// Cross-platform because the guarantee is: whoever loses the create still gets a validated
/// directory back. Unix has always held it - `create_dir_all` accepts an existing directory - and
/// Windows now does too.
#[cfg(test)]
mod concurrent_tests {
    use super::*;

    /// Every thread that asks for a private directory gets one, however many ask at once.
    ///
    /// `ensure_private_dir` looks the directory up and then creates it, so on a path that does not
    /// exist yet every thread takes the create branch. On Windows that create is a `FILE_CREATE`,
    /// which reports `ERROR_ALREADY_EXISTS` rather than accepting the directory the winner just
    /// made; the losers used to propagate that as a hard failure, so a caller's first use of a
    /// managed directory could fail for no reason but timing.
    ///
    /// A race, so it is a stress test rather than a proof: threads that happen to serialise still
    /// pass. It cannot fail spuriously, and with the create branch unguarded it failed on every
    /// one of 20 Windows runs.
    #[test]
    fn losing_the_create_race_still_yields_a_validated_directory() {
        let dir = std::env::temp_dir().join(format!(
            "relswap-fs-security-test-race-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);

        let threads: Vec<_> = (0..16)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || ensure_private_dir(&dir))
            })
            .collect();
        for thread in threads {
            thread
                .join()
                .expect("thread completes")
                .expect("a lost create race is not a failure");
        }
        // The directory the racers agreed on is a real one, not a handle each of them invented.
        ensure_private_dir(&dir).expect("the directory the race left behind is private");

        let _ = fs::remove_dir_all(&dir);
    }
}
