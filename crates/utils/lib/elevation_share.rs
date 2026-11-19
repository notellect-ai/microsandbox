//! Keep what an elevated run leaves behind usable by the same user's normal runs.
//!
//! An elevated Windows token gives every kernel object it creates without explicit security
//! (named pipes, file mappings, events, its own process) a default DACL that grants only
//! BUILTIN\Administrators and SYSTEM. The same user's non-elevated token holds Administrators
//! for deny only, so a later normal `msb` cannot connect to an elevated sandbox's agent or
//! control pipe, open its metrics, or stop it. Granting the token user SID fixes that: both
//! tokens of one account carry the same user SID. A non-elevated process changes nothing.

#[cfg(windows)]
pub use windows::{share_current_process_with_user, share_new_objects_with_user};

/// Non-Windows platforms have no elevated token split; nothing to do.
#[cfg(not(windows))]
pub fn share_new_objects_with_user() -> std::io::Result<()> {
    Ok(())
}

/// Non-Windows platforms have no elevated token split; nothing to do.
#[cfg(not(windows))]
pub fn share_current_process_with_user() -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) mod windows {
    use std::io;
    use std::ptr::null_mut;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1, SE_KERNEL_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
        GetTokenInformation, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetTokenInformation,
        TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
        TokenDefaultDacl, TokenElevation, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Rights a normal run needs on an elevated runtime process: check its identity, wait for
    /// it and stop it. Never memory, thread or handle access, which would let a medium process
    /// take over the elevated one.
    const USER_PROCESS_RIGHTS: &str = "0x101001"; // SYNCHRONIZE | QUERY_LIMITED_INFORMATION | TERMINATE

    pub(super) struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    pub(super) fn open_token(access: u32) -> io::Result<Token> {
        let mut handle = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Token(handle))
    }

    pub(super) fn elevated(token: &Token) -> io::Result<bool> {
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut length = 0;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    pub(super) fn user_sid_string(token: &Token) -> io::Result<String> {
        let mut length = 0;
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut length) };
        if length == 0 || length > 65536 {
            return Err(io::Error::other("invalid account token size"));
        }
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        Ok(value)
    }

    fn descriptor(sddl: &str) -> io::Result<Descriptor> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }

    fn dacl(sd: &Descriptor) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
        if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(acl)
    }

    /// The user SID of an elevated process, or `None` when the process is not elevated.
    fn elevated_user() -> io::Result<Option<String>> {
        let token = open_token(TOKEN_QUERY)?;
        if !elevated(&token)? {
            return Ok(None);
        }
        user_sid_string(&token).map(Some)
    }

    /// Make every kernel object this process creates from now on without explicit security
    /// (pipes, file mappings, events) grant the account's user SID as well as SYSTEM.
    ///
    /// Only an elevated process changes its token; a normal one already grants its user.
    pub fn share_new_objects_with_user() -> io::Result<()> {
        static DONE: OnceLock<Result<(), String>> = OnceLock::new();
        DONE.get_or_init(|| apply_default_dacl().map_err(|e| e.to_string()))
            .clone()
            .map_err(io::Error::other)
    }

    fn apply_default_dacl() -> io::Result<()> {
        let Some(user) = elevated_user()? else {
            return Ok(());
        };
        let sd = descriptor(&format!("D:(A;;GA;;;{user})(A;;GA;;;SY)"))?;
        let token = open_token(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)?;
        let default = TOKEN_DEFAULT_DACL {
            DefaultDacl: dacl(&sd)?,
        };
        if unsafe {
            SetTokenInformation(
                token.0,
                TokenDefaultDacl,
                (&default as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// For the sandbox runtime: share new objects as above, and let the same user's normal
    /// runs find, wait for and stop this process even while it runs elevated.
    ///
    /// The process object gets a Medium mandatory label, since a Medium caller cannot open a
    /// High one for termination at all, and a DACL that grants the user only identity, wait
    /// and terminate rights. Administrators (enabled only in elevated tokens) and SYSTEM keep
    /// full access.
    pub fn share_current_process_with_user() -> io::Result<()> {
        share_new_objects_with_user()?;
        let Some(user) = elevated_user()? else {
            return Ok(());
        };
        let sd = descriptor(&format!(
            "D:(A;;{USER_PROCESS_RIGHTS};;;{user})(A;;GA;;;BA)(A;;GA;;;SY)S:(ML;;NWNR;;;ME)"
        ))?;
        let (mut present, mut defaulted, mut sacl) = (0, 0, null_mut());
        if unsafe { GetSecurityDescriptorSacl(sd.0, &mut present, &mut sacl, &mut defaulted) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let error = unsafe {
            SetSecurityInfo(
                GetCurrentProcess(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl(&sd)?,
                sacl,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

    fn sddl(handle: windows_sys::Win32::Foundation::HANDLE, info: u32) -> String {
        let mut sd = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                info,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        };
        assert_eq!(error, 0, "GetSecurityInfo");
        let mut text = null_mut();
        let mut len = 0;
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    info,
                    &mut text,
                    &mut len,
                )
            },
            0
        );
        let n = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, n) });
        unsafe {
            LocalFree(text.cast());
            LocalFree(sd);
        }
        value
    }

    /// Run elevated (as the Windows CI and test VM are) this checks the real grants; run
    /// normally it checks the calls are harmless no-ops that leave the user granted.
    #[test]
    fn objects_and_runtime_process_grant_the_user_sid() {
        let handle = super::windows::open_token(windows_sys::Win32::Security::TOKEN_QUERY).unwrap();
        let user = super::windows::user_sid_string(&handle).unwrap();
        let elevated = super::windows::elevated(&handle).unwrap();
        super::share_current_process_with_user().expect("share");
        // A second call is a no-op for the default DACL and reapplies the same process SD.
        super::share_current_process_with_user().expect("share again");

        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null());
        let event_dacl = sddl(event, DACL_SECURITY_INFORMATION);
        unsafe { CloseHandle(event) };
        assert!(
            event_dacl.contains(&format!(";;;{})", user)),
            "new objects must grant the user: {event_dacl}"
        );

        if elevated {
            assert!(!event_dacl.contains(";;;BA)"), "{event_dacl}");
            let process = sddl(
                unsafe { GetCurrentProcess() },
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            );
            assert!(
                process.contains(&format!("(A;;0x101001;;;{})", user)),
                "user gets only identity, wait and terminate: {process}"
            );
            assert!(
                process.contains("(ML;;NWNR;;;ME)"),
                "medium label: {process}"
            );
        }
    }
}
