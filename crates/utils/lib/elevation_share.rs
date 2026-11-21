//! Let a non-elevated run reach a sandbox that an elevated run of the same account started.
//!
//! With UAC, one account logs on with a split token: a filtered token (Medium integrity,
//! BUILTIN\Administrators for deny only) and a full one (High integrity, Administrators
//! enabled). Objects the full token creates without explicit security are owned by
//! Administrators, and their default DACL or, for named pipes, the pipe default DACL grants
//! Administrators, SYSTEM and the owner. The filtered token of the same account then cannot
//! open the sandbox's pipes or the metrics registry, and cannot stop the runtime process.
//!
//! This module gives only the objects a non-elevated run needs an explicit security
//! descriptor that also grants the account's user SID, and makes the runtime process
//! stoppable but nothing more. It never changes the process token's defaults. It acts only in
//! a process whose token is the full half of a split token (`TokenElevationTypeFull`), so it
//! covers one account's elevated and non-elevated runs; over-the-shoulder elevation as a
//! different account and non-UAC administrator tokens are left unchanged.

use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetSecurityDescriptorSacl, GetTokenInformation, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION_TYPE,
    TOKEN_QUERY, TOKEN_USER, TokenElevationType, TokenElevationTypeFull, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Pipe rights for the user: `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without
/// `FILE_CREATE_PIPE_INSTANCE` (the same bit as `FILE_APPEND_DATA`), so a non-elevated process
/// can connect, read and write but cannot add a server instance of its own to the pipe.
const USER_PIPE_RIGHTS: &str = "0x12019b";

/// Mapping rights for the user: `SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ |
/// READ_CONTROL`. No `WRITE_DAC`, `WRITE_OWNER` or `DELETE`.
const USER_MAPPING_RIGHTS: &str = "0x20007";

/// Process rights for the user and for the object's owner: check its identity, wait for it
/// and stop it (`SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE`). Never
/// memory, thread, handle or security access, which would let a Medium process take over the
/// elevated one.
const USER_PROCESS_RIGHTS: &str = "0x101001";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A kind of object a non-elevated run of the same account must open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedObject {
    /// A named pipe server a client connects to.
    Pipe,
    /// A named file mapping a client maps for reading and writing.
    Mapping,
}

/// Security attributes for one object creation, owning their security descriptor.
pub struct SharedSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

struct Token(HANDLE);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SharedSecurity {
    /// The `SECURITY_ATTRIBUTES` to pass to the creating call. Valid while `self` lives.
    pub fn as_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        self.attributes.lpSecurityDescriptor = self.descriptor;
        &mut self.attributes
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SharedSecurity {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor) };
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Security attributes for creating `object` so that a non-elevated run of this account can
/// open it, or `None` when this process is not the full half of a split token (then the
/// default security already serves the same account).
pub fn shared_security(object: SharedObject) -> io::Result<Option<SharedSecurity>> {
    match split_elevated_user()? {
        Some(user) => security_for_user(object, &user).map(Some),
        None => Ok(None),
    }
}

/// Let a non-elevated run of this account find, wait for and stop this process, and nothing
/// more. Does nothing unless this process is the full half of a split token.
pub fn protect_runtime_process() -> io::Result<()> {
    match split_elevated_user()? {
        Some(user) => protect_process_for_user(&user),
        None => Ok(()),
    }
}

/// The security attributes [`shared_security`] uses, for the user SID `user` (string form).
///
/// Owner BUILTIN\Administrators; full access for SYSTEM and Administrators; the user gets
/// only the rights a client needs.
#[doc(hidden)]
pub fn security_for_user(object: SharedObject, user: &str) -> io::Result<SharedSecurity> {
    let rights = match object {
        SharedObject::Pipe => USER_PIPE_RIGHTS,
        SharedObject::Mapping => USER_MAPPING_RIGHTS,
    };
    let descriptor = descriptor(&format!(
        "O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;{rights};;;{user})"
    ))?;
    Ok(SharedSecurity {
        descriptor,
        attributes: SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
    })
}

/// What [`protect_runtime_process`] applies, for the user SID `user` (string form).
///
/// The process object gets owner BUILTIN\Administrators, a DACL that grants the user, and the
/// owner through OWNER RIGHTS, only identity, wait and terminate, keeps full access for
/// Administrators and SYSTEM, and a Medium mandatory label (a Medium caller cannot open a
/// High-labelled process for termination at all). The owner is reset because whoever owns a
/// process object holds implicit `WRITE_DAC`, which the Medium label no longer blocks; the
/// OWNER RIGHTS entry removes that implicit right from any owner.
#[doc(hidden)]
pub fn protect_process_for_user(user: &str) -> io::Result<()> {
    let sd = descriptor(&format!(
        "O:BAD:(A;;{USER_PROCESS_RIGHTS};;;{user})(A;;{USER_PROCESS_RIGHTS};;;OW)\
         (A;;GA;;;BA)(A;;GA;;;SY)S:(ML;;NWNR;;;ME)"
    ))?;
    let result = apply_process_security(sd);
    unsafe { LocalFree(sd) };
    result
}

/// Set the owner, DACL and label of `sd` on this process.
fn apply_process_security(sd: PSECURITY_DESCRIPTOR) -> io::Result<()> {
    let (mut present, mut defaulted) = (0, 0);
    let (mut owner, mut dacl, mut sacl) = (null_mut(), null_mut(), null_mut());
    if unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let error = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            sacl,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
}

/// The string user SID of this process's token.
#[doc(hidden)]
pub fn current_user_sid() -> io::Result<String> {
    user_sid_string(&open_token()?)
}

/// This process's `TOKEN_ELEVATION_TYPE` (1 default, 2 full, 3 limited).
#[doc(hidden)]
pub fn elevation_type() -> io::Result<TOKEN_ELEVATION_TYPE> {
    let token = open_token()?;
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(kind)
}

/// The user SID when this process is the full half of a split token.
fn split_elevated_user() -> io::Result<Option<String>> {
    if elevation_type()? != TokenElevationTypeFull {
        return Ok(None);
    }
    current_user_sid().map(Some)
}

fn open_token() -> io::Result<Token> {
    let mut handle = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Token(handle))
}

fn user_sid_string(token: &Token) -> io::Result<String> {
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

fn descriptor(sddl: &str) -> io::Result<PSECURITY_DESCRIPTOR> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd: *mut c_void = null_mut();
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
    Ok(sd)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, SE_KERNEL_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, ImpersonateLoggedOnUser, OWNER_SECURITY_INFORMATION, RevertToSelf,
        SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, OpenFileMappingW, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_WRITE,
    };

    use super::SharedObject;

    const CHILD_ENV: &str = "MSB_TEST_ELEVATION_SHARE_CHILD";
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn sid(text: &str) -> *mut core::ffi::c_void {
        let mut sid = null_mut();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) },
            0,
            "{text}"
        );
        sid
    }

    /// Make this process look like the full half of a split token: new objects default to
    /// owner Administrators and a DACL of Administrators and SYSTEM. This process's own object
    /// is owned by the user, as when the launcher's default owner is the user (and as on
    /// GitHub's runners). Then apply what an elevated runtime applies.
    fn emulate_elevated_runtime(user: &str) {
        use windows_sys::Win32::Security::{
            TOKEN_DEFAULT_DACL, TOKEN_OWNER, TokenDefaultDacl, TokenOwner,
        };
        let mut token = null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                    &mut token,
                )
            },
            0
        );
        let defaults = super::descriptor("O:BAD:(A;;GA;;;BA)(A;;GA;;;SY)").unwrap();
        let (mut owner, mut dacl, mut present, mut defaulted) = (null_mut(), null_mut(), 0, 0);
        unsafe {
            super::GetSecurityDescriptorOwner(defaults, &mut owner, &mut defaulted);
            super::GetSecurityDescriptorDacl(defaults, &mut present, &mut dacl, &mut defaulted);
        }
        let owner = TOKEN_OWNER { Owner: owner };
        assert_ne!(
            unsafe {
                SetTokenInformation(
                    token,
                    TokenOwner,
                    (&owner as *const TOKEN_OWNER).cast(),
                    size_of::<TOKEN_OWNER>() as u32,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        let dacl = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
        assert_ne!(
            unsafe {
                SetTokenInformation(
                    token,
                    TokenDefaultDacl,
                    (&dacl as *const TOKEN_DEFAULT_DACL).cast(),
                    size_of::<TOKEN_DEFAULT_DACL>() as u32,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        unsafe { CloseHandle(token) };

        let user_sid = sid(user);
        let error = unsafe {
            SetSecurityInfo(
                GetCurrentProcess(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                user_sid,
                null_mut(),
                null(),
                null(),
            )
        };
        assert_eq!(error, 0, "make the user the owner of this process");

        super::protect_process_for_user(user).expect("protect the runtime process");
    }

    /// Child half of `split_token_user_can_stop_but_not_take_over_the_runtime`: an emulated
    /// elevated runtime with one shared pipe and one shared mapping.
    #[test]
    fn elevated_runtime_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let user = super::current_user_sid().unwrap();
        emulate_elevated_runtime(&user);

        let id = std::process::id();
        let pipe_name = format!(r"\\.\pipe\msb-elevation-share-test-{id}");
        let mut pipe_security = super::security_for_user(SharedObject::Pipe, &user).unwrap();
        let pipe = unsafe {
            CreateNamedPipeW(
                wide(&pipe_name).as_ptr(),
                PIPE_ACCESS_DUPLEX,
                0,
                1,
                512,
                512,
                0,
                pipe_security.as_ptr(),
            )
        };
        assert_ne!(
            pipe,
            INVALID_HANDLE_VALUE,
            "{}",
            std::io::Error::last_os_error()
        );
        let mapping_name = format!("Local\\msb-elevation-share-test-{id}");
        let mut mapping_security = super::security_for_user(SharedObject::Mapping, &user).unwrap();
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                mapping_security.as_ptr(),
                PAGE_READWRITE,
                0,
                4096,
                wide(&mapping_name).as_ptr(),
            )
        };
        assert!(!mapping.is_null(), "{}", std::io::Error::last_os_error());

        println!("ready {pipe_name} {mapping_name}");
        std::io::stdout().flush().unwrap();
        // Stay alive, holding the pipe and the mapping, until the parent closes stdin.
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        unsafe {
            CloseHandle(pipe);
            CloseHandle(mapping);
        }
    }

    /// This process's token with Administrators for deny only and Medium integrity: the
    /// filtered half of the same account's split token.
    fn filtered_token() -> HANDLE {
        let mut token = null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                    &mut token,
                )
            },
            0
        );
        let administrators = SID_AND_ATTRIBUTES {
            Sid: sid("S-1-5-32-544"),
            Attributes: 0,
        };
        let mut filtered = null_mut();
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    token,
                    0,
                    1,
                    &administrators,
                    0,
                    null(),
                    0,
                    null(),
                    &mut filtered,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        unsafe { CloseHandle(token) };
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid("S-1-16-8192"),
                Attributes: windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY as u32,
            },
        };
        assert_ne!(
            unsafe {
                SetTokenInformation(
                    filtered,
                    TokenIntegrityLevel,
                    (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                    size_of::<TOKEN_MANDATORY_LABEL>() as u32,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        filtered
    }

    /// Whether the impersonated caller can open process `pid` with `access`.
    fn can_open_process(pid: u32, access: u32) -> bool {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return false;
        }
        unsafe { CloseHandle(handle) };
        true
    }

    /// A non-elevated run of the same account (Administrators deny-only, Medium) can stop
    /// the elevated runtime and open its shared pipe and mapping, but cannot get security,
    /// ownership or memory access to the runtime process.
    #[test]
    fn split_token_user_can_stop_but_not_take_over_the_runtime() {
        println!(
            "elevation type of this test process: {:?}",
            super::elevation_type()
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "elevation_share::tests::elevated_runtime_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = None;
        let mut transcript = String::new();
        let mut line = String::new();
        while stdout.read_line(&mut line).unwrap() > 0 {
            transcript.push_str(&line);
            if let Some(rest) = line.trim().strip_prefix("ready ") {
                ready = Some(rest.to_string());
                break;
            }
            line.clear();
        }
        let Some(ready) = ready else {
            let status = child.wait().unwrap();
            panic!("child did not get ready ({status}):\n{transcript}");
        };
        let (pipe_name, mapping_name) = ready.split_once(' ').unwrap();
        let (pipe_name, mapping_name) = (pipe_name.to_string(), mapping_name.to_string());

        // Impersonate on a separate thread, so this one never runs as the filtered token.
        let filtered = filtered_token() as usize;
        let results = std::thread::spawn(move || {
            assert_ne!(
                unsafe { ImpersonateLoggedOnUser(filtered as HANDLE) },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            let stop = can_open_process(
                pid,
                PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            );
            let write_dac = can_open_process(pid, WRITE_DAC);
            let write_owner = can_open_process(pid, WRITE_OWNER);
            let vm_write = can_open_process(pid, PROCESS_VM_WRITE);
            let pipe = unsafe {
                CreateFileW(
                    wide(&pipe_name).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            let pipe_error = std::io::Error::last_os_error();
            let pipe_ok = pipe != INVALID_HANDLE_VALUE;
            if pipe_ok {
                unsafe { CloseHandle(pipe) };
            }
            let mapping = unsafe {
                OpenFileMappingW(
                    FILE_MAP_READ | FILE_MAP_WRITE,
                    0,
                    wide(&mapping_name).as_ptr(),
                )
            };
            let mapping_error = std::io::Error::last_os_error();
            let mapping_ok = !mapping.is_null();
            if mapping_ok {
                unsafe { CloseHandle(mapping) };
            }
            assert_ne!(unsafe { RevertToSelf() }, 0);
            (
                stop,
                write_dac,
                write_owner,
                vm_write,
                (pipe_ok, pipe_error.to_string()),
                (mapping_ok, mapping_error.to_string()),
            )
        })
        .join()
        .unwrap();
        unsafe { CloseHandle(filtered as HANDLE) };
        drop(child.stdin.take());
        let status = child.wait().unwrap();

        let (stop, write_dac, write_owner, vm_write, pipe, mapping) = results;
        println!(
            "stop={stop} write_dac={write_dac} write_owner={write_owner} vm_write={vm_write} \
             pipe={pipe:?} mapping={mapping:?}"
        );
        assert!(status.success(), "child failed: {status}");
        assert!(stop, "a non-elevated run must be able to stop the runtime");
        assert!(!write_dac, "WRITE_DAC on the elevated runtime process");
        assert!(!write_owner, "WRITE_OWNER on the elevated runtime process");
        assert!(
            !vm_write,
            "PROCESS_VM_WRITE on the elevated runtime process"
        );
        assert!(pipe.0, "open the shared pipe for read/write: {}", pipe.1);
        assert!(mapping.0, "open the shared mapping: {}", mapping.1);
    }
}
