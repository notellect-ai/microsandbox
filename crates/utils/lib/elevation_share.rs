//! Let a non-elevated run reach a sandbox that an elevated run of the same account started,
//! when the user opts in.
//!
//! With UAC, one account logs on with a split token: a filtered token (Medium integrity,
//! BUILTIN\Administrators for deny only) and a full one (High integrity, Administrators
//! enabled). Named pipes the full token creates without explicit security are owned by
//! Administrators, and the pipe default DACL grants full access only to SYSTEM,
//! Administrators and that owner (everyone else gets read). The filtered token of the same
//! account therefore cannot connect to the sandbox's pipes, so it cannot exec in, control or
//! stop the sandbox (stopping sends a shutdown request over the agent pipe). That is the UAC
//! boundary, and it stays the default: [`explain_access_denied`] turns the resulting
//! access-denied error into one that says what happened and what to do.
//!
//! Other runtime objects already let the filtered token in. The runtime process gets the full
//! token's default DACL, which grants the logon SID (shared by both halves of a split token)
//! read and execute, and a High label with no-write-up and no-read-up; together they leave the
//! filtered token exactly `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION |
//! PROCESS_TERMINATE`, enough to find and wait for the runtime but never to read its memory or
//! change its security. Other kernel objects the runtime creates without explicit security,
//! such as the metrics registry mapping, get the same default DACL, so the filtered token can
//! open them for reading, which is all metrics readers ask for.
//!
//! When the user opts in (`runtime.share_elevated_sandboxes`), the runtime's pipes get an
//! explicit security descriptor that also grants the user SID of the runtime's token; nothing
//! else changes. It applies only in a process whose token is the full half of a split token
//! (`TokenElevationTypeFull`); non-UAC administrator tokens (`TokenElevationTypeDefault`) are
//! left unchanged. The grant names the account whose full token runs the runtime: when a
//! standard user elevates with an administrator's credentials, that is the administrator, so
//! the administrator's non-elevated runs get access, not the standard user's. Pipe names are
//! machine-wide, so the account's non-elevated runs in other logon sessions on the same
//! machine get access too.

use std::error::Error;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION_TYPE,
    TOKEN_QUERY, TOKEN_USER, TokenElevationType, TokenElevationTypeFull, TokenElevationTypeLimited,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Pipe rights for the user: `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without
/// `FILE_CREATE_PIPE_INSTANCE` (the same bit as `FILE_APPEND_DATA`), so a non-elevated process
/// can connect, read and write but cannot add a server instance of its own to the pipe.
const USER_PIPE_RIGHTS: &str = "0x12019b";

/// What a non-elevated process is told when a sandbox refuses it with access denied.
pub const ELEVATED_SANDBOX_HINT: &str = "the sandbox was most likely started by an elevated \
    (administrator) process, and this process is not elevated. Run this process elevated, or \
    stop the sandbox from an elevated process and then start it again from this one. To let \
    non-elevated processes reach sandboxes that elevated processes start, set \
    runtime.share_elevated_sandboxes to true in the microsandbox config file \
    (~/.microsandbox/config.json by default)";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Security attributes for one object creation, owning their security descriptor.
pub struct SharedSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

/// An access-denied error that [`explain_access_denied`] explained: it displays the original
/// error followed by [`ELEVATED_SANDBOX_HINT`], and keeps the original as its source. Found
/// as the payload of the returned `io::Error`, so callers can add guidance of their own.
#[derive(Debug)]
pub struct ElevatedSandboxDenied {
    source: io::Error,
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

impl fmt::Display for ElevatedSandboxDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {ELEVATED_SANDBOX_HINT}", self.source)
    }
}

impl Error for ElevatedSandboxDenied {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

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

/// Whether an elevated runtime shares its pipes with the same account's
/// non-elevated runs: only when the user opted in (`opt_in`) and the token is the full half of
/// a split token (`elevation`, see [`elevation_type`]). Everything else keeps the default
/// security, and with it the UAC boundary.
pub fn shares_with_non_elevated(opt_in: bool, elevation: TOKEN_ELEVATION_TYPE) -> bool {
    opt_in && elevation == TokenElevationTypeFull
}

/// This process's `TOKEN_ELEVATION_TYPE`: `TokenElevationTypeDefault` without a split token,
/// `TokenElevationTypeFull` for the elevated half of one, `TokenElevationTypeLimited` for the
/// filtered half.
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

/// Security attributes for creating a named pipe server instance that non-elevated runs of
/// this process's account can connect to. Callers decide with [`shares_with_non_elevated`]
/// first; without sharing, create the pipe with its default security instead.
pub fn shared_pipe_security() -> io::Result<SharedSecurity> {
    pipe_security_for_user(&current_user_sid()?)
}

/// Explain an error a client got opening a sandbox's pipe or runtime process.
///
/// When this process is the filtered (non-elevated) half of a split token and the error is
/// access denied, the sandbox was most likely started by an elevated process that did not
/// share it (a recycled PID can also be refused); the returned error has the same kind and an
/// [`ElevatedSandboxDenied`] payload that adds [`ELEVATED_SANDBOX_HINT`] to the original text.
/// Every other error is returned unchanged.
pub fn explain_access_denied(error: io::Error) -> io::Error {
    match elevation_type() {
        Ok(elevation) => explain_access_denied_as(error, elevation),
        Err(_) => error,
    }
}

/// Whether `error` is one that [`explain_access_denied`] explained, so its payload is an
/// [`ElevatedSandboxDenied`].
pub fn is_elevated_sandbox_denial(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|payload| payload.is::<ElevatedSandboxDenied>())
}

/// [`explain_access_denied`] for a process with token elevation type `elevation`.
fn explain_access_denied_as(error: io::Error, elevation: TOKEN_ELEVATION_TYPE) -> io::Error {
    let _ = elevation;
    error
}

/// The security attributes [`shared_pipe_security`] uses, for the user SID `user` (string
/// form).
///
/// Owner BUILTIN\Administrators; full access for SYSTEM and Administrators; the user gets
/// only the rights a client needs.
fn pipe_security_for_user(user: &str) -> io::Result<SharedSecurity> {
    let descriptor = descriptor(&format!(
        "O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;{USER_PIPE_RIGHTS};;;{user})"
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

/// The string user SID of this process's token.
fn current_user_sid() -> io::Result<String> {
    user_sid_string(&open_token()?)
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
    use std::error::Error;
    use std::ffi::c_void;
    use std::io::{self, BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::channel;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        ImpersonateLoggedOnUser, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        RevertToSelf, SID_AND_ATTRIBUTES, SetKernelObjectSecurity, SetTokenInformation,
        TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE,
        TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TokenDefaultDacl,
        TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited,
        TokenIntegrityLevel, TokenLogonSid, TokenOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, OpenFileMappingW, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
    };

    const CHILD_ENV: &str = "MSB_TEST_ELEVATION_SHARE_CHILD";
    /// What the child prints, followed by the pipe and mapping names, once they exist.
    const READY: &str = "elevation-share-child-ready";
    /// What the filtered token may open an elevated runtime process for, with or without the
    /// opt-in, and nothing else: `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION |
    /// PROCESS_TERMINATE`, the logon SID's read and execute (`0x121411`) less what the High
    /// label's no-read-up takes away. A real elevated runtime gave exactly this under UAC.
    const ALLOWED_PROCESS_RIGHTS: u32 = 0x0010_1001;
    /// Every specific process right (bits 0-15), every standard right (`DELETE`,
    /// `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`) and `ACCESS_SYSTEM_SECURITY`.
    /// Generic bits map onto these, and `MAXIMUM_ALLOWED` is not a right.
    const PROBED_PROCESS_RIGHTS: u32 = 0x011f_ffff;
    /// The child is killed, and the test fails, if the parent has not finished by then.
    const DEADLINE: Duration = Duration::from_secs(60);

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn sid(text: &str) -> *mut c_void {
        let mut sid = null_mut();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) },
            0,
            "{text}"
        );
        sid
    }

    /// The string logon SID of this process's token, which both halves of a split token carry.
    fn logon_sid() -> String {
        let mut token = null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let mut length = 0;
        unsafe { GetTokenInformation(token, TokenLogonSid, null_mut(), 0, &mut length) };
        assert_ne!(length, 0, "{}", io::Error::last_os_error());
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenLogonSid,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        unsafe { CloseHandle(token) };

        let groups = buffer.as_ptr() as *const TOKEN_GROUPS;
        assert_eq!(unsafe { (*groups).GroupCount }, 1);
        let mut text = null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW((*groups).Groups[0].Sid, &mut text) },
            0
        );
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        value
    }

    /// Make this process look like the full half of a split token, as a real one is set up:
    /// new objects default to owner Administrators and a DACL of full access for
    /// Administrators and SYSTEM and read and execute for the logon SID. This process's own
    /// object gets what an elevated launcher gives a process it creates: that DACL mapped to
    /// process rights and a High label with no-write-up and no-read-up.
    fn emulate_elevated_runtime() {
        let logon = logon_sid();
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
        let defaults = super::descriptor(&format!(
            "O:BAD:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;{logon})"
        ))
        .unwrap();
        let (mut owner, mut dacl, mut present, mut defaulted) = (null_mut(), null_mut(), 0, 0);
        unsafe {
            GetSecurityDescriptorOwner(defaults, &mut owner, &mut defaulted);
            GetSecurityDescriptorDacl(defaults, &mut present, &mut dacl, &mut defaulted);
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
            io::Error::last_os_error()
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
            io::Error::last_os_error()
        );
        unsafe { CloseHandle(token) };

        // As seen on an elevated runtime under real UAC (`0x121411` is GENERIC_READ |
        // GENERIC_EXECUTE for a process).
        let process = super::descriptor(&format!(
            "O:BAD:(A;;0x1fffff;;;BA)(A;;0x1fffff;;;SY)(A;;0x121411;;;{logon})S:(ML;;NWNR;;;HI)"
        ))
        .unwrap();
        assert_ne!(
            unsafe {
                SetKernelObjectSecurity(
                    GetCurrentProcess(),
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | LABEL_SECURITY_INFORMATION,
                    process,
                )
            },
            0,
            "give this process an elevated runtime's security: {}",
            io::Error::last_os_error()
        );
    }

    /// Child half of the access tests: an emulated elevated runtime with the opt-in on
    /// (`CHILD_ENV` = `shared`) or off (`default`), one runtime pipe and one mapping created
    /// with default security.
    #[test]
    fn elevated_runtime_child() {
        let share = match std::env::var(CHILD_ENV).as_deref() {
            Ok("shared") => true,
            Ok("default") => false,
            _ => return,
        };
        let user = super::current_user_sid().unwrap();
        // What an elevated runtime decides from the launch's opt-in.
        let share = super::shares_with_non_elevated(share, TokenElevationTypeFull);
        eprintln!("child: emulating an elevated runtime (share={share})");
        emulate_elevated_runtime();
        eprintln!("child: creating the pipe and the mapping");

        let id = std::process::id();
        let pipe_name = format!(r"\\.\pipe\msb-elevation-share-test-{id}");
        let mut pipe_security = share.then(|| super::pipe_security_for_user(&user).unwrap());
        let pipe = unsafe {
            CreateNamedPipeW(
                wide(&pipe_name).as_ptr(),
                PIPE_ACCESS_DUPLEX,
                0,
                1,
                512,
                512,
                0,
                pipe_security
                    .as_mut()
                    .map_or(null_mut(), |security| security.as_ptr()),
            )
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        // Default security, as the metrics registry creates its mapping; readers open it
        // read-only, which the logon SID's read access allows: no sharing needed.
        let mapping_name = format!("Local\\msb-elevation-share-test-{id}");
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                null(),
                PAGE_READWRITE,
                0,
                4096,
                wide(&mapping_name).as_ptr(),
            )
        };
        assert!(!mapping.is_null(), "{}", io::Error::last_os_error());

        // libtest has already printed `test <name> ... ` without a newline.
        println!("\n{READY} {pipe_name} {mapping_name}");
        io::stdout().flush().unwrap();
        // Stay alive, holding the pipe and the mapping, until the parent closes stdin.
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        eprintln!("child: stdin closed, exiting");
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
                    DISABLE_MAX_PRIVILEGE,
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
            io::Error::last_os_error()
        );
        unsafe { CloseHandle(token) };
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid("S-1-16-8192"),
                Attributes: SE_GROUP_INTEGRITY as u32,
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
            io::Error::last_os_error()
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

    /// What a filtered token of this account gets on an emulated elevated runtime.
    struct Access {
        /// `PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` opened, or
        /// the error.
        stop: io::Result<()>,
        /// Union of the probed process rights that open one at a time.
        granted: u32,
        /// The runtime pipe opened for read/write, or the error.
        pipe: io::Result<()>,
        /// The default-security mapping opened for reading, as metrics readers do, or the
        /// error.
        mapping: io::Result<()>,
    }

    fn opened(ok: bool) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Start an emulated elevated runtime with the opt-in `share`, and probe it while
    /// impersonating the filtered half of this account's split token.
    fn probe_elevated_runtime(share: bool) -> Access {
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
            .env(CHILD_ENV, if share { "shared" } else { "default" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let (finished, deadline) = channel::<()>();
        let watchdog_target = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) } as usize;
        assert_ne!(watchdog_target, 0, "{}", io::Error::last_os_error());
        let watchdog = std::thread::spawn(move || {
            if deadline.recv_timeout(DEADLINE).is_err() {
                eprintln!("parent: deadline passed, killing the child");
                unsafe { TerminateProcess(watchdog_target as HANDLE, 1) };
                return true;
            }
            false
        });
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = None;
        let mut transcript = String::new();
        let mut line = String::new();
        while stdout.read_line(&mut line).unwrap() > 0 {
            transcript.push_str(&line);
            if let Some((_, rest)) = line.trim().split_once(READY) {
                ready = Some(rest.trim().to_string());
                break;
            }
            line.clear();
        }
        let Some(ready) = ready else {
            let status = child.wait().unwrap();
            panic!("child did not get ready ({status}):\n{transcript}");
        };
        eprintln!("parent: child ready: {ready}");
        let (pipe_name, mapping_name) = ready.split_once(' ').unwrap();
        let (pipe_name, mapping_name) = (pipe_name.to_string(), mapping_name.to_string());

        // Impersonate on a separate thread, so this one never runs as the filtered token.
        let filtered = filtered_token() as usize;
        let access = std::thread::spawn(move || {
            assert_ne!(
                unsafe { ImpersonateLoggedOnUser(filtered as HANDLE) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            eprintln!("parent: impersonating the filtered token");
            let stop = {
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        pid,
                    )
                };
                let result = opened(!handle.is_null());
                if !handle.is_null() {
                    unsafe { CloseHandle(handle) };
                }
                result
            };
            // Each right on its own: the union of those that open is what the caller can get.
            let granted = (0..32)
                .map(|bit| 1u32 << bit)
                .filter(|&right| PROBED_PROCESS_RIGHTS & right != 0)
                .filter(|&right| can_open_process(pid, right))
                .fold(0, |granted, right| granted | right);
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
            let pipe_result = opened(pipe != INVALID_HANDLE_VALUE);
            if pipe != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(pipe) };
            }
            let mapping =
                unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wide(&mapping_name).as_ptr()) };
            let mapping_result = opened(!mapping.is_null());
            if !mapping.is_null() {
                unsafe { CloseHandle(mapping) };
            }
            assert_ne!(unsafe { RevertToSelf() }, 0);
            Access {
                stop,
                granted,
                pipe: pipe_result,
                mapping: mapping_result,
            }
        })
        .join()
        .unwrap();
        unsafe { CloseHandle(filtered as HANDLE) };
        eprintln!("parent: closing the child's stdin");
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        let _ = finished.send(());
        let killed = watchdog.join().unwrap();
        unsafe { CloseHandle(watchdog_target as HANDLE) };
        assert!(!killed, "the test did not finish within {DEADLINE:?}");
        println!(
            "share={share} stop={:?} granted={:#010x} pipe={:?} mapping={:?}",
            access.stop, access.granted, access.pipe, access.mapping
        );
        assert!(status.success(), "child failed: {status}");
        access
    }

    /// With the opt-in, a non-elevated run of the same account (Administrators deny-only,
    /// Medium) can open the elevated runtime's pipe, and opens its process and a mapping it
    /// created with default security exactly as it could without the opt-in.
    #[test]
    fn split_token_user_reaches_the_shared_runtime_pipe() {
        let Access {
            stop,
            granted,
            pipe,
            mapping,
        } = probe_elevated_runtime(true);
        assert!(
            pipe.is_ok(),
            "open the shared pipe for read/write: {pipe:?}"
        );
        assert!(
            stop.is_ok(),
            "open the runtime process to stop it: {stop:?}"
        );
        assert_eq!(
            granted, ALLOWED_PROCESS_RIGHTS,
            "process rights a non-elevated run gets on the elevated runtime \
             (granted {granted:#010x}, expected {ALLOWED_PROCESS_RIGHTS:#010x})"
        );
        assert!(
            mapping.is_ok(),
            "open a default-security mapping for reading: {mapping:?}"
        );
    }

    /// Without the opt-in, a non-elevated run of the same account cannot open the elevated
    /// runtime's pipe, which every request and the shutdown that stops a sandbox go through,
    /// and the error it reports says why and what to do. The runtime process itself grants
    /// the same rights as with the opt-in: those come from the elevated token's defaults.
    #[test]
    fn split_token_user_is_refused_the_runtime_pipe_without_the_opt_in_and_told_why() {
        let Access {
            stop: _,
            granted,
            pipe,
            mapping,
        } = probe_elevated_runtime(false);
        let pipe = pipe.expect_err("a non-elevated run must not open an unshared pipe");
        assert_eq!(
            pipe.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "{pipe}"
        );
        assert_eq!(
            granted, ALLOWED_PROCESS_RIGHTS,
            "process rights a non-elevated run gets on the elevated runtime \
             (granted {granted:#010x}, expected {ALLOWED_PROCESS_RIGHTS:#010x})"
        );
        // The registry mapping never depended on the opt-in.
        assert!(
            mapping.is_ok(),
            "open a default-security mapping for reading: {mapping:?}"
        );

        let original = pipe.to_string();
        let explained = super::explain_access_denied_as(pipe, TokenElevationTypeLimited);
        let message = explained.to_string();
        println!("explained: {message}");
        assert_eq!(explained.kind(), io::ErrorKind::PermissionDenied);
        assert!(super::is_elevated_sandbox_denial(&explained), "{message}");
        for phrase in [
            original.as_str(),
            "most likely started by an elevated (administrator) process",
            "Run this process elevated",
            "stop the sandbox from an elevated process and then start it again from this one",
            "set runtime.share_elevated_sandboxes to true",
        ] {
            assert!(
                message.contains(phrase),
                "error a non-elevated run reports for an elevated sandbox is missing \
                 {phrase:?}: {message}"
            );
        }
    }

    /// Only access denied in the filtered half of a split token is explained.
    #[test]
    fn only_access_denied_in_a_non_elevated_run_is_explained() {
        let denied = || io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        for elevation in [TokenElevationTypeDefault, TokenElevationTypeFull] {
            let error = super::explain_access_denied_as(denied(), elevation);
            assert_eq!(error.to_string(), denied().to_string(), "type {elevation}");
        }
        let missing = || io::Error::from_raw_os_error(2);
        let error = super::explain_access_denied_as(missing(), TokenElevationTypeLimited);
        assert_eq!(error.to_string(), missing().to_string());
        let error = super::explain_access_denied_as(denied(), TokenElevationTypeLimited);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            format!("{}: {}", denied(), super::ELEVATED_SANDBOX_HINT)
        );
        let source = Error::source(error.get_ref().unwrap()).unwrap();
        assert_eq!(source.to_string(), denied().to_string());
    }

    /// Only the opt-in together with an elevated split token shares.
    #[test]
    fn sharing_needs_the_opt_in_and_an_elevated_split_token() {
        for (opt_in, elevation, expected) in [
            (false, TokenElevationTypeDefault, false),
            (false, TokenElevationTypeFull, false),
            (false, TokenElevationTypeLimited, false),
            (true, TokenElevationTypeDefault, false),
            (true, TokenElevationTypeFull, true),
            (true, TokenElevationTypeLimited, false),
        ] {
            assert_eq!(
                super::shares_with_non_elevated(opt_in, elevation),
                expected,
                "opt_in={opt_in} elevation type {elevation}"
            );
        }
    }
}
