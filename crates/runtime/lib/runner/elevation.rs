//! Opt-in sharing of an elevated runtime with the same account's non-elevated runs.
//!
//! By default an elevated runtime keeps the UAC boundary: its pipes get their default
//! security. When the launcher passes `share_elevated_sandboxes` and this runtime is the full
//! half of a split token, the pipes are shared as [`microsandbox_utils::elevation_share`]
//! describes.

use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use microsandbox_utils::elevation_share;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Security::TOKEN_ELEVATION_TYPE;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Whether this runtime shares its pipes, decided once when the runtime starts, before any
/// pipe exists.
static SHARE_ELEVATED: AtomicBool = AtomicBool::new(false);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide from the launch's opt-in whether this runtime shares its pipes with the same
/// account's non-elevated runs. Without the opt-in nothing is queried. Best effort; a failure
/// only keeps the default security.
pub(crate) fn share_with_non_elevated(opt_in: bool) {
    share_with_non_elevated_as(opt_in, elevation_share::elevation_type);
}

/// Create a named pipe server instance, shared with non-elevated runs of this account when
/// [`share_with_non_elevated`] decided so. Falls back to the default security (and logs why)
/// if the shared descriptor cannot be built.
pub(crate) fn create_shared_pipe(
    options: &ServerOptions,
    name: impl AsRef<OsStr>,
) -> io::Result<NamedPipeServer> {
    if !SHARE_ELEVATED.load(Ordering::Relaxed) {
        return options.create(name);
    }

    match elevation_share::shared_pipe_security() {
        Ok(mut security) => unsafe {
            options.create_with_security_attributes_raw(name, security.as_ptr().cast())
        },
        Err(error) => {
            tracing::warn!(%error, "could not share a runtime pipe with non-elevated runs");
            options.create(name)
        }
    }
}

/// [`share_with_non_elevated`] with this process's token elevation type read by `elevation`.
fn share_with_non_elevated_as(
    opt_in: bool,
    elevation: impl FnOnce() -> io::Result<TOKEN_ELEVATION_TYPE>,
) {
    let share = match elevation() {
        Ok(elevation) => elevation_share::shares_with_non_elevated(opt_in, elevation),
        Err(error) => {
            tracing::warn!(%error, "could not read this runtime's token elevation type");
            false
        }
    };
    SHARE_ELEVATED.store(share, Ordering::Relaxed);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use std::sync::atomic::Ordering;

    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, TokenElevationTypeDefault, TokenElevationTypeFull,
        TokenElevationTypeLimited,
    };

    use super::{SHARE_ELEVATED, create_shared_pipe, share_with_non_elevated_as};

    /// The DACL of the kernel object `handle`, in lowercase SDDL.
    fn dacl(handle: HANDLE) -> String {
        let mut descriptor = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(error, 0, "read the DACL");

        let mut text = null_mut();
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        assert_ne!(converted, 0, "{}", io::Error::last_os_error());
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let sddl = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        sddl.to_ascii_lowercase()
    }

    /// The opt-in reaches the runtime's pipes only in the full half of a split token: then a
    /// pipe created the way the runtime's servers create theirs grants the user client rights
    /// (`0x12019b`); every other start keeps the default security, which does not. Without the
    /// opt-in the elevation type is not even read.
    #[test]
    fn opt_in_shares_the_runtime_pipes_only_when_elevated() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        for (index, (opt_in, elevation, shared)) in [
            (true, TokenElevationTypeFull, true),
            (false, TokenElevationTypeFull, false),
            (true, TokenElevationTypeDefault, false),
            (true, TokenElevationTypeLimited, false),
        ]
        .into_iter()
        .enumerate()
        {
            let mut queried = false;
            share_with_non_elevated_as(opt_in, || {
                queried = true;
                Ok(elevation)
            });
            assert_eq!(queried, opt_in, "opt_in={opt_in}: elevation type read");

            let name = format!(
                r"\\.\pipe\msb-runtime-elevation-test-{}-{index}",
                std::process::id()
            );
            let mut options = ServerOptions::new();
            options.first_pipe_instance(true);
            let pipe = create_shared_pipe(&options, &name).unwrap();
            let pipe = dacl(pipe.as_raw_handle());
            println!("opt_in={opt_in} elevation type {elevation}: pipe {pipe}");
            assert_eq!(
                pipe.contains("(a;;0x12019b;;;s-1-5-"),
                shared,
                "pipe DACL for opt_in={opt_in} elevation type {elevation}: {pipe}"
            );
        }
        share_with_non_elevated_as(false, || unreachable!());
        assert!(!SHARE_ELEVATED.load(Ordering::Relaxed));
    }
}
