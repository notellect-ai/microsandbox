//! Opt-in sharing of an elevated runtime with the same account's non-elevated runs.
//!
//! By default an elevated runtime keeps the UAC boundary: its pipes and process get their
//! default security. When the launcher passes `share_elevated_sandboxes`, the pipes and the
//! process are shared as [`microsandbox_utils::elevation_share`] describes.

use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use microsandbox_utils::elevation_share;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The launch's `share_elevated_sandboxes` opt-in, set once when the runtime starts, before
/// any pipe exists.
static SHARE_ELEVATED: AtomicBool = AtomicBool::new(false);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Record the launch's opt-in and, when it applies to this process, let non-elevated runs of
/// this account stop it. Best effort; a failure only keeps the default security.
pub(crate) fn share_with_non_elevated(opt_in: bool) {
    SHARE_ELEVATED.store(opt_in, Ordering::Relaxed);

    if let Err(error) = elevation_share::protect_runtime_process(opt_in) {
        tracing::warn!(%error, "could not let non-elevated runs stop this runtime");
    }
}

/// Create a named pipe server instance, shared with non-elevated runs of this account when the
/// launch opted in and this runtime is the full half of a split token. Falls back to the
/// default security (and logs why) if the shared descriptor cannot be built.
pub(crate) fn create_shared_pipe(
    options: &ServerOptions,
    name: impl AsRef<OsStr>,
) -> io::Result<NamedPipeServer> {
    match elevation_share::shared_pipe_security(SHARE_ELEVATED.load(Ordering::Relaxed)) {
        Ok(Some(mut security)) => unsafe {
            options.create_with_security_attributes_raw(name, security.as_ptr().cast())
        },
        Ok(None) => options.create(name),
        Err(error) => {
            tracing::warn!(%error, "could not share a runtime pipe with non-elevated runs");
            options.create(name)
        }
    }
}
