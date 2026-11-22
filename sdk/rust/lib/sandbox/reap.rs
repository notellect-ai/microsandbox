//! Identity-checked cleanup for Windows sandbox runtime processes.

use std::io;
use std::time::{Duration, Instant};

use microsandbox_db::entity::run as run_entity;
use microsandbox_utils::elevation_share;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{MicrosandboxError, MicrosandboxResult, runtime::reap};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What [`reap_leaked_runtime_process`] established about the recorded run PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeakedReapVerdict {
    /// No live runtime process remains (already dead, or terminated here).
    NoProcess,

    /// A live process holds the PID but is provably not the runtime; it was left alone.
    RecycledPid,

    /// The live process could not be queried, so its ownership is unknown and it was left alone.
    Unverifiable {
        /// The OS error from opening the process, when that is what failed.
        open_error: Option<i32>,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Terminate a leftover VM process only when its identity matches the sandbox's latest run.
///
/// A stopped database row can still have a Windows VM process serving the sandbox's named pipes.
/// Checking the recorded start time and image before termination prevents a recycled PID from
/// causing an unrelated process to be killed.
pub(crate) async fn reap_leaked_runtime_process(
    local_backend: &crate::context::LocalContext,
    sandbox_id: i32,
    name: &str,
) -> MicrosandboxResult<LeakedReapVerdict> {
    let pools = local_backend.db().await?;
    let run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .order_by_desc(run_entity::Column::Id)
        .one(pools.read())
        .await?;
    let Some(run) = run else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let (Some(pid), Some(started_at)) = (run.pid, run.started_at) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let Ok(pid_u32) = u32::try_from(pid) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    if !pid_is_alive(pid) {
        return Ok(LeakedReapVerdict::NoProcess);
    }

    let outcome =
        reap::terminate_runtime_process_checked(pid_u32, started_at.and_utc().timestamp_micros());
    match outcome {
        Ok(reap::ReapOutcome::AlreadyDead) => return Ok(LeakedReapVerdict::NoProcess),
        Ok(reap::ReapOutcome::IdentityMismatch) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID is now a different process (recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::RecycledPid);
        }
        Ok(reap::ReapOutcome::Unverifiable { open_error }) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                ?open_error,
                "recorded runtime PID cannot be queried (likely recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::Unverifiable { open_error });
        }
        Ok(reap::ReapOutcome::Terminated) => {
            tracing::warn!(pid, sandbox = %name, "terminated leftover sandbox VM process");
        }
        // Termination can fail while a verified process is already exiting. The liveness check
        // below is authoritative, so wait before deciding whether cleanup failed.
        Err(err) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                error = %err,
                "failed to terminate leftover sandbox VM process; waiting for exit"
            );
        }
    }

    wait_for_pids_to_exit(&[pid], reap::REAP_EXIT_WAIT).await;
    if pid_is_alive(pid) {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox process {pid} for '{name}' is still running after termination"
        )));
    }

    Ok(LeakedReapVerdict::NoProcess)
}

/// Why sandbox `name` cannot be removed while its recorded runtime process is unverifiable
/// ([`LeakedReapVerdict::Unverifiable`]). When opening the process was refused with access
/// denied in a non-elevated process, the error explains that an elevated process most likely
/// started the runtime.
pub(crate) fn unverifiable_runtime_error(name: &str, open_error: Option<i32>) -> MicrosandboxError {
    let message = format!(
        "cannot remove sandbox {name:?}: its recorded runtime process could not be verified"
    );
    let Some(code) = open_error else {
        return MicrosandboxError::Runtime(message);
    };

    let cause = io::Error::from_raw_os_error(code);
    let explained = elevation_share::explain_access_denied(io::Error::new(
        cause.kind(),
        format!("{message}: {cause}"),
    ));
    if elevation_share::is_elevated_sandbox_denial(&explained) {
        return explained.into();
    }

    MicrosandboxError::Runtime(message)
}

fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

async fn wait_for_pids_to_exit(pids: &[i32], timeout: Duration) {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) || start.elapsed() >= timeout {
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;

    use microsandbox_utils::elevation_share::{self, ELEVATED_SANDBOX_HINT};
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::Security::TokenElevationTypeLimited;

    use super::unverifiable_runtime_error;
    use crate::MicrosandboxError;

    /// An unverifiable runtime keeps the plain error, unless opening it was refused with access
    /// denied in the filtered half of a split token: then the error says an elevated process
    /// most likely started it. GitHub's runners are not split tokens, so there both cases keep
    /// the plain error.
    #[test]
    fn unverifiable_runtime_error_explains_only_a_denied_non_elevated_open() {
        let expected =
            r#"cannot remove sandbox "box": its recorded runtime process could not be verified"#;
        let limited = elevation_share::elevation_type().unwrap() == TokenElevationTypeLimited;

        let unopened = unverifiable_runtime_error("box", None);
        let denied = unverifiable_runtime_error("box", Some(ERROR_ACCESS_DENIED as i32));

        assert!(
            matches!(&unopened, MicrosandboxError::Runtime(message) if message == expected),
            "{unopened}"
        );
        if limited {
            let message = denied.to_string();
            assert!(
                matches!(&denied, MicrosandboxError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied),
                "{message}"
            );
            assert!(message.contains(expected), "{message}");
            assert!(message.contains(ELEVATED_SANDBOX_HINT), "{message}");
        } else {
            assert!(
                matches!(&denied, MicrosandboxError::Runtime(message) if message == expected),
                "{denied}"
            );
        }
    }
}
