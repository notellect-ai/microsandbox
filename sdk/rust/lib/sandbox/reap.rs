//! Identity-checked cleanup for Windows sandbox runtime processes.

use std::time::{Duration, Instant};

use microsandbox_db::entity::run as run_entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::MicrosandboxResult;
use crate::context::local::sandbox::safe_kill::{Ending, RunProcess};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What [`reap_leaked_runtime_process`] established about the recorded run PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeakedReapVerdict {
    /// No live runtime process remains: none had the PID, a later process holds
    /// it (left alone), or the runtime was terminated here.
    NoProcess,

    /// The live process could not be queried, so its ownership is unknown and it was left alone.
    Unverifiable,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Terminate a leftover VM process only when it is the sandbox's latest run's runtime.
///
/// A stopped database row can still have a Windows VM process serving the sandbox's named pipes.
/// [`RunProcess::resolve`] compares the recorded start time and image before anything is
/// terminated, so a recycled PID never causes an unrelated process to be killed.
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
    let runtime_dir = local_backend.sandboxes_dir().join(name).join("runtime");
    let runtime = match RunProcess::resolve(&run, Some(&runtime_dir)) {
        RunProcess::Alive(runtime) => runtime,
        RunProcess::Exited => return Ok(LeakedReapVerdict::NoProcess),
        RunProcess::Unknown => {
            tracing::warn!(
                pid = ?run.pid,
                sandbox = %name,
                "recorded runtime PID cannot be verified (likely recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::Unverifiable);
        }
    };
    match runtime.end(Ending::Kill) {
        Ok(_) => {
            tracing::warn!(pid = ?run.pid, sandbox = %name, "terminated leftover sandbox VM process")
        }
        // Termination can fail while a verified process is already exiting. The wait
        // below is authoritative.
        Err(error) => tracing::warn!(
            pid = ?run.pid,
            sandbox = %name,
            %error,
            "failed to terminate leftover sandbox VM process; waiting for exit"
        ),
    }

    let start = Instant::now();
    while !runtime.has_exited() && start.elapsed() < crate::runtime::reap::REAP_EXIT_WAIT {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !runtime.has_exited() {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox process {:?} for '{name}' is still running after termination",
            run.pid
        )));
    }

    Ok(LeakedReapVerdict::NoProcess)
}
