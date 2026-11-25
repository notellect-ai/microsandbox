//! Cleanup of a Windows sandbox runtime that outlived its stopped database row.

use microsandbox_db::entity::run as run_entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::MicrosandboxResult;
use crate::runtime::ownership::{RunRuntime, run_runtime};
use crate::runtime::reap::REAP_EXIT_WAIT;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What [`reap_leaked_runtime_process`] established about the recorded run PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeakedReapVerdict {
    /// No runtime process remains (already gone, or the recorded runtime was ended here).
    NoProcess,

    /// A live process holds the PID and nothing proves whose it is; it was left alone.
    Unverifiable,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// End a leftover runtime process of the sandbox's latest run, only when it is the process the
/// SDK recorded (see [`run_runtime`]).
///
/// A stopped database row can still have a Windows VM process serving the sandbox's named pipes.
/// A recycled PID must never cause an unrelated process to be killed.
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
    let directory = local_backend.sandboxes_dir().join(name).join("runtime");
    let process = match run_runtime(&directory, &run)? {
        RunRuntime::Gone => return Ok(LeakedReapVerdict::NoProcess),
        RunRuntime::Unknown(reason) => {
            tracing::warn!(sandbox = %name, "{reason}");
            return Ok(LeakedReapVerdict::Unverifiable);
        }
        RunRuntime::Owned(process) => process,
    };
    // Termination can fail while the runtime is already exiting; its exit is authoritative.
    if let Err(error) = process.terminate() {
        tracing::warn!(
            sandbox = %name,
            %error,
            "failed to terminate leftover sandbox VM process; waiting for exit"
        );
    }
    if !process.exited_within(REAP_EXIT_WAIT).await? {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox process {} for '{name}' is still running after termination",
            run.pid.unwrap_or_default()
        )));
    }
    tracing::warn!(sandbox = %name, "terminated leftover sandbox VM process");
    Ok(LeakedReapVerdict::NoProcess)
}
