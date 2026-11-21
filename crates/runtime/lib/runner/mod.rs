//! VM runner implementation linked into the `msb` process.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(crate) mod bootstrap_fs;
pub(crate) mod clock;
pub mod console;
pub(crate) mod control;
pub mod cpu;
pub(crate) mod exec_control;
pub mod exec_log;
pub(crate) mod finished_ids;
pub mod heartbeat;
pub(crate) mod jobs;
pub(crate) mod logging;
pub mod metrics;
pub(crate) mod metrics_memory;
pub mod policy;
pub(crate) mod progress;
pub mod relay;
pub(crate) mod startup;
pub(crate) mod storage_observation;
pub mod vm;
pub(crate) mod workload_control;
pub(crate) mod writeback;

/// Create a named pipe server instance that a non-elevated run of this account can also
/// open when this runtime is the full half of a split token. Falls back to the default
/// security (and logs why) if the shared descriptor cannot be built.
#[cfg(windows)]
pub(crate) fn create_shared_pipe(
    options: &tokio::net::windows::named_pipe::ServerOptions,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use microsandbox_utils::elevation_share::{SharedObject, shared_security};
    match shared_security(SharedObject::Pipe) {
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
