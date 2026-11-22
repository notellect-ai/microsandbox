//! Existing database run rows and kernel peer credentials bind every exchange.

#[cfg(windows)]
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(windows)]
use std::sync::Mutex;

use microsandbox_control_client::{
    ClientError, ControlClientError, ControlClientResult, ErrorKind, VerifiedControlConnector,
};
use microsandbox_db::{
    DbReadConnection,
    entity::{run, sandbox},
};
use microsandbox_protocol_client::{BoxFuture, BoxTransport};
#[cfg(windows)]
use microsandbox_utils::elevation_share;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use tokio::time::Instant;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use super::super::LocalContext;
use super::identity::{DatabaseIdentity, ProcessIdentity};
use super::registry::{RuntimeKey, SharedError};
use super::session::ControlSession;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RuntimeOwner {
    database: Arc<DatabaseIdentity>,
    db: DbReadConnection,
    key: RuntimeKey,
    process: ProcessIdentity,
    endpoints: Vec<PathBuf>,
    allow_starting: bool,
    #[cfg(windows)]
    denial: PipeDenial,
}

/// The explained access denial of a control pipe open, kept for the session setup's caller:
/// the protocol client's error keeps only the error kind, which would drop the explanation.
#[cfg(windows)]
#[derive(Default)]
struct PipeDenial(Mutex<Option<io::Error>>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    pub(crate) fn invalidate_control_session(&self, sandbox_id: i32) {
        self.inner.control_sessions.invalidate_sandbox(sandbox_id);
    }

    pub(crate) async fn control_session(
        &self,
        name: &str,
    ) -> MicrosandboxResult<Option<ControlSession>> {
        self.control_session_with(name, false).await
    }

    /// Like [`Self::control_session`], but also accepts a sandbox that is still `Starting`.
    /// Only for the creator of a checkpoint restore, which reads the restored CPU and memory
    /// targets before it publishes the sandbox as `Running`.
    pub(crate) async fn control_session_while_starting(
        &self,
        name: &str,
    ) -> MicrosandboxResult<Option<ControlSession>> {
        self.control_session_with(name, true).await
    }

    async fn control_session_with(
        &self,
        name: &str,
        allow_starting: bool,
    ) -> MicrosandboxResult<Option<ControlSession>> {
        let pools = self.db().await?;
        let database = self
            .inner
            .control_sessions
            .database()
            .map_err(MicrosandboxError::ControlClient)?;
        let endpoints = self
            .agent_socket_paths(name)
            .iter()
            .map(|path| microsandbox_runtime::control::control_socket_path_for(path))
            .collect::<Vec<_>>();
        // Absence is the existing unsupported-feature signal for older runtimes
        // or VMs with no mutable capacity. An existing but failing peer is not.
        if !endpoints.iter().any(|path| path.exists()) {
            return Ok(None);
        }
        let model = microsandbox_db::catalog::sandbox_query(pools.read())
            .await?
            .filter(sandbox::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
        let run = current_run(pools.read(), model.id, allow_starting)
            .await
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        let pid = run.pid.ok_or_else(|| {
            MicrosandboxError::ControlClient(Arc::new(ControlClientError::RuntimeChanged))
        })?;
        let process = ProcessIdentity::capture(pid)
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        let key = RuntimeKey {
            sandbox_id: model.id,
            run_id: run.id,
            pid,
            start: process.start,
        };
        let owner = Arc::new(RuntimeOwner {
            database,
            db: pools.read().clone(),
            key,
            process,
            endpoints,
            allow_starting,
            #[cfg(windows)]
            denial: PipeDenial::default(),
        });
        owner
            .verify_session(Instant::now() + std::time::Duration::from_secs(10))
            .await
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        self.inner
            .control_sessions
            .get(key, owner.clone())
            .await
            .map(Some)
            .map_err(|error| owner.setup_error(error))
    }
}

impl RuntimeOwner {
    /// The error a failed control session setup reports.
    fn setup_error(&self, error: SharedError) -> MicrosandboxError {
        #[cfg(windows)]
        return self.denial.setup_error(error);
        #[cfg(not(windows))]
        MicrosandboxError::ControlClient(error)
    }
}

#[cfg(windows)]
impl PipeDenial {
    /// The protocol error for a control pipe open that failed with `error`. An access denial
    /// that [`elevation_share::explain_access_denied`] explained is kept for
    /// [`Self::setup_error`].
    fn refused(&self, error: io::Error) -> ClientError {
        let client = ClientError::new(ErrorKind::Io(error.kind()));
        if elevation_share::is_elevated_sandbox_denial(&error) {
            *self.0.lock().unwrap() = Some(error);
        }
        client
    }

    /// The error a failed session setup reports: a kept denial, so its explanation reaches
    /// the caller, otherwise `error`.
    fn setup_error(&self, error: SharedError) -> MicrosandboxError {
        match self.0.lock().unwrap().take() {
            Some(denied) => MicrosandboxError::Io(denied),
            None => MicrosandboxError::ControlClient(error),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VerifiedControlConnector for RuntimeOwner {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
        Box::pin(async move {
            self.verify_session(deadline).await?;
            #[cfg(unix)]
            {
                let mut last_error = None;
                for path in &self.endpoints {
                    match tokio::net::UnixStream::connect(path).await {
                        Ok(stream) => {
                            let pid = stream
                                .peer_cred()
                                .map_err(ClientError::from)?
                                .pid()
                                .ok_or_else(|| ClientError::new(ErrorKind::UnsupportedOperation))?;
                            self.process.verify_peer(pid)?;
                            self.verify_session(deadline).await?;
                            return Ok(Box::new(stream) as BoxTransport);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::ConnectionRefused
                            ) =>
                        {
                            last_error = Some(error)
                        }
                        Err(error) => return Err(ClientError::from(error).into()),
                    }
                }
                Err(ClientError::from(
                    last_error
                        .unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)),
                )
                .into())
            }
            #[cfg(windows)]
            {
                let path = self
                    .endpoints
                    .first()
                    .ok_or_else(|| ClientError::new(ErrorKind::InvalidOptions))?;
                loop {
                    if Instant::now() >= deadline {
                        return Err(ClientError::new(ErrorKind::Timeout).into());
                    }
                    match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                        Ok(stream) => {
                            let mut pid = 0;
                            if unsafe {
                                GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid)
                            } == 0
                            {
                                return Err(
                                    ClientError::from(std::io::Error::last_os_error()).into()
                                );
                            }
                            self.process.verify_peer(
                                i32::try_from(pid)
                                    .map_err(|_| ControlClientError::RuntimeChanged)?,
                            )?;
                            self.verify_session(deadline).await?;
                            return Ok(Box::new(stream) as BoxTransport);
                        }
                        Err(error) if error.raw_os_error() == Some(231) => {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await
                        }
                        Err(error) => {
                            let error = elevation_share::explain_access_denied(error);
                            return Err(self.denial.refused(error).into());
                        }
                    }
                }
            }
        })
    }

    fn verify_session(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
        Box::pin(async move {
            if Instant::now() >= deadline {
                return Err(ClientError::new(ErrorKind::Timeout).into());
            }
            self.database.verify()?;
            self.process.verify()?;
            let run = tokio::time::timeout_at(
                deadline,
                current_run(&self.db, self.key.sandbox_id, self.allow_starting),
            )
            .await
            .map_err(|_| ClientError::new(ErrorKind::Timeout))??;
            if run.id != self.key.run_id || run.pid != Some(self.key.pid) {
                return Err(ControlClientError::RuntimeChanged);
            }
            // Catch replacement while the database read was in flight too.
            self.database.verify()?;
            self.process.verify()
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn current_run(
    db: &DbReadConnection,
    sandbox_id: i32,
    allow_starting: bool,
) -> ControlClientResult<run::Model> {
    // Resident pause keeps the same host runtime and run alive. Operation-specific guards
    // decide what is allowed while paused; identity verification must not retire its session.
    let mut statuses = vec![
        sandbox::SandboxStatus::Running,
        sandbox::SandboxStatus::Paused,
        sandbox::SandboxStatus::Draining,
    ];
    if allow_starting {
        statuses.push(sandbox::SandboxStatus::Starting);
    }
    run::Entity::find()
        .inner_join(sandbox::Entity)
        .filter(run::Column::SandboxId.eq(sandbox_id))
        .filter(run::Column::Status.eq(run::RunStatus::Running))
        .filter(sandbox::Column::Status.is_in(statuses))
        .order_by_desc(run::Column::Id)
        .one(db)
        .await
        .map_err(database_error)?
        .ok_or(ControlClientError::RuntimeChanged)
}

fn database_error(_: sea_orm::DbErr) -> ControlClientError {
    // Queries can contain runtime data. The public transport error retains the
    // failure category without exposing SQL or prepared secret material.
    ClientError::new(ErrorKind::Io(std::io::ErrorKind::Other)).into()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests {
    use std::io;
    use std::sync::Arc;

    use microsandbox_control_client::{ClientError, ControlClientError, ErrorKind};
    use microsandbox_utils::elevation_share;
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::Security::{TokenElevationTypeDefault, TokenElevationTypeLimited};

    use super::PipeDenial;
    use crate::MicrosandboxError;

    fn denied() -> io::Error {
        io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)
    }

    fn setup_failure(client: ClientError) -> Arc<ControlClientError> {
        Arc::new(ControlClientError::Client(client))
    }

    /// A non-elevated process refused the control pipe gets the explained denial from the
    /// session setup, as an `io::Error` source the CLI can find, not the bare error kind the
    /// protocol client keeps; every other failure stays the control client error.
    #[test]
    fn a_refused_control_pipe_reports_the_explained_denial() {
        let denial = PipeDenial::default();
        let explained =
            elevation_share::explain_access_denied_as(denied(), TokenElevationTypeLimited);
        let client = denial.refused(explained);
        assert_eq!(client.kind, ErrorKind::Io(io::ErrorKind::PermissionDenied));
        let error = denial.setup_error(setup_failure(client));
        assert!(matches!(error, MicrosandboxError::Io(_)), "{error}");
        assert!(
            elevation_share::has_elevated_sandbox_denial(&error),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains(elevation_share::ELEVATED_SANDBOX_HINT),
            "{error}"
        );

        // Kept once: a later failure of the same owner is reported as it is.
        let client = ClientError::new(ErrorKind::Timeout);
        let error = denial.setup_error(setup_failure(client));
        assert!(
            matches!(error, MicrosandboxError::ControlClient(_)),
            "{error}"
        );

        // Access denied that was not explained (not a non-elevated process) is not kept.
        let unexplained =
            elevation_share::explain_access_denied_as(denied(), TokenElevationTypeDefault);
        let client = denial.refused(unexplained);
        let error = denial.setup_error(setup_failure(client));
        assert!(
            matches!(error, MicrosandboxError::ControlClient(_)),
            "{error}"
        );
        assert!(!elevation_share::has_elevated_sandbox_denial(&error));
    }
}
