//! Exact Windows process ownership for runtimes predating the lifecycle lock.
//!
//! The SDK records the runtime it started (PID and creation time) in `sdk-process.json`.
//! That record is the only evidence that may end a process: Windows reuses PIDs, so a PID
//! alone can name any process. See [`run_runtime`].

use std::io::{self, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use microsandbox_db::entity::run;
use microsandbox_utils::elevation_share;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A kernel handle pins the process object even after Windows recycles its PID.
pub(crate) struct RuntimeProcess {
    pid: i32,
    birth: u64,
    handle: OwnedHandle,
}

/// Kept outside SQLite so old SDKs can continue to open the shared catalog.
#[derive(Serialize, Deserialize)]
struct Record {
    sandbox_id: i32,
    run_id: i32,
    pid: i32,
    birth: u64,
    lifecycle_lock: bool,
}

/// A matching record distinguishes an exited process from missing ownership evidence.
pub(crate) struct RecordedOwner {
    pub lifecycle_lock: bool,
    pub process: Option<RuntimeProcess>,
    /// The recorded PID is live but this token may not open it (ERROR_ACCESS_DENIED):
    /// a process of another account or a protected process now holds the PID, or the
    /// runtime itself belongs to one. Like [`microsandbox_utils::process::pid_is_alive`],
    /// that counts as alive, so the run is left alone rather than reported as an error
    /// or reconciled as exited.
    pub inaccessible: bool,
}

impl RecordedOwner {
    /// Whether the recorded runtime still holds its run. An exited or recycled process
    /// is not alive; one this token may not open is (see [`Self::inaccessible`]).
    pub(crate) fn alive(&self) -> io::Result<bool> {
        if self.inaccessible {
            return Ok(true);
        }
        Ok(self
            .process
            .as_ref()
            .map(RuntimeProcess::alive)
            .transpose()?
            .unwrap_or(false))
    }
}

/// What a run's evidence proves about its runtime process. Only [`Self::Owned`], the process
/// the SDK recorded, matched by its exact creation time, may ever be ended.
pub(crate) enum RunRuntime {
    /// No process can still be the run's runtime: it has no PID, its PID is free or names an
    /// exited process, the recorded runtime exited, or the PID's holder was created after the
    /// run began (a recycled PID).
    Gone,
    /// The runtime the SDK recorded, still running.
    Owned(RuntimeProcess),
    /// A live process holds the PID and nothing proves whose it is: no matching record (the
    /// SDK stopped between starting the runtime and recording it) or a recorded runtime this
    /// account may not open. It may be the runtime, so it is not gone, and it may be any other
    /// process, so it is never ended.
    Unknown(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeProcess {
    pub(crate) fn capture(pid: i32) -> io::Result<Option<Self>> {
        if pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid runtime PID",
            ));
        }
        // SAFETY: rights only permit identity inspection and waiting, never termination.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid as u32,
            )
        };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: OpenProcess returned a new owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        Ok(Some(Self {
            pid,
            birth: creation_time(&handle)?,
            handle,
        }))
    }

    /// Ends this runtime. The handle `self` holds keeps Windows from giving the PID to another
    /// process, and the terminating handle's creation time is checked against the recorded one
    /// as well, so nothing but this process can be ended. Termination is asynchronous: wait
    /// with [`Self::exited_within`].
    pub(crate) fn terminate(&self) -> io::Result<()> {
        // SAFETY: a new handle with terminate rights, owned below.
        let raw = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                self.pid as u32,
            )
        };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return if self.alive()? { Err(error) } else { Ok(()) };
        }
        // SAFETY: OpenProcess returned a new owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if creation_time(&handle)? != self.birth {
            return Err(io::Error::other(
                "runtime process identity changed before termination",
            ));
        }
        if unsafe { TerminateProcess(raw, 1) } == 0 {
            // A process already exiting refuses termination.
            let error = io::Error::last_os_error();
            return if self.alive()? { Err(error) } else { Ok(()) };
        }
        Ok(())
    }

    /// Whether the process has exited by the end of `timeout`.
    pub(crate) async fn exited_within(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.alive()? {
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(true)
    }

    pub(crate) fn alive(&self) -> io::Result<bool> {
        // WAIT_FAILED is an observation error, never evidence of process exit.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub(crate) fn publish(
        &self,
        directory: &Path,
        run: &run::Model,
        lifecycle_lock: bool,
    ) -> MicrosandboxResult<()> {
        if run.pid != Some(self.pid) || !self.alive()? {
            return Err(changed());
        }
        let record = Record {
            sandbox_id: run.sandbox_id,
            run_id: run.id,
            pid: self.pid,
            birth: self.birth,
            lifecycle_lock,
        };
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer(&mut file, &record)?;
        file.flush()?;
        // The transition guard serializes publication with cooperative restart/removal.
        file.persist(directory.join("sdk-process.json"))
            .map_err(|error| error.error)?;
        Ok(())
    }

    /// Check the actual pipe server before handing the stream to the agent client.
    pub(crate) async fn connect_agent(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> MicrosandboxResult<crate::agent::AgentClient> {
        self.connect_agent_as(path, timeout, elevation_share::explain_access_denied)
            .await
    }

    /// [`Self::connect_agent`] with a failed pipe open explained by `explain`.
    async fn connect_agent_as(
        &self,
        path: &Path,
        timeout: Duration,
        explain: impl FnOnce(io::Error) -> io::Error,
    ) -> MicrosandboxResult<crate::agent::AgentClient> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !self.alive()? {
                return Err(changed());
            }
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                Ok(stream) => {
                    let mut pid = 0;
                    if unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid) } == 0
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                    if pid != self.pid as u32 || !self.alive()? {
                        return Err(changed());
                    }
                    return Ok(crate::agent::AgentClient::connect_stream_with_timeout(
                        stream,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await?);
                }
                Err(error)
                    if error.raw_os_error() == Some(231)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(explain(error).into()),
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn recorded_owner(
    directory: &Path,
    run: &run::Model,
) -> MicrosandboxResult<Option<RecordedOwner>> {
    let path = directory.join("sdk-process.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(record_error(&path, None, error).into()),
    };
    // A partial or unreadable record proves nothing about any process: no matching record.
    let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
        return Ok(None);
    };
    // An old file must never bind an unrelated run, including after removal/recreation.
    if record.sandbox_id != run.sandbox_id || record.run_id != run.id || Some(record.pid) != run.pid
    {
        return Ok(None);
    }
    let owner = owner_from_capture(
        RuntimeProcess::capture(record.pid),
        record.birth,
        record.lifecycle_lock,
    )
    .map_err(|error| record_error(&path, Some(record.pid), error))?;
    Ok(Some(owner))
}

/// What the evidence proves about `run`'s runtime process; see [`RunRuntime`]. `directory` is
/// the sandbox's runtime directory, where the SDK keeps its record.
pub(crate) fn run_runtime(directory: &Path, run: &run::Model) -> MicrosandboxResult<RunRuntime> {
    let Some(pid) = run.pid.filter(|pid| *pid > 0) else {
        return Ok(RunRuntime::Gone);
    };
    match recorded_owner(directory, run)? {
        Some(owner) => Ok(recorded_runtime(owner, pid)?),
        None => unrecorded_runtime(RuntimeProcess::capture(pid), run, pid).map_err(|error| {
            record_error(&directory.join("sdk-process.json"), Some(pid), error).into()
        }),
    }
}

/// The runtime a matching record names: ended only through its verified process.
fn recorded_runtime(owner: RecordedOwner, pid: i32) -> io::Result<RunRuntime> {
    if owner.inaccessible {
        return Ok(RunRuntime::Unknown(format!(
            "runtime pid {pid} is not accessible to this user; stop it from the account that \
             started it"
        )));
    }
    Ok(match owner.process {
        Some(process) if process.alive()? => RunRuntime::Owned(process),
        _ => RunRuntime::Gone,
    })
}

/// A run with no matching record: its PID's holder is gone, proven not the runtime by its
/// creation time, or unknown. Never owned.
fn unrecorded_runtime(
    captured: io::Result<Option<RuntimeProcess>>,
    run: &run::Model,
    pid: i32,
) -> io::Result<RunRuntime> {
    let unknown = || {
        RunRuntime::Unknown(format!(
            "runtime pid {pid} has no matching SDK process record, so the process holding it \
             may be another program; it was left running"
        ))
    };
    match captured {
        Ok(None) => Ok(RunRuntime::Gone),
        Ok(Some(process)) if !process.alive()? => Ok(RunRuntime::Gone),
        Ok(Some(process)) if created_after_run(process.birth, run) => Ok(RunRuntime::Gone),
        Ok(Some(_)) => Ok(unknown()),
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => Ok(unknown()),
        Err(error) => Err(error),
    }
}

/// Whether a process created at `birth` came too late to be `run`'s runtime, which starts
/// before it writes the run row.
fn created_after_run(birth: u64, run: &run::Model) -> bool {
    run.started_at.is_some_and(|started| {
        !super::reap::creation_may_belong_to_run(
            super::reap::filetime_ticks_to_unix_micros(birth),
            started.and_utc().timestamp_micros(),
        )
    })
}

/// The creation time of the process `handle` refers to, as FILETIME ticks.
fn creation_time(handle: &OwnedHandle) -> io::Result<u64> {
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Turns the capture of a recorded PID into its owner. ERROR_ACCESS_DENIED means the
/// PID is live but not openable by this token; like `pid_is_alive`, that is alive.
fn owner_from_capture(
    captured: io::Result<Option<RuntimeProcess>>,
    birth: u64,
    lifecycle_lock: bool,
) -> io::Result<RecordedOwner> {
    let (process, inaccessible) = match captured {
        Ok(process) => (process.filter(|process| process.birth == birth), false),
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => (None, true),
        Err(error) => return Err(error),
    };
    Ok(RecordedOwner {
        lifecycle_lock,
        process,
        inaccessible,
    })
}

/// Names the record (and the PID it holds) an I/O error came from; a bare OS error
/// from `msb list` gives no clue which sandbox or process failed.
fn record_error(path: &Path, pid: Option<i32>, error: io::Error) -> io::Error {
    let subject = match pid {
        Some(pid) => format!("runtime pid {pid} recorded in {}", path.display()),
        None => path.display().to_string(),
    };
    io::Error::new(error.kind(), format!("{subject}: {error}"))
}

fn changed() -> MicrosandboxError {
    MicrosandboxError::Runtime("runtime process identity changed during lifecycle operation".into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
    use windows_sys::Win32::Security::{TokenElevationTypeDefault, TokenElevationTypeLimited};

    struct ChildFixture(Child);

    impl ChildFixture {
        fn start() -> Self {
            Self(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "runtime::ownership::tests::ownership_child",
                        "--ignored",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
    }

    impl Drop for ChildFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn run(pid: i32) -> run::Model {
        run::Model {
            id: 17,
            sandbox_id: 11,
            pid: Some(pid),
            status: run::RunStatus::Running,
            exit_code: None,
            exit_signal: None,
            termination_reason: None,
            termination_detail: None,
            signals_sent: None,
            started_at: None,
            terminated_at: None,
        }
    }

    #[test]
    fn retained_owner_observes_real_exit_and_survives_record_reload() {
        let mut child = ChildFixture::start();
        let process = RuntimeProcess::capture(child.0.id() as i32)
            .unwrap()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let run = run(process.pid);
        process.publish(directory.path(), &run, false).unwrap();
        let reattached = recorded_owner(directory.path(), &run).unwrap().unwrap();
        assert!(!reattached.lifecycle_lock);
        assert!(reattached.process.as_ref().unwrap().alive().unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!process.alive().unwrap());
        assert!(!reattached.process.as_ref().unwrap().alive().unwrap());
    }

    #[test]
    fn old_record_cannot_follow_a_replacement_run_or_recycled_pid() {
        let process = RuntimeProcess::capture(std::process::id() as i32)
            .unwrap()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut run = run(process.pid);
        process.publish(directory.path(), &run, false).unwrap();
        run.id += 1;
        assert!(recorded_owner(directory.path(), &run).unwrap().is_none());
        run.id -= 1;
        let path = directory.path().join("sdk-process.json");
        let mut record: Record = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record.birth -= 1;
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            recorded_owner(directory.path(), &run)
                .unwrap()
                .unwrap()
                .process
                .is_none()
        );
        assert!(process.alive().unwrap());
    }

    #[tokio::test]
    async fn shutdown_connection_rejects_a_different_pipe_owner() {
        let child = ChildFixture::start();
        let process = RuntimeProcess::capture(child.0.id() as i32)
            .unwrap()
            .unwrap();
        let path = format!(r"\\.\pipe\msb-owner-test-{}", std::process::id());
        let _server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        assert!(
            process
                .connect_agent(Path::new(&path), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(process.alive().unwrap());
    }

    /// A non-elevated process whose shutdown request is refused the agent pipe gets the
    /// explained denial; any other process gets the plain access-denied error.
    #[tokio::test]
    async fn a_refused_shutdown_connection_is_explained_as_an_elevated_sandbox() {
        let process = RuntimeProcess::capture(std::process::id() as i32)
            .unwrap()
            .unwrap();
        let path = format!(r"\\.\pipe\msb-owner-denied-test-{}", std::process::id());
        // Inbound only, so the client's read/write open is refused with access denied, as an
        // elevated runtime's unshared pipe refuses a non-elevated client.
        let _server = ServerOptions::new()
            .first_pipe_instance(true)
            .access_outbound(false)
            .create(&path)
            .unwrap();
        let explain_as = |elevation| {
            move |error: io::Error| elevation_share::explain_access_denied_as(error, elevation)
        };

        let explained = process
            .connect_agent_as(
                Path::new(&path),
                Duration::from_secs(1),
                explain_as(TokenElevationTypeLimited),
            )
            .await
            .err()
            .unwrap();
        let plain = process
            .connect_agent_as(
                Path::new(&path),
                Duration::from_secs(1),
                explain_as(TokenElevationTypeDefault),
            )
            .await
            .err()
            .unwrap();

        assert!(
            elevation_share::has_elevated_sandbox_denial(&explained),
            "{explained}"
        );
        let MicrosandboxError::Io(plain) = plain else {
            panic!("the refused open is no longer an I/O error");
        };
        assert_eq!(
            plain.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "{plain}"
        );
        assert!(!elevation_share::is_elevated_sandbox_denial(&plain));
    }

    /// A recorded PID this token may not open (another account's or a protected process)
    /// counts as alive, as `pid_is_alive` does, instead of failing `msb list` with a bare
    /// "Access is denied (os error 5)".
    #[test]
    fn an_inaccessible_recorded_pid_is_alive_not_an_error() {
        let denied = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        let owner = owner_from_capture(Err(denied), 1, false).unwrap();
        assert!(owner.inaccessible);
        assert!(owner.process.is_none());
        assert!(owner.alive().unwrap());

        let exited = owner_from_capture(Ok(None), 1, false).unwrap();
        assert!(!exited.inaccessible);
        assert!(!exited.alive().unwrap());

        let other = io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32);
        let error = owner_from_capture(Err(other), 1, false).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_HANDLE as i32));
    }

    /// Other I/O errors name the record and the PID it holds.
    #[test]
    fn record_errors_name_the_record_and_pid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sdk-process.json");
        let error = record_error(
            &path,
            Some(4321),
            io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32),
        );
        let message = error.to_string();
        assert!(message.contains("runtime pid 4321"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");

        // An unreadable record (here a directory in its place) names its path.
        std::fs::create_dir(&path).unwrap();
        let MicrosandboxError::Io(error) =
            recorded_owner(directory.path(), &run(4321)).err().unwrap()
        else {
            panic!("an unreadable record is no longer an I/O error");
        };
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    fn started(pid: i32, started_at: Option<chrono::NaiveDateTime>) -> run::Model {
        run::Model {
            started_at,
            ..run(pid)
        }
    }

    fn an_hour(sign: i64) -> Option<chrono::NaiveDateTime> {
        Some(chrono::Utc::now().naive_utc() + chrono::Duration::hours(sign))
    }

    fn owned(runtime: &RunRuntime) -> bool {
        matches!(runtime, RunRuntime::Owned(_))
    }

    fn unknown(runtime: &RunRuntime) -> bool {
        matches!(runtime, RunRuntime::Unknown(_))
    }

    fn gone(runtime: &RunRuntime) -> bool {
        matches!(runtime, RunRuntime::Gone)
    }

    fn running(child: &mut ChildFixture) -> bool {
        child.0.try_wait().unwrap().is_none()
    }

    /// W-31m: a crash between starting the runtime and recording it leaves no record. The PID
    /// may since name any process (11-24: a `ping` started after the run). Nothing without a
    /// matching record is ever owned, so nothing ends it.
    #[test]
    fn an_unrecorded_pid_is_never_owned() {
        let mut bystander = ChildFixture::start();
        let pid = bystander.0.id() as i32;
        let directory = tempfile::tempdir().unwrap();
        // Created after the run began: a recycled PID, so the runtime is gone.
        let recycled = run_runtime(directory.path(), &started(pid, an_hour(-1))).unwrap();
        assert!(gone(&recycled));
        // Not provably later than the run (or the run has no start time): unknown.
        let unproven = run_runtime(directory.path(), &started(pid, an_hour(1))).unwrap();
        assert!(unknown(&unproven));
        let undated = run_runtime(directory.path(), &started(pid, None)).unwrap();
        assert!(unknown(&undated));
        assert!(running(&mut bystander));
    }

    /// A record cut short (or otherwise unreadable as a record) proves nothing.
    #[test]
    fn a_partial_record_is_no_record() {
        let mut bystander = ChildFixture::start();
        let pid = bystander.0.id() as i32;
        let directory = tempfile::tempdir().unwrap();
        let run = started(pid, None);
        let process = RuntimeProcess::capture(pid).unwrap().unwrap();
        process.publish(directory.path(), &run, false).unwrap();
        let path = directory.path().join("sdk-process.json");
        let whole = std::fs::read(&path).unwrap();
        for cut in [0, 1, whole.len() / 2, whole.len() - 1] {
            std::fs::write(&path, &whole[..cut]).unwrap();
            assert!(recorded_owner(directory.path(), &run).unwrap().is_none());
            assert!(unknown(&run_runtime(directory.path(), &run).unwrap()));
        }
        assert!(running(&mut bystander));
    }

    /// A record whose creation time is not the live process's: the recorded runtime exited and
    /// its PID was reused. Gone, and the process holding the PID is left alone.
    #[test]
    fn a_record_with_another_creation_time_owns_nothing() {
        let mut bystander = ChildFixture::start();
        let pid = bystander.0.id() as i32;
        let directory = tempfile::tempdir().unwrap();
        let run = started(pid, an_hour(1));
        RuntimeProcess::capture(pid)
            .unwrap()
            .unwrap()
            .publish(directory.path(), &run, false)
            .unwrap();
        let path = directory.path().join("sdk-process.json");
        for delta in [-1i64, 1] {
            let mut record: Record =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            record.birth = record.birth.wrapping_add_signed(delta);
            std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(gone(&run_runtime(directory.path(), &run).unwrap()));
            record.birth = record.birth.wrapping_add_signed(-delta);
            std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        assert!(running(&mut bystander));
    }

    /// Termination checks the creation time on the terminating handle too.
    #[test]
    fn terminate_refuses_a_process_with_another_creation_time() {
        let mut bystander = ChildFixture::start();
        let mut impostor = RuntimeProcess::capture(bystander.0.id() as i32)
            .unwrap()
            .unwrap();
        impostor.birth -= 1;
        assert!(impostor.terminate().is_err());
        assert!(running(&mut bystander));
    }

    /// The recorded runtime is ended through its record alone: the SDK that started it, and its
    /// Job, are gone. A bystander is untouched.
    #[tokio::test]
    async fn the_recorded_runtime_is_ended_without_its_job() {
        let mut runtime = ChildFixture::start();
        let mut bystander = ChildFixture::start();
        let directory = tempfile::tempdir().unwrap();
        let run = started(runtime.0.id() as i32, an_hour(-1));
        RuntimeProcess::capture(runtime.0.id() as i32)
            .unwrap()
            .unwrap()
            .publish(directory.path(), &run, false)
            .unwrap();
        let RunRuntime::Owned(process) = run_runtime(directory.path(), &run).unwrap() else {
            panic!("the recorded runtime is not owned");
        };
        process.terminate().unwrap();
        assert!(process.exited_within(Duration::from_secs(5)).await.unwrap());
        assert!(!running(&mut runtime));
        assert!(running(&mut bystander));
        // Once it has exited, the record owns nothing, and termination is a no-op.
        assert!(gone(&run_runtime(directory.path(), &run).unwrap()));
        process.terminate().unwrap();
    }

    /// Access denied, recorded or not, is unknown: alive for status, never ended.
    #[test]
    fn access_denied_is_unknown_recorded_or_not() {
        let denied = || io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        let owner = owner_from_capture(Err(denied()), 1, true).unwrap();
        assert!(unknown(&recorded_runtime(owner, 7).unwrap()));
        let run = started(7, an_hour(-1));
        assert!(unknown(
            &unrecorded_runtime(Err(denied()), &run, 7).unwrap()
        ));
        assert!(gone(&unrecorded_runtime(Ok(None), &run, 7).unwrap()));
        let other = io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32);
        assert!(unrecorded_runtime(Err(other), &run, 7).is_err());
        // A run without a usable PID has no runtime to end.
        for pid in [None, Some(0), Some(-4)] {
            let run = run::Model { pid, ..run.clone() };
            let directory = tempfile::tempdir().unwrap();
            assert!(gone(&run_runtime(directory.path(), &run).unwrap()));
        }
    }

    /// A matching record for a live runtime is owned; status callers see it as running.
    #[test]
    fn a_matching_record_owns_the_live_runtime() {
        let runtime = ChildFixture::start();
        let directory = tempfile::tempdir().unwrap();
        let run = started(runtime.0.id() as i32, an_hour(1));
        RuntimeProcess::capture(runtime.0.id() as i32)
            .unwrap()
            .unwrap()
            .publish(directory.path(), &run, true)
            .unwrap();
        assert!(owned(&run_runtime(directory.path(), &run).unwrap()));
    }

    #[test]
    #[ignore = "subprocess fixture controlled by the ownership tests"]
    fn ownership_child() {
        // EOF also releases the fixture if its test parent exits unexpectedly.
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0]);
    }
}
