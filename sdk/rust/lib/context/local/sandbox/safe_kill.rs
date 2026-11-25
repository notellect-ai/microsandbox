//! The one way the SDK judges or ends a sandbox runtime by its recorded PID.
//!
//! Windows reuses a PID as soon as its process ends, and every OS reuses one
//! eventually, so a bare `run.pid` may name an unrelated process (W-31m: `msb
//! remove --force` after a crash terminated a `ping` of the same user). A run's
//! process is therefore named by its PID and its start time:
//!
//! - `sdk-process.json` (Windows) records the runtime's exact creation time.
//! - Without it, the run row itself: the runtime inserts its row while running,
//!   so it was born no later than `run.started_at`, and any later holder of the
//!   PID was born after the runtime ended, i.e. after `started_at`.
//!
//! A process born later than `started_at` is a later holder (the rules, with
//! Linux's slack for its estimated birth, live in [`crate::runtime::reap`]). As a backstop against wall-clock steps (NTP, a user setting the time
//! back) that could make a later holder look older, the process must also run the
//! runtime's executable (`msb`): any other image is a later holder too.
//!
//! The process is opened once, compared, and ended through that same handle
//! (Windows process handle, Linux pidfd; macOS compares the start time right
//! before `kill`). What cannot be compared (no start time, access denied) is
//! [`RunProcess::Unknown`]: never alive, never killed, never reconciled.

use std::io;
use std::path::Path;

use microsandbox_db::entity::run as run_entity;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::context::local::control::identity::ProcessIdentity;
#[cfg(windows)]
use crate::runtime::reap::filetime_ticks_to_unix_micros;
use crate::runtime::reap::{creation_may_belong_to_run, image_basename_is_msb};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What a run's recorded PID names now.
pub(crate) enum RunProcess {
    /// The run's runtime, held so that a later holder of the PID is never hit.
    Alive(RuntimeHandle),
    /// The runtime has exited: no process has the PID, or a younger one does.
    Exited,
    /// Cannot tell: no start time to compare, or the process cannot be opened.
    Unknown,
}

/// A held runtime process.
pub(crate) struct RuntimeHandle {
    #[cfg(windows)]
    process: crate::runtime::ownership::RuntimeProcess,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    process: ProcessIdentity,
}

/// How a held process is asked to end.
#[derive(Clone, Copy)]
pub(crate) enum Ending {
    /// SIGTERM; Windows has no graceful equivalent and terminates.
    Graceful,
    /// SIGKILL / TerminateProcess.
    Kill,
    /// SIGUSR1, the legacy drain request (Unix only).
    #[cfg_attr(
        any(target_os = "linux", target_os = "macos", not(unix)),
        allow(dead_code)
    )]
    Drain,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RunProcess {
    /// Resolve `run`'s PID. `runtime_dir` is the sandbox's `runtime` directory,
    /// where Windows keeps `sdk-process.json`, when the caller knows it.
    pub(crate) fn resolve(run: &run_entity::Model, runtime_dir: Option<&Path>) -> Self {
        // A run without a PID never had a process to end.
        let Some(pid) = run.pid.filter(|pid| *pid > 0) else {
            return Self::Exited;
        };
        #[cfg(windows)]
        {
            use crate::runtime::ownership::{RuntimeProcess, recorded_birth};
            use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
            // Terminate rights first; an account that may only inspect the process
            // still learns whether it is the runtime (a stop then fails as before).
            let captured = match RuntimeProcess::capture_terminable(pid) {
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    RuntimeProcess::capture(pid)
                }
                result => result,
            };
            let process = match captured {
                Ok(Some(process)) => process,
                Ok(None) => return Self::Exited,
                // ACCESS_DENIED on a reused PID is not an error, and not alive.
                Err(_) => return Self::Unknown,
            };
            match process.alive() {
                Ok(true) => {}
                Ok(false) => return Self::Exited,
                Err(_) => return Self::Unknown,
            }
            let ours = match runtime_dir.and_then(|dir| recorded_birth(dir, run)) {
                Some(birth) => process.birth() == birth,
                None => match run.started_at {
                    Some(started) => {
                        born_by(filetime_ticks_to_unix_micros(process.birth()), started)
                    }
                    None => return Self::Unknown,
                },
            };
            if !ours {
                return Self::Exited;
            }
            match image(process.image_path()) {
                Image::Runtime => Self::Alive(RuntimeHandle { process }),
                Image::Other => Self::Exited,
                Image::Unknown => Self::Unknown,
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let _ = runtime_dir;
            use microsandbox_control_client::ControlClientError;
            let process = match ProcessIdentity::capture(pid) {
                Ok(process) => process,
                Err(ControlClientError::RuntimeChanged) => return Self::Exited,
                Err(_) => return Self::Unknown,
            };
            let (Some(started), Some(born)) = (run.started_at, process.born_micros()) else {
                return Self::Unknown;
            };
            if !born_by(born, started) {
                return Self::Exited;
            }
            match image(unix_image_path(pid)) {
                Image::Runtime => Self::Alive(RuntimeHandle { process }),
                Image::Other => Self::Exited,
                Image::Unknown => Self::Unknown,
            }
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = (pid, runtime_dir);
            Self::Unknown
        }
    }

    /// Whether the run's runtime may still hold its resources: alive or unknown.
    pub(crate) fn may_be_alive(&self) -> bool {
        !matches!(self, Self::Exited)
    }
}

impl RuntimeHandle {
    /// Ask the held process to end. Returns `Ok(false)` when it had already exited.
    pub(crate) fn end(&self, how: Ending) -> io::Result<bool> {
        #[cfg(windows)]
        {
            if matches!(how, Ending::Drain) {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            if !self.process.alive()? {
                return Ok(false);
            }
            self.process.terminate()?;
            Ok(true)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let signal = match how {
                Ending::Graceful => libc::SIGTERM,
                Ending::Kill => libc::SIGKILL,
                Ending::Drain => libc::SIGUSR1,
            };
            self.process.signal(signal)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = how;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Whether the held process has exited. Never follows a reused PID.
    pub(crate) fn has_exited(&self) -> bool {
        #[cfg(windows)]
        {
            // WAIT_FAILED is no evidence of exit.
            matches!(self.process.alive(), Ok(false))
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            matches!(
                self.process.verify(),
                Err(microsandbox_control_client::ControlClientError::RuntimeChanged)
            )
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a process born at `born` (Unix microseconds) can be the runtime of a
/// run that started at `started`.
fn born_by(born: i64, started: chrono::NaiveDateTime) -> bool {
    creation_may_belong_to_run(born, started.and_utc().timestamp_micros())
}

/// What a process's executable image says about it.
enum Image {
    Runtime,
    Other,
    Unknown,
}

/// The runtime is the `msb` binary (Linux marks a replaced one " (deleted)").
fn image(path: io::Result<std::path::PathBuf>) -> Image {
    let Ok(path) = path else {
        return Image::Unknown;
    };
    let Some(path) = path.to_str() else {
        return Image::Unknown;
    };
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    #[cfg(all(test, any(windows, target_os = "linux", target_os = "macos")))]
    if let Some(name) = tests::RUNTIME_IMAGE.with(|image| image.get()) {
        let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let stem = base.split('.').next().unwrap_or(base);
        return if stem.eq_ignore_ascii_case(name) {
            Image::Runtime
        } else {
            Image::Other
        };
    }
    if image_basename_is_msb(path) {
        Image::Runtime
    } else {
        Image::Other
    }
}

#[cfg(target_os = "macos")]
fn unix_image_path(pid: i32) -> io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer holds `buffer.len()` bytes.
    let length =
        unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(std::ffi::OsString::from_vec(buffer).into())
}

#[cfg(target_os = "linux")]
fn unix_image_path(pid: i32) -> io::Result<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

/// Tests elsewhere stand a child (`sleep`, `ping`) in for the runtime: accept its
/// image as the runtime's on this thread.
#[cfg(all(test, any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn accept_runtime_image_for_tests(name: &'static str) {
    tests::RUNTIME_IMAGE.with(|image| image.set(Some(name)));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, any(windows, target_os = "linux", target_os = "macos")))]
mod tests {
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use chrono::{NaiveDateTime, Utc};
    use microsandbox_db::entity::run as run_entity;

    use super::{Ending, Image, RunProcess, born_by, image};
    use crate::runtime::reap::IDENTITY_CREATION_SLACK_MICROS;

    thread_local! {
        /// The runtime image name these tests accept instead of `msb`.
        pub(super) static RUNTIME_IMAGE: std::cell::Cell<Option<&'static str>> =
            const { std::cell::Cell::new(None) };
    }

    /// Accept the sleeper's image (`sleep`, `PING.EXE`) as the runtime's.
    fn sleeper_is_runtime() {
        #[cfg(windows)]
        RUNTIME_IMAGE.with(|image| image.set(Some("ping")));
        #[cfg(unix)]
        RUNTIME_IMAGE.with(|image| image.set(Some("sleep")));
    }

    /// A child that runs until it is ended or dropped.
    struct Sleeper(Child);

    impl Sleeper {
        fn start() -> Self {
            sleeper_is_runtime();
            #[cfg(windows)]
            let child = Command::new("ping").args(["-n", "60", "127.0.0.1"]).spawn();
            #[cfg(unix)]
            let child = Command::new("sleep").arg("60").spawn();
            Self(child.unwrap())
        }

        fn pid(&self) -> i32 {
            self.0.id() as i32
        }

        fn running(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }

        /// Whether it exits within a few seconds.
        fn ends(&mut self) -> bool {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if !self.running() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn run(pid: Option<i32>, started_at: Option<NaiveDateTime>) -> run_entity::Model {
        run_entity::Model {
            id: 7,
            sandbox_id: 3,
            pid,
            status: run_entity::RunStatus::Running,
            exit_code: None,
            exit_signal: None,
            termination_reason: None,
            termination_detail: None,
            signals_sent: None,
            started_at,
            terminated_at: None,
        }
    }

    fn hour_ago() -> Option<NaiveDateTime> {
        Some((Utc::now() - chrono::Duration::hours(1)).naive_utc())
    }

    fn hour_ahead() -> Option<NaiveDateTime> {
        Some((Utc::now() + chrono::Duration::hours(1)).naive_utc())
    }

    /// W-31m: the run's runtime crashed and its PID now names an unrelated, younger
    /// process; no sdk-process.json exists. That process is not the run's: it
    /// resolves to Exited, so nothing ends it and the run is reconciled.
    #[test]
    fn a_younger_holder_of_the_pid_is_not_the_runs_runtime() {
        let mut unrelated = Sleeper::start();
        let directory = tempfile::tempdir().unwrap();
        let process = RunProcess::resolve(
            &run(Some(unrelated.pid()), hour_ago()),
            Some(directory.path()),
        );
        assert!(matches!(process, RunProcess::Exited));
        assert!(!process.may_be_alive());
        std::thread::sleep(Duration::from_millis(100));
        assert!(unrelated.running(), "the unrelated process was ended");
    }

    /// The run's own runtime (born before its row) resolves Alive and ends
    /// through the held process.
    #[test]
    fn the_runs_runtime_is_held_and_ended() {
        let mut runtime = Sleeper::start();
        let RunProcess::Alive(held) =
            RunProcess::resolve(&run(Some(runtime.pid()), hour_ahead()), None)
        else {
            panic!("the run's runtime did not resolve alive");
        };
        assert!(!held.has_exited());
        assert!(held.end(Ending::Kill).unwrap());
        assert!(runtime.ends(), "the run's runtime still runs after Kill");
        assert!(held.has_exited());
    }

    /// No start time to compare: never alive, never killed, never reconciled.
    #[test]
    fn a_run_without_a_start_time_is_unknown() {
        let mut process = Sleeper::start();
        let resolved = RunProcess::resolve(&run(Some(process.pid()), None), None);
        assert!(matches!(resolved, RunProcess::Unknown));
        assert!(resolved.may_be_alive());
        assert!(process.running());
    }

    #[test]
    fn a_run_without_a_live_pid_has_exited() {
        let mut ended = Sleeper::start();
        let pid = ended.pid();
        ended.0.kill().unwrap();
        ended.0.wait().unwrap();
        for record in [
            run(Some(pid), hour_ahead()),
            run(None, hour_ahead()),
            run(Some(0), None),
        ] {
            assert!(matches!(
                RunProcess::resolve(&record, None),
                RunProcess::Exited
            ));
        }
    }

    /// The runtime exits (and is reaped) between resolve and end: end reports it
    /// had already exited and hits nothing.
    #[test]
    fn a_runtime_that_exits_after_resolve_is_not_signalled() {
        let mut runtime = Sleeper::start();
        let RunProcess::Alive(held) =
            RunProcess::resolve(&run(Some(runtime.pid()), hour_ahead()), None)
        else {
            panic!("the run's runtime did not resolve alive");
        };
        runtime.0.kill().unwrap();
        runtime.0.wait().unwrap();
        assert!(held.has_exited());
        assert!(!held.end(Ending::Kill).unwrap());
        assert!(!held.end(Ending::Graceful).unwrap());
    }

    /// Process 1 belongs to root. macOS refuses to inspect it (access denied:
    /// Unknown, never killed); Linux shows it, but born long after 1971 it is not a
    /// 1971 run's runtime, and this account's signal to it is refused, never
    /// reported done.
    #[cfg(unix)]
    #[test]
    fn another_accounts_process() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let ancient = chrono::DateTime::from_timestamp(31_536_000, 0).map(|time| time.naive_utc());
        assert!(!matches!(
            RunProcess::resolve(&run(Some(1), ancient), None),
            RunProcess::Alive(_)
        ));
        match RunProcess::resolve(&run(Some(1), hour_ahead()), None) {
            RunProcess::Alive(held) => assert!(held.end(Ending::Graceful).is_err()),
            RunProcess::Unknown => {}
            RunProcess::Exited => panic!("process 1 resolved as exited"),
        }
    }

    /// The System process (4): not openable for termination by this account.
    /// Whatever it resolves to, ending it never succeeds.
    #[cfg(windows)]
    #[test]
    fn the_system_process() {
        let ancient = chrono::DateTime::from_timestamp(31_536_000, 0).map(|time| time.naive_utc());
        assert!(!matches!(
            RunProcess::resolve(&run(Some(4), ancient), None),
            RunProcess::Alive(_)
        ));
        if let RunProcess::Alive(held) = RunProcess::resolve(&run(Some(4), hour_ahead()), None) {
            assert!(held.end(Ending::Kill).is_err());
        }
    }

    /// sdk-process.json names the runtime exactly: a record whose birth differs
    /// is a reused PID, even when the run's start time would accept the process.
    #[cfg(windows)]
    #[test]
    fn a_recorded_birth_decides_over_the_start_time() {
        use crate::runtime::ownership::RuntimeProcess;

        let mut runtime = Sleeper::start();
        let directory = tempfile::tempdir().unwrap();
        let model = run(Some(runtime.pid()), hour_ahead());
        RuntimeProcess::capture(runtime.pid())
            .unwrap()
            .unwrap()
            .publish(directory.path(), &model, false)
            .unwrap();
        assert!(matches!(
            RunProcess::resolve(&model, Some(directory.path())),
            RunProcess::Alive(_)
        ));
        let path = directory.path().join("sdk-process.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["birth"] = (record["birth"].as_u64().unwrap() - 1).into();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            RunProcess::resolve(&model, Some(directory.path())),
            RunProcess::Exited
        ));
        // A partial record is no record: the start time decides.
        std::fs::write(&path, b"{\"pid\":").unwrap();
        assert!(matches!(
            RunProcess::resolve(&model, Some(directory.path())),
            RunProcess::Alive(_)
        ));
        assert!(runtime.running());
    }

    /// A wall-clock step back (NTP, a user setting the time) can make a later
    /// holder of the PID look born before the run started. It still runs another
    /// executable than the runtime's, so it is not the run's runtime.
    #[test]
    fn a_holder_of_another_image_is_not_the_runtime_whatever_its_birth() {
        let mut unrelated = Sleeper::start();
        RUNTIME_IMAGE.with(|image| image.set(Some("msb")));
        let process = RunProcess::resolve(&run(Some(unrelated.pid()), hour_ahead()), None);
        assert!(matches!(process, RunProcess::Exited));
        std::thread::sleep(Duration::from_millis(100));
        assert!(unrelated.running(), "the unrelated process was ended");
    }

    /// Births compare at the microsecond: on Windows and macOS a runtime born
    /// after the stored start is a later holder; Linux, whose birth is an
    /// estimate, allows its slack and no more.
    #[test]
    fn the_start_time_boundary() {
        let started = chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789)
            .unwrap()
            .naive_utc();
        let started_us = 1_700_000_000_123_456i64;
        for (born, expected) in [
            (started_us - 60_000_000, true),
            (started_us, true),
            (started_us + IDENTITY_CREATION_SLACK_MICROS, true),
            (started_us + IDENTITY_CREATION_SLACK_MICROS + 1, false),
            (started_us + 3_600_000_000, false),
        ] {
            assert_eq!(born_by(born, started), expected, "born {born}");
        }
    }

    #[test]
    fn runtime_image_names() {
        for (path, runtime) in [
            ("/usr/local/bin/msb", true),
            (r"C:\Users\a\AppData\Local\Notellect\MSB.EXE", true),
            ("/opt/msb (deleted)", true),
            ("/usr/bin/msbuild", false),
            (r"C:\Windows\System32\PING.EXE", false),
            ("/bin/sleep", false),
        ] {
            let found = image(Ok(path.into()));
            assert_eq!(matches!(found, Image::Runtime), runtime, "{path}");
        }
        assert!(matches!(
            image(Err(std::io::Error::from_raw_os_error(1))),
            Image::Unknown
        ));
    }
}
