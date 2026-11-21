//! Upper bounds for tests that wait.
//!
//! Every test step that blocks (a read, write, join, recv or wait) must have
//! an explicit limit, so a hang fails with the step that hung instead of
//! stalling CI until its job timeout.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Run `work` on its own thread and return its result, or fail the test if
/// it is still running after `limit`. A panic in `work` is re-raised here.
///
/// For work that borrows from the test (scoped threads, local references),
/// hold a [`Deadline`] instead.
pub fn with_deadline<T: Send + 'static>(
    step: &str,
    limit: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name(format!("deadline: {step}"))
        .spawn(move || {
            let _ = sender.send(work());
        })
        .expect("spawn deadline worker");
    match receiver.recv_timeout(limit) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => {
            panic!("timed out after {limit:?}: {step}")
        }
        Err(RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => unreachable!("deadline worker ended without a result"),
        },
    }
}

/// Receive from `receiver`, failing the test if nothing arrives within
/// `limit` or the sender is gone.
pub fn recv_within<T>(receiver: &mpsc::Receiver<T>, step: &str, limit: Duration) -> T {
    match receiver.recv_timeout(limit) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => panic!("timed out after {limit:?}: {step}"),
        Err(RecvTimeoutError::Disconnected) => panic!("sender gone while waiting: {step}"),
    }
}

/// Join `thread`, failing the test if it has not finished after `limit`.
/// A panic in the thread is re-raised here. A thread that never finishes is
/// left behind; the test still fails, naming `step`.
pub fn join_within<T>(thread: JoinHandle<T>, step: &str, limit: Duration) -> T {
    let deadline = Instant::now() + limit;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            panic!("timed out after {limit:?}: {step}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    match thread.join() {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A watchdog for code that cannot move to another thread: if the guard is
/// still alive after `limit`, it reports `step` and ends the test process
/// with a failure. Dropping the guard disarms it.
///
/// Ending the process is deliberate: a thread blocked in a system call
/// cannot be cancelled, and a scoped thread would hold its scope open, so
/// failing only the current test would still hang the run.
#[must_use = "the deadline is disarmed when the guard is dropped"]
pub struct Deadline {
    disarm: Option<mpsc::Sender<()>>,
}

impl Deadline {
    /// Arm a watchdog for `step`.
    pub fn start(step: &str, limit: Duration) -> Self {
        let (disarm, armed) = mpsc::channel::<()>();
        let step = step.to_string();
        std::thread::Builder::new()
            .name(format!("deadline watchdog: {step}"))
            .spawn(move || {
                if let Err(RecvTimeoutError::Timeout) = armed.recv_timeout(limit) {
                    eprintln!("test deadline: timed out after {limit:?}: {step}");
                    std::process::exit(101);
                }
            })
            .expect("spawn deadline watchdog");
        Self {
            disarm: Some(disarm),
        }
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(disarm) = self.disarm.take() {
            let _ = disarm.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_result_in_time() {
        assert_eq!(with_deadline("add", Duration::from_secs(5), || 2 + 2), 4);
    }

    #[test]
    #[should_panic(expected = "timed out after 50ms: sleeping step")]
    fn names_the_step_that_hung() {
        with_deadline("sleeping step", Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5))
        });
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn re_raises_a_panic_from_the_work() {
        with_deadline("panicking step", Duration::from_secs(5), || panic!("boom"));
    }

    #[test]
    #[should_panic(expected = "timed out after 20ms: empty channel")]
    fn recv_within_names_the_step() {
        let (_sender, receiver) = mpsc::channel::<()>();
        recv_within(&receiver, "empty channel", Duration::from_millis(20));
    }

    #[test]
    #[should_panic(expected = "timed out after 20ms: stuck thread")]
    fn join_within_names_the_step() {
        let thread = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(5)));
        join_within(thread, "stuck thread", Duration::from_millis(20));
    }

    #[test]
    #[should_panic(expected = "thread boom")]
    fn join_within_re_raises_a_panic() {
        let thread = std::thread::spawn(|| panic!("thread boom"));
        join_within(thread, "panicking thread", Duration::from_secs(5));
    }

    #[test]
    fn a_dropped_deadline_never_fires() {
        drop(Deadline::start("quick step", Duration::from_millis(20)));
        std::thread::sleep(Duration::from_millis(100));
    }
}
