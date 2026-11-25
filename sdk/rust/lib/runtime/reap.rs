//! Creation-time evidence about Windows runtime PIDs.
//!
//! The runtime inserts its run row moments after it starts, so a process created well after the
//! row's `started_at` cannot be that run's runtime: its PID was recycled. This proves a PID is
//! *not* the runtime; it never proves that it is (see `ownership::run_runtime`).

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Allowed clock/timer slack when comparing a process creation time against the run row's `started_at`.
pub(crate) const IDENTITY_CREATION_SLACK_MICROS: i64 = 5_000_000;

/// How long callers should wait for a terminated process to disappear before treating the reap as failed.
pub(crate) const REAP_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Offset between the Windows FILETIME epoch (1601-01-01) and the Unix epoch, in microseconds.
const FILETIME_UNIX_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a live process created at `creation_unix_micros` can be the runtime process that
/// recorded `run_started_unix_micros`.
///
/// The runtime writes its run row right after the process starts, so the true process is always
/// created at-or-before `started_at` (within timer granularity). A recycled PID is created only
/// after the original process died, i.e. strictly after `started_at`.
pub(crate) fn creation_may_belong_to_run(
    creation_unix_micros: i64,
    run_started_unix_micros: i64,
) -> bool {
    creation_unix_micros <= run_started_unix_micros + IDENTITY_CREATION_SLACK_MICROS
}

/// Convert FILETIME ticks (100ns units since 1601-01-01) to Unix microseconds.
pub(crate) fn filetime_ticks_to_unix_micros(ticks: u64) -> i64 {
    (ticks / 10) as i64 - FILETIME_UNIX_EPOCH_OFFSET_MICROS
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_before_run_start_matches() {
        assert!(creation_may_belong_to_run(1_000_000, 2_000_000));
        assert!(creation_may_belong_to_run(2_000_000, 2_000_000));
    }

    #[test]
    fn creation_within_slack_after_run_start_matches() {
        assert!(creation_may_belong_to_run(
            2_000_000 + IDENTITY_CREATION_SLACK_MICROS,
            2_000_000
        ));
    }

    #[test]
    fn creation_after_slack_is_a_recycled_pid() {
        assert!(!creation_may_belong_to_run(
            2_000_001 + IDENTITY_CREATION_SLACK_MICROS,
            2_000_000
        ));
    }

    #[test]
    fn filetime_epoch_offset_maps_to_unix_epoch() {
        // 1601-01-01 → Unix epoch is exactly 11644473600 seconds of 100ns ticks.
        assert_eq!(filetime_ticks_to_unix_micros(116_444_736_000_000_000), 0);
        assert_eq!(
            filetime_ticks_to_unix_micros(116_444_736_000_000_000 + 10_000_000),
            1_000_000
        );
    }
}
