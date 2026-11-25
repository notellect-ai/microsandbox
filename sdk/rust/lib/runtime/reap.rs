//! The identity rules for a run's recorded runtime PID.
//!
//! A sandbox runtime can outlive its database row, and its recorded PID can be
//! reused by an unrelated process. A process is the run's runtime only when it was
//! created no later than the run row's `started_at` (the runtime inserts that row
//! moments after it starts, while a reused PID is created only after the original
//! process died) and its executable is the `msb` binary.
//! `context::local::sandbox::safe_kill` applies these rules and is the one place
//! that judges or ends a process by its recorded PID.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// How far a process's creation time may lie after the run row's `started_at` and
/// still be the runtime. Windows and macOS take both from the same wall clock and
/// round the creation time down, so none is needed; Linux estimates the creation
/// time from the boot time and its clock tick, so it gets a second.
#[cfg(target_os = "linux")]
pub(crate) const IDENTITY_CREATION_SLACK_MICROS: i64 = 1_000_000;
#[cfg(not(target_os = "linux"))]
pub(crate) const IDENTITY_CREATION_SLACK_MICROS: i64 = 0;

/// How long callers wait for a terminated process to disappear before treating the
/// reap as failed.
pub(crate) const REAP_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Offset between the Windows FILETIME epoch (1601-01-01) and the Unix epoch, in microseconds.
const FILETIME_UNIX_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a live process created at `creation_unix_micros` can be the runtime process that
/// recorded `run_started_unix_micros`.
pub(crate) fn creation_may_belong_to_run(
    creation_unix_micros: i64,
    run_started_unix_micros: i64,
) -> bool {
    creation_unix_micros <= run_started_unix_micros + IDENTITY_CREATION_SLACK_MICROS
}

/// Convert FILETIME ticks (100ns units since 1601-01-01) to Unix microseconds.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn filetime_ticks_to_unix_micros(ticks: u64) -> i64 {
    (ticks / 10) as i64 - FILETIME_UNIX_EPOCH_OFFSET_MICROS
}

/// Whether an executable path names the `msb` binary (`msb` or `msb.exe`, any directory, any case).
///
/// String-based on purpose: `Path` parsing of `C:\...` differs across host platforms, and this
/// must stay unit-testable everywhere.
pub(crate) fn image_basename_is_msb(image_path: &str) -> bool {
    let basename = image_path.rsplit(['/', '\\']).next().unwrap_or(image_path);
    let stem = match basename.len().checked_sub(4) {
        Some(idx)
            if basename.is_char_boundary(idx) && basename[idx..].eq_ignore_ascii_case(".exe") =>
        {
            &basename[..idx]
        }
        _ => basename,
    };
    stem.eq_ignore_ascii_case("msb")
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

    #[test]
    fn msb_image_names_match() {
        assert!(image_basename_is_msb(r"C:\Program Files\msb\msb.exe"));
        assert!(image_basename_is_msb(r"C:\Users\dev\MSB.EXE"));
        assert!(image_basename_is_msb("/usr/local/bin/msb"));
        assert!(image_basename_is_msb("msb"));
    }

    #[test]
    fn non_msb_image_names_do_not_match() {
        assert!(!image_basename_is_msb(r"C:\Windows\System32\svchost.exe"));
        assert!(!image_basename_is_msb(r"C:\tools\msb-agent.exe"));
        assert!(!image_basename_is_msb("/usr/bin/cargo"));
        assert!(!image_basename_is_msb(""));
    }
}
