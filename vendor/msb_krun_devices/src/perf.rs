//! Measurement-only counters (scratch branch perf/m1-instr, never shipped).
//!
//! Enabled when `MSB_PERF_DIR` is set in the runtime's environment. A dumper thread
//! rewrites `$MSB_PERF_DIR/perf-<pid>.txt` (cumulative summary) and appends interval
//! deltas to `$MSB_PERF_DIR/timeline-<pid>.txt` (every 100 ms for the first 8 s, then
//! every 1 s). Times are nanoseconds from a monotonic epoch; the summary header gives
//! the epoch's UTC so lines can be matched with runtime.log and marks.txt.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BUCKETS: usize = 24; // log2(µs): <1µs, <2µs, ... <8s

pub struct Stat {
    count: AtomicU64,
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
    buckets: [AtomicU64; BUCKETS],
}

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);

impl Stat {
    pub const fn new() -> Self {
        Self {
            count: ZERO,
            sum_ns: ZERO,
            max_ns: ZERO,
            buckets: [ZERO; BUCKETS],
        }
    }

    pub fn add(&self, ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
        let us = ns / 1000;
        let b = if us == 0 {
            0
        } else {
            (64 - us.leading_zeros() as usize).min(BUCKETS - 1)
        };
        self.buckets[b].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Snap {
        Snap {
            count: self.count.load(Ordering::Relaxed),
            sum_ns: self.sum_ns.load(Ordering::Relaxed),
            max_ns: self.max_ns.load(Ordering::Relaxed),
            buckets: std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed)),
        }
    }
}

impl Default for Stat {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Default)]
struct Snap {
    count: u64,
    sum_ns: u64,
    max_ns: u64,
    buckets: [u64; BUCKETS],
}

impl Snap {
    fn minus(&self, o: &Snap) -> Snap {
        Snap {
            count: self.count - o.count,
            sum_ns: self.sum_ns - o.sum_ns,
            max_ns: self.max_ns,
            buckets: std::array::from_fn(|i| self.buckets[i] - o.buckets[i]),
        }
    }

    /// Approximate percentile from the log2 histogram (upper bucket bound, µs).
    fn pct_us(&self, p: f64) -> u64 {
        let target = (self.count as f64 * p).ceil() as u64;
        let mut acc = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            acc += n;
            if acc >= target && target > 0 {
                return 1u64 << i;
            }
        }
        0
    }
}

// --- FUSE opcodes ---------------------------------------------------------------------------

const OPS: usize = 64;
#[allow(clippy::declare_interior_mutable_const)]
const STAT: Stat = Stat::new();
/// Handler time per FUSE opcode (index = opcode; >= 63 folded into 63).
pub static FUSE_OP: [Stat; OPS] = [STAT; OPS];

// --- Named stats ----------------------------------------------------------------------------

/// MMIO QueueNotify write on the vCPU thread -> fs worker woken in handle_event.
pub static FS_KICK_TO_WAKE: Stat = Stat::new();
/// Duration of the vCPU-side QueueNotify eventfd write (part of the MMIO exit).
pub static FS_KICK_WRITE: Stat = Stat::new();
/// queue.pop + Reader/Writer setup per request.
pub static FS_POP: Stat = Stat::new();
/// add_used per request.
pub static FS_ADD_USED: Stat = Stat::new();
/// signal_used_queue (interrupt injection call) duration.
pub static FS_SIGNAL: Stat = Stat::new();
/// fs worker: end of signal_used_queue -> next QueueNotify from the guest (same queue).
pub static FS_GUEST_GAP: Stat = Stat::new();
/// Requests handled per worker wake.
pub static FS_REQS_PER_WAKE: Stat = Stat::new();
/// Worker wake -> back to epoll wait (whole handle_event).
pub static FS_HANDLE_EVENT: Stat = Stat::new();

/// vCPU: time inside the hypervisor run call (guest executing or blocked in hypervisor).
pub static VCPU_RUN: Stat = Stat::new();
/// vCPU exit handling time per reason (index from exit_reason_index).
pub const EXIT_NAMES: [&str; 12] = [
    "none",
    "mmio",
    "ioport",
    "halt",
    "cpuid",
    "msr",
    "apic_eoi",
    "interrupt_window",
    "canceled",
    "sipi_trap",
    "unrecoverable",
    "other",
];
pub static VCPU_EXIT: [Stat; 12] = [STAT; 12];
/// Interrupt request call (e.g. WHvRequestInterrupt) duration.
pub static IRQ_REQUEST: Stat = Stat::new();
/// MMIO exits by guest physical page bucket for fs devices vs others.
pub static MMIO_FS_NOTIFY: Stat = Stat::new();

const NAMED: [(&str, &Stat); 12] = [
    ("fs_kick_to_wake", &FS_KICK_TO_WAKE),
    ("fs_kick_write", &FS_KICK_WRITE),
    ("fs_handle_event", &FS_HANDLE_EVENT),
    ("fs_reqs_per_wake(ns=reqs)", &FS_REQS_PER_WAKE),
    ("fs_pop", &FS_POP),
    ("fs_add_used", &FS_ADD_USED),
    ("fs_signal", &FS_SIGNAL),
    ("fs_guest_gap", &FS_GUEST_GAP),
    ("vcpu_run", &VCPU_RUN),
    ("irq_request", &IRQ_REQUEST),
    ("mmio_fs_notify", &MMIO_FS_NOTIFY),
    ("unused", &UNUSED),
];
static UNUSED: Stat = Stat::new();

// --- Kick bookkeeping, keyed by the queue event's identity ----------------------------------

const SLOTS: usize = 128;
#[allow(clippy::declare_interior_mutable_const)]
const ZU: AtomicUsize = AtomicUsize::new(0);
static KICK_KEY: [AtomicUsize; SLOTS] = [ZU; SLOTS];
static KICK_NS: [AtomicU64; SLOTS] = [ZERO; SLOTS];
static SIGNAL_END_NS: [AtomicU64; SLOTS] = [ZERO; SLOTS];

fn slot(key: usize) -> Option<usize> {
    if key == 0 {
        return None;
    }
    for i in 0..SLOTS {
        let k = KICK_KEY[i].load(Ordering::Acquire);
        if k == key {
            return Some(i);
        }
        if k == 0
            && KICK_KEY[i]
                .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                .map_or_else(|cur| cur == key, |_| true)
        {
            return Some(i);
        }
    }
    None
}

/// vCPU thread: a QueueNotify for the queue whose event is identified by `key`.
pub fn kick(key: usize) {
    if !enabled() {
        return;
    }
    if let Some(i) = slot(key) {
        let now = now_ns();
        let _ = KICK_NS[i].compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
        let sig = SIGNAL_END_NS[i].swap(0, Ordering::AcqRel);
        if sig != 0 && now > sig {
            FS_GUEST_GAP.add(now - sig);
        }
    }
}

/// fs worker: woken for the queue whose event is identified by `key`.
pub fn woke(key: usize, now: u64) {
    if let Some(i) = slot(key) {
        let k = KICK_NS[i].swap(0, Ordering::AcqRel);
        if k != 0 && now >= k {
            FS_KICK_TO_WAKE.add(now - k);
        }
    }
}

/// fs worker: signal_used_queue finished for the queue identified by `key`.
pub fn signaled(key: usize, now: u64) {
    if let Some(i) = slot(key) {
        SIGNAL_END_NS[i].store(now, Ordering::Release);
    }
}

// --- Clock and enable -----------------------------------------------------------------------

static EPOCH: OnceLock<(Instant, u128)> = OnceLock::new();
static ENABLED: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
static DUMPER: AtomicBool = AtomicBool::new(false);

fn epoch() -> &'static (Instant, u128) {
    EPOCH.get_or_init(|| {
        let utc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        (Instant::now(), utc)
    })
}

#[inline]
pub fn now_ns() -> u64 {
    epoch().0.elapsed().as_nanos() as u64
}

#[inline]
pub fn enabled() -> bool {
    let dir = ENABLED.get_or_init(|| std::env::var_os("MSB_PERF_DIR").map(Into::into));
    if dir.is_some() && !DUMPER.swap(true, Ordering::AcqRel) {
        start_dumper();
    }
    dir.is_some()
}

pub fn fuse_op(opcode: u32, ns: u64) {
    FUSE_OP[(opcode as usize).min(OPS - 1)].add(ns);
}

fn op_name(op: usize) -> &'static str {
    match op {
        1 => "lookup",
        2 => "forget",
        3 => "getattr",
        4 => "setattr",
        5 => "readlink",
        6 => "symlink",
        8 => "mknod",
        9 => "mkdir",
        10 => "unlink",
        11 => "rmdir",
        12 => "rename",
        13 => "link",
        14 => "open",
        15 => "read",
        16 => "write",
        17 => "statfs",
        18 => "release",
        20 => "fsync",
        21 => "setxattr",
        22 => "getxattr",
        23 => "listxattr",
        24 => "removexattr",
        25 => "flush",
        26 => "init",
        27 => "opendir",
        28 => "readdir",
        29 => "releasedir",
        30 => "fsyncdir",
        31 => "getlk",
        32 => "setlk",
        33 => "setlkw",
        34 => "access",
        35 => "create",
        36 => "interrupt",
        37 => "bmap",
        38 => "destroy",
        39 => "ioctl",
        40 => "poll",
        41 => "notify_reply",
        42 => "batch_forget",
        43 => "fallocate",
        44 => "readdirplus",
        45 => "rename2",
        46 => "lseek",
        47 => "copy_file_range",
        48 => "setupmapping",
        49 => "removemapping",
        _ => "other",
    }
}

fn line(out: &mut String, name: &str, s: &Snap) {
    if s.count == 0 {
        return;
    }
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "{name:<28} n={:<9} sum_ms={:<10.1} avg_us={:<9.1} p50_us<={:<7} p90_us<={:<7} p99_us<={:<7} max_us={}",
        s.count,
        s.sum_ns as f64 / 1e6,
        s.sum_ns as f64 / s.count as f64 / 1e3,
        s.pct_us(0.5),
        s.pct_us(0.9),
        s.pct_us(0.99),
        s.max_ns / 1000
    );
}

fn all() -> Vec<(String, Snap)> {
    let mut v = Vec::new();
    for (i, s) in FUSE_OP.iter().enumerate() {
        v.push((format!("fuse.{}", op_name(i)), s.snapshot()));
    }
    for (n, s) in NAMED {
        v.push((n.to_string(), s.snapshot()));
    }
    for (i, s) in VCPU_EXIT.iter().enumerate() {
        v.push((format!("exit.{}", EXIT_NAMES[i]), s.snapshot()));
    }
    v
}

fn start_dumper() {
    let Some(Some(dir)) = ENABLED.get().cloned() else {
        return;
    };
    let _ = epoch();
    let pid = std::process::id();
    let _ = std::thread::Builder::new()
        .name("msb-perf".into())
        .spawn(move || {
            let _ = std::fs::create_dir_all(&dir);
            let summary = dir.join(format!("perf-{pid}.txt"));
            let timeline = dir.join(format!("timeline-{pid}.txt"));
            let mut prev = all();
            let mut tick = 0u64;
            loop {
                let interval = if tick < 80 { 100 } else { 1000 };
                std::thread::sleep(Duration::from_millis(interval));
                tick += 1;
                let cur = all();
                let t = now_ns();
                let mut delta = String::new();
                for ((name, c), (_, p)) in cur.iter().zip(prev.iter()) {
                    let d = c.minus(p);
                    if d.count > 0 {
                        line(&mut delta, name, &d);
                    }
                }
                if !delta.is_empty() {
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&timeline)
                    {
                        let _ = write!(f, "@t_ms={:.1}\n{delta}", t as f64 / 1e6);
                    }
                }
                let mut s = format!(
                    "pid={pid} epoch_utc_us={} now_ms={:.1}\n",
                    epoch().1,
                    t as f64 / 1e6
                );
                for (name, c) in &cur {
                    line(&mut s, name, c);
                }
                let tmp = summary.with_extension("tmp");
                if std::fs::write(&tmp, s).is_ok() {
                    let _ = std::fs::rename(&tmp, &summary);
                }
                prev = cur;
            }
        });
}

/// Identity of a queue event shared by its clones (the vCPU's MMIO notify and the worker).
#[cfg(target_os = "windows")]
pub fn event_key(ev: &utils::eventfd::EventFd) -> usize {
    ev.get_write_handle() as usize
}

#[cfg(not(target_os = "windows"))]
pub fn event_key(_ev: &utils::eventfd::EventFd) -> usize {
    0
}

/// Records one vCPU exit's handling time when dropped (covers every `continue`/`return`).
pub struct ExitTimer {
    idx: usize,
    t0: u64,
    on: bool,
}

impl ExitTimer {
    pub fn new(idx: usize) -> Self {
        let on = enabled();
        Self {
            idx: idx.min(VCPU_EXIT.len() - 1),
            t0: if on { now_ns() } else { 0 },
            on,
        }
    }
}

impl Drop for ExitTimer {
    fn drop(&mut self) {
        if self.on {
            VCPU_EXIT[self.idx].add(now_ns() - self.t0);
        }
    }
}
