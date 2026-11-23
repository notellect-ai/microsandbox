# Notellect's microsandbox

This fork exists only to ship `msb` with the small fixes Notellect needs
before they are available upstream. Each upstream version Notellect uses has a
branch `notellect/vX.Y.Z` (the upstream tag plus Notellect's commits) and
release tags `vX.Y.Z-notellect.N`. Pushing such a tag builds `msb` (with agentd
embedded) and `libkrunfw` for macOS, Linux and Windows from this source, as
upstream's release does, and publishes them with `checksums.sha256`.

For v0.8.1 the branch is `notellect/v0.8.1-ci8`. `notellect/v0.8.1`,
`notellect/v0.8.1-ci`, `notellect/v0.8.1-ci2` to `notellect/v0.8.1-ci7` are
earlier pushes of the same work, left as they were: the CI commit, the Windows
vsock and Windows unlink commits (Windows-only clippy 1.100 lints), the Windows
vsock commit again (read room measured after a write), the fixes from a review
(below), and then the Windows check workflow, the test timeout rule and the
fault-injection tests (with the fixes they found) were reworked after them,
and the namespace race matrix (with the fixes it and a review found) after
those.
`v0.8.1-notellect.1` was cut from `notellect/v0.8.1-ci3`,
`v0.8.1-notellect.2` from `notellect/v0.8.1-ci4`; later v0.8.1 tags are cut
from `notellect/v0.8.1-ci8`.

Commits on top of upstream v0.8.1 (carried over from `notellect/v0.7.16`; the
`snapshot restore` mount flags were dropped because 0.8 boots snapshots with
`create --from-snapshot`, which takes every create flag):

- Directory mounts turn off FUSE entry and attribute caching, so a running
  guest sees a file the Host has atomically replaced.
- Windows directory mounts keep a file the guest has open usable after it is
  unlinked or replaced by a rename (POSIX semantics): fstat, read, write and
  chmod work through the handle until its last close. A request for an inode
  whose name is gone returns ESTALE instead of EBADF, so the guest kernel
  redoes an open or stat that raced the removal with a fresh lookup. An open
  by path that races a rename-over and reaches the replacing file also
  returns ESTALE, so the replaced inode is never attached to the new file.
  When the Host itself replaces a name (delete and rename, or rename over,
  of a file or a directory), the next lookup gives it a new inode, and the
  old inode and the names cached under it are finished as an unlink would.
- Mount host paths may contain `,`, `;` and `:`, as real folder and file
  names do (for example "Smith, John"). The SDK percent-encodes `%`, `,`, `;`
  and `:` in the host path on the spawn-to-runtime wire, and the runtime
  decodes it (an escape is `%` and exactly two hex digits), so a name can
  never inject mount options. A single-file mount
  is exported under the guest file name, so the host file name never reaches
  the agentd file-mount list.
- On Windows, a detached runtime that cannot leave its launcher's job
  (Task Scheduler, some terminals and CI agents give their children a job
  without JOB_OBJECT_LIMIT_BREAKAWAY_OK, so CREATE_BREAKAWAY_FROM_JOB fails
  with ERROR_ACCESS_DENIED) starts inside that job instead. It then ends with
  the job, and a warning says so.
- On Windows, the memory snapshot cache grants the account's user SID instead
  of OWNER RIGHTS. An elevated run makes BUILTIN\Administrators the owner of
  what it creates, so with OWNER RIGHTS a later non-elevated run of the same
  user was denied the cache. The user SID is the same in both runs.
- On Windows, `runtime.share_elevated_sandboxes` defaults to on (upstream
  default: off). An elevated `msb` (the full half of a UAC split token) then
  tells its runtime to create its agent, control and console pipes with a
  security descriptor that grants the sign-in's logon SID read and write (no
  new pipe instances). Both halves of the split token carry that SID and no
  other logon does, so a later non-elevated run in the same sign-in session can
  exec into, stop and remove a sandbox an elevated run left running, while
  another logon of the same user (RDP, SSH, a service, an S4U task) cannot. The runtime process keeps Windows' default security, which already
  gives that session wait and terminate but not WRITE_DAC; the metrics mapping
  is reachable through the session object directory's ACL. The upstream PR is
  the same code with the default off; with it off, a non-elevated run gets an
  access-denied error that explains the cause. This replaces the earlier fork
  design (user SID as owner), which let a medium process gain WRITE_DAC on the
  elevated runtime.
- On Windows, vsock blocks on the Host named pipe instead of polling it every
  10 ms, and a Host that replies and closes delivers its reply, then EOF.
- A vsock reset carries the Host's receive credit (buf_alloc and the
  connection's real fwd_cnt) instead of zeros, so
  a guest that connects with a timeout sees its socket writable when the Host
  accepts, replies and closes before the guest reads. This lives in
  `vendor/msb_krun_devices` (libkrun `src/devices` at the rev the workspace
  pins, patched in for that git source); the vendoring and the fix are
  separate commits. Re-vendor from the new rev when upstream moves libkrun.

Known and left as they are (from a review of the v0.8.1 commits):

- Intentional: the elevated-run sharing above weakens the UAC boundary for
  this user: any medium-integrity process of that user in the same sign-in
  session can talk to the elevated runtime's pipes (exec, stop). It cannot
  take over the runtime process. Runs in another sign-in session (RDP, fast
  user switching, over-the-shoulder elevation) are not reached. Notellect
  accepts this for a single-user desktop tool.
- Windows open-after-unlink: the retain fallback reads a removed file's
  ownership and mode from its old path's stat store entry, which after a
  rename-over (ADS store) is the new file's and after an unlink is gone; a
  failure while preparing the pin fails the unlink instead of skipping the
  pin; a pinned clone of a read-only handle cannot chmod in mirror-perms mode;
  the fallback takes a file mutex under the inode table write lock, so an
  unlink can wait for a long fsync; capture fails while a directory snapshot
  still lists a retained inode; ESTALE replaces EBADF where retaining failed.
- Windows memory snapshot cache: SYSTEM is no longer granted; a directory an
  older elevated run created cannot be repaired by a normal run; with
  over-the-shoulder elevation the elevated token's user is the administrator,
  not the logged-in user.
- Windows vsock: a guest close() drops bytes not yet written to the Host and
  a guest shutdown(SHUT_WR) never reaches it (both upstream behaviour); a
  Host that closes with DisconnectNamedPipe without flushing can lose its
  reply; a worker that panics on a poisoned lock leaves the stream connected.
- Directory mounts without entry and attribute caching still send every
  path component to the Host as its own lookup. On Windows each lookup now
  opens the object once by its full path and checks the opened name instead
  of opening every ancestor (local NTFS/ReFS roots only; other roots, names
  in another case and filter-served reparse points take the old walk).
  Measured in a guest on a Windows 10 19045 handheld, 2000 ops each, 3
  rounds: stat 0.95 -> 0.88 ms, six levels deep stat 4.72 -> 3.45 ms and
  stat of a missing name 4.31 -> 2.88 ms; create, pread unchanged. What is
  left is mostly one guest-to-Host round trip per component.
- A detached spawn that hits ERROR_ACCESS_DENIED for another reason (an exe
  ACL, antivirus) also retries inside the job, with the same warning.

`notellect-windows-check.yml` runs formatting, clippy and the tests of these
commits that need no microVM on a GitHub Windows runner, on every push to a
`notellect/*` branch; the release waits for it. Tests that boot a microVM run
on Notellect's Windows VM. Every test step that waits (a read, write, join,
recv or wait) has an explicit limit and fails naming that step; use
`test_utils::{with_deadline, join_within, recv_within, Deadline}`.

To move to a new upstream version, branch from its tag, cherry-pick these
commits (the CI commit again deletes every upstream workflow but
`notellect-release.yml` and `notellect-windows-check.yml`, including ones
upstream added since), and push `vX.Y.Z-notellect.1`.
