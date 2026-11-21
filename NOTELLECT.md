# Notellect's microsandbox

This fork exists only to ship `msb` with the small fixes Notellect needs
before they are available upstream. Each upstream version Notellect uses has a
branch `notellect/vX.Y.Z` (the upstream tag plus Notellect's commits) and
release tags `vX.Y.Z-notellect.N`. Pushing such a tag builds `msb` (with agentd
embedded) and `libkrunfw` for macOS, Linux and Windows from this source, as
upstream's release does, and publishes them with `checksums.sha256`.

For v0.8.1 the branch is `notellect/v0.8.1-ci`, not `notellect/v0.8.1`: the
CI commit was reworked after `notellect/v0.8.1` was pushed, and that branch
is left as it was. Release tags for v0.8.1 are cut from `notellect/v0.8.1-ci`.

Commits on top of upstream v0.8.1 (carried over from `notellect/v0.7.16`; the
`snapshot restore` mount flags were dropped because 0.8 boots snapshots with
`create --from-snapshot`, which takes every create flag):

- Directory mounts turn off FUSE entry and attribute caching, so a running
  guest sees a file the Host has atomically replaced.
- Windows directory mounts keep a file the guest has open usable after it is
  unlinked or replaced by a rename (POSIX semantics): fstat, read, write and
  chmod work through the handle until its last close. A request for an inode
  whose name is gone returns ESTALE instead of EBADF, so the guest kernel
  redoes an open or stat that raced the removal with a fresh lookup.
- Mount host paths may contain `,`, `;` and `:`, as real folder and file
  names do (for example "Smith, John"). The SDK percent-encodes `%`, `,`, `;`
  and `:` in the host path on the spawn-to-runtime wire, and the runtime
  decodes it, so a name can never inject mount options. A single-file mount
  is exported under the guest file name, so the host file name never reaches
  the agentd file-mount list.
- On Windows, a detached runtime that cannot leave its launcher's job
  (Task Scheduler, some terminals and CI agents give their children a job
  without JOB_OBJECT_LIMIT_BREAKAWAY_OK, so CREATE_BREAKAWAY_FROM_JOB fails
  with ERROR_ACCESS_DENIED) starts inside that job instead. It then ends with
  the job.
- On Windows, the memory snapshot cache grants the account's user SID instead
  of OWNER RIGHTS. An elevated run makes BUILTIN\Administrators the owner of
  what it creates, so with OWNER RIGHTS a later non-elevated run of the same
  user was denied the cache. The user SID is the same in both runs.
- On Windows, an elevated `msb` and its runtime make the user SID the
  default owner of what they create (named pipes grant their creator owner)
  and give the metrics mapping and events a default DACL of the user SID and
  SYSTEM instead of Administrators and SYSTEM, and the runtime gives its own process
  a Medium label and grants the user only identity, wait and terminate
  rights. A later non-elevated run of the same user can then exec into, stop
  and remove a sandbox that an elevated run left running, without being able
  to take over the elevated process.
- On Windows, vsock blocks on the Host named pipe instead of polling it every
  10 ms, and a Host that replies and closes delivers its reply, then EOF.
- A vsock reset carries the Host's receive credit instead of buf_alloc 0, so
  a guest that connects with a timeout sees its socket writable when the Host
  accepts, replies and closes before the guest reads. This lives in
  `vendor/msb_krun_devices` (libkrun `src/devices` at the rev the workspace
  pins, patched in for that git source); the vendoring and the fix are
  separate commits. Re-vendor from the new rev when upstream moves libkrun.

To move to a new upstream version, branch from its tag, cherry-pick these
commits (the CI commit again deletes every upstream workflow but
`notellect-release.yml`, including ones upstream added since), and push
`vX.Y.Z-notellect.1`.
