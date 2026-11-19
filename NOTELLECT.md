# Notellect's microsandbox

This fork exists only to ship `msb` with the small fixes Notellect needs
before they are available upstream. Each upstream version Notellect uses has a
branch `notellect/vX.Y.Z` (the upstream tag plus Notellect's commits) and
release tags `vX.Y.Z-notellect.N`. Pushing such a tag builds `msb` for macOS,
Linux and Windows and publishes it with `checksums.sha256`.

Commits on top of upstream v0.7.16 (carried over from `notellect/v0.7.11`):

- Directory mounts turn off FUSE entry and attribute caching, so a running
  guest sees a file the Host has atomically replaced.
- `snapshot restore` accepts create's `--mount-file` and `--tmpfs`, and both
  fork forms accept `--mount-file`, so a disk snapshot boots with config files
  and tmpfs on /tmp and /home through restore's hard-linked layers and qcow2
  overlay instead of a copied root disk. The parsers are shared with create.
  Shaped to go upstream unchanged (follows superradcompany/microsandbox#1733).
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
- On Windows, an elevated `msb` and its runtime give the pipes, metrics
  mapping and events they create a default DACL of the user SID and SYSTEM
  instead of Administrators and SYSTEM, and the runtime gives its own process
  a Medium label and grants the user only identity, wait and terminate
  rights. A later non-elevated run of the same user can then exec into, stop
  and remove a sandbox that an elevated run left running, without being able
  to take over the elevated process.

To move to a new upstream version, branch from its tag, cherry-pick these
commits (the CI commit again deletes every upstream workflow but
`notellect-release.yml`, including ones upstream added since), and push
`vX.Y.Z-notellect.1`.
