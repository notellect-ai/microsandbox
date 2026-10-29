# Notellect's microsandbox

This fork exists only to ship `msb` with the small fixes Notellect needs
before they are available upstream. Each upstream version Notellect uses has a
branch `notellect/vX.Y.Z` (the upstream tag plus Notellect's commits) and
release tags `vX.Y.Z-notellect.N`. Pushing such a tag builds `msb` for macOS,
Linux and Windows and publishes it with `checksums.sha256`.

Commits on top of upstream v0.7.11:

- Directory mounts turn off FUSE entry and attribute caching, so a running
  guest sees a file the Host has atomically replaced.
- `snapshot restore` accepts create's `--mount-file` and `--tmpfs`, and both
  fork forms accept `--mount-file`, so a disk snapshot boots with config files
  and tmpfs on /tmp and /home through restore's hard-linked layers and qcow2
  overlay instead of a copied root disk. The parsers are shared with create.
  Shaped to go upstream unchanged (follows superradcompany/microsandbox#1733).

To move to a new upstream version, branch from its tag, cherry-pick these
commits (the CI commit again deletes every upstream workflow but
`notellect-release.yml`), and push `vX.Y.Z-notellect.1`.
