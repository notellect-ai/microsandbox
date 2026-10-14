# Notellect's microsandbox

This fork exists only to ship `msb` with the small fixes Notellect needs
before they are available upstream. Each upstream version Notellect uses has a
branch `notellect/vX.Y.Z` (the upstream tag plus Notellect's commits) and
release tags `vX.Y.Z-notellect.N`. Pushing such a tag builds `msb` for macOS,
Linux and Windows and publishes it with `checksums.sha256`.

Commits on top of upstream v0.7.8:

- Directory mounts turn off FUSE entry and attribute caching, so a running
  guest sees a file the Host has atomically replaced.

To move to a new upstream version, branch from its tag, cherry-pick these
commits, and push `vX.Y.Z-notellect.1`.
