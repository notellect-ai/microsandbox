//! Attribute operations for the Windows passthrough backend.

#[cfg(test)]
use std::cell::RefCell;

use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// Runs after a call found the inode's own file behind its name (in
    /// `own_file`, or `open_inode_file`'s open by path) and before it acts on
    /// that file, so a test can replace or remove the name inside that
    /// window.
    pub(super) static AFTER_OWN_CHECK: RefCell<Option<Box<dyn FnOnce()>>> =
        const { RefCell::new(None) };
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn inode_metadata(&self, data: &InodeData) -> io::Result<std::fs::Metadata> {
        if let Some(file) = data.retained.lock().unwrap().as_ref() {
            file.metadata().map_err(host_error)
        } else if let Some(file) = self.own_file(data, false)? {
            file.metadata().map_err(host_error)
        } else {
            self.safe_metadata(&data.path())
        }
    }

    /// The inode's own file, opened for a metadata call (`write` adds
    /// FILE_WRITE_ATTRIBUTES): its retained file, or the file behind its
    /// name once that is checked. `None` for the root (which serves whatever
    /// directory is at the mount path) or an inode whose host identity is
    /// unknown: those follow their path.
    ///
    /// The name an inode tracks can hold another file once the host renames
    /// or writes a file over it (the guest's next lookup of the name gives
    /// that file an inode of its own), or nothing once the host removes it.
    /// So the name is opened and its file checked against the inode's
    /// identity, and the caller acts through that handle, never the name
    /// again. When the name misses, an open guest handle of the inode stands
    /// in (for `write`, a writable one, or a read-only one the file can be
    /// reopened from by ID); with none, the inode is stale, and the guest's
    /// next lookup of any of its names finds the file again.
    ///
    /// Takes no inode table lock: callers may hold it.
    pub(super) fn own_file(&self, data: &InodeData, write: bool) -> io::Result<Option<File>> {
        if let Some(file) = data.retained.lock().unwrap().as_ref() {
            return file.try_clone().map(Some).map_err(host_error);
        }
        let Some(identity) = data.identity else {
            return Ok(None);
        };
        if data.inode == ROOT_INODE {
            return Ok(None);
        }
        let access = if write {
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
        } else {
            FILE_READ_ATTRIBUTES
        };

        let path = data.path();
        let miss = match open_if_identity(&self.root, &path, access, identity) {
            Ok(file) => {
                after_own_check();
                return Ok(Some(file));
            }
            Err(error) if matches!(error.raw_os_error(), Some(LINUX_ENOENT | LINUX_ESTALE)) => {
                error
            }
            // Another file at the name can refuse the open (say through its
            // ACL), as can a name being deleted: unless the name is seen to
            // hold the inode's file, it misses.
            Err(error) => match self.path_identity(&path) {
                Ok(Some(found)) if found == identity => return Err(error),
                Ok(Some(_)) => linux_error(LINUX_ESTALE),
                _ => error,
            },
        };

        let handle = {
            let handles = self.handles.read().unwrap();
            let mut handles = handles.values().filter(|handle| handle.inode == data.inode);
            let first = handles.next().cloned();
            if write
                && first
                    .as_ref()
                    .is_some_and(|h| !open_flags_writable(h.flags))
            {
                handles
                    .find(|handle| open_flags_writable(handle.flags))
                    .cloned()
                    .or(first)
            } else {
                first
            }
        };
        let Some(handle) = handle else {
            return Err(miss);
        };
        // `insert_handle` checked that the handle holds the inode's file.
        let file = handle.file.lock().unwrap();
        match owned_metadata::reopen_by_id(&file, access) {
            Ok(file) => Ok(Some(file)),
            // A read-only handle cannot change attributes: the file has no
            // name left to reopen it by, so the inode stands as stale.
            Err(_) if write && !open_flags_writable(handle.flags) => Err(miss),
            Err(_) => file.try_clone().map(Some).map_err(host_error),
        }
    }

    pub(super) fn safe_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        ensure_lexically_under_root(&self.root, path)?;
        safe_metadata_under_root(&self.root, path)
    }

    pub(super) fn stat_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<stat64> {
        if !self.cfg.stat_virtualization_enabled() {
            return self.stat_link_count(host_stat_from_metadata(metadata, data.inode), data);
        }

        if let Some(override_stat) = owned_metadata::read_retained_stat(data)? {
            let mut st = host_stat_from_metadata(metadata, data.inode);
            apply_override_stat(&mut st, override_stat);
            return self.stat_link_count(st, data);
        }

        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
        {
            // A file with no name left keeps its metadata in memory, below.
            if let Some(stored) = self.read_store(store, data)? {
                let mut st = host_stat_from_metadata(metadata, data.inode);
                if let Some(override_stat) = stored {
                    apply_override_stat(&mut st, override_stat);
                } else if let Some((uid, gid)) = self.cfg.default_owner {
                    // No per-file override: a host-created file. Present the
                    // configured default owner instead of the raw 0:0.
                    st.st_uid = uid;
                    st.st_gid = gid;
                }
                return self.stat_link_count(st, data);
            }
        }

        // Storeless path (e.g. relaxed mode with no persistent stat store),
        // or a file with no name left: virtual metadata lives only in memory.
        // A host-created file the guest never touched has no virtual mode
        // set, so present the configured default owner instead of the raw
        // 0:0 from the default VirtualMetadata.
        let mut st = stat_from_metadata(metadata, data);
        if let Some((uid, gid)) = self.cfg.default_owner
            && data.virtual_meta.read().unwrap().mode.is_none()
        {
            st.st_uid = uid;
            st.st_gid = gid;
        }
        self.stat_link_count(st, data)
    }

    pub(super) fn entry_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<Entry> {
        Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: self.stat_from_metadata(metadata, data)?,
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    pub(super) fn current_override(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<OverrideStat> {
        self.current_override_with(metadata, data, |store| self.read_store(store, data))
    }

    /// Like `current_override`, but reads a stored entry at `path`, one of
    /// the inode's names, rather than at the inode's own path: that can be
    /// another hard link, which the host may have replaced since.
    pub(super) fn current_override_at(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
        path: &Path,
    ) -> io::Result<OverrideStat> {
        self.current_override_with(metadata, data, |store| store.read(path).map(Some))
    }

    /// The body of `current_override`, with `read` reading the stored entry
    /// as `read_store` does.
    fn current_override_with(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
        read: impl FnOnce(&StatStore) -> io::Result<Option<Option<OverrideStat>>>,
    ) -> io::Result<OverrideStat> {
        if let Some(stat) = owned_metadata::read_retained_stat(data)? {
            return Ok(stat);
        }
        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
        {
            match read(store)? {
                Some(Some(override_stat)) => return Ok(override_stat),
                Some(None) => return Ok(self.default_override(metadata)),
                // The file has no name left: its metadata is in memory.
                None => {}
            }
        }

        let virtual_meta = data.virtual_meta.read().unwrap();
        // Storeless host-created file (no virtual mode set): baseline its owner
        // to default_owner too, so a partial setattr does not collapse it to 0:0.
        let (uid, gid) = match self.cfg.default_owner {
            Some(owner) if virtual_meta.mode.is_none() => owner,
            _ => (virtual_meta.uid, virtual_meta.gid),
        };
        Ok(OverrideStat {
            version: OVERRIDE_VERSION,
            _pad: [0; 3],
            uid,
            gid,
            mode: virtual_meta
                .mode
                .unwrap_or_else(|| mode_from_metadata(metadata)),
            rdev: virtual_meta.rdev.try_into().unwrap_or(u32::MAX),
        })
    }

    /// The metadata of a file with no stored entry yet: a host-created file.
    /// It seeds the mutation baseline with the configured default owner
    /// (falling back to 0:0), so a later setattr persists that owner instead
    /// of resetting it to root, matching the read path in `stat_from_metadata`.
    pub(super) fn default_override(&self, metadata: &std::fs::Metadata) -> OverrideStat {
        let (uid, gid) = self.cfg.default_owner.unwrap_or((0, 0));
        OverrideStat::new(uid, gid, mode_from_metadata(metadata), 0)
    }

    /// Read the stored entry of an inode that is not retained: from a
    /// stream of its own file when the store follows the file (see
    /// `own_file`), else under its path. `Ok(Some(None))` when it has none;
    /// `Ok(None)` when its file has no name left, so its metadata is only in
    /// memory: what the guest set through this mount, or last read here.
    fn read_store(
        &self,
        store: &StatStore,
        data: &InodeData,
    ) -> io::Result<Option<Option<OverrideStat>>> {
        if store.follows_file()
            && let Some(file) = self.own_file(data, false)?
        {
            let before = data.virtual_meta.read().unwrap().clone();
            let stored = owned_metadata::read_stat_at(&file)?;
            // Kept in memory too, for when the file has no name left.
            if let Some(Some(stat)) = stored {
                remember_stat(data, &before, stat);
            }
            return Ok(stored);
        }
        store.read(&data.path()).map(Some)
    }

    pub(super) fn set_virtual_metadata(
        &self,
        data: &InodeData,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        let mirror = (self.cfg.mirror_host_permissions()
            || !self.cfg.stat_virtualization_enabled())
            && mirror_eligible_type(mode & S_IFMT);
        let follows = self
            .stat_store
            .as_ref()
            .is_some_and(|store| store.follows_file());
        // The inode's own file, checked before anything changes: a stale
        // inode fails without a partial update.
        let own = if mirror || follows {
            self.own_file(data, mirror)?
        } else {
            None
        };

        if self.cfg.stat_virtualization_enabled() {
            let mut meta = data.virtual_meta.write().unwrap();
            meta.uid = uid;
            meta.gid = gid;
            meta.mode = Some(mode);
            meta.rdev = u64::from(rdev);
        }

        let stat = OverrideStat::new(uid, gid, mode, rdev);
        let retained_stat = owned_metadata::write_retained_stat(data, stat)?;
        if let Some(store) = &self.stat_store
            && !retained_stat
            && data.retained.lock().unwrap().is_none()
        {
            if follows && let Some(file) = &own {
                // A file with no name left keeps the copy in memory above.
                owned_metadata::write_stat_at(file, stat)?;
            } else {
                store.write(&data.path(), uid, gid, mode, rdev)?;
            }
        }
        self.propagate_sidecar_stat(data, stat)?;

        if mirror {
            match &own {
                Some(file) => apply_file_permissions(file, mode)?,
                None => apply_host_permissions(&data.path(), mode)?,
            }
        }

        Ok(())
    }

    pub(super) fn clear_priv_bits(&self, data: &InodeData) -> io::Result<()> {
        let metadata = self.inode_metadata(data)?;
        let current = self.current_override(&metadata, data)?;
        let mode = current.mode & !(S_ISUID | S_ISGID);
        if mode != current.mode {
            self.set_virtual_metadata(data, current.uid, current.gid, mode, current.rdev)?;
        }
        Ok(())
    }

    pub(super) fn do_getattr(
        &self,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok((init_stat(), self.cfg.attr_timeout));
        }

        let data = self.inode(inode)?;
        // An open handle names the object itself, even while its path is being
        // replaced and before the inode bookkeeping catches up.
        let metadata = match handle.map(|handle| self.handle(inode, handle)) {
            Some(Ok(handle)) => handle.file.lock().unwrap().metadata().map_err(host_error)?,
            _ => self.inode_metadata(&data)?,
        };
        Ok((
            self.stat_from_metadata(&metadata, data.as_ref())?,
            self.cfg.attr_timeout,
        ))
    }

    pub(super) fn do_setattr(
        &self,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }
        if valid.intersects(
            SetattrValid::SIZE
                | SetattrValid::MODE
                | SetattrValid::UID
                | SetattrValid::GID
                | SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW
                | SetattrValid::CTIME,
        ) {
            self.require_writable()?;
        }

        let data = self.inode(inode)?;
        let metadata = self.inode_metadata(&data)?;
        if metadata.file_type().is_dir() && valid.contains(SetattrValid::SIZE) {
            return Err(linux_error(LINUX_EISDIR));
        }

        if valid.contains(SetattrValid::SIZE) {
            self.quota_ensure_baseline();
            let size: u64 = attr
                .st_size
                .try_into()
                .map_err(|_| linux_error(LINUX_EINVAL))?;

            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                let state = self.dax_files.get(&handle.file.lock().unwrap())?;
                self.with_file_mappings_suspended(&state, || {
                    let file = handle.file.lock().unwrap();
                    self.quota_charge_growth(metadata.len(), size)?;
                    file.set_len(size).map_err(host_error)
                })?;
            } else {
                self.resize_inode(inode, || {
                    let file = self.open_inode_file(&data, LINUX_O_WRONLY as u32)?;
                    reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
                    self.quota_charge_growth(metadata.len(), size)?;
                    file.set_len(size).map_err(host_error)
                })?;
            }
        }

        let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
            || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));
        if valid.intersects(SetattrValid::MODE | SetattrValid::UID | SetattrValid::GID) {
            if !self.cfg.stat_virtualization_enabled()
                && valid.intersects(SetattrValid::UID | SetattrValid::GID)
            {
                return Err(linux_error(LINUX_EPERM));
            }

            let current = self.current_override(&metadata, data.as_ref())?;
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                current.uid
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                current.gid
            };
            let mode = if valid.contains(SetattrValid::MODE) {
                (current.mode & S_IFMT) | (attr.st_mode & !S_IFMT)
            } else {
                current.mode
            };
            let mode = if kill_priv {
                mode & !(S_ISUID | S_ISGID)
            } else {
                mode
            };
            self.set_virtual_metadata(data.as_ref(), uid, gid, mode, current.rdev)?;
        } else if kill_priv {
            self.clear_priv_bits(data.as_ref())?;
        }

        if valid.intersects(
            SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW,
        ) {
            let times = build_file_times(attr, valid)?;
            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                handle
                    .file
                    .lock()
                    .unwrap()
                    .set_times(times)
                    .map_err(host_error)?;
            } else {
                let file = if data.retained.lock().unwrap().is_some() {
                    self.open_inode_file(&data, LINUX_O_WRONLY as u32)?
                } else if let Some(file) = self.own_file(&data, true)? {
                    file
                } else {
                    StdOpenOptions::new()
                        .write(true)
                        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                        .open(data.path())
                        .map_err(host_error)?
                };
                reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
                file.set_times(times).map_err(host_error)?;
            }
        }

        self.do_getattr(inode, handle)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the test's `AFTER_OWN_CHECK` hook, if armed.
#[cfg(test)]
pub(super) fn after_own_check() {
    if let Some(hook) = AFTER_OWN_CHECK.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

/// Nothing outside tests.
#[cfg(not(test))]
pub(super) fn after_own_check() {}

/// Open `path` with `access` if it holds the file with `identity`. ESTALE
/// when it holds another file, ENOENT when it holds nothing.
fn open_if_identity(
    root: &Path,
    path: &Path,
    access: u32,
    identity: (u32, u64),
) -> io::Result<File> {
    ensure_lexically_under_root(root, path)?;
    let file = StdOpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    if mobility::file_identity(&file)? != identity {
        return Err(linux_error(LINUX_ESTALE));
    }
    reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
    Ok(file)
}

/// Set the host read-only attribute of the file `file` holds from `mode`.
fn apply_file_permissions(file: &File, mode: u32) -> io::Result<()> {
    let mut permissions = file.metadata().map_err(host_error)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions).map_err(host_error)
}

/// Keep `stat`, read from the inode's own metadata stream, in memory, unless
/// the memory copy changed from `before` while it was read: a concurrent
/// change of metadata set it, and the stream already holds that too.
fn remember_stat(data: &InodeData, before: &inode::VirtualMetadata, stat: OverrideStat) {
    let fields = |meta: &inode::VirtualMetadata| (meta.uid, meta.gid, meta.mode, meta.rdev);
    let mut meta = data.virtual_meta.write().unwrap();
    if fields(&meta) == fields(before) {
        *meta = inode::VirtualMetadata {
            uid: stat.uid,
            gid: stat.gid,
            mode: Some(stat.mode),
            rdev: u64::from(stat.rdev),
        };
    }
}
