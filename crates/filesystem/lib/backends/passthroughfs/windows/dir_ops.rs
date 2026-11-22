//! Directory enumeration helpers for the Windows passthrough backend.

use std::ffi::CString;

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn dir_snapshot(
        &self,
        inode: u64,
        handle: u64,
    ) -> io::Result<Vec<DirSnapshotEntry>> {
        let handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let mut snapshot = handle.snapshot.lock().unwrap();
        if snapshot.is_none() {
            *snapshot = Some(
                self.dir_entries(inode)?
                    .into_iter()
                    .map(|(entry, _)| DirSnapshotEntry {
                        inode: entry.ino,
                        name: entry.name.to_vec(),
                        offset: entry.offset,
                        file_type: entry.type_,
                    })
                    .collect(),
            );
        }
        Ok(snapshot.as_ref().unwrap().clone())
    }

    /// Read the attributes of a listed entry. `Ok(None)` when its name has
    /// gone, turned into a reparse point or keeps being replaced since the
    /// listing: the entry is left out, as `dir_entries` leaves out a
    /// reparse point.
    pub(super) fn snapshot_entry_attributes(
        &self,
        parent: u64,
        entry: &DirSnapshotEntry,
    ) -> io::Result<Option<Entry>> {
        if self.cfg.inject_init && entry.inode == INIT_INODE {
            return Ok(Some(init_entry(
                self.cfg.entry_timeout,
                self.cfg.attr_timeout,
            )));
        }
        if entry.name == b"." || entry.name == b".." {
            let data = self.inode(entry.inode)?;
            let metadata = self.inode_metadata(&data)?;
            return self.entry_from_metadata(&metadata, data.as_ref()).map(Some);
        }
        let name = CString::new(entry.name.clone()).map_err(|_| linux_error(LINUX_EINVAL))?;
        let path = self.child_path(parent, &name)?;
        // The name still holds the listed inode's file: read it as before.
        if let Ok(data) = self.inode(entry.inode)
            && data.identity.is_some()
            && self.path_identity(&path).ok().flatten() == data.identity
        {
            match self
                .inode_metadata(&data)
                .and_then(|metadata| self.entry_from_metadata(&metadata, data.as_ref()))
            {
                Err(error) if is_name_miss(&error) => {}
                result => return result.map(Some),
            }
        }
        // The host can have put another file at the name since the listing:
        // report what the name holds now, as a lookup would.
        match self.entry_for_path(path) {
            Err(error) if is_name_miss(&error) => Ok(None),
            result => result.map(Some),
        }
    }

    pub(super) fn dir_entries(&self, inode: u64) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path())?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let mut entries = Vec::new();
        entries.push((
            DirEntry {
                ino: inode,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            self.entry_from_metadata(&metadata, data.as_ref())?,
        ));
        entries.push((
            DirEntry {
                ino: ROOT_INODE,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
            self.parent_entry(data.as_ref())?,
        ));

        if self.cfg.inject_init && inode == ROOT_INODE {
            entries.push((
                DirEntry {
                    ino: INIT_INODE,
                    offset: entries.len() as u64 + 1,
                    type_: DT_REG,
                    name: INIT_NAME,
                },
                init_entry(self.cfg.entry_timeout, self.cfg.attr_timeout),
            ));
        }

        for entry in std::fs::read_dir(data.path()).map_err(host_error)? {
            let entry = entry.map_err(host_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| linux_error(LINUX_EINVAL))?;
            if is_reserved_name(name) {
                continue;
            }
            let name_buffer = format!("{name}\0");
            let name = CStr::from_bytes_with_nul(name_buffer.as_bytes())
                .map_err(|_| linux_error(LINUX_EINVAL))?;
            validate_component(name)?;

            // A rejected reparse point must not hide its ordinary siblings.
            // Direct lookup and access still enforce the same reparse guard.
            let full_entry = match self.entry_for_path(entry.path()) {
                Ok(full_entry) => full_entry,
                Err(error) if error.raw_os_error() == Some(LINUX_ELOOP) => continue,
                Err(error) => return Err(error),
            };
            let dir_entry = DirEntry {
                ino: full_entry.inode,
                offset: entries.len() as u64 + 1,
                type_: dirent_type_from_mode(full_entry.attr.st_mode),
                name: leak_name(name.to_bytes()),
            };
            entries.push((dir_entry, full_entry));
        }

        Ok(entries)
    }

    pub(super) fn parent_entry(&self, data: &InodeData) -> io::Result<Entry> {
        let path = data.path();
        let parent_path = path.parent().unwrap_or(&self.root);
        let parent_path = if data.inode == ROOT_INODE || !parent_path.starts_with(&self.root) {
            self.root.clone()
        } else {
            parent_path.to_path_buf()
        };
        self.entry_for_path(parent_path)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn snapshot_dir_entry(entry: DirSnapshotEntry) -> DirEntry<'static> {
    DirEntry {
        ino: entry.inode,
        offset: entry.offset,
        type_: entry.file_type,
        name: leak_name(&entry.name),
    }
}

/// Whether `error` says a listed name no longer holds a file to report.
fn is_name_miss(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(LINUX_ENOENT | LINUX_ESTALE | LINUX_ELOOP)
    )
}
