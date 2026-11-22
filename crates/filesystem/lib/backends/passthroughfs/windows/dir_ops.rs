//! Directory enumeration helpers for the Windows passthrough backend.

use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
};

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
                    .map(|entry| DirSnapshotEntry {
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

    pub(super) fn snapshot_entry_attributes(&self, entry: &DirSnapshotEntry) -> io::Result<Entry> {
        if self.cfg.inject_init && entry.inode == INIT_INODE {
            return Ok(init_entry(self.cfg.entry_timeout, self.cfg.attr_timeout));
        }
        let data = self.inode(entry.inode)?;
        let metadata = self.inode_metadata(&data)?;
        self.entry_from_metadata(&metadata, data.as_ref())
    }

    /// List a directory for readdir: names, inodes and entry types only. Children
    /// come from one bulk enumeration of the directory's own handle; their
    /// attributes are read only when the guest asks for them.
    pub(super) fn dir_entries(&self, inode: u64) -> io::Result<Vec<DirEntry<'static>>> {
        let data = self.inode(inode)?;
        let path = data.path();
        let (directory, attrs) = safe_open_under_root(
            &self.root,
            &path,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        )?;
        if !attrs.metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let mut entries = vec![
            DirEntry {
                ino: inode,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            DirEntry {
                ino: ROOT_INODE,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
        ];

        if self.cfg.inject_init && inode == ROOT_INODE {
            entries.push(DirEntry {
                ino: INIT_INODE,
                offset: entries.len() as u64 + 1,
                type_: DT_REG,
                name: INIT_NAME,
            });
        }

        // NTFS reports the same 64-bit file reference in a directory listing as
        // through a handle to the file. Other filesystems (ReFS uses 128-bit
        // IDs) read each child's identity through its own handle instead.
        let volume = (volume_filesystem(&directory)? == "NTFS" && !listing_ids_disabled())
            .then_some(attrs.identity.0);
        for_each_directory_entry(&directory, |name, attributes, file_id| {
            if name == "." || name == ".." || is_reserved_name(name) {
                return Ok(());
            }
            // A rejected reparse point must not hide its ordinary siblings.
            // Direct lookup and access still enforce the same reparse guard.
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Ok(());
            }
            let child_path = path.join(name);
            let identity = match volume {
                Some(volume) => Some((volume, file_id)),
                None => match self.path_identity(&child_path) {
                    Ok(identity) => identity,
                    Err(error) if error.raw_os_error() == Some(LINUX_ELOOP) => return Ok(()),
                    Err(error) => return Err(error),
                },
            };
            let child = self.intern_identified_path(child_path, identity)?;
            entries.push(DirEntry {
                ino: child.inode,
                offset: entries.len() as u64 + 1,
                type_: self.guest_dirent_type(child.as_ref(), attributes)?,
                name: leak_name(name.as_bytes()),
            });
            Ok(())
        })?;

        Ok(entries)
    }

    /// The entry type `getattr` would report, without reading the Host attributes
    /// the type does not depend on.
    fn guest_dirent_type(&self, data: &InodeData, attributes: u32) -> io::Result<u32> {
        let host = if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            DT_DIR
        } else {
            DT_REG
        };
        if !self.cfg.stat_virtualization_enabled() {
            return Ok(host);
        }
        if let Some(override_stat) = owned_metadata::read_retained_stat(data)? {
            return Ok(dirent_type_from_mode(override_stat.mode));
        }
        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
        {
            return Ok(store.read(&data.path())?.map_or(host, |override_stat| {
                dirent_type_from_mode(override_stat.mode)
            }));
        }
        Ok(data
            .virtual_meta
            .read()
            .unwrap()
            .mode
            .map_or(host, dirent_type_from_mode))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The filesystem name of the volume holding `file` ("NTFS", "ReFS", ...).
fn volume_filesystem(file: &File) -> io::Result<String> {
    let mut name = [0u16; 32];
    // The borrowed File keeps the handle live; the API writes at most
    // `name.len()` UTF-16 units into the buffer and nothing else.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(host_error(io::Error::last_os_error()));
    }
    let len = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..len]))
}

/// Enumerate an open directory in batches: one call returns as many entries as
/// fit in the buffer, each with its name, attributes and file ID. A name that is
/// not valid UTF-16 fails the listing, as the guest cannot be given it.
fn for_each_directory_entry(
    directory: &File,
    mut visit: impl FnMut(&str, u32, u64) -> io::Result<()>,
) -> io::Result<()> {
    // u64 elements keep the buffer aligned for FILE_ID_BOTH_DIR_INFO.
    let mut buffer = vec![0u64; 8 * 1024];
    let mut class = FileIdBothDirectoryRestartInfo;
    loop {
        count_host_enumeration();
        // The borrowed File keeps the handle live; the API fills at most the
        // buffer's byte length with whole FILE_ID_BOTH_DIR_INFO records.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * std::mem::size_of::<u64>()) as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                return Ok(());
            }
            return Err(host_error(error));
        }
        class = FileIdBothDirectoryInfo;
        let base = buffer.as_ptr().cast::<u8>();
        let mut offset = 0usize;
        loop {
            // Records are 8-byte aligned and lie wholly inside the filled buffer;
            // the name is FileNameLength bytes of UTF-16 starting at FileName.
            let (attributes, file_id, name, next) = unsafe {
                let record = base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>();
                let name_ptr = std::ptr::addr_of!((*record).FileName).cast::<u16>();
                let units = (*record).FileNameLength as usize / 2;
                (
                    (*record).FileAttributes,
                    (*record).FileId as u64,
                    std::slice::from_raw_parts(name_ptr, units),
                    (*record).NextEntryOffset as usize,
                )
            };
            let name = String::from_utf16(name).map_err(|_| linux_error(LINUX_EINVAL))?;
            visit(&name, attributes, file_id)?;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
}

pub(super) fn snapshot_dir_entry(entry: DirSnapshotEntry) -> DirEntry<'static> {
    DirEntry {
        ino: entry.inode,
        offset: entry.offset,
        type_: entry.file_type,
        name: leak_name(&entry.name),
    }
}
