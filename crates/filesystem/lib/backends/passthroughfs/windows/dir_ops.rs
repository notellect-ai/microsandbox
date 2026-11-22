//! Directory enumeration helpers for the Windows passthrough backend.

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_LEVEL, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES,
    ERROR_NOT_SUPPORTED, MAX_PATH, SetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY,
    FILE_REMOTE_PROTOCOL_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    FileRemoteProtocolInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
};

use windows_sys::Win32::System::SystemServices::FILE_SUPPORTS_OPEN_BY_FILE_ID;

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
        if data.retained.lock().unwrap().is_some() {
            let metadata = self.inode_metadata(&data)?;
            return self.entry_from_metadata(&metadata, data.as_ref());
        }
        let attrs = self.safe_attrs(&data.path())?;
        self.entry_from_metadata_links(&attrs.metadata, data.as_ref(), Some(attrs.links))
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

        // Local NTFS reports the same 64-bit file reference in a directory
        // listing as through a handle to the file. Elsewhere (ReFS uses 128-bit
        // IDs; a share or a third-party driver may call itself NTFS and list
        // IDs of 0 or IDs its handles do not report) each child's identity is
        // read through its own handle instead.
        let volume = listing_ids_match_handles(&directory).then_some(attrs.identity.0);
        for_each_directory_entry(&directory, &path, |name, attributes, file_id| {
            if name == "." || name == ".." || is_reserved_name(name) {
                return Ok(());
            }
            // A rejected reparse point must not hide its ordinary siblings.
            // Direct lookup and access still enforce the same reparse guard.
            // (NTFS may list another hard link's name of a reparse file with
            // stale attributes; it then lists as a file, and every access
            // through it is still refused.)
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Ok(());
            }
            // A child the Host removed or replaced by a reparse point since the
            // listing is left out, as if listed a moment later.
            let gone = |error: &io::Error| {
                matches!(error.raw_os_error(), Some(LINUX_ELOOP | LINUX_ENOENT))
            };
            let child_path = path.join(name);
            let identity = match (volume, file_id) {
                (Some(volume), Some(file_id)) => Some((volume, file_id)),
                _ => match self.path_identity(&child_path) {
                    Ok(identity) => identity,
                    Err(error) if gone(&error) => return Ok(()),
                    Err(error) => return Err(error),
                },
            };
            let child = match self.intern_identified_path(child_path, identity) {
                Ok(child) => child,
                Err(error) if gone(&error) => return Ok(()),
                Err(error) => return Err(error),
            };
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

/// Whether a listing's file IDs equal the identities read through handles: a
/// local NTFS volume that opens files by ID. Any doubt answers no.
fn listing_ids_match_handles(directory: &File) -> bool {
    if listing_ids_disabled() {
        return false;
    }
    let mut name = [0u16; MAX_PATH as usize + 1];
    let mut flags = 0u32;
    // The borrowed File keeps the handle live; the API writes at most
    // `name.len()` UTF-16 units into `name` and one u32 into `flags`.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 || flags & FILE_SUPPORTS_OPEN_BY_FILE_ID == 0 {
        return false;
    }
    let len = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    if String::from_utf16_lossy(&name[..len]) != "NTFS" {
        return false;
    }
    // Remote protocol information exists only for a file on a share; a local
    // volume refuses the class with ERROR_INVALID_PARAMETER. Any other answer
    // is doubt.
    // SAFETY: a plain C struct of integers; all zeroes is a valid value.
    let mut remote: FILE_REMOTE_PROTOCOL_INFO = unsafe { std::mem::zeroed() };
    // The API writes at most size_of::<FILE_REMOTE_PROTOCOL_INFO>() bytes.
    let remote_ok = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            FileRemoteProtocolInfo,
            std::ptr::addr_of_mut!(remote).cast(),
            std::mem::size_of::<FILE_REMOTE_PROTOCOL_INFO>() as u32,
        )
    };
    remote_ok == 0
        && io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32)
}

/// Enumerate an open directory in batches: one call returns as many entries as
/// fit in the buffer, each with its name, attributes and file ID (None when the
/// listing has none). A name that is not valid UTF-16 fails the listing, as the
/// guest cannot be given it. A filesystem without this listing class is read
/// with `std::fs::read_dir` at `path`, as before the batched listing.
fn for_each_directory_entry(
    directory: &File,
    path: &Path,
    mut visit: impl FnMut(&str, u32, Option<u64>) -> io::Result<()>,
) -> io::Result<()> {
    // u64 elements keep the buffer aligned for FILE_ID_BOTH_DIR_INFO.
    let mut buffer = vec![0u64; 8 * 1024];
    let mut class = FileIdBothDirectoryRestartInfo;
    loop {
        count_host_enumeration();
        let ok = if listing_class_unsupported() {
            // SAFETY: sets this thread's last-error value only.
            unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
            0
        } else {
            // The borrowed File keeps the handle live; the API fills at most the
            // buffer's byte length with whole FILE_ID_BOTH_DIR_INFO records.
            unsafe {
                GetFileInformationByHandleEx(
                    directory.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * std::mem::size_of::<u64>()) as u32,
                )
            }
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            let first = class == FileIdBothDirectoryRestartInfo;
            return match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_NO_MORE_FILES) => Ok(()),
                // A directory with no entries at all (a volume root has no `.`).
                Some(ERROR_FILE_NOT_FOUND) if first => Ok(()),
                Some(ERROR_INVALID_PARAMETER | ERROR_INVALID_LEVEL | ERROR_NOT_SUPPORTED)
                    if first =>
                {
                    for_each_read_dir_entry(path, visit)
                }
                _ => Err(host_error(error)),
            };
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
            // An ID of 0 is no ID.
            visit(&name, attributes, (file_id != 0).then_some(file_id))?;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
}

/// The listing of a filesystem without batched listings: names and attributes
/// from FindFirstFile/FindNextFile, no file IDs.
fn for_each_read_dir_entry(
    path: &Path,
    mut visit: impl FnMut(&str, u32, Option<u64>) -> io::Result<()>,
) -> io::Result<()> {
    for entry in std::fs::read_dir(path).map_err(host_error)? {
        let entry = entry.map_err(host_error)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let attributes = entry.metadata().map_err(host_error)?.file_attributes();
        visit(name, attributes, None)?;
    }
    Ok(())
}

pub(super) fn snapshot_dir_entry(entry: DirSnapshotEntry) -> DirEntry<'static> {
    DirEntry {
        ino: entry.inode,
        offset: entry.offset,
        type_: entry.file_type,
        name: leak_name(&entry.name),
    }
}
