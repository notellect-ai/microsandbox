//! Creation and link operations for the Windows passthrough backend.

use std::os::windows::io::AsRawHandle;

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_LINK_INFORMATION, FileLinkInformation, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_LIST_DIRECTORY, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn do_create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        let options = open_options_from_flags(flags, true)?;
        let file = if flags & LINUX_O_TRUNC as u32 != 0 && self.safe_metadata(&path).is_ok() {
            let data = self.intern_path(path.clone())?;
            self.resize_inode(data.inode, || options.open(&path).map_err(host_error))?
        } else {
            options.open(&path).map_err(host_error)?
        };

        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path.clone())?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            ctx.uid,
            ctx.gid,
            (mode_from_metadata(&metadata) & S_IFMT) | (mode & !umask & 0o7777),
            0,
        ) {
            let _ = std::fs::remove_file(&path);
            self.remove_inode_path(&path);
            return Err(error);
        }

        let handle = self.insert_handle(data.inode, flags, file)?;

        Ok((
            self.entry_from_metadata(&metadata, data.as_ref())?,
            Some(handle),
            OpenOptions::empty(),
        ))
    }

    pub(super) fn do_mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let file_type = mode & S_IFMT;
        if !self.cfg.stat_virtualization_enabled() && file_type != 0 && file_type != S_IFREG {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path)?;
        let virtual_type = if file_type == 0 { S_IFREG } else { file_type };
        let virtual_mode = virtual_type | (mode & !umask & 0o7777);
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, virtual_mode, rdev)
        {
            let _ = std::fs::remove_file(data.path());
            self.remove_inode_path(&data.path());
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        if !self.cfg.stat_virtualization_enabled() {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        if let Err(error) = self.quota_charge_file_to(&file, linkname.to_bytes().len() as u64) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Err(error) = file.write_all(linkname.to_bytes()).map_err(host_error) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path)?;
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, S_IFLNK | 0o777, 0)
        {
            let _ = std::fs::remove_file(data.path());
            self.remove_inode_path(&data.path());
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_readlink(&self, inode: u64) -> io::Result<Vec<u8>> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EINVAL));
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path())?;
        let current = self.current_override(&metadata, data.as_ref())?;
        if current.mode & S_IFMT != S_IFLNK {
            return Err(linux_error(LINUX_EINVAL));
        }

        let mut file = StdOpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(data.path())
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let mut target = Vec::new();
        file.read_to_end(&mut target).map_err(host_error)?;
        Ok(target)
    }

    pub(super) fn do_link(&self, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.require_writable()?;
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }

        let source = self.inode(inode)?;
        // Through the source's own file, before anything is linked: a source
        // whose name the host has put another file at, or removed, fails
        // here unless the guest has it open.
        let source_metadata = self.inode_metadata(&source)?;
        let current = self.current_override(&source_metadata, source.as_ref())?;
        let new_path = self.child_path(newparent, newname)?;
        let parent_path = new_path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        // Linked through the checked handle, so the new name never goes to
        // another file the source's name holds by now.
        match self.own_file(&source, true)? {
            Some(file) => link_at(&file, parent_path, newname)?,
            None => std::fs::hard_link(source.path(), &new_path).map_err(host_error)?,
        }
        let metadata = self.safe_metadata(&new_path)?;
        let data = self.intern_path(new_path.clone())?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            current.uid,
            current.gid,
            current.mode,
            current.rdev,
        ) {
            let _ = std::fs::remove_file(&new_path);
            self.remove_inode_path(&new_path);
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Give the file `file` holds the name `name` in the directory at `parent`.
/// A handle opened through a name the host has since replaced or removed
/// can no longer link the file (Windows reports delete pending or access
/// denied); the file is then reached through a reopen by file ID. A file
/// with no name left is gone (ENOENT).
fn link_at(file: &File, parent: &Path, name: &CStr) -> io::Result<()> {
    let name: Vec<u16> = name
        .to_str()
        .map_err(|_| linux_error(LINUX_EINVAL))?
        .encode_utf16()
        .collect();
    let directory = StdOpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)
        .map_err(host_error)?;
    let error = match set_link(file, &directory, &name) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    // As on Linux, a file with no name left gets none.
    if owned_metadata::link_count(file)? == 0 {
        return Err(linux_error(LINUX_ENOENT));
    }
    let Ok(file) = owned_metadata::reopen_by_id(file, FILE_WRITE_ATTRIBUTES) else {
        return Err(host_error(error));
    };
    set_link(&file, &directory, &name).map_err(host_error)
}

/// Link the file `file` holds as `name` in `directory`, by FileLinkInformation.
/// Errors are the host's, not yet mapped to Linux.
fn set_link(file: &File, directory: &File, name: &[u16]) -> io::Result<()> {
    // A validated name component is short, so its length in bytes fits.
    let name_bytes = (name.len() * 2) as u32;
    let size = (std::mem::offset_of!(FILE_LINK_INFORMATION, FileName) + name_bytes as usize)
        .max(std::mem::size_of::<FILE_LINK_INFORMATION>());

    // Pointer-sized words provide the alignment of FILE_LINK_INFORMATION; the
    // flags stay zero, so an existing name is not replaced.
    let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    let mut status_block = IO_STATUS_BLOCK::default();

    // SAFETY: buffer is aligned and large enough for the header and name, and
    // both handles stay open until the synchronous call returns.
    let status = unsafe {
        (*info).RootDirectory = directory.as_raw_handle();
        (*info).FileNameLength = name_bytes;
        let destination = info
            .cast::<u8>()
            .add(std::mem::offset_of!(FILE_LINK_INFORMATION, FileName))
            .cast::<u16>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            info.cast(),
            size as u32,
            FileLinkInformation,
        )
    };
    if status < 0 {
        // SAFETY: RtlNtStatusToDosError only maps the status code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }

    Ok(())
}
