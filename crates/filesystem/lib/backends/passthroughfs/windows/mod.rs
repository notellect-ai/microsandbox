//! Windows passthrough filesystem backend.
//!
//! This backend is owned by microsandbox and is used instead of libkrun's
//! platform passthrough implementation. It exposes a host directory through
//! virtio-fs while keeping guest metadata private and rejecting Windows path
//! features that could escape the mount root.

use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs::{File, FileTimes, OpenOptions as StdOpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_NAME_OPENED, FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileRemoteProtocolInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, ReOpenFile, VOLUME_NAME_NT,
};

use crate::agentd::agentd_bytes;
use crate::{
    AddDirEntry, AddDirEntryPlus, Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions,
    GetxattrReply, ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
    stat64, statvfs64,
};

mod builder;
mod create_ops;
mod dax;
mod dir_ops;
mod file_ops;
mod inode;
mod memory_mapping;
mod metadata;
mod mobility;
mod ops;
mod owned_metadata;
mod remove_ops;
mod stat_store;

use dax::{DaxFiles, DaxWindows};
use inode::{DirHandle, DirSnapshotEntry, HandleData, InodeData, InodeTable};
pub(super) use owned_metadata::{
    capture_owned_metadata, clear_owned_payload_metadata, owned_component, restore_owned_metadata,
};

pub use builder::{HostPermissions, PassthroughConfig, StatVirtualization};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const INIT_INODE: u64 = 2;
const INIT_HANDLE: u64 = 0;
const INIT_NAME: &[u8] = b"init.krun";
const FALLBACK_METADATA_DIR_NAME: &str = ".msb_override_stat";
const METADATA_ROOT_NAME: &str = "__root";
const METADATA_STAT_NAME: &str = "stat.bin";
const ADS_STREAM_NAME: &str = "msb.override_stat";
const ADS_PROBE_STREAM_NAME: &str = "msb._probe";

const DT_UNKNOWN: u32 = 0;
const DT_FIFO: u32 = 1;
const DT_CHR: u32 = 2;
const DT_DIR: u32 = 4;
const DT_BLK: u32 = 6;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;
const DT_SOCK: u32 = 12;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFSOCK: u32 = 0o140000;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EBUSY: i32 = 16;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
#[cfg(test)]
const LINUX_ENOSPC: i32 = 28;
const LINUX_EROFS: i32 = 30;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENODATA: i32 = 61;
const LINUX_ESTALE: i32 = 116;
const LINUX_EOPNOTSUPP: i32 = 95;
const LINUX_ENOSYS: i32 = 38;

const LINUX_O_ACCMODE: i32 = 0o3;
const LINUX_O_WRONLY: i32 = 0o1;
const LINUX_O_RDWR: i32 = 0o2;
const LINUX_O_CREAT: i32 = 0o100;
const LINUX_O_EXCL: i32 = 0o200;
const LINUX_O_TRUNC: i32 = 0o1000;
const LINUX_O_APPEND: i32 = 0o2000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECTORY: i32 = 0x4000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECTORY: i32 = 0x10000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECT: i32 = 0x10000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECT: i32 = 0x4000;

const LINUX_ACCESS_W_OK: u32 = 0o2;
const LINUX_ACCESS_X_OK: u32 = 0o1;
const LINUX_ACCESS_R_OK: u32 = 0o4;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_WHITEOUT: u32 = 4;

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_NOT_SAME_DEVICE: i32 = 17;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_INVALID_NAME: i32 = 123;
const ERROR_DIR_NOT_EMPTY: i32 = 145;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
const OVERRIDE_VERSION: u8 = 1;
const OVERRIDE_SIZE: usize = std::mem::size_of::<OverrideStat>();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Windows passthrough filesystem backend.
pub struct PassthroughFs {
    cfg: PassthroughConfig,
    root: PathBuf,
    inodes: RwLock<InodeTable>,
    next_inode: AtomicU64,
    handles: RwLock<BTreeMap<u64, Arc<HandleData>>>,
    dir_handles: RwLock<BTreeMap<u64, Arc<DirHandle>>>,
    next_handle: AtomicU64,
    init_file: Option<Mutex<File>>,
    stat_store: Option<StatStore>,
    quota: Option<super::quota::DirQuota>,
    invalid_inodes: RwLock<std::collections::BTreeSet<u64>>,
    /// Installed DAX mappings, keyed by guest address.
    map_windows: Mutex<DaxWindows>,
    /// Host-file coordination shared by hardlink aliases, separate from worker waits.
    dax_files: DaxFiles,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct OverrideStat {
    version: u8,
    _pad: [u8; 3],
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
}

#[derive(Clone, Debug)]
struct StatStore {
    root: PathBuf,
    backend: StatStoreBackend,
}

#[derive(Clone, Debug)]
enum StatStoreBackend {
    AlternateDataStream,
    Sidecar { dir: PathBuf },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(crate) fn max_state_bytes(&self) -> usize {
        self.cfg.max_state_bytes
    }

    /// Validate an external checkpoint without opening any destination host paths.
    pub fn validate_external_state_with_limit(bytes: &[u8], limit: usize) -> io::Result<()> {
        mobility::validate_unavailable(bytes, limit)
    }

    /// Validate external state with the default filesystem budget.
    pub fn validate_external_state(bytes: &[u8]) -> io::Result<()> {
        Self::validate_external_state_with_limit(
            bytes,
            msb_krun::DEFAULT_MAX_FS_BACKEND_STATE_BYTES,
        )
    }

    /// Validate and translate only the isolated facade's selected host basename.
    pub(crate) fn prepare_single_file_state(
        bytes: &[u8],
        source: &CStr,
        destination: &CStr,
        limit: usize,
    ) -> io::Result<(Vec<u8>, super::ExternalSingleFileIndex)> {
        mobility::prepare_single_file_state(bytes, source, destination, limit)
    }

    /// Charge the quota for growing from `old_len` to `new_end` bytes.
    pub(super) fn quota_charge_growth(&self, old_len: u64, new_end: u64) -> io::Result<()> {
        if let Some(quota) = &self.quota {
            quota.charge(new_end.saturating_sub(old_len))?;
        }
        Ok(())
    }

    /// Charge the quota for growing an open file to `new_end` bytes.
    ///
    /// Used on create-like paths where the file was just created and the
    /// handle metadata is enough to determine growth before bytes are written.
    pub(super) fn quota_charge_file_to(&self, file: &File, new_end: u64) -> io::Result<()> {
        self.quota_charge_growth(super::quota::file_size(file), new_end)
    }

    /// Capture the quota baseline now if it has not been captured yet.
    ///
    /// The first write-intent operation pays the one-time directory walk so
    /// pre-existing host files become baseline instead of guest growth.
    pub(super) fn quota_ensure_baseline(&self) {
        if let Some(quota) = &self.quota {
            quota.ensure_baseline();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_component(name: &CStr) -> io::Result<&str> {
    let component = name.to_str().map_err(|_| linux_error(LINUX_EINVAL))?;
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.contains(':')
        || is_reserved_name(component)
    {
        return Err(linux_error(LINUX_EPERM));
    }

    Ok(component)
}

fn is_reserved_name(component: &str) -> bool {
    component.eq_ignore_ascii_case(FALLBACK_METADATA_DIR_NAME)
}

fn ensure_lexically_under_root(root: &Path, path: &Path) -> io::Result<()> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(linux_error(LINUX_EACCES))
    }
}

/// Resolve the mount root trusting no component of the provided path.
///
/// Walks `root_dir` from the volume root, rejecting a reparse point (symlink or
/// junction) at every component and refusing `..`, so neither a planted reparse
/// point nor an injected `..` can move the mount off its intended target. The
/// only implicitly trusted object is the volume root (e.g. `C:\`), which cannot
/// be a reparse point. Each component is checked with a non-following
/// `symlink_metadata` only after its ancestors are verified clean, so path
/// resolution never crosses a reparse point. Unlike `canonicalize`, this never
/// follows a reparse point out of the intended subtree.
fn resolve_root_no_reparse(root_dir: &Path) -> io::Result<PathBuf> {
    // Reject `..` from the RAW path string, not from `Path::components()`.
    //
    // For verbatim (`\\?\`) paths, `components()` collapses `a\..` lexically
    // before we ever see a `ParentDir` or `Normal("..")`, so a `..` would slip
    // through and the filesystem would resolve it out of the subtree. Splitting
    // the raw string on separators catches a `..` segment in any path form.
    // (`..` is pure ASCII, so a lossy conversion can neither hide nor fabricate
    // one.)
    if root_dir
        .as_os_str()
        .to_string_lossy()
        .split(['\\', '/'])
        .any(|segment| segment == "..")
    {
        return Err(linux_error(LINUX_EINVAL));
    }

    // Split into the trusted base and the segments below it. For an absolute
    // path the base is the volume root (prefix + root); for a relative path it
    // is the working directory. Neither is attacker-controllable.
    let mut cursor = PathBuf::new();
    let mut names = Vec::new();
    for component in root_dir.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => cursor.push(component.as_os_str()),
            Component::Normal(part) => names.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => return Err(linux_error(LINUX_EINVAL)),
        }
    }
    if cursor.as_os_str().is_empty() {
        cursor.push(".");
    }

    // Descend one component at a time; each ancestor is verified non-reparse
    // before the next lookup, so resolution never follows a reparse point.
    for name in &names {
        if name.to_str().is_some_and(is_reserved_name) {
            return Err(linux_error(LINUX_EPERM));
        }
        cursor.push(name);
        let metadata = std::fs::symlink_metadata(&cursor).map_err(host_error)?;
        reject_reparse_metadata(&metadata)?;
    }

    let metadata = std::fs::symlink_metadata(&cursor).map_err(host_error)?;
    if !metadata.file_type().is_dir() {
        return Err(linux_error(LINUX_ENOTDIR));
    }
    Ok(cursor)
}

/// Host metadata, identity and link count of one object, read through one handle.
struct HostAttrs {
    metadata: std::fs::Metadata,
    identity: (u32, u64),
    links: u32,
}

/// Resolve `path` under `root` without following a reparse point, and open the
/// final object once with `access`. Every ancestor, the root included, is checked
/// by its own metadata before the next name is resolved under it; the final
/// object's metadata, identity and link count all come from the returned handle.
fn safe_open_under_root(root: &Path, path: &Path, access: u32) -> io::Result<(File, HostAttrs)> {
    ensure_lexically_under_root(root, path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| linux_error(LINUX_EACCES))?;
    let components = relative.components().collect::<Vec<_>>();
    if let Some(found) = open_by_final_path(root, &components, access)? {
        return Ok(found);
    }
    let mut cursor = root.to_path_buf();
    let last = components
        .iter()
        .rposition(|component| matches!(component, Component::Normal(_)));
    if last.is_some() {
        reject_reparse_metadata(&host_symlink_metadata(&cursor)?)?;
    }

    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_some_and(is_reserved_name) {
                    return Err(linux_error(LINUX_EPERM));
                }
                cursor.push(part);
                if Some(index) != last {
                    reject_reparse_metadata(&host_symlink_metadata(&cursor)?)?;
                }
            }
            Component::CurDir => {}
            _ => return Err(linux_error(LINUX_EACCES)),
        }
    }

    let file = open_host_object(&cursor, access)?;
    let attrs = host_attrs(&file)?;
    reject_reparse_metadata(&attrs.metadata)?;
    Ok((file, attrs))
}

/// The fast path of [`safe_open_under_root`]: open the object by its full path
/// in one call (never following a reparse point at the last name) and read back
/// the name the handle was opened by. Windows reissues an open that crosses a
/// symlink, junction or mount point under the target's name, so the handle's
/// opened name equals the mount root's own name plus the requested components
/// only when no component below the root redirected the open elsewhere.
/// Anything else (a mismatch, an error the walk would word differently) returns
/// `None` and the caller walks component by component as before. Saves one Host
/// open per path component per lookup and getattr, which a mount with no
/// attribute cache makes for every guest path operation.
///
/// What this proves differs from the walk in one respect: a directory carrying
/// a reparse tag a filter driver serves in place (cloud files, ProjFS) keeps
/// its name, so an object below it is reached where the walk would refuse it.
/// Such a tag never moves the open off the mount's own names, which is what the
/// walk's reparse check protects. Remote roots never take this path: an SMB
/// server follows junctions on its side and the client's name does not change
/// (see [`root_opened_name`]).
///
/// Only attribute reads open the object before its name is checked. Other
/// access (a directory listing) is first proven with an attribute open, then
/// opened again and checked again, so an object outside the mount is never
/// opened for more than its attributes.
fn open_by_final_path(
    root: &Path,
    components: &[Component<'_>],
    access: u32,
) -> io::Result<Option<(File, HostAttrs)>> {
    let mut expected = match root_opened_name(root) {
        Some(name) => name,
        None => return Ok(None),
    };
    let mut target = root.to_path_buf();
    let mut parent = None;
    for component in components {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_some_and(is_reserved_name) {
                    return Err(linux_error(LINUX_EPERM));
                }
                parent = Some((target.clone(), expected.len()));
                target.push(part);
                expected.push(u16::from(b'\\'));
                expected.extend(part.encode_wide());
            }
            Component::CurDir => {}
            _ => return Err(linux_error(LINUX_EACCES)),
        }
    }
    let file = match open_host_object(&target, FILE_READ_ATTRIBUTES) {
        Ok(file) => file,
        // The name is missing: prove its directory is the one the walk would
        // reach, so a miss costs two opens rather than one per component.
        Err(error) if error.raw_os_error() == Some(LINUX_ENOENT) => {
            if let Some((parent, len)) = parent
                && let Ok(dir) = open_host_object(&parent, FILE_READ_ATTRIBUTES)
                && opened_name(&dir).as_deref() == Some(&expected[..len])
                && host_attrs(&dir).is_ok_and(|attrs| {
                    attrs.metadata.is_dir() && reject_reparse_metadata(&attrs.metadata).is_ok()
                })
            {
                return Err(error);
            }
            return Ok(None);
        }
        Err(_) => return Ok(None),
    };
    if opened_name(&file).as_deref() != Some(&expected[..]) {
        return Ok(None);
    }
    let attrs = host_attrs(&file)?;
    reject_reparse_metadata(&attrs.metadata)?;
    if access == FILE_READ_ATTRIBUTES {
        return Ok(Some((file, attrs)));
    }
    // Reopen the proven object through its handle, not its path, so nothing
    // swapped in since is opened with more than attribute access.
    count_host_open();
    // The proven handle stays live for the call; on success the result is a
    // new handle this function owns.
    let reopened = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if reopened.is_null() || reopened == INVALID_HANDLE_VALUE {
        return Ok(None);
    }
    // SAFETY: a valid handle just returned to us and owned by nothing else.
    let reopened = unsafe { File::from_raw_handle(reopened) };
    Ok(Some((reopened, attrs)))
}

/// The NT name (`\Device\HarddiskVolumeN\...`) a handle was opened by, as
/// given, without normalizing case or short names.
fn opened_name(file: &File) -> Option<Vec<u16>> {
    let mut buffer = vec![0u16; 512];
    // The needed length grows only if the name changes between calls.
    for _ in 0..4 {
        // The handle stays live for the call; the API writes at most
        // `buffer.len()` units and returns the length it needs otherwise.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_OPENED | VOLUME_NAME_NT,
            )
        } as usize;
        if len == 0 {
            return None;
        }
        if len < buffer.len() {
            buffer.truncate(len);
            // Only a volume root's name ends in a separator; drop it so the
            // root and the names below it compare alike.
            if buffer.last() == Some(&u16::from(b'\\')) {
                buffer.pop();
            }
            return Some(buffer);
        }
        buffer.resize(len + 1, 0);
    }
    None
}

/// The opened name of a mount root, read once per root path. It depends only on
/// the root's ancestors, which the mount trusts (see
/// [`resolve_root_no_reparse`]): with the last name opened as itself, a root
/// the Host later replaces with a reparse point keeps this name, while every
/// path through that reparse point is reissued under its target's name and no
/// longer matches. `None` (always walk) for a root not on a local NTFS or ReFS
/// disk volume: a network redirector reports the client's name for an open the
/// server sent through a junction. One entry per distinct mount root.
fn root_opened_name(root: &Path) -> Option<Vec<u16>> {
    type Names = Mutex<std::collections::HashMap<PathBuf, Option<Vec<u16>>>>;
    static NAMES: std::sync::OnceLock<Names> = std::sync::OnceLock::new();
    let names = NAMES.get_or_init(Default::default);
    if let Some(name) = names.lock().unwrap().get(root) {
        return name.clone();
    }
    let file = open_host_object(root, FILE_READ_ATTRIBUTES).ok()?;
    let name = opened_name(&file)?;
    let name = on_local_ntfs_or_refs(&file, &name).then_some(name);
    names
        .lock()
        .unwrap()
        .insert(root.to_path_buf(), name.clone());
    name
}

/// Whether `file` (opened by the NT name `name`) is on a local NTFS or ReFS
/// disk volume. An allowlist: the name is on a `\Device\HarddiskVolumeN`
/// device (fixed disks, VHDs, Storage Spaces and Dev Drives all are; every
/// network, RDP and user-mode redirector is not), the handle has no remote
/// protocol information, and the file system is NTFS or ReFS.
/// Whether an NT name is on a `\Device\HarddiskVolumeN` device.
fn nt_name_on_disk_volume(name: &[u16]) -> bool {
    const PREFIX: &str = r"\device\harddiskvolume";
    let lower = String::from_utf16_lossy(name).to_ascii_lowercase();
    lower
        .strip_prefix(PREFIX)
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

fn on_local_ntfs_or_refs(file: &File, name: &[u16]) -> bool {
    if !nt_name_on_disk_volume(name) {
        return false;
    }
    // Succeeds only for a file a network redirector serves.
    // SAFETY: a plain-data struct; all zeroes is a valid value.
    let mut remote: FILE_REMOTE_PROTOCOL_INFO = unsafe { std::mem::zeroed() };
    // The handle stays live; the API writes at most the struct's size.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileRemoteProtocolInfo,
            (&mut remote as *mut FILE_REMOTE_PROTOCOL_INFO).cast(),
            std::mem::size_of::<FILE_REMOTE_PROTOCOL_INFO>() as u32,
        )
    } != 0
    {
        return false;
    }
    let mut file_system = [0u16; 32];
    // The handle stays live; the API writes at most `file_system.len()` units.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            file_system.as_mut_ptr(),
            file_system.len() as u32,
        )
    } == 0
    {
        return false;
    }
    let end = file_system.iter().position(|unit| *unit == 0).unwrap_or(0);
    matches!(
        String::from_utf16_lossy(&file_system[..end]).as_str(),
        "NTFS" | "ReFS"
    )
}

fn safe_attrs_under_root(root: &Path, path: &Path) -> io::Result<HostAttrs> {
    safe_open_under_root(root, path, FILE_READ_ATTRIBUTES).map(|(_, attrs)| attrs)
}

fn safe_metadata_under_root(root: &Path, path: &Path) -> io::Result<std::fs::Metadata> {
    safe_attrs_under_root(root, path).map(|attrs| attrs.metadata)
}

/// Open the object at `path` itself (never a reparse target) for attribute reads.
fn open_host_object(path: &Path, access: u32) -> io::Result<File> {
    count_host_open();
    StdOpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)
}

fn host_symlink_metadata(path: &Path) -> io::Result<std::fs::Metadata> {
    count_host_open();
    std::fs::symlink_metadata(path).map_err(host_error)
}

fn host_attrs(file: &File) -> io::Result<HostAttrs> {
    let metadata = file.metadata().map_err(host_error)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // The borrowed File keeps the handle live for the query; the API fills only
    // this initialized information struct.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(host_error(io::Error::last_os_error()));
    }
    Ok(HostAttrs {
        metadata,
        identity: (
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ),
        links: info.nNumberOfLinks,
    })
}

#[cfg(test)]
thread_local! {
    static HOST_OPENS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static HOST_ENUMERATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static LISTING_IDS_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LISTING_CLASS_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Count Host opens made by the lookup, getattr and readdir paths (tests only).
fn count_host_open() {
    #[cfg(test)]
    HOST_OPENS.with(|opens| opens.set(opens.get() + 1));
}

/// Tests take the path of readdir that reads identity per child on NTFS.
#[cfg(test)]
fn listing_ids_disabled() -> bool {
    LISTING_IDS_DISABLED.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn listing_ids_disabled() -> bool {
    false
}

/// Tests take the `read_dir` fallback for filesystems without batched listings.
#[cfg(test)]
fn listing_class_unsupported() -> bool {
    LISTING_CLASS_UNSUPPORTED.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn listing_class_unsupported() -> bool {
    false
}

/// Count bulk directory enumeration calls (tests only).
fn count_host_enumeration() {
    #[cfg(test)]
    HOST_ENUMERATIONS.with(|calls| calls.set(calls.get() + 1));
}

#[cfg(test)]
fn host_enumerations() -> u64 {
    HOST_ENUMERATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn host_opens() -> u64 {
    HOST_OPENS.with(std::cell::Cell::get)
}

fn reject_reparse_metadata(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(linux_error(LINUX_ELOOP))
    } else {
        Ok(())
    }
}

fn open_options_from_flags(flags: u32, create: bool) -> io::Result<StdOpenOptions> {
    let flags = flags as i32;
    if flags & LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }
    if !create && flags & (LINUX_O_CREAT | LINUX_O_EXCL) != 0 {
        return Err(linux_error(LINUX_EINVAL));
    }
    if flags & LINUX_O_DIRECTORY != 0 {
        return Err(linux_error(LINUX_EISDIR));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    let mut options = StdOpenOptions::new();
    match accmode {
        0 => {
            options.read(true);
        }
        LINUX_O_WRONLY => {
            options.write(true);
        }
        LINUX_O_RDWR => {
            options.read(true).write(true);
        }
        _ => return Err(linux_error(LINUX_EINVAL)),
    }

    if flags & LINUX_O_APPEND != 0 {
        options.append(true);
    }
    if flags & LINUX_O_TRUNC != 0 {
        if accmode == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        options.truncate(true);
    }
    if create {
        if flags & LINUX_O_EXCL != 0 {
            options.create_new(true);
        } else {
            options.create(true);
        }
    }
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);

    Ok(options)
}

fn open_flags_readable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == 0 || accmode == LINUX_O_RDWR
}

fn open_flags_writable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == LINUX_O_WRONLY || accmode == LINUX_O_RDWR || flags as i32 & LINUX_O_APPEND != 0
}

fn open_flags_write(flags: u32) -> bool {
    open_flags_writable(flags) || flags as i32 & (LINUX_O_TRUNC | LINUX_O_CREAT) != 0
}

fn stat_from_metadata(metadata: &std::fs::Metadata, data: &InodeData) -> stat64 {
    let mut st = host_stat_from_metadata(metadata, data.inode);
    let virtual_meta = data.virtual_meta.read().unwrap();
    st.st_uid = virtual_meta.uid;
    st.st_gid = virtual_meta.gid;
    st.st_mode = virtual_meta
        .mode
        .unwrap_or_else(|| mode_from_metadata(metadata));
    st.st_rdev = virtual_meta.rdev;
    st
}

fn host_stat_from_metadata(metadata: &std::fs::Metadata, inode: u64) -> stat64 {
    let (atime, atime_nsec) = filetime_to_unix(metadata.last_access_time());
    let (mtime, mtime_nsec) = filetime_to_unix(metadata.last_write_time());
    let (ctime, ctime_nsec) = filetime_to_unix(metadata.creation_time());

    stat64 {
        st_ino: inode,
        st_size: metadata.file_size() as i64,
        st_blocks: blocks_for_size(metadata.file_size()),
        st_atime: atime,
        st_mtime: mtime,
        st_ctime: ctime,
        st_atime_nsec: atime_nsec,
        st_mtime_nsec: mtime_nsec,
        st_ctime_nsec: ctime_nsec,
        st_mode: mode_from_metadata(metadata),
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_blksize: 4096,
    }
}

fn apply_override_stat(st: &mut stat64, override_stat: OverrideStat) {
    st.st_uid = override_stat.uid;
    st.st_gid = override_stat.gid;
    st.st_mode = override_stat.mode;
    st.st_rdev = u64::from(override_stat.rdev);
}

fn check_access(ctx: Context, st: &stat64, mask: u32) -> io::Result<()> {
    if mask == 0 {
        return Ok(());
    }

    let mode = st.st_mode;
    if ctx.uid == 0 {
        if mask & LINUX_ACCESS_X_OK != 0 && mode & 0o111 == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        return Ok(());
    }

    let bits = if st.st_uid == ctx.uid {
        (mode >> 6) & 0o7
    } else if st.st_gid == ctx.gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };

    if mask & LINUX_ACCESS_R_OK != 0 && bits & 0o4 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_W_OK != 0 && bits & 0o2 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_X_OK != 0 && bits & 0o1 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }

    Ok(())
}

fn build_file_times(attr: stat64, valid: SetattrValid) -> io::Result<FileTimes> {
    let mut times = FileTimes::new();
    if valid.contains(SetattrValid::ATIME_NOW) {
        times = times.set_accessed(SystemTime::now());
    } else if valid.contains(SetattrValid::ATIME) {
        times = times.set_accessed(system_time_from_unix(attr.st_atime, attr.st_atime_nsec)?);
    }

    if valid.contains(SetattrValid::MTIME_NOW) {
        times = times.set_modified(SystemTime::now());
    } else if valid.contains(SetattrValid::MTIME) {
        times = times.set_modified(system_time_from_unix(attr.st_mtime, attr.st_mtime_nsec)?);
    }

    Ok(times)
}

fn system_time_from_unix(seconds: i64, nanos: i64) -> io::Result<SystemTime> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(linux_error(LINUX_EINVAL));
    }

    Ok(UNIX_EPOCH + Duration::new(seconds as u64, nanos as u32))
}

fn apply_host_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path).map_err(host_error)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions).map_err(host_error)
}

fn mirror_eligible_type(file_type: u32) -> bool {
    file_type == S_IFREG || file_type == S_IFDIR
}

fn read_override_stream(path: &Path) -> io::Result<OverrideStat> {
    count_host_open();
    let mut file = StdOpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_stream(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let mut file = StdOpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    file.write_all(&override_stat.as_bytes())
        .map_err(host_error)?;
    file.sync_data().map_err(host_error)
}

fn read_override_sidecar_file(path: &Path) -> io::Result<OverrideStat> {
    count_host_open();
    let bytes = std::fs::read(path).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_sidecar_file(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
    std::fs::create_dir_all(parent).map_err(host_error)?;

    let mut temp = parent.to_path_buf();
    temp.push(format!("{}.tmp-{}", METADATA_STAT_NAME, unique_suffix()));
    {
        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temp)
            .map_err(host_error)?;
        file.write_all(&override_stat.as_bytes())
            .map_err(host_error)?;
        file.sync_data().map_err(host_error)?;
    }

    if path.exists() {
        std::fs::remove_file(path).map_err(host_error)?;
    }

    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(host_error(error));
    }

    Ok(())
}

fn ads_override_path(path: &Path) -> PathBuf {
    ads_stream_path(path, ADS_STREAM_NAME)
}

fn ads_probe_path(path: &Path) -> PathBuf {
    ads_stream_path(path, ADS_PROBE_STREAM_NAME)
}

/// Build an alternate-data-stream path without changing the base path.
///
/// Capability probes must use their own stream name: writing to the real
/// override stream would destroy persisted metadata for the mount root.
fn ads_stream_path(path: &Path, stream_name: &str) -> PathBuf {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    encoded.push(b':' as u16);
    encoded.extend(stream_name.encode_utf16());
    PathBuf::from(OsString::from_wide(&encoded))
}

fn encode_metadata_component(component: &std::ffi::OsStr) -> String {
    let mut encoded = String::new();
    for unit in component.encode_wide() {
        encoded.push(hex_digit(((unit >> 12) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 8) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 4) & 0xf) as u8));
        encoded.push(hex_digit((unit & 0xf) as u8));
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn init_entry(entry_timeout: Duration, attr_timeout: Duration) -> Entry {
    Entry {
        inode: INIT_INODE,
        generation: 0,
        attr: init_stat(),
        attr_flags: 0,
        attr_timeout,
        entry_timeout,
    }
}

fn init_stat() -> stat64 {
    stat64 {
        st_ino: INIT_INODE,
        st_size: agentd_bytes().len() as i64,
        st_blocks: blocks_for_size(agentd_bytes().len() as u64),
        st_mode: S_IFREG | 0o755,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn mode_from_metadata(metadata: &std::fs::Metadata) -> u32 {
    let type_bits = if metadata.file_type().is_dir() {
        S_IFDIR
    } else if metadata.file_type().is_file() {
        S_IFREG
    } else {
        0
    };

    // NTFS has no Unix execute bit, so synthesize a default mode for files
    // that have no virtual override yet. Default to executable (matching
    // libkrun's own Windows fs passthrough and WSL DrvFs's no-metadata
    // behavior) so binaries on a bind mount or bind rootfs can run: without
    // this, every host file is exposed as 0o666 and the guest cannot exec
    // anything before it has a chance to chmod it. Precise per-file modes
    // still come from the virtual stat store once the guest sets them.
    let perms = if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        0o555
    } else {
        0o777
    };
    type_bits | perms
}

fn dirent_type_from_mode(mode: u32) -> u32 {
    match mode & S_IFMT {
        S_IFIFO => DT_FIFO,
        S_IFCHR => DT_CHR,
        S_IFDIR => DT_DIR,
        S_IFBLK => DT_BLK,
        S_IFREG => DT_REG,
        S_IFLNK => DT_LNK,
        S_IFSOCK => DT_SOCK,
        _ => DT_UNKNOWN,
    }
}

fn blocks_for_size(size: u64) -> i64 {
    size.div_ceil(512).try_into().unwrap_or(i64::MAX)
}

fn filetime_to_unix(filetime: u64) -> (i64, i64) {
    let seconds = filetime / WINDOWS_TICKS_PER_SECOND;
    if seconds < WINDOWS_TO_UNIX_EPOCH_SECONDS {
        return (0, 0);
    }

    let unix_seconds = seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS;
    let nanos = (filetime % WINDOWS_TICKS_PER_SECOND) * 100;
    (
        unix_seconds.try_into().unwrap_or(i64::MAX),
        nanos.try_into().unwrap_or(i64::MAX),
    )
}

fn leak_name(name: &[u8]) -> &'static [u8] {
    Box::leak(name.to_vec().into_boxed_slice())
}

fn host_error(error: io::Error) -> io::Error {
    let errno = match error.raw_os_error() {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => LINUX_ENOENT,
        Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD) => LINUX_EACCES,
        Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => LINUX_EEXIST,
        Some(ERROR_DIR_NOT_EMPTY) => LINUX_ENOTEMPTY,
        Some(ERROR_SHARING_VIOLATION) => LINUX_EBUSY,
        Some(ERROR_INVALID_NAME) => LINUX_EINVAL,
        Some(ERROR_NOT_SAME_DEVICE) => LINUX_EXDEV,
        _ => match error.kind() {
            io::ErrorKind::NotFound => LINUX_ENOENT,
            io::ErrorKind::PermissionDenied => LINUX_EACCES,
            io::ErrorKind::AlreadyExists => LINUX_EEXIST,
            io::ErrorKind::InvalidInput => LINUX_EINVAL,
            io::ErrorKind::Unsupported => LINUX_EOPNOTSUPP,
            _ => LINUX_EIO,
        },
    };

    linux_error(errno)
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
