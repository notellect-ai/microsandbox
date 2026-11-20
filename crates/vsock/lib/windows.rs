use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use msb_krun::backends::vsock::{
    VsockConnectRequest, VsockConnectState, VsockNotifier, VsockPortBackend, VsockShutdown,
    VsockStreamBackend,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};

use crate::common::{DEFAULT_MAX_ACTIVE_PEERS, PeerLease, PeerLimit};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_BUFFERED_BYTES: usize = 8 * 1024 * 1024;
const IO_CHUNK_SIZE: usize = 64 * 1024;
const PIPE_BUSY_WAIT_MS: u32 = 50;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Factory that connects guest streams to one existing local Windows named pipe.
pub struct WindowsNamedPipePortBackend {
    path: PathBuf,
    peers: PeerLimit,
}

struct WindowsNamedPipeBackend {
    shared: Arc<SharedState>,
    _lease: PeerLease,
}

struct SharedState {
    state: Mutex<PipeState>,
    /// Auto-reset event the worker waits on next to its pipe I/O: set when
    /// the guest queues bytes, frees read space, shuts down or drops.
    wake_worker: Event,
    notifier: VsockNotifier,
}

struct PipeState {
    connection: ConnectionState,
    incoming: VecDeque<u8>,
    outgoing: VecDeque<u8>,
    read_shutdown: bool,
    write_shutdown: bool,
    terminate: bool,
}

enum ConnectionState {
    Connecting,
    Connected,
    Failed(StoredError),
}

#[derive(Clone)]
struct StoredError {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

struct PipeHandle(HANDLE);

// Windows named-pipe handles are process-wide opaque values and all access to
// this one is confined to its worker thread.
unsafe impl Send for PipeHandle {}

struct Event(HANDLE);

// Event handles may be set and waited on from any thread.
unsafe impl Send for Event {}
unsafe impl Sync for Event {}

/// One overlapped operation on the pipe: its OVERLAPPED and buffer stay put
/// (boxed) until the operation has completed or been cancelled and reaped.
struct PendingIo {
    overlapped: Box<OVERLAPPED>,
    event: Event,
    buffer: Vec<u8>,
    pending: bool,
}

/// What ended the wait for an overlapped operation.
enum IoWait {
    Completed(io::Result<usize>),
    Terminated,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsNamedPipePortBackend {
    /// Create a route to an existing local `\\.\pipe\...` named pipe.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_max_active_peers(path, DEFAULT_MAX_ACTIVE_PEERS)
    }

    /// Create a route with an explicit cap on active guest connections.
    pub fn with_max_active_peers(path: impl AsRef<Path>, max: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        validate_named_pipe_path(&path)?;
        if max == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vsock stream peer limit must be non-zero",
            ));
        }
        Ok(Self {
            path,
            peers: PeerLimit::new(max),
        })
    }
}

impl StoredError {
    fn capture(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        self.raw_os_error
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::new(self.kind, self.message.clone()))
    }
}

impl SharedState {
    fn fail(&self, error: io::Error) {
        let mut state = self.state.lock().unwrap();
        state.connection = ConnectionState::Failed(StoredError::capture(error));
        state.read_shutdown = true;
        state.write_shutdown = true;
        drop(state);
        let _ = self.notifier.notify();
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.read_shutdown = true;
        state.write_shutdown = true;
        drop(state);
        let _ = self.notifier.notify();
    }

    fn terminating(&self) -> bool {
        self.state.lock().unwrap().terminate
    }
}

impl PipeHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Event {
    fn new(manual_reset: bool) -> io::Result<Self> {
        let handle =
            unsafe { CreateEventW(std::ptr::null(), manual_reset as i32, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn set(&self) {
        unsafe {
            SetEvent(self.0);
        }
    }
}

impl PendingIo {
    fn new(capacity: usize) -> io::Result<Self> {
        Ok(Self {
            overlapped: Box::new(unsafe { std::mem::zeroed() }),
            event: Event::new(true)?,
            buffer: vec![0; capacity],
            pending: false,
        })
    }

    /// Start a read of up to `count` bytes into the buffer.
    fn start_read(&mut self, pipe: &PipeHandle, count: usize) -> io::Result<()> {
        self.prepare();
        let started = unsafe {
            ReadFile(
                pipe.raw(),
                self.buffer.as_mut_ptr(),
                count.min(self.buffer.len()) as u32,
                std::ptr::null_mut(),
                &mut *self.overlapped,
            )
        };
        self.started(started)
    }

    /// Start a write of `bytes`, which the buffer keeps until it completes.
    fn start_write(&mut self, pipe: &PipeHandle, bytes: Vec<u8>) -> io::Result<()> {
        self.prepare();
        self.buffer = bytes;
        let started = unsafe {
            WriteFile(
                pipe.raw(),
                self.buffer.as_ptr(),
                self.buffer.len() as u32,
                std::ptr::null_mut(),
                &mut *self.overlapped,
            )
        };
        self.started(started)
    }

    fn prepare(&mut self) {
        debug_assert!(!self.pending);
        *self.overlapped = unsafe { std::mem::zeroed() };
        self.overlapped.hEvent = self.event.0;
    }

    fn started(&mut self, started: i32) -> io::Result<()> {
        // Success and ERROR_IO_PENDING both complete through the event.
        if started == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        self.pending = true;
        Ok(())
    }

    /// The finished operation's byte count, once its event is set.
    fn finish(&mut self, pipe: &PipeHandle) -> io::Result<usize> {
        let mut transferred = 0;
        let ok =
            unsafe { GetOverlappedResult(pipe.raw(), &*self.overlapped, &mut transferred, 0) };
        self.pending = false;
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
                return Ok(transferred as usize);
            }
            return Err(error);
        }
        Ok(transferred as usize)
    }

    /// Cancel the operation if it is still running and wait until the
    /// system no longer uses its OVERLAPPED and buffer.
    fn cancel(&mut self, pipe: &PipeHandle) {
        if !self.pending {
            return;
        }
        let mut transferred = 0;
        unsafe {
            CancelIoEx(pipe.raw(), &*self.overlapped);
            GetOverlappedResult(pipe.raw(), &*self.overlapped, &mut transferred, 1);
        }
        self.pending = false;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VsockPortBackend for WindowsNamedPipePortBackend {
    fn connect(
        &self,
        _request: VsockConnectRequest,
        notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockStreamBackend>> {
        let lease = self.peers.acquire()?;
        let shared = Arc::new(SharedState {
            state: Mutex::new(PipeState {
                connection: ConnectionState::Connecting,
                incoming: VecDeque::new(),
                outgoing: VecDeque::new(),
                read_shutdown: false,
                write_shutdown: false,
                terminate: false,
            }),
            wake_worker: Event::new(false)?,
            notifier,
        });
        let worker_shared = Arc::clone(&shared);
        let path = self.path.clone();
        std::thread::Builder::new()
            .name("vsock named pipe".to_string())
            .spawn(move || named_pipe_worker(path, worker_shared))?;

        Ok(Box::new(WindowsNamedPipeBackend {
            shared,
            _lease: lease,
        }))
    }
}

impl VsockStreamBackend for WindowsNamedPipeBackend {
    fn connect_state(&self) -> io::Result<VsockConnectState> {
        match &self.shared.state.lock().unwrap().connection {
            ConnectionState::Connecting => Ok(VsockConnectState::Connecting),
            ConnectionState::Connected => Ok(VsockConnectState::Connected),
            ConnectionState::Failed(error) => Err(error.to_io_error()),
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock().unwrap();
        if let ConnectionState::Failed(error) = &state.connection {
            return Err(error.to_io_error());
        }
        if state.incoming.is_empty() {
            return if state.read_shutdown {
                Ok(0)
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            };
        }

        let count = buf.len().min(state.incoming.len());
        for slot in &mut buf[..count] {
            *slot = state.incoming.pop_front().unwrap();
        }
        drop(state);
        self.shared.wake_worker.set();
        Ok(count)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock().unwrap();
        if let ConnectionState::Failed(error) = &state.connection {
            return Err(error.to_io_error());
        }
        if state.write_shutdown {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if !matches!(state.connection, ConnectionState::Connected) {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let count = buf
            .len()
            .min(MAX_BUFFERED_BYTES.saturating_sub(state.outgoing.len()));
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        state.outgoing.extend(&buf[..count]);
        drop(state);
        self.shared.wake_worker.set();
        Ok(count)
    }

    fn shutdown(&self, how: VsockShutdown) -> io::Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match how {
            VsockShutdown::Read => state.read_shutdown = true,
            VsockShutdown::Write => state.write_shutdown = true,
            VsockShutdown::Both => {
                state.read_shutdown = true;
                state.write_shutdown = true;
                state.terminate = true;
            }
        }
        drop(state);
        // A terminating worker cancels its own pending pipe I/O.
        self.shared.wake_worker.set();
        Ok(())
    }
}

impl Drop for WindowsNamedPipeBackend {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().terminate = true;
        // A named-pipe server can stop reading indefinitely. The worker waits
        // on its overlapped I/O and this event together, so it wakes, cancels
        // that I/O and exits: dropping a guest connection cannot strand a
        // thread outside the peer limit.
        self.shared.wake_worker.set();
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_named_pipe_path(path: &Path) -> io::Result<()> {
    let text = path.as_os_str().to_string_lossy();
    let Some(name) = text.get(LOCAL_PIPE_PREFIX.len()..) else {
        return Err(invalid_pipe_path());
    };
    if !text[..LOCAL_PIPE_PREFIX.len()].eq_ignore_ascii_case(LOCAL_PIPE_PREFIX)
        || name.is_empty()
        || name
            .split(['\\', '/'])
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid_pipe_path());
    }
    Ok(())
}

fn invalid_pipe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        r"vsock host path must be a local Windows named pipe such as \\.\pipe\api",
    )
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn connect_named_pipe(path: &Path, shared: &SharedState) -> io::Result<PipeHandle> {
    let path = wide_null(path.as_os_str());
    loop {
        if shared.terminating() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "vsock named-pipe connection was cancelled",
            ));
        }

        // Overlapped, so a read can wait for the Host while writes still go
        // out: synchronous I/O on one handle is serialized by Windows.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(PipeHandle(handle));
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        unsafe {
            WaitNamedPipeW(path.as_ptr(), PIPE_BUSY_WAIT_MS);
        }
    }
}

/// Whether a pipe error means the Host closed its end (end of stream).
fn is_pipe_closed(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_PIPE_NOT_CONNECTED as i32
    )
}

/// Wait until the operation's event or the wake event is set. Returns
/// whether the operation's event was the one set.
fn wait_for(io: &PendingIo, wake: &Event) -> io::Result<bool> {
    let handles = [io.event.0, wake.0];
    let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
    if result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(result == WAIT_OBJECT_0)
}

/// Write all of `bytes`, waiting on the write and the wake event together
/// so a terminating guest connection stops a write the Host never reads.
fn write_all(
    pipe: &PipeHandle,
    write: &mut PendingIo,
    bytes: Vec<u8>,
    shared: &SharedState,
) -> IoWait {
    let length = bytes.len();
    if let Err(error) = write.start_write(pipe, bytes) {
        return IoWait::Completed(Err(error));
    }
    loop {
        match wait_for(write, &shared.wake_worker) {
            Ok(true) => {
                return IoWait::Completed(write.finish(pipe).and_then(|written| {
                    if written == length {
                        Ok(written)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Windows named pipe accepted only part of a stream write",
                        ))
                    }
                }));
            }
            Ok(false) if shared.terminating() => {
                write.cancel(pipe);
                return IoWait::Terminated;
            }
            // Other guest activity: the main loop rereads all state once
            // this write is done, so the wake needs no keeping.
            Ok(false) => {}
            Err(error) => {
                write.cancel(pipe);
                return IoWait::Completed(Err(error));
            }
        }
    }
}

fn named_pipe_worker(path: PathBuf, shared: Arc<SharedState>) {
    let handle = match connect_named_pipe(&path, &shared) {
        Ok(handle) => handle,
        Err(error) => {
            shared.fail(error);
            return;
        }
    };
    let (mut read, mut write) = match (PendingIo::new(IO_CHUNK_SIZE), PendingIo::new(0)) {
        (Ok(read), Ok(write)) => (read, write),
        (Err(error), _) | (_, Err(error)) => {
            shared.fail(error);
            return;
        }
    };
    {
        let mut state = shared.state.lock().unwrap();
        if state.terminate {
            return;
        }
        state.connection = ConnectionState::Connected;
    }
    let _ = shared.notifier.notify();

    pump(&handle, &mut read, &mut write, &shared);
    // Nothing may outlive the worker that still writes into its buffers.
    read.cancel(&handle);
    write.cancel(&handle);
}

/// Move bytes both ways until the connection ends: guest bytes are written
/// as they are queued, and a read is always pending while there is room, so
/// Host bytes reach the guest as soon as they arrive.
fn pump(handle: &PipeHandle, read: &mut PendingIo, write: &mut PendingIo, shared: &SharedState) {
    loop {
        let (outgoing, read_capacity) = {
            let mut state = shared.state.lock().unwrap();
            if state.terminate {
                return;
            }
            let count = state.outgoing.len().min(IO_CHUNK_SIZE);
            let bytes = state.outgoing.drain(..count).collect::<Vec<_>>();
            let capacity = if state.read_shutdown {
                0
            } else {
                MAX_BUFFERED_BYTES.saturating_sub(state.incoming.len())
            };
            (bytes, capacity)
        };

        if !outgoing.is_empty() {
            match write_all(handle, write, outgoing, shared) {
                IoWait::Completed(Ok(_)) => {
                    let _ = shared.notifier.notify();
                }
                IoWait::Completed(Err(error)) => {
                    shared.fail(error);
                    return;
                }
                IoWait::Terminated => return,
            }
        }

        if !read.pending
            && read_capacity > 0
            && let Err(error) = read.start_read(handle, read_capacity.min(IO_CHUNK_SIZE))
        {
            if is_pipe_closed(&error) {
                shared.close();
            } else {
                shared.fail(error);
            }
            return;
        }

        // More guest bytes are queued: write them before waiting.
        if !shared.state.lock().unwrap().outgoing.is_empty() {
            if read.pending && read_ready(read) && !deliver(handle, read, shared) {
                return;
            }
            continue;
        }

        if read.pending {
            match wait_for(read, &shared.wake_worker) {
                Ok(true) => {
                    if !deliver(handle, read, shared) {
                        return;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    shared.fail(error);
                    return;
                }
            }
        } else {
            // No room to read until the guest consumes bytes: wait for it.
            unsafe { WaitForMultipleObjects(1, &shared.wake_worker.0, 0, INFINITE) };
        }
    }
}

/// Whether a pending read has completed, without waiting.
fn read_ready(read: &PendingIo) -> bool {
    unsafe { WaitForMultipleObjects(1, &read.event.0, 0, 0) == WAIT_OBJECT_0 }
}

/// Hand a completed read's bytes to the guest. Returns false when the
/// connection has ended.
fn deliver(handle: &PipeHandle, read: &mut PendingIo, shared: &SharedState) -> bool {
    match read.finish(handle) {
        Ok(count) => {
            if count > 0 {
                shared
                    .state
                    .lock()
                    .unwrap()
                    .incoming
                    .extend(&read.buffer[..count]);
                let _ = shared.notifier.notify();
            }
            true
        }
        Err(error) if is_pipe_closed(&error) => {
            shared.close();
            false
        }
        Err(error) => {
            shared.fail(error);
            false
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use super::*;

    #[test]
    fn rejects_remote_and_ambiguous_pipe_paths() {
        assert!(validate_named_pipe_path(Path::new(r"\\.\pipe\api")).is_ok());
        assert!(validate_named_pipe_path(Path::new(r"\\server\pipe\api")).is_err());
        assert!(validate_named_pipe_path(Path::new(r"\\.\pipe\..\api")).is_err());
        assert!(validate_named_pipe_path(Path::new(r"C:\api")).is_err());
    }

    #[test]
    fn named_pipe_backend_moves_stream_bytes_in_both_directions() {
        let name = format!(r"\\.\pipe\msb-vsock-test-{}", std::process::id());
        let wide = wide_null(OsStr::new(&name));
        let server = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        let server = PipeHandle(server);
        let host = std::thread::spawn(move || {
            let connected = unsafe { ConnectNamedPipe(server.raw(), std::ptr::null_mut()) };
            if connected == 0 {
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(ERROR_PIPE_CONNECTED as i32)
                );
            }

            let mut request = [0_u8; 5];
            let mut read = 0;
            assert_ne!(
                unsafe {
                    ReadFile(
                        server.raw(),
                        request.as_mut_ptr(),
                        request.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(&request[..read as usize], b"guest");

            let mut written = 0;
            assert_ne!(
                unsafe {
                    WriteFile(
                        server.raw(),
                        b"host".as_ptr(),
                        4,
                        &mut written,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(written, 4);
        });

        let service = WindowsNamedPipePortBackend::new(&name).unwrap();
        let endpoint = service
            .connect(
                VsockConnectRequest {
                    guest_cid: 3,
                    guest_port: 4000,
                    host_port: 5000,
                },
                VsockNotifier::new().unwrap(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while endpoint.connect_state().unwrap() != VsockConnectState::Connected {
            assert!(Instant::now() < deadline, "named-pipe connect timed out");
            std::thread::yield_now();
        }
        assert_eq!(endpoint.write(b"guest").unwrap(), 5);

        let mut response = [0_u8; 4];
        loop {
            match endpoint.read(&mut response) {
                Ok(4) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "named-pipe read timed out");
                    std::thread::yield_now();
                }
                result => panic!("unexpected named-pipe read result: {result:?}"),
            }
        }
        assert_eq!(&response, b"host");
        host.join().unwrap();
    }

    //----------------------------------------------------------------------------------------------
    // Hostile cases for the overlapped relay
    //----------------------------------------------------------------------------------------------

    const DEADLINE: Duration = Duration::from_secs(10);

    fn pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\msb-vsock-test-{}-{tag}", std::process::id())
    }

    /// A Host end with small buffers, so streams split across reads.
    fn host_pipe(name: &str) -> PipeHandle {
        let wide = wide_null(OsStr::new(name));
        let server = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        PipeHandle(server)
    }

    fn host_accept(server: &PipeHandle) {
        if unsafe { ConnectNamedPipe(server.raw(), std::ptr::null_mut()) } == 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(ERROR_PIPE_CONNECTED as i32)
            );
        }
    }

    fn host_read(server: &PipeHandle, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        let ok = unsafe {
            ReadFile(
                server.raw(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }

    fn host_read_exact(server: &PipeHandle, count: usize) -> Vec<u8> {
        let mut out = vec![0; count];
        let mut filled = 0;
        while filled < count {
            let read = host_read(server, &mut out[filled..]).unwrap();
            assert!(read > 0);
            filled += read;
        }
        out
    }

    fn host_write_all(server: &PipeHandle, bytes: &[u8]) {
        let mut written = 0;
        assert_ne!(
            unsafe {
                WriteFile(
                    server.raw(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(written as usize, bytes.len());
    }

    fn guest_connect(name: &str) -> Box<dyn VsockStreamBackend> {
        let endpoint = WindowsNamedPipePortBackend::new(name)
            .unwrap()
            .connect(
                VsockConnectRequest {
                    guest_cid: 3,
                    guest_port: 4000,
                    host_port: 5000,
                },
                VsockNotifier::new().unwrap(),
            )
            .unwrap();
        let deadline = Instant::now() + DEADLINE;
        while endpoint.connect_state().unwrap() != VsockConnectState::Connected {
            assert!(Instant::now() < deadline, "named-pipe connect timed out");
            std::thread::yield_now();
        }
        endpoint
    }

    fn guest_write_all(endpoint: &dyn VsockStreamBackend, mut bytes: &[u8]) {
        let deadline = Instant::now() + DEADLINE;
        while !bytes.is_empty() {
            match endpoint.write(bytes) {
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "guest write timed out");
                    std::thread::yield_now();
                }
                Err(error) => panic!("guest write failed: {error}"),
            }
        }
    }

    /// Read until `count` bytes or end of stream.
    fn guest_read_up_to(endpoint: &dyn VsockStreamBackend, count: usize) -> Vec<u8> {
        let deadline = Instant::now() + DEADLINE;
        let mut out = Vec::with_capacity(count);
        let mut chunk = vec![0; 70_000];
        while out.len() < count {
            let want = (count - out.len()).min(chunk.len());
            match endpoint.read(&mut chunk[..want]) {
                Ok(0) => break,
                Ok(read) => out.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "guest read timed out");
                    std::thread::yield_now();
                }
                Err(error) => panic!("guest read failed: {error}"),
            }
        }
        out
    }

    fn pattern(length: usize, seed: u8) -> Vec<u8> {
        (0..length).map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    /// Run `host` on its own thread and wait at most DEADLINE for it, so a
    /// relay that never lets go of the pipe fails instead of hanging.
    fn within_deadline<T: Send + 'static>(host: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(host());
        });
        receiver
            .recv_timeout(DEADLINE)
            .expect("Host end did not finish in time")
    }

    #[test]
    fn host_replies_reach_the_guest_without_a_polling_interval() {
        let name = pipe_name("latency");
        let server = host_pipe(&name);
        const ROUNDS: usize = 200;
        let host = std::thread::spawn(move || {
            host_accept(&server);
            let mut request = [0_u8; 8];
            for _ in 0..ROUNDS {
                let mut filled = 0;
                while filled < request.len() {
                    filled += host_read(&server, &mut request[filled..]).unwrap();
                }
                host_write_all(&server, &request);
            }
        });
        let endpoint = guest_connect(&name);
        let started = Instant::now();
        for round in 0..ROUNDS {
            let request = (round as u64).to_le_bytes();
            guest_write_all(&*endpoint, &request);
            assert_eq!(guest_read_up_to(&*endpoint, 8), request);
        }
        let average = started.elapsed() / ROUNDS as u32;
        host.join().unwrap();
        // The polling relay took one Windows timer tick (about 15.6 ms) per
        // reply; a blocking read takes well under a millisecond.
        assert!(
            average < Duration::from_millis(3),
            "average round trip {average:?}"
        );
    }

    #[test]
    fn streams_larger_than_a_read_arrive_whole_and_in_order() {
        let name = pipe_name("large");
        let server = host_pipe(&name);
        const LENGTH: usize = 300_000;
        let host = std::thread::spawn(move || {
            host_accept(&server);
            assert_eq!(host_read_exact(&server, LENGTH), pattern(LENGTH, 1));
            host_write_all(&server, &pattern(LENGTH, 2));
        });
        let endpoint = guest_connect(&name);
        guest_write_all(&*endpoint, &pattern(LENGTH, 1));
        assert_eq!(guest_read_up_to(&*endpoint, LENGTH), pattern(LENGTH, 2));
        host.join().unwrap();
    }

    #[test]
    fn host_closing_mid_stream_ends_the_stream_after_its_bytes() {
        let name = pipe_name("hostclose");
        let server = host_pipe(&name);
        let host = std::thread::spawn(move || {
            host_accept(&server);
            host_write_all(&server, b"partial reply");
            // The Host goes away in the middle of a reply.
            drop(server);
        });
        let endpoint = guest_connect(&name);
        host.join().unwrap();
        assert_eq!(guest_read_up_to(&*endpoint, 1 << 20), b"partial reply");
        let deadline = Instant::now() + DEADLINE;
        loop {
            match endpoint.write(b"more") {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline);
                    std::thread::yield_now();
                }
                Err(_) => break,
                Ok(_) => {
                    assert!(Instant::now() < deadline, "writes to a closed Host kept succeeding");
                    std::thread::yield_now();
                }
            }
        }
    }

    #[test]
    fn dropping_the_guest_end_during_a_pending_read_releases_the_pipe() {
        let name = pipe_name("dropread");
        let server = host_pipe(&name);
        let accepted = Arc::new(std::sync::Barrier::new(2));
        let host_accepted = Arc::clone(&accepted);
        let host = std::thread::spawn(move || {
            host_accept(&server);
            host_accepted.wait();
            server
        });
        let endpoint = guest_connect(&name);
        accepted.wait();
        let server = host.join().unwrap();
        // The relay's read is pending: the Host has written nothing.
        std::thread::sleep(Duration::from_millis(50));
        drop(endpoint);
        let result = within_deadline(move || host_read(&server, &mut [0_u8; 16]));
        assert!(result.is_err(), "the relay kept its pipe end open: {result:?}");
    }

    #[test]
    fn dropping_the_guest_end_during_a_blocked_write_releases_the_pipe() {
        let name = pipe_name("dropwrite");
        let server = host_pipe(&name);
        let accepted = Arc::new(std::sync::Barrier::new(2));
        let host_accepted = Arc::clone(&accepted);
        let host = std::thread::spawn(move || {
            host_accept(&server);
            host_accepted.wait();
            server
        });
        let endpoint = guest_connect(&name);
        accepted.wait();
        let server = host.join().unwrap();
        // Far more than the pipe buffers while the Host reads nothing, so the
        // relay's write cannot complete.
        guest_write_all(&*endpoint, &pattern(1 << 20, 3));
        std::thread::sleep(Duration::from_millis(100));
        drop(endpoint);
        let drained = within_deadline(move || {
            let mut buf = vec![0_u8; 65_536];
            let mut total = 0;
            loop {
                match host_read(&server, &mut buf) {
                    Ok(read) => total += read,
                    Err(error) => return (total, error),
                }
            }
        });
        assert!(drained.0 < 1 << 20, "the whole write went through: {drained:?}");
    }

    #[test]
    fn many_concurrent_connections_each_keep_their_own_stream() {
        let name = pipe_name("many");
        const CONNECTIONS: usize = 32;
        let hosts = (0..CONNECTIONS)
            .map(|_| {
                let server = host_pipe(&name);
                std::thread::spawn(move || {
                    host_accept(&server);
                    let mut header = host_read_exact(&server, 1);
                    let body = host_read_exact(&server, 20_000);
                    assert_eq!(body, pattern(20_000, header[0]));
                    header.extend(pattern(20_000, header[0].wrapping_add(1)));
                    host_write_all(&server, &header);
                })
            })
            .collect::<Vec<_>>();
        let guests = (0..CONNECTIONS)
            .map(|index| {
                let name = name.clone();
                std::thread::spawn(move || {
                    let endpoint = guest_connect(&name);
                    let seed = index as u8;
                    guest_write_all(&*endpoint, &[seed]);
                    guest_write_all(&*endpoint, &pattern(20_000, seed));
                    let reply = guest_read_up_to(&*endpoint, 20_001);
                    assert_eq!(reply[0], seed);
                    assert_eq!(&reply[1..], pattern(20_000, seed.wrapping_add(1)));
                })
            })
            .collect::<Vec<_>>();
        for guest in guests {
            guest.join().unwrap();
        }
        for host in hosts {
            host.join().unwrap();
        }
    }
}
