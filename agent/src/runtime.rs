//! Private runtime-directory and key-load FIFO creation.

use rustix::fs::{self, FlockOperation, Mode, OFlags, CWD};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use crate::keystore::MAX_FILTERED_BYTES;
use crate::load::PayloadFilter;

const RUNTIME_NAME: &str = "qs-bitwarden-cli";
const FIFO_NAME: &str = "ssh-keys.fifo";
const LOCK_NAME: &str = "ssh-agent.lock";
const SOCKET_NAME: &str = "ssh-agent.sock";

/// Sanitized runtime setup failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Io,
    UnsafeDirectory,
    UnsafeFifo,
    UnsafeLock,
    UnsafeSocket,
    AlreadyRunning,
    ReadTimeout,
}

/// Open private runtime paths. The FIFO stays open read/write so writers never
/// see EOF or SIGPIPE between loads.
pub struct Runtime {
    directory: PathBuf,
    fifo_path: PathBuf,
    fifo: File,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime { verified private paths }")
    }
}

/// Bytes read from the FIFO at a time.
const CHUNK_BYTES: usize = 8192;

/// Splits the FIFO stream into newline-terminated lines and keeps the first
/// one the load's filter accepts. Every other line is wiped and dropped, so a
/// payload left over from an earlier load can never be taken for this one.
/// A line past the payload cap is dropped up to its newline rather than
/// failing the load: it cannot be this load's (`decode` would refuse it), and
/// the load's own payload may still follow it.
struct PayloadAccumulator {
    filter: PayloadFilter,
    line: Zeroizing<Vec<u8>>,
    /// Inside a line already past the cap: skip to its newline.
    oversized: bool,
}

impl PayloadAccumulator {
    fn new(filter: PayloadFilter) -> Self {
        Self {
            filter,
            line: Zeroizing::new(Vec::new()),
            oversized: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        // Only the new bytes are searched for a newline. Rescanning the whole
        // line on every chunk made an 8 MiB stream quadratic, slow enough in a
        // debug build to miss a 30 s deadline.
        let mut rest = chunk;
        while !rest.is_empty() {
            let (part, ends_line) = match rest.iter().position(|byte| *byte == b'\n') {
                Some(newline) => (&rest[..newline], true),
                None => (rest, false),
            };
            rest = if ends_line {
                &rest[part.len() + 1..]
            } else {
                &[]
            };
            if !self.oversized {
                if self.line.len() + part.len() > MAX_FILTERED_BYTES {
                    self.line.zeroize();
                    self.oversized = true;
                } else {
                    extend_wiping(&mut self.line, part);
                }
            }
            if ends_line {
                let start = if self.oversized {
                    None
                } else {
                    self.filter.locate(&self.line)
                };
                if let Some(start) = start {
                    // An exact-size copy, so no spare capacity holds a key.
                    let payload = Zeroizing::new(self.line[start..].to_vec());
                    self.line.zeroize();
                    return Some(payload);
                }
                self.line.zeroize();
                self.oversized = false;
            }
        }
        None
    }
}

/// Append without letting `Vec` grow in place: a reallocation frees the old
/// buffer unwiped, which would leave copies of private keys in freed memory.
/// The old buffer is a `Zeroizing` and is wiped as it is replaced.
fn extend_wiping(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buffer.len() + bytes.len();
    if needed > buffer.capacity() {
        let capacity = needed.max(buffer.capacity().saturating_mul(2).min(MAX_FILTERED_BYTES));
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(bytes);
}

impl Runtime {
    /// Create a fresh FIFO under `runtime_root`, refusing any existing path and
    /// any directory that is not a same-owner real 0700 directory.
    pub fn create(runtime_root: &Path) -> Result<Self, RuntimeError> {
        let directory = ensure_runtime_directory(runtime_root)?;
        Self::create_in(directory)
    }

    fn create_in(directory: PathBuf) -> Result<Self, RuntimeError> {
        let fifo_path = directory.join(FIFO_NAME);
        if std::fs::symlink_metadata(&fifo_path).is_ok() {
            return Err(RuntimeError::UnsafeFifo);
        }
        fs::mkfifoat(CWD, &fifo_path, Mode::RUSR | Mode::WUSR).map_err(|_| RuntimeError::Io)?;
        let fd = fs::open(
            &fifo_path,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RuntimeError::UnsafeFifo)?;
        let fifo = File::from(fd);
        let metadata = fifo.metadata().map_err(|_| RuntimeError::Io)?;
        if !metadata.file_type().is_fifo()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(RuntimeError::UnsafeFifo);
        }
        Ok(Self {
            directory,
            fifo_path,
            fifo,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn fifo_path(&self) -> &Path {
        &self.fifo_path
    }

    pub fn fifo(&self) -> &File {
        &self.fifo
    }

    pub fn fifo_reader(&self) -> Result<File, RuntimeError> {
        self.fifo.try_clone().map_err(|_| RuntimeError::Io)
    }

    /// Read until this load's newline-delimited `jq -c` payload arrives,
    /// under hard byte/time bounds; other lines are dropped (see
    /// `PayloadAccumulator`).
    pub fn read_payload(
        &mut self,
        timeout: Duration,
        filter: &PayloadFilter,
    ) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
        let deadline = Instant::now() + timeout;
        let mut accumulator = PayloadAccumulator::new(filter.clone());
        let mut chunk = Zeroizing::new([0_u8; CHUNK_BYTES]);
        loop {
            let idle = match self.fifo.read(&mut chunk[..]) {
                Ok(0) => true,
                Ok(count) => match accumulator.push(&chunk[..count]) {
                    Some(payload) => return Ok(payload),
                    None => false,
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(_) => return Err(RuntimeError::Io),
            };
            if Instant::now() >= deadline {
                return Err(RuntimeError::ReadTimeout);
            }
            if idle {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Wipe whatever sits in the FIFO right now, without waiting. Run when no
    /// load is reading (a lock cancelled it, or it failed): anything buffered
    /// then belongs to no load, and it holds private keys. Bounded, so a
    /// writer that keeps writing cannot hold the control loop; what it writes
    /// later is dropped by the next load's filter instead.
    pub fn discard_buffered(&self) {
        let mut chunk = Zeroizing::new([0_u8; CHUNK_BYTES]);
        let mut discarded = 0_usize;
        while discarded <= MAX_FILTERED_BYTES {
            match (&self.fifo).read(&mut chunk[..]) {
                Ok(0) => break,
                Ok(count) => discarded += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                // WouldBlock: empty. The descriptor is non-blocking.
                Err(_) => break,
            }
        }
    }
}

/// Async FIFO read: `AsyncFd` waits without a blocking thread, so control
/// messages stay serviceable while a producer is slow. Returns the first line
/// `filter` accepts, as `Runtime::read_payload` does.
pub async fn read_payload_async(
    fifo: File,
    timeout: Duration,
    filter: PayloadFilter,
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let fifo = tokio::io::unix::AsyncFd::new(fifo).map_err(|_| RuntimeError::Io)?;
    tokio::time::timeout(timeout, async {
        let mut accumulator = PayloadAccumulator::new(filter);
        let mut chunk = Zeroizing::new([0_u8; CHUNK_BYTES]);
        loop {
            let mut ready = fifo.readable().await.map_err(|_| RuntimeError::Io)?;
            match ready.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut chunk[..])
            }) {
                // EOF: `try_io` only clears readiness on `WouldBlock`, so it
                // stays readable; pace the retry (as the blocking reader does)
                // instead of spinning until the timeout.
                Ok(Ok(0)) => tokio::time::sleep(Duration::from_millis(1)).await,
                Ok(Ok(count)) => {
                    if let Some(payload) = accumulator.push(&chunk[..count]) {
                        return Ok(payload);
                    }
                }
                Ok(Err(_)) => return Err(RuntimeError::Io),
                Err(_) => continue,
            }
        }
    })
    .await
    .map_err(|_| RuntimeError::ReadTimeout)?
}

/// Singleton runtime: the lock is taken before stale paths are touched, so two
/// companions cannot race a restart.
pub struct ServiceRuntime {
    runtime: Runtime,
    socket_path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
}

impl ServiceRuntime {
    pub fn acquire(runtime_root: &Path) -> Result<Self, RuntimeError> {
        let directory = ensure_runtime_directory(runtime_root)?;
        let lock_path = directory.join(LOCK_NAME);
        let lock = File::from(
            fs::open(
                &lock_path,
                OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| RuntimeError::UnsafeLock)?,
        );
        let metadata = lock.metadata().map_err(|_| RuntimeError::Io)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(RuntimeError::UnsafeLock);
        }
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| RuntimeError::AlreadyRunning)?;

        remove_stale(&directory.join(FIFO_NAME), StaleKind::Fifo)?;
        let socket_path = directory.join(SOCKET_NAME);
        remove_stale(&socket_path, StaleKind::Socket)?;
        let runtime = Runtime::create_in(directory)?;
        Ok(Self {
            runtime,
            socket_path,
            lock_path,
            _lock: lock,
        })
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn bind_socket(&self) -> Result<tokio::net::UnixListener, RuntimeError> {
        let listener = std::os::unix::net::UnixListener::bind(&self.socket_path)
            .map_err(|_| RuntimeError::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| RuntimeError::Io)?;
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| RuntimeError::Io)?;
        let metadata =
            std::fs::symlink_metadata(&self.socket_path).map_err(|_| RuntimeError::Io)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(RuntimeError::UnsafeSocket);
        }
        tokio::net::UnixListener::from_std(listener).map_err(|_| RuntimeError::Io)
    }
}

impl Drop for ServiceRuntime {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(self.runtime.fifo_path());
        let _ = std::fs::remove_file(&self.lock_path);
        let _ = std::fs::remove_dir(self.runtime.directory());
    }
}

fn ensure_runtime_directory(runtime_root: &Path) -> Result<PathBuf, RuntimeError> {
    let directory = runtime_root.join(RUNTIME_NAME);
    match std::fs::create_dir(&directory) {
        Ok(()) => std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| RuntimeError::Io)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(RuntimeError::Io),
    }
    let metadata = std::fs::symlink_metadata(&directory).map_err(|_| RuntimeError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(RuntimeError::UnsafeDirectory);
    }

    Ok(directory)
}

enum StaleKind {
    Fifo,
    Socket,
}

fn remove_stale(path: &Path, kind: StaleKind) -> Result<(), RuntimeError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RuntimeError::Io),
    };
    let expected = match kind {
        StaleKind::Fifo => metadata.file_type().is_fifo(),
        StaleKind::Socket => metadata.file_type().is_socket(),
    };
    if !expected
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(match kind {
            StaleKind::Fifo => RuntimeError::UnsafeFifo,
            StaleKind::Socket => RuntimeError::UnsafeSocket,
        });
    }
    std::fs::remove_file(path).map_err(|_| RuntimeError::Io)
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.fifo_path);
    }
}
