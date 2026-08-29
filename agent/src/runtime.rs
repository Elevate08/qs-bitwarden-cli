//! Private runtime-directory and key-load FIFO creation.

use rustix::fs::{self, FlockOperation, Mode, OFlags, CWD};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::keystore::MAX_FILTERED_BYTES;

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
    PayloadTooLarge,
    MultiplePayloads,
    ReadTimeout,
}

/// Open private runtime paths. The FIFO descriptor remains open read/write so
/// writers do not observe transient EOF or SIGPIPE between loads.
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

impl Runtime {
    /// Create a fresh FIFO below `runtime_root`, refusing every existing FIFO
    /// path and every directory that is not a same-owner real `0700` directory.
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

    /// Drain one newline-delimited `jq -c` payload under hard byte/time bounds.
    pub fn read_payload(&mut self, timeout: Duration) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
        let deadline = Instant::now() + timeout;
        let mut payload = Zeroizing::new(Vec::new());
        let mut chunk = [0_u8; 8192];
        loop {
            let idle = match self.fifo.read(&mut chunk) {
                Ok(0) => true,
                Ok(count) => {
                    payload.extend_from_slice(&chunk[..count]);
                    if payload.len() > MAX_FILTERED_BYTES + 1 {
                        return Err(RuntimeError::PayloadTooLarge);
                    }
                    if let Some(newline) = payload.iter().position(|byte| *byte == b'\n') {
                        if payload[newline + 1..]
                            .iter()
                            .any(|byte| !byte.is_ascii_whitespace())
                        {
                            return Err(RuntimeError::MultiplePayloads);
                        }
                        payload.truncate(newline);
                        return Ok(payload);
                    }
                    false
                }
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
}

/// Async FIFO drain used by the current-thread companion. `AsyncFd` waits for
/// readiness without a blocking worker thread, so control/lock messages remain
/// serviceable while a producer is slow.
pub async fn read_payload_async(
    fifo: File,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let fifo = tokio::io::unix::AsyncFd::new(fifo).map_err(|_| RuntimeError::Io)?;
    tokio::time::timeout(timeout, async {
        let mut payload = Zeroizing::new(Vec::new());
        let mut chunk = [0_u8; 8192];
        loop {
            let mut ready = fifo.readable().await.map_err(|_| RuntimeError::Io)?;
            match ready.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut chunk)
            }) {
                // EOF, not a spurious wakeup. `try_io` only clears readiness
                // on `WouldBlock`, so a producer that closed without a newline
                // leaves this readable for good: continuing straight back would
                // spin a core flat out until the timeout. Paced the same way
                // the blocking twin above paces its idle reads.
                Ok(Ok(0)) => tokio::time::sleep(Duration::from_millis(1)).await,
                Ok(Ok(count)) => {
                    payload.extend_from_slice(&chunk[..count]);
                    if payload.len() > MAX_FILTERED_BYTES + 1 {
                        return Err(RuntimeError::PayloadTooLarge);
                    }
                    if let Some(newline) = payload.iter().position(|byte| *byte == b'\n') {
                        if payload[newline + 1..]
                            .iter()
                            .any(|byte| !byte.is_ascii_whitespace())
                        {
                            return Err(RuntimeError::MultiplePayloads);
                        }
                        payload.truncate(newline);
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

/// Singleton-owned runtime. The lock is acquired before stale paths are ever
/// inspected or removed, closing the restart race between two companions.
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
    pub fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
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
