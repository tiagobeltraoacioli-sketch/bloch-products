//! Bounded single-host coordination for local state and cursor composition.
//!
//! Every cooperating reader/writer for one state identity must use the same
//! directory. This is not a distributed lock or a cross-host atomicity proof.

use std::marker::PhantomData;
use std::path::Path;
#[cfg(unix)]
use std::{
    fs::{File, Metadata, OpenOptions},
    time::{Duration, Instant},
};
use thiserror::Error;

#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(500);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(unix)]
const LOCK_NAME: &str = ".local-state.coordination.lock";

/// Capability available only while the host-local coordination lock is held.
#[derive(Debug)]
pub struct LocalStateCoordination<'lock> {
    _lifetime: PhantomData<&'lock mut ()>,
}

impl LocalStateCoordination<'_> {
    pub fn local_exclusion_held(&self) -> bool {
        true
    }

    pub fn cross_host_atomicity_proven(&self) -> bool {
        false
    }

    pub fn remote_fencing_proven(&self) -> bool {
        false
    }

    pub fn high_availability_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum CoordinationError {
    #[error("local state coordination lock is busy")]
    Busy,
    #[error("unsafe local state coordination object: {0}")]
    UnsafeObject(&'static str),
    #[error("local state coordination is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local state coordination I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum CoordinatedError<E> {
    #[error("local state coordination failed")]
    Coordination(#[source] CoordinationError),
    #[error("coordinated local state operation failed")]
    Operation(#[source] E),
}

/// Explicitly provisions a fixed owner-only coordination directory.
/// Operational acquisition never creates a missing directory.
#[cfg(unix)]
pub fn provision_local_state_coordination_directory(
    directory_path: &Path,
) -> Result<(), CoordinationError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let directory = open_coordination_directory(directory_path)?;
    provision_lock_file(&directory)?;
    let parent = directory_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?
        .sync_all()?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub fn provision_local_state_coordination_directory(
    _directory_path: &Path,
) -> Result<(), CoordinationError> {
    Err(CoordinationError::UnsupportedPlatform)
}

/// Coordinates the full read-only startup sequence across checkpoint,
/// cursor, state loading and semantic validation.
pub fn with_coordinated_startup_admission<T, E, F>(
    directory_path: &Path,
    operation: F,
) -> Result<T, CoordinatedError<E>>
where
    F: for<'lock> FnOnce(&LocalStateCoordination<'lock>) -> Result<T, E>,
{
    with_local_state_coordination(directory_path, operation)
}

/// Coordinates the full writer sequence across state persistence, checkpoint
/// publication and monotonic cursor advancement.
pub fn with_coordinated_state_transition<T, E, F>(
    directory_path: &Path,
    operation: F,
) -> Result<T, CoordinatedError<E>>
where
    F: for<'lock> FnOnce(&LocalStateCoordination<'lock>) -> Result<T, E>,
{
    with_local_state_coordination(directory_path, operation)
}

/// Runs one complete local state operation while holding bounded host-local
/// exclusion. The capability cannot escape the closure's lifetime.
#[cfg(unix)]
pub fn with_local_state_coordination<T, E, F>(
    directory_path: &Path,
    operation: F,
) -> Result<T, CoordinatedError<E>>
where
    F: for<'lock> FnOnce(&LocalStateCoordination<'lock>) -> Result<T, E>,
{
    let directory =
        open_coordination_directory(directory_path).map_err(CoordinatedError::Coordination)?;
    let lock = CoordinationLock::acquire(&directory).map_err(CoordinatedError::Coordination)?;
    verify_directory_path(directory_path, &directory).map_err(CoordinatedError::Coordination)?;
    let scope = LocalStateCoordination {
        _lifetime: PhantomData,
    };
    let result = operation(&scope);
    lock.verify(&directory)
        .map_err(CoordinatedError::Coordination)?;
    verify_directory_path(directory_path, &directory).map_err(CoordinatedError::Coordination)?;
    drop(lock);
    result.map_err(CoordinatedError::Operation)
}

#[cfg(not(unix))]
pub fn with_local_state_coordination<T, E, F>(
    _directory_path: &Path,
    _operation: F,
) -> Result<T, CoordinatedError<E>>
where
    F: for<'lock> FnOnce(&LocalStateCoordination<'lock>) -> Result<T, E>,
{
    Err(CoordinatedError::Coordination(
        CoordinationError::UnsupportedPlatform,
    ))
}

#[cfg(unix)]
struct CoordinationLock {
    file: File,
}

#[cfg(unix)]
impl CoordinationLock {
    fn acquire(directory: &File) -> Result<Self, CoordinationError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(LOCK_NAME)?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ELOOP) {
                Err(CoordinationError::UnsafeObject("lockType"))
            } else {
                Err(error.into())
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_lock_file(&file.metadata()?)?;
        let started = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                    if started.elapsed() >= MAX_LOCK_WAIT {
                        return Err(CoordinationError::Busy);
                    }
                    std::thread::sleep(
                        LOCK_RETRY_INTERVAL.min(MAX_LOCK_WAIT.saturating_sub(started.elapsed())),
                    );
                }
                Some(libc::EINTR) if started.elapsed() < MAX_LOCK_WAIT => {}
                Some(libc::EINTR) => return Err(CoordinationError::Busy),
                _ => return Err(error.into()),
            }
        }
        validate_named_lock(directory, &file.metadata()?)?;
        Ok(Self { file })
    }

    fn verify(&self, directory: &File) -> Result<(), CoordinationError> {
        let metadata = self.file.metadata()?;
        validate_lock_file(&metadata)?;
        validate_named_lock(directory, &metadata)
    }
}

#[cfg(unix)]
fn provision_lock_file(directory: &File) -> Result<(), CoordinationError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(LOCK_NAME)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ELOOP) {
            Err(CoordinationError::UnsafeObject("lockType"))
        } else {
            Err(error.into())
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    validate_lock_file(&metadata)?;
    validate_named_lock(directory, &metadata)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
impl Drop for CoordinationLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
fn open_coordination_directory(path: &Path) -> Result<File, CoordinationError> {
    use std::os::unix::fs::OpenOptionsExt;
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(CoordinationError::UnsafeObject("directoryType"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&directory.metadata()?)?;
    if !same_object(&link, &directory.metadata()?) {
        return Err(CoordinationError::UnsafeObject("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn verify_directory_path(path: &Path, directory: &File) -> Result<(), CoordinationError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !same_object(&link, &directory.metadata()?) {
        return Err(CoordinationError::UnsafeObject("directoryChanged"));
    }
    validate_directory(&directory.metadata()?)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), CoordinationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CoordinationError::UnsafeObject("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_lock_file(metadata: &Metadata) -> Result<(), CoordinationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != 0
    {
        return Err(CoordinationError::UnsafeObject("lockPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_named_lock(directory: &File, metadata: &Metadata) -> Result<(), CoordinationError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let name = c_name(LOCK_NAME)?;
    let mut status = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(CoordinationError::UnsafeObject("lockChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
        || status.st_mode & 0o077 != 0
        || status.st_uid != unsafe { libc::geteuid() }
    {
        return Err(CoordinationError::UnsafeObject("lockChanged"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, CoordinationError> {
    std::ffi::CString::new(name).map_err(|_| CoordinationError::UnsafeObject("lockName"))
}
