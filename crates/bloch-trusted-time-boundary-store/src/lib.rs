//! Unix reference store for a monotonic trusted-time rollback boundary.
//!
//! This single-host primitive protects normal filesystem updates with strict
//! ownership checks, a bounded advisory lock, and durable atomic replacement.
//! It does not protect against rollback of the filesystem, volume, mount, VM,
//! or host snapshot; deployments need an independent anti-rollback mechanism.

use bloch_trusted_time::{TrustedTimeBoundary, parse_trusted_time_boundary};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

pub const TRUSTED_TIME_BOUNDARY_STORE_SCHEMA: &str =
    "bloch.products.trusted-time-boundary-store.v1";
const MAX_STATE_BYTES: u64 = 4096;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// The audience to which a persisted rollback floor is permanently bound.
#[derive(Clone, Copy, Debug)]
pub struct TrustedTimeBoundaryAudience<'a> {
    pub trusted_time_policy_sha256: &'a str,
    pub state_identity: &'a str,
    pub remote_cursor_policy_sha256: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    trusted_time_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    boundary: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum BoundaryStoreError {
    #[error("trusted-time boundary store input is invalid")]
    InvalidInput,
    #[error("trusted-time boundary store is missing")]
    StateMissing,
    #[error("trusted-time boundary store is already provisioned")]
    AlreadyProvisioned,
    #[error("trusted-time boundary store state is invalid or non-canonical")]
    InvalidState,
    #[error("trusted-time boundary rollback was refused")]
    RollbackRefused,
    #[error("trusted-time boundary store is busy")]
    StoreBusy,
    #[error("unsafe trusted-time boundary store: {0}")]
    UnsafeStore(&'static str),
    #[error("trusted-time boundary storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("trusted-time boundary store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Explicitly creates a new store and commits its initial rollback floor.
///
/// Normal load/update paths never create the directory, lock, or state file.
#[cfg(unix)]
pub fn provision_trusted_time_boundary_store(
    store: &Path,
    audience: TrustedTimeBoundaryAudience<'_>,
    initial: &TrustedTimeBoundary,
) -> Result<(), BoundaryStoreError> {
    use std::os::unix::fs::DirBuilderExt;
    validate_input(audience, initial)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(store) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(BoundaryStoreError::AlreadyProvisioned)
        } else {
            Err(error.into())
        };
    }
    let directory = open_directory(store)?;
    sync_parent_directory(store)?;
    let lock = create_file_exclusive(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    lock.sync_all()?;
    directory.sync_all()?;
    let _lock = StoreLock::acquire(&directory)?;
    let state = make_state(audience, initial)?;
    atomic_replace(&directory, &encode_state(&state)?)?;
    let published = read_state(&directory)?.ok_or(BoundaryStoreError::StateMissing)?;
    if published != state {
        return Err(BoundaryStoreError::InvalidState);
    }
    verify_store_path(store, &directory)
}

#[cfg(not(unix))]
pub fn provision_trusted_time_boundary_store(
    _store: &Path,
    _audience: TrustedTimeBoundaryAudience<'_>,
    _initial: &TrustedTimeBoundary,
) -> Result<(), BoundaryStoreError> {
    Err(BoundaryStoreError::UnsupportedPlatform)
}

/// Reads the current floor without creating or repairing any store object.
#[cfg(unix)]
pub fn load_trusted_time_boundary(
    store: &Path,
    audience: TrustedTimeBoundaryAudience<'_>,
) -> Result<TrustedTimeBoundary, BoundaryStoreError> {
    validate_audience(audience)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(BoundaryStoreError::StateMissing)?;
    boundary_from_state(&state, audience)
}

#[cfg(not(unix))]
pub fn load_trusted_time_boundary(
    _store: &Path,
    _audience: TrustedTimeBoundaryAudience<'_>,
) -> Result<TrustedTimeBoundary, BoundaryStoreError> {
    Err(BoundaryStoreError::UnsupportedPlatform)
}

/// Advances the floor, accepts an exact replay idempotently, and rejects a
/// lower floor. Concurrent updates serialize and can only leave the maximum.
#[cfg(unix)]
pub fn advance_trusted_time_boundary(
    store: &Path,
    audience: TrustedTimeBoundaryAudience<'_>,
    candidate: &TrustedTimeBoundary,
) -> Result<TrustedTimeBoundary, BoundaryStoreError> {
    validate_input(audience, candidate)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let state = read_state(&directory)?.ok_or(BoundaryStoreError::StateMissing)?;
    let current = boundary_from_state(&state, audience)?;
    if candidate.not_before_unix_seconds() < current.not_before_unix_seconds() {
        return Err(BoundaryStoreError::RollbackRefused);
    }
    if candidate.not_before_unix_seconds() == current.not_before_unix_seconds() {
        return Ok(current);
    }
    let next = make_state(audience, candidate)?;
    atomic_replace(&directory, &encode_state(&next)?)?;
    let published = read_state(&directory)?.ok_or(BoundaryStoreError::StateMissing)?;
    if published != next {
        return Err(BoundaryStoreError::InvalidState);
    }
    verify_store_path(store, &directory)?;
    boundary_from_state(&published, audience)
}

#[cfg(not(unix))]
pub fn advance_trusted_time_boundary(
    _store: &Path,
    _audience: TrustedTimeBoundaryAudience<'_>,
    _candidate: &TrustedTimeBoundary,
) -> Result<TrustedTimeBoundary, BoundaryStoreError> {
    Err(BoundaryStoreError::UnsupportedPlatform)
}

fn validate_input(
    audience: TrustedTimeBoundaryAudience<'_>,
    boundary: &TrustedTimeBoundary,
) -> Result<(), BoundaryStoreError> {
    validate_audience(audience)?;
    if boundary.trusted_time_policy_sha256() != audience.trusted_time_policy_sha256 {
        return Err(BoundaryStoreError::InvalidInput);
    }
    boundary
        .canonical_bytes()
        .map_err(|_| BoundaryStoreError::InvalidInput)?;
    Ok(())
}

fn validate_audience(audience: TrustedTimeBoundaryAudience<'_>) -> Result<(), BoundaryStoreError> {
    if !valid_sha256(audience.trusted_time_policy_sha256)
        || !valid_id(audience.state_identity)
        || !valid_sha256(audience.remote_cursor_policy_sha256)
    {
        return Err(BoundaryStoreError::InvalidInput);
    }
    Ok(())
}

fn make_state(
    audience: TrustedTimeBoundaryAudience<'_>,
    boundary: &TrustedTimeBoundary,
) -> Result<DurableState, BoundaryStoreError> {
    Ok(DurableState {
        schema: TRUSTED_TIME_BOUNDARY_STORE_SCHEMA.into(),
        trusted_time_policy_sha256: audience.trusted_time_policy_sha256.into(),
        state_identity: audience.state_identity.into(),
        remote_cursor_policy_sha256: audience.remote_cursor_policy_sha256.into(),
        boundary: boundary
            .canonical_bytes()
            .map_err(|_| BoundaryStoreError::InvalidInput)?,
    })
}

fn boundary_from_state(
    state: &DurableState,
    audience: TrustedTimeBoundaryAudience<'_>,
) -> Result<TrustedTimeBoundary, BoundaryStoreError> {
    validate_state(state)?;
    if state.trusted_time_policy_sha256 != audience.trusted_time_policy_sha256
        || state.state_identity != audience.state_identity
        || state.remote_cursor_policy_sha256 != audience.remote_cursor_policy_sha256
    {
        return Err(BoundaryStoreError::InvalidInput);
    }
    parse_trusted_time_boundary(&state.boundary, audience.trusted_time_policy_sha256)
        .map_err(|_| BoundaryStoreError::InvalidState)
}

fn validate_state(state: &DurableState) -> Result<(), BoundaryStoreError> {
    if state.schema != TRUSTED_TIME_BOUNDARY_STORE_SCHEMA
        || !valid_sha256(&state.trusted_time_policy_sha256)
        || !valid_id(&state.state_identity)
        || !valid_sha256(&state.remote_cursor_policy_sha256)
        || state.boundary.is_empty()
        || state.boundary.len() > 1024
        || parse_trusted_time_boundary(&state.boundary, &state.trusted_time_policy_sha256).is_err()
    {
        return Err(BoundaryStoreError::InvalidState);
    }
    Ok(())
}

fn encode_state(state: &DurableState) -> Result<Vec<u8>, BoundaryStoreError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| BoundaryStoreError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(BoundaryStoreError::InvalidState);
    }
    Ok(bytes)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, BoundaryStoreError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, BoundaryStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BoundaryStoreError::StateMissing
        } else {
            error.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(BoundaryStoreError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(BoundaryStoreError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), BoundaryStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_path)?;
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), BoundaryStoreError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(BoundaryStoreError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, BoundaryStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Err(BoundaryStoreError::StateMissing)
        } else {
            Err(error.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, BoundaryStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
struct StoreLock {
    file: File,
}

#[cfg(unix)]
impl StoreLock {
    fn acquire(directory: &File) -> Result<Self, BoundaryStoreError> {
        use std::os::fd::AsRawFd;
        let file = open_existing_file(directory, "store.lock")?;
        validate_file(&file.metadata()?)?;
        validate_named_file(directory, "store.lock", &file.metadata()?)?;
        let deadline = Instant::now() + MAX_LOCK_WAIT;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                validate_file(&file.metadata()?)?;
                validate_named_file(directory, "store.lock", &file.metadata()?)?;
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK)
                && error.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Err(BoundaryStoreError::StoreBusy);
            }
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
fn read_state(directory: &File) -> Result<Option<DurableState>, BoundaryStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata()?;
    validate_file(&before)?;
    validate_named_file(directory, "state.json", &before)?;
    if before.len() == 0 || before.len() > MAX_STATE_BYTES {
        return Err(BoundaryStoreError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_snapshot(&before, &after)
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
    {
        return Err(BoundaryStoreError::UnsafeStore("fileChanged"));
    }
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| BoundaryStoreError::InvalidState)?;
    if encode_state(&state)? != bytes {
        return Err(BoundaryStoreError::InvalidState);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), BoundaryStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(BoundaryStoreError::InvalidState);
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| BoundaryStoreError::Io(std::io::Error::other(error.to_string())))?;
    let temporary_name = format!(".state.json.tmp-{}", hex_string(&random));
    let temporary = c_name(&temporary_name)?;
    let destination = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(BoundaryStoreError::Io(std::io::Error::last_os_error()));
        }
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    result
}

#[cfg(unix)]
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), BoundaryStoreError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            return Ok(());
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(".state.json.tmp-") else {
            continue;
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            continue;
        }
        let c = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        use std::os::fd::FromRawFd;
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        validate_file(&metadata)?;
        validate_named_file(directory, name, &metadata)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
    })();
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), BoundaryStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BoundaryStoreError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata) -> Result<(), BoundaryStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(BoundaryStoreError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), BoundaryStoreError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let name = c_name(name)?;
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
        return Err(BoundaryStoreError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
    {
        return Err(BoundaryStoreError::UnsafeStore("fileChanged"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, BoundaryStoreError> {
    std::ffi::CString::new(name).map_err(|_| BoundaryStoreError::InvalidInput)
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
