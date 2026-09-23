//! Monotonic, fail-closed admission of authenticated local-state checkpoints.
//!
//! Input is a [`VerifiedRootCheckpoint`], never untrusted artifact fields.
//! The expected cursor must be retained independently. This single-host store
//! does not provide remote monotonicity, WORM retention or high availability.

use bloch_local_state_checkpoint::VerifiedRootCheckpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

pub const CURSOR_SCHEMA: &str = "bloch.products.local-state-checkpoint-cursor.v2";
pub const MAX_CURSOR_BYTES: usize = 4096;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckpointCursor {
    schema: String,
    state_identity: String,
    generation: u64,
    checkpoint_sha256: String,
    checkpoint_policy_sha256: String,
    semantic_manifest_sha256: String,
    state_root_sha256: String,
    state_sha256: String,
}

impl CheckpointCursor {
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn checkpoint_sha256(&self) -> &str {
        &self.checkpoint_sha256
    }
    pub fn checkpoint_policy_sha256(&self) -> &str {
        &self.checkpoint_policy_sha256
    }
    pub fn semantic_manifest_sha256(&self) -> &str {
        &self.semantic_manifest_sha256
    }
    pub fn state_root_sha256(&self) -> &str {
        &self.state_root_sha256
    }
    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }

    /// Canonical bytes to retain through an independent authenticated path.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CursorError> {
        serde_json::to_vec(self).map_err(|_| CursorError::InvalidCursor)
    }
}

#[derive(Debug, Error)]
pub enum CursorError {
    #[error("checkpoint cursor is invalid or non-canonical")]
    InvalidCursor,
    #[error("checkpoint cursor is missing")]
    CursorMissing,
    #[error("checkpoint cursor does not match the independent expectation")]
    ExpectationMismatch,
    #[error("presented checkpoint is not the admitted checkpoint")]
    CheckpointMismatch,
    #[error("checkpoint is a rollback")]
    Rollback,
    #[error("checkpoint forks the admitted state history")]
    Fork,
    #[error("checkpoint generation is not the immediate successor")]
    GenerationGap,
    #[error("checkpoint cursor store is busy")]
    StoreBusy,
    #[error("unsafe checkpoint cursor store: {0}")]
    UnsafeStore(&'static str),
    #[error("checkpoint cursor persistence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("checkpoint cursor I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub fn parse_cursor(bytes: &[u8]) -> Result<CheckpointCursor, CursorError> {
    if bytes.is_empty() || bytes.len() > MAX_CURSOR_BYTES {
        return Err(CursorError::InvalidCursor);
    }
    let cursor: CheckpointCursor =
        serde_json::from_slice(bytes).map_err(|_| CursorError::InvalidCursor)?;
    validate_cursor(&cursor)?;
    if cursor.canonical_bytes()? != bytes {
        return Err(CursorError::InvalidCursor);
    }
    Ok(cursor)
}

/// Creates or advances the cursor with compare-and-swap semantics.
///
/// The first admission must be generation zero. Thereafter, callers supply
/// the independently retained current cursor. Exact current replay is
/// idempotent; advancement is exactly one generation and must link to the
/// canonical digest of the currently admitted state root.
#[cfg(unix)]
pub fn admit_checkpoint(
    store: &Path,
    checkpoint: &VerifiedRootCheckpoint,
    expected_current: Option<&CheckpointCursor>,
) -> Result<CheckpointCursor, CursorError> {
    if let Some(expected) = expected_current {
        validate_cursor(expected)?;
    }
    let candidate = candidate(checkpoint)?;
    let directory = open_store(store, true)?;
    let _lock = CursorLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let current = read_cursor(&directory)?;

    match current.as_ref() {
        None => {
            if expected_current.is_some() {
                return Err(CursorError::ExpectationMismatch);
            }
            if candidate.generation != 0 || checkpoint.root().previous_root_sha256().is_some() {
                return Err(CursorError::GenerationGap);
            }
        }
        Some(current) => {
            if expected_current != Some(current) {
                return Err(CursorError::ExpectationMismatch);
            }
            if &candidate == current {
                return Ok(candidate);
            }
            if candidate.state_identity != current.state_identity {
                return Err(CursorError::Fork);
            }
            if candidate.generation < current.generation {
                return Err(CursorError::Rollback);
            }
            if candidate.generation == current.generation {
                return Err(CursorError::Fork);
            }
            if candidate.generation
                != current
                    .generation
                    .checked_add(1)
                    .ok_or(CursorError::GenerationGap)?
            {
                return Err(CursorError::GenerationGap);
            }
            if checkpoint.root().previous_root_sha256() != Some(current.state_root_sha256.as_str())
            {
                return Err(CursorError::Fork);
            }
        }
    }

    let bytes = candidate.canonical_bytes()?;
    atomic_replace(&directory, &bytes)?;
    let published = read_cursor(&directory)?.ok_or(CursorError::CursorMissing)?;
    if published != candidate {
        return Err(CursorError::InvalidCursor);
    }
    verify_store_path(store, &directory)?;
    Ok(candidate)
}

#[cfg(not(unix))]
pub fn admit_checkpoint(
    _store: &Path,
    _checkpoint: &VerifiedRootCheckpoint,
    _expected_current: Option<&CheckpointCursor>,
) -> Result<CheckpointCursor, CursorError> {
    Err(CursorError::UnsupportedPlatform)
}

/// Loads the cursor only when it exactly matches an independent expectation.
#[cfg(unix)]
pub fn load_cursor(
    store: &Path,
    expected: &CheckpointCursor,
) -> Result<CheckpointCursor, CursorError> {
    validate_cursor(expected)?;
    let directory = open_store(store, false)?;
    let _lock = CursorLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let current = read_cursor(&directory)?.ok_or(CursorError::CursorMissing)?;
    if &current != expected {
        return Err(CursorError::ExpectationMismatch);
    }
    Ok(current)
}

#[cfg(not(unix))]
pub fn load_cursor(
    _store: &Path,
    _expected: &CheckpointCursor,
) -> Result<CheckpointCursor, CursorError> {
    Err(CursorError::UnsupportedPlatform)
}

/// Read-only startup admission for an already persisted checkpoint.
///
/// The local cursor must equal the independently retained expectation, and
/// the authenticated checkpoint must equal that cursor. This function never
/// creates or advances durable state.
#[cfg(unix)]
pub fn verify_admitted_checkpoint(
    store: &Path,
    checkpoint: &VerifiedRootCheckpoint,
    expected_cursor: &CheckpointCursor,
) -> Result<CheckpointCursor, CursorError> {
    validate_cursor(expected_cursor)?;
    let presented = candidate(checkpoint)?;
    let directory = open_store(store, false)?;
    let _lock = CursorLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let current = read_cursor(&directory)?.ok_or(CursorError::CursorMissing)?;
    if &current != expected_cursor {
        return Err(CursorError::ExpectationMismatch);
    }
    if presented != current {
        return Err(CursorError::CheckpointMismatch);
    }
    Ok(current)
}

#[cfg(not(unix))]
pub fn verify_admitted_checkpoint(
    _store: &Path,
    _checkpoint: &VerifiedRootCheckpoint,
    _expected_cursor: &CheckpointCursor,
) -> Result<CheckpointCursor, CursorError> {
    Err(CursorError::UnsupportedPlatform)
}

fn candidate(checkpoint: &VerifiedRootCheckpoint) -> Result<CheckpointCursor, CursorError> {
    let root_bytes = checkpoint
        .root()
        .canonical_bytes()
        .map_err(|_| CursorError::InvalidCursor)?;
    let cursor = CheckpointCursor {
        schema: CURSOR_SCHEMA.into(),
        state_identity: checkpoint.root().state_identity().into(),
        generation: checkpoint.root().generation(),
        checkpoint_sha256: checkpoint.checkpoint_sha256().into(),
        checkpoint_policy_sha256: checkpoint.checkpoint_policy_sha256().into(),
        semantic_manifest_sha256: checkpoint.semantic_manifest_sha256().into(),
        state_root_sha256: hash(&root_bytes),
        state_sha256: checkpoint.root().state_sha256().into(),
    };
    validate_cursor(&cursor)?;
    Ok(cursor)
}

fn validate_cursor(cursor: &CheckpointCursor) -> Result<(), CursorError> {
    if cursor.schema != CURSOR_SCHEMA
        || !valid_id(&cursor.state_identity)
        || !valid_sha256(&cursor.checkpoint_sha256)
        || !valid_sha256(&cursor.checkpoint_policy_sha256)
        || !valid_sha256(&cursor.semantic_manifest_sha256)
        || !valid_sha256(&cursor.state_root_sha256)
        || !valid_sha256(&cursor.state_sha256)
    {
        return Err(CursorError::InvalidCursor);
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
struct CursorLock {
    file: File,
}

#[cfg(unix)]
impl CursorLock {
    fn acquire(directory: &File) -> Result<Self, CursorError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(".cursor.lock")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_file(&file.metadata()?, false)?;
        let started = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                    if started.elapsed() >= MAX_LOCK_WAIT {
                        return Err(CursorError::StoreBusy);
                    }
                    std::thread::sleep(
                        LOCK_RETRY_INTERVAL.min(MAX_LOCK_WAIT.saturating_sub(started.elapsed())),
                    );
                }
                Some(libc::EINTR) if started.elapsed() < MAX_LOCK_WAIT => {}
                Some(libc::EINTR) => return Err(CursorError::StoreBusy),
                _ => return Err(error.into()),
            }
        }
        validate_named_file(directory, ".cursor.lock", &file.metadata()?)?;
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for CursorLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn open_store(path: &Path, create: bool) -> Result<File, CursorError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut created = false;
    if create && !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => created = true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let link = match std::fs::symlink_metadata(path) {
        Ok(link) => link,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CursorError::CursorMissing);
        }
        Err(error) => return Err(error.into()),
    };
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(CursorError::UnsafeStore("directoryType"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&file.metadata()?)?;
    if !same_object(&link, &file.metadata()?) {
        return Err(CursorError::UnsafeStore("directoryChanged"));
    }
    if created {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?
            .sync_all()?;
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), CursorError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !same_object(&link, &directory.metadata()?) {
        return Err(CursorError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&directory.metadata()?)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), CursorError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CursorError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata, require_nonempty: bool) -> Result<(), CursorError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || (require_nonempty && metadata.len() == 0)
        || metadata.len() > MAX_CURSOR_BYTES as u64
    {
        return Err(CursorError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, CursorError> {
    std::ffi::CString::new(name).map_err(|_| CursorError::UnsafeStore("fileName"))
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), CursorError> {
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
        return Err(CursorError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
        || status.st_mode & 0o077 != 0
        || status.st_uid != unsafe { libc::geteuid() }
    {
        return Err(CursorError::UnsafeStore("fileChanged"));
    }
    Ok(())
}

#[cfg(unix)]
fn read_cursor(directory: &File) -> Result<Option<CheckpointCursor>, CursorError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name("cursor.json")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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
    let metadata = file.metadata()?;
    validate_file(&metadata, true)?;
    validate_named_file(directory, "cursor.json", &metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_CURSOR_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after, true)?;
    validate_named_file(directory, "cursor.json", &after)?;
    if !same_object(&metadata, &after)
        || metadata.len() != after.len()
        || bytes.len() as u64 != after.len()
    {
        return Err(CursorError::UnsafeStore("fileChanged"));
    }
    Ok(Some(parse_cursor(&bytes)?))
}

#[cfg(unix)]
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), CursorError> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
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

    let result = (|| {
        loop {
            let mut entry = MaybeUninit::<libc::dirent>::uninit();
            let mut result = std::ptr::null_mut();
            #[allow(deprecated)]
            let error = unsafe { libc::readdir_r(stream, entry.as_mut_ptr(), &mut result) };
            if error != 0 {
                return Err(CursorError::Io(std::io::Error::from_raw_os_error(error)));
            }
            if result.is_null() {
                return Ok(());
            }
            let entry = unsafe { entry.assume_init() };
            let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
            let Ok(name) = name.to_str() else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(".cursor.json.tmp-") else {
                continue;
            };
            if suffix.len() != 32
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                continue;
            }
            remove_stale_temporary_file(directory, name)?;
        }
    })();
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(unix)]
fn remove_stale_temporary_file(directory: &File, name: &str) -> Result<(), CursorError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else if error.raw_os_error() == Some(libc::ELOOP) {
            Err(CursorError::UnsafeStore("temporaryFile"))
        } else {
            Err(error.into())
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    validate_file(&metadata, false)?;
    validate_named_file(
        directory,
        name.to_str().map_err(|_| CursorError::InvalidCursor)?,
        &metadata,
    )?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), CursorError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() > MAX_CURSOR_BYTES {
        return Err(CursorError::InvalidCursor);
    }
    let destination = c_name("cursor.json")?;
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|e| CursorError::Io(std::io::Error::other(e.to_string())))?;
    let temporary_name = format!(".cursor.json.tmp-{}", hex::encode(random));
    let temporary = c_name(&temporary_name)?;
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
            return Err(CursorError::Io(std::io::Error::last_os_error()));
        }
        directory.sync_all()?;
        let published = read_cursor(directory)?.ok_or(CursorError::CursorMissing)?;
        if published.canonical_bytes()? != bytes {
            return Err(CursorError::InvalidCursor);
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}
