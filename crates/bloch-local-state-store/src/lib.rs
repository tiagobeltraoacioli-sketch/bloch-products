//! Crash-safe local persistence for canonical Bloch product state.
//!
//! This crate protects one Unix-host copy from partial writes, unsafe file
//! objects and concurrent local writers. It does not encrypt state, replicate
//! it, authenticate the host or retain the anti-rollback root independently.

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

pub const STATE_STORE_SCHEMA: &str = "bloch.products.local-state-envelope.v1";
pub const STATE_ROOT_SCHEMA: &str = "bloch.products.local-state-root.v1";
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ROOT_BYTES: usize = 1024;
const MAX_ENVELOPE_BYTES: u64 = (MAX_STATE_BYTES as u64 * 2) + 4096;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StateRoot {
    schema: String,
    state_identity: String,
    generation: u64,
    state_sha256: String,
}

impl StateRoot {
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }

    /// Canonical bytes to retain through an independent, authenticated path.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(self).map_err(|_| StoreError::InvalidRoot)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StateEnvelope {
    schema: String,
    state_identity: String,
    generation: u64,
    state_sha256: String,
    previous_root_sha256: Option<String>,
    state_hex: String,
}

#[cfg(unix)]
struct StoredState {
    root: StateRoot,
    bytes: Vec<u8>,
    previous_root_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("local state input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("independent state root is invalid")]
    InvalidRoot,
    #[error("local state is missing")]
    StateMissing,
    #[error("local state envelope is invalid")]
    InvalidState,
    #[error("local state does not match the independent root")]
    ExpectationMismatch,
    #[error("local state generation conflicts with durable state")]
    GenerationConflict,
    #[error("local state store is busy")]
    StoreBusy,
    #[error("local state exceeds the bounded store")]
    StoreFull,
    #[error("unsafe local state store: {0}")]
    UnsafeStore(&'static str),
    #[error("secure local persistence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local state store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Parses an independently retained root and requires its canonical encoding.
/// Parsing does not make the root independent or authenticated.
pub fn parse_state_root(bytes: &[u8]) -> Result<StateRoot, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES {
        return Err(StoreError::InvalidRoot);
    }
    let root: StateRoot = serde_json::from_slice(bytes).map_err(|_| StoreError::InvalidRoot)?;
    validate_root(&root)?;
    if root.canonical_bytes()? != bytes {
        return Err(StoreError::InvalidRoot);
    }
    Ok(root)
}

/// Atomically persists an exact product-state byte string with compare-and-swap.
/// The initial write must use generation zero and no predecessor. Every later
/// write must advance exactly once from the independently retained predecessor.
#[cfg(unix)]
pub fn write_state(
    store: &Path,
    state_identity: &str,
    generation: u64,
    state: &[u8],
    expected_previous: Option<&StateRoot>,
) -> Result<StateRoot, StoreError> {
    validate_identity(state_identity)?;
    if state.is_empty() {
        return Err(StoreError::InvalidInput("state"));
    }
    if state.len() > MAX_STATE_BYTES {
        return Err(StoreError::StoreFull);
    }
    if let Some(root) = expected_previous {
        validate_root(root)?;
        if root.state_identity != state_identity {
            return Err(StoreError::ExpectationMismatch);
        }
    }

    let next = StateRoot {
        schema: STATE_ROOT_SCHEMA.to_owned(),
        state_identity: state_identity.to_owned(),
        generation,
        state_sha256: hash(state),
    };
    let directory = open_store(store, true)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let current = read_state(&directory)?;

    match current {
        None if expected_previous.is_none() && generation == 0 => {}
        None if expected_previous.is_some() => return Err(StoreError::ExpectationMismatch),
        None => return Err(StoreError::GenerationConflict),
        Some(StoredState {
            root,
            bytes,
            previous_root_sha256: predecessor,
        }) if root == next && bytes == state => {
            let supplied_predecessor = expected_previous.map(root_hash).transpose()?;
            if predecessor == supplied_predecessor {
                return Ok(root);
            }
            return Err(StoreError::ExpectationMismatch);
        }
        Some(StoredState { root, .. }) => {
            if expected_previous != Some(&root) {
                return Err(StoreError::ExpectationMismatch);
            }
            if generation
                != root
                    .generation
                    .checked_add(1)
                    .ok_or(StoreError::GenerationConflict)?
            {
                return Err(StoreError::GenerationConflict);
            }
        }
    }

    let envelope = StateEnvelope {
        schema: STATE_STORE_SCHEMA.to_owned(),
        state_identity: next.state_identity.clone(),
        generation: next.generation,
        state_sha256: next.state_sha256.clone(),
        previous_root_sha256: expected_previous.map(root_hash).transpose()?,
        state_hex: hex::encode(state),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| StoreError::InvalidState)?;
    atomic_replace(&directory, "state.json", &bytes)?;
    verify_store_path(store, &directory)?;
    Ok(next)
}

#[cfg(not(unix))]
pub fn write_state(
    _store: &Path,
    _state_identity: &str,
    _generation: u64,
    _state: &[u8],
    _expected_previous: Option<&StateRoot>,
) -> Result<StateRoot, StoreError> {
    Err(StoreError::UnsupportedPlatform)
}

/// Loads bytes only when the complete local envelope matches a root obtained
/// independently from this store.
#[cfg(unix)]
pub fn load_state(store: &Path, expected: &StateRoot) -> Result<Vec<u8>, StoreError> {
    validate_root(expected)?;
    let directory = open_store(store, false)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let stored = read_state(&directory)?.ok_or(StoreError::StateMissing)?;
    if &stored.root != expected {
        return Err(StoreError::ExpectationMismatch);
    }
    Ok(stored.bytes)
}

#[cfg(not(unix))]
pub fn load_state(_store: &Path, _expected: &StateRoot) -> Result<Vec<u8>, StoreError> {
    Err(StoreError::UnsupportedPlatform)
}

fn validate_root(root: &StateRoot) -> Result<(), StoreError> {
    validate_identity(&root.state_identity).map_err(|_| StoreError::InvalidRoot)?;
    if root.schema != STATE_ROOT_SCHEMA || !valid_sha256(&root.state_sha256) {
        return Err(StoreError::InvalidRoot);
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StoreError::InvalidInput("stateIdentity"));
    }
    Ok(())
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

fn root_hash(root: &StateRoot) -> Result<String, StoreError> {
    Ok(hash(&root.canonical_bytes()?))
}

#[cfg(unix)]
struct StoreLock {
    file: File,
}

#[cfg(unix)]
impl StoreLock {
    fn acquire(directory: &File) -> Result<Self, StoreError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(".state.lock")?;
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
                        return Err(StoreError::StoreBusy);
                    }
                    std::thread::sleep(
                        LOCK_RETRY_INTERVAL.min(MAX_LOCK_WAIT.saturating_sub(started.elapsed())),
                    );
                }
                Some(libc::EINTR) if started.elapsed() < MAX_LOCK_WAIT => {}
                Some(libc::EINTR) => return Err(StoreError::StoreBusy),
                _ => return Err(error.into()),
            }
        }
        validate_named_file(directory, ".state.lock", &file.metadata()?)?;
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn open_store(path: &Path, create: bool) -> Result<File, StoreError> {
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
            return Err(StoreError::StateMissing);
        }
        Err(error) => return Err(error.into()),
    };
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(StoreError::UnsafeStore("directoryType"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&file.metadata()?)?;
    if !same_object(&link, &file.metadata()?) {
        return Err(StoreError::UnsafeStore("directoryChanged"));
    }
    if created {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?;
        parent.sync_all()?;
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), StoreError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !same_object(&link, &directory.metadata()?) {
        return Err(StoreError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&directory.metadata()?)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(StoreError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata, require_nonempty: bool) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || (require_nonempty && metadata.len() == 0)
        || metadata.len() > MAX_ENVELOPE_BYTES
    {
        return Err(StoreError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, StoreError> {
    std::ffi::CString::new(name).map_err(|_| StoreError::UnsafeStore("fileName"))
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), StoreError> {
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
        return Err(StoreError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || u128::try_from(status.st_dev).ok() != Some(u128::from(metadata.dev()))
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
        || status.st_mode & 0o077 != 0
        || status.st_uid != unsafe { libc::geteuid() }
    {
        return Err(StoreError::UnsafeStore("fileChanged"));
    }
    Ok(())
}

#[cfg(unix)]
fn read_state(directory: &File) -> Result<Option<StoredState>, StoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    validate_file(&metadata, true)?;
    validate_named_file(directory, "state.json", &metadata)?;
    let mut serialized = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_ENVELOPE_BYTES + 1)
        .read_to_end(&mut serialized)?;
    let after = file.metadata()?;
    validate_file(&after, true)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_object(&metadata, &after)
        || metadata.len() != after.len()
        || serialized.len() as u64 != after.len()
    {
        return Err(StoreError::UnsafeStore("fileChanged"));
    }
    let envelope: StateEnvelope =
        serde_json::from_slice(&serialized).map_err(|_| StoreError::InvalidState)?;
    if serde_json::to_vec(&envelope).map_err(|_| StoreError::InvalidState)? != serialized
        || envelope.schema != STATE_STORE_SCHEMA
        || envelope.state_hex.len() > MAX_STATE_BYTES * 2
    {
        return Err(StoreError::InvalidState);
    }
    validate_identity(&envelope.state_identity).map_err(|_| StoreError::InvalidState)?;
    if envelope
        .previous_root_sha256
        .as_deref()
        .is_some_and(|digest| !valid_sha256(digest))
        || (envelope.generation == 0) != envelope.previous_root_sha256.is_none()
    {
        return Err(StoreError::InvalidState);
    }
    let state = hex::decode(&envelope.state_hex).map_err(|_| StoreError::InvalidState)?;
    if state.is_empty() || state.len() > MAX_STATE_BYTES || hash(&state) != envelope.state_sha256 {
        return Err(StoreError::InvalidState);
    }
    let root = StateRoot {
        schema: STATE_ROOT_SCHEMA.to_owned(),
        state_identity: envelope.state_identity,
        generation: envelope.generation,
        state_sha256: envelope.state_sha256,
    };
    validate_root(&root).map_err(|_| StoreError::InvalidState)?;
    Ok(Some(StoredState {
        root,
        bytes: state,
        previous_root_sha256: envelope.previous_root_sha256,
    }))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(StoreError::StoreFull);
    }
    let destination = c_name(name)?;
    let temp_name = format!(".{name}.tmp-{}-{}", std::process::id(), temporary_nonce());
    let temporary = c_name(&temp_name)?;
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
            return Err(StoreError::Io(std::io::Error::last_os_error()));
        }
        directory.sync_all()?;
        validate_destination(directory, name)?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

#[cfg(unix)]
fn validate_destination(directory: &File, name: &str) -> Result<(), StoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name_c = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    validate_file(&metadata, true)?;
    validate_named_file(directory, name, &metadata)
}

#[cfg(unix)]
fn temporary_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bloch-local-state-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn writes_loads_and_exactly_replays_initial_state() {
        let path = temporary_path("roundtrip");
        let root = write_state(&path, "data:tenant-a:lifecycle", 0, b"state-0", None).unwrap();
        let before = std::fs::read(path.join("state.json")).unwrap();
        assert_eq!(load_state(&path, &root).unwrap(), b"state-0");
        assert_eq!(
            write_state(&path, "data:tenant-a:lifecycle", 0, b"state-0", None).unwrap(),
            root
        );
        assert_eq!(std::fs::read(path.join("state.json")).unwrap(), before);
        assert_eq!(
            parse_state_root(&root.canonical_bytes().unwrap()).unwrap(),
            root
        );
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn compare_and_swap_requires_exact_root_and_next_generation() {
        let path = temporary_path("cas");
        let root0 = write_state(&path, "pay:merchant-a:adjustments", 0, b"state-0", None).unwrap();
        assert!(matches!(
            write_state(
                &path,
                "pay:merchant-a:adjustments",
                2,
                b"state-2",
                Some(&root0)
            ),
            Err(StoreError::GenerationConflict)
        ));
        let root1 = write_state(
            &path,
            "pay:merchant-a:adjustments",
            1,
            b"state-1",
            Some(&root0),
        )
        .unwrap();
        assert_eq!(
            write_state(
                &path,
                "pay:merchant-a:adjustments",
                1,
                b"state-1",
                Some(&root0)
            )
            .unwrap(),
            root1
        );
        assert!(matches!(
            load_state(&path, &root0),
            Err(StoreError::ExpectationMismatch)
        ));
        assert_eq!(load_state(&path, &root1).unwrap(), b"state-1");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn wrong_identity_and_stale_predecessor_fail_closed() {
        let path = temporary_path("stale");
        let root0 = write_state(&path, "data:one", 0, b"zero", None).unwrap();
        assert!(matches!(
            write_state(&path, "data:two", 1, b"one", Some(&root0)),
            Err(StoreError::ExpectationMismatch)
        ));
        let root1 = write_state(&path, "data:one", 1, b"one", Some(&root0)).unwrap();
        assert!(matches!(
            write_state(&path, "data:one", 2, b"two", Some(&root0)),
            Err(StoreError::ExpectationMismatch)
        ));
        assert_eq!(load_state(&path, &root1).unwrap(), b"one");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corruption_and_noncanonical_root_fail_closed() {
        let path = temporary_path("corrupt");
        let root = write_state(&path, "data:one", 0, b"zero", None).unwrap();
        let mut bytes = root.canonical_bytes().unwrap();
        bytes.push(b'\n');
        assert!(matches!(
            parse_state_root(&bytes),
            Err(StoreError::InvalidRoot)
        ));
        let mut envelope = std::fs::read(path.join("state.json")).unwrap();
        let index = envelope.iter().position(|byte| *byte == b'0').unwrap();
        envelope[index] = b'1';
        std::fs::write(path.join("state.json"), envelope).unwrap();
        assert!(matches!(
            load_state(&path, &root),
            Err(StoreError::InvalidState | StoreError::ExpectationMismatch)
        ));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unsafe_directory_and_symlink_are_rejected() {
        let path = temporary_path("mode");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            write_state(&path, "data:one", 0, b"zero", None),
            Err(StoreError::UnsafeStore(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(&path).unwrap();
        let target = temporary_path("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(matches!(
            write_state(&path, "data:one", 0, b"zero", None),
            Err(StoreError::UnsafeStore(_))
        ));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(target).unwrap();
    }

    #[test]
    fn absent_load_has_no_filesystem_side_effect() {
        let path = temporary_path("missing");
        let root_bytes = br#"{"schema":"bloch.products.local-state-root.v1","stateIdentity":"data:one","generation":0,"stateSha256":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
        let root = parse_state_root(root_bytes).unwrap();
        assert!(matches!(
            load_state(&path, &root),
            Err(StoreError::StateMissing)
        ));
        assert!(!path.exists());
        assert!(matches!(
            parse_state_root(&vec![b'x'; MAX_ROOT_BYTES + 1]),
            Err(StoreError::InvalidRoot)
        ));
    }

    #[test]
    fn hardlinked_state_file_is_rejected() {
        let path = temporary_path("hardlink");
        let root = write_state(&path, "data:one", 0, b"zero", None).unwrap();
        let alias = path.join("state-alias.json");
        std::fs::hard_link(path.join("state.json"), &alias).unwrap();
        assert!(matches!(
            load_state(&path, &root),
            Err(StoreError::UnsafeStore(_))
        ));
        std::fs::remove_dir_all(path).unwrap();
    }
}
