//! Crash-safe single-host store for a writer-fencing epoch floor.
//!
//! This is not WORM or snapshot-rollback-proof storage. It also does not
//! provide consensus, leader election, or a linearizable lease issuer.

use bloch_local_state_writer_fencing::VerifiedWriterLease;
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

pub const WRITER_EPOCH_FLOOR_STORE_SCHEMA: &str = "bloch.products.writer-epoch-floor-store.v2";
pub const WRITER_EPOCH_FLOOR_EVIDENCE_SCHEMA: &str =
    "bloch.products.writer-epoch-floor-evidence.v1";
const MAX_STATE_BYTES: u64 = 4096;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug)]
pub struct WriterEpochFloorAudience<'a> {
    pub writer_fencing_policy_sha256: &'a str,
    pub state_identity: &'a str,
    pub remote_cursor_policy_sha256: &'a str,
    pub cas_service_id: &'a str,
    pub cas_policy_sha256: &'a str,
}

/// Non-constructible evidence loaded from one provisioned epoch-floor store.
///
/// This capability is deliberately non-cloneable. It authenticates the
/// canonical state observed while holding the store lock, but cannot prove
/// that another process did not advance or snapshot-rollback the store after
/// the lock was released.
#[derive(Debug, PartialEq, Eq)]
pub struct WriterEpochFloor {
    store_id: String,
    writer_fencing_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    cas_service_id: String,
    cas_policy_sha256: String,
    epoch: u64,
    writer_id: String,
    lease_certificate_sha256: String,
    state_sha256: String,
    evidence_sha256: String,
}

impl WriterEpochFloor {
    pub fn store_id(&self) -> &str {
        &self.store_id
    }
    pub fn writer_fencing_policy_sha256(&self) -> &str {
        &self.writer_fencing_policy_sha256
    }
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn cas_service_id(&self) -> &str {
        &self.cas_service_id
    }
    pub fn cas_policy_sha256(&self) -> &str {
        &self.cas_policy_sha256
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn writer_id(&self) -> &str {
        &self.writer_id
    }
    pub fn lease_certificate_sha256(&self) -> &str {
        &self.lease_certificate_sha256
    }
    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
    pub fn worm_proven(&self) -> bool {
        false
    }
    pub fn snapshot_rollback_proven(&self) -> bool {
        false
    }
    pub fn multi_host_linearizability_proven(&self) -> bool {
        false
    }
    pub fn post_load_currentness_proven(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    store_id: String,
    writer_fencing_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    cas_service_id: String,
    cas_policy_sha256: String,
    epoch: u64,
    writer_id: String,
    lease_certificate_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FloorEvidence<'a> {
    schema: &'static str,
    store_id: &'a str,
    writer_fencing_policy_sha256: &'a str,
    state_identity: &'a str,
    remote_cursor_policy_sha256: &'a str,
    cas_service_id: &'a str,
    cas_policy_sha256: &'a str,
    epoch: u64,
    writer_id: &'a str,
    lease_certificate_sha256: &'a str,
    state_sha256: &'a str,
}

#[derive(Debug, Error)]
pub enum WriterEpochFloorStoreError {
    #[error("writer epoch floor store input is invalid")]
    InvalidInput,
    #[error("writer epoch floor store is missing")]
    StateMissing,
    #[error("writer epoch floor store is already provisioned")]
    AlreadyProvisioned,
    #[error("writer epoch floor state is invalid or non-canonical")]
    InvalidState,
    #[error("writer epoch floor did not advance strictly")]
    EpochDidNotAdvance,
    #[error("writer lease is expired")]
    ExpiredLease,
    #[error("writer epoch floor store is busy")]
    StoreBusy,
    #[error("unsafe writer epoch floor store: {0}")]
    UnsafeStore(&'static str),
    #[error("writer epoch floor store is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("writer epoch floor storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(unix)]
pub fn provision_writer_epoch_floor_store(
    store: &Path,
    audience: WriterEpochFloorAudience<'_>,
    initial: &VerifiedWriterLease,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    use std::os::unix::fs::DirBuilderExt;
    validate_lease(audience, initial)?;
    // Generate all fallible identity material before creating any filesystem
    // object, so entropy failure cannot leave a half-provisioned store.
    let store_id = random_store_id()?;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(store) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(WriterEpochFloorStoreError::AlreadyProvisioned)
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
    // The capability may have expired while filesystem setup or lock
    // acquisition was in progress.
    validate_lease(audience, initial)?;
    let state = make_state(audience, initial, store_id);
    atomic_replace(&directory, &encode_state(&state)?)?;
    let published = read_state(&directory)?.ok_or(WriterEpochFloorStoreError::StateMissing)?;
    if published != state {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    verify_store_path(store, &directory)?;
    floor_from_state(&published, audience)
}

#[cfg(not(unix))]
pub fn provision_writer_epoch_floor_store(
    _store: &Path,
    _audience: WriterEpochFloorAudience<'_>,
    _initial: &VerifiedWriterLease,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    Err(WriterEpochFloorStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn load_writer_epoch_floor(
    store: &Path,
    audience: WriterEpochFloorAudience<'_>,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    validate_audience(audience)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(WriterEpochFloorStoreError::StateMissing)?;
    floor_from_state(&state, audience)
}

#[cfg(not(unix))]
pub fn load_writer_epoch_floor(
    _store: &Path,
    _audience: WriterEpochFloorAudience<'_>,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    Err(WriterEpochFloorStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn advance_writer_epoch_floor(
    store: &Path,
    audience: WriterEpochFloorAudience<'_>,
    lease: &VerifiedWriterLease,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    validate_lease(audience, lease)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    // Never commit a lease that expired while waiting for the store lock.
    validate_lease(audience, lease)?;
    cleanup_stale_temporary_files(&directory)?;
    let state = read_state(&directory)?.ok_or(WriterEpochFloorStoreError::StateMissing)?;
    let current = floor_from_state(&state, audience)?;
    if lease.epoch() <= current.epoch {
        return Err(WriterEpochFloorStoreError::EpochDidNotAdvance);
    }
    let next = make_state(audience, lease, state.store_id.clone());
    atomic_replace(&directory, &encode_state(&next)?)?;
    let published = read_state(&directory)?.ok_or(WriterEpochFloorStoreError::StateMissing)?;
    if published != next {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    verify_store_path(store, &directory)?;
    floor_from_state(&published, audience)
}

#[cfg(not(unix))]
pub fn advance_writer_epoch_floor(
    _store: &Path,
    _audience: WriterEpochFloorAudience<'_>,
    _lease: &VerifiedWriterLease,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    Err(WriterEpochFloorStoreError::UnsupportedPlatform)
}

fn validate_lease(
    audience: WriterEpochFloorAudience<'_>,
    lease: &VerifiedWriterLease,
) -> Result<(), WriterEpochFloorStoreError> {
    validate_audience(audience)?;
    lease
        .ensure_monotonic_freshness()
        .map_err(|_| WriterEpochFloorStoreError::ExpiredLease)?;
    if lease.writer_fencing_policy_sha256() != audience.writer_fencing_policy_sha256
        || lease.state_identity() != audience.state_identity
        || lease.remote_cursor_policy_sha256() != audience.remote_cursor_policy_sha256
        || lease.cas_service_id() != audience.cas_service_id
        || lease.cas_policy_sha256() != audience.cas_policy_sha256
        || lease.epoch() == 0
    {
        return Err(WriterEpochFloorStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_audience(a: WriterEpochFloorAudience<'_>) -> Result<(), WriterEpochFloorStoreError> {
    if !valid_sha256(a.writer_fencing_policy_sha256)
        || !valid_id(a.state_identity)
        || !valid_sha256(a.remote_cursor_policy_sha256)
        || !valid_id(a.cas_service_id)
        || !valid_sha256(a.cas_policy_sha256)
    {
        return Err(WriterEpochFloorStoreError::InvalidInput);
    }
    Ok(())
}

fn make_state(
    a: WriterEpochFloorAudience<'_>,
    lease: &VerifiedWriterLease,
    store_id: String,
) -> DurableState {
    DurableState {
        schema: WRITER_EPOCH_FLOOR_STORE_SCHEMA.into(),
        store_id,
        writer_fencing_policy_sha256: a.writer_fencing_policy_sha256.into(),
        state_identity: a.state_identity.into(),
        remote_cursor_policy_sha256: a.remote_cursor_policy_sha256.into(),
        cas_service_id: a.cas_service_id.into(),
        cas_policy_sha256: a.cas_policy_sha256.into(),
        epoch: lease.epoch(),
        writer_id: lease.writer_id().into(),
        lease_certificate_sha256: lease.certificate_sha256().into(),
    }
}

fn floor_from_state(
    s: &DurableState,
    a: WriterEpochFloorAudience<'_>,
) -> Result<WriterEpochFloor, WriterEpochFloorStoreError> {
    validate_state(s)?;
    if s.writer_fencing_policy_sha256 != a.writer_fencing_policy_sha256
        || s.state_identity != a.state_identity
        || s.remote_cursor_policy_sha256 != a.remote_cursor_policy_sha256
        || s.cas_service_id != a.cas_service_id
        || s.cas_policy_sha256 != a.cas_policy_sha256
    {
        return Err(WriterEpochFloorStoreError::InvalidInput);
    }
    let state_sha256 = hash(&encode_state(s)?);
    let evidence = FloorEvidence {
        schema: WRITER_EPOCH_FLOOR_EVIDENCE_SCHEMA,
        store_id: &s.store_id,
        writer_fencing_policy_sha256: &s.writer_fencing_policy_sha256,
        state_identity: &s.state_identity,
        remote_cursor_policy_sha256: &s.remote_cursor_policy_sha256,
        cas_service_id: &s.cas_service_id,
        cas_policy_sha256: &s.cas_policy_sha256,
        epoch: s.epoch,
        writer_id: &s.writer_id,
        lease_certificate_sha256: &s.lease_certificate_sha256,
        state_sha256: &state_sha256,
    };
    let evidence_bytes =
        serde_json::to_vec(&evidence).map_err(|_| WriterEpochFloorStoreError::InvalidState)?;
    Ok(WriterEpochFloor {
        store_id: s.store_id.clone(),
        writer_fencing_policy_sha256: s.writer_fencing_policy_sha256.clone(),
        state_identity: s.state_identity.clone(),
        remote_cursor_policy_sha256: s.remote_cursor_policy_sha256.clone(),
        cas_service_id: s.cas_service_id.clone(),
        cas_policy_sha256: s.cas_policy_sha256.clone(),
        epoch: s.epoch,
        writer_id: s.writer_id.clone(),
        lease_certificate_sha256: s.lease_certificate_sha256.clone(),
        state_sha256,
        evidence_sha256: hash(&evidence_bytes),
    })
}

fn validate_state(s: &DurableState) -> Result<(), WriterEpochFloorStoreError> {
    if s.schema != WRITER_EPOCH_FLOOR_STORE_SCHEMA
        || !valid_sha256(&s.store_id)
        || !valid_sha256(&s.writer_fencing_policy_sha256)
        || !valid_id(&s.state_identity)
        || !valid_sha256(&s.remote_cursor_policy_sha256)
        || !valid_id(&s.cas_service_id)
        || !valid_sha256(&s.cas_policy_sha256)
        || s.epoch == 0
        || !valid_id(&s.writer_id)
        || !valid_sha256(&s.lease_certificate_sha256)
    {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    Ok(())
}

fn encode_state(s: &DurableState) -> Result<Vec<u8>, WriterEpochFloorStoreError> {
    validate_state(s)?;
    let bytes = serde_json::to_vec(s).map_err(|_| WriterEpochFloorStoreError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    Ok(bytes)
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

fn random_store_id() -> Result<String, WriterEpochFloorStoreError> {
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).map_err(|error| {
        WriterEpochFloorStoreError::Io(std::io::Error::other(error.to_string()))
    })?;
    Ok(format!("0x{}", hex_string(&random)))
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex_string(&Sha256::digest(bytes)))
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, WriterEpochFloorStoreError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, WriterEpochFloorStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            WriterEpochFloorStoreError::StateMissing
        } else {
            e.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(WriterEpochFloorStoreError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(WriterEpochFloorStoreError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), WriterEpochFloorStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_path)?;
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), WriterEpochFloorStoreError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(WriterEpochFloorStoreError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, WriterEpochFloorStoreError> {
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
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::NotFound {
            Err(WriterEpochFloorStoreError::StateMissing)
        } else {
            Err(e.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, WriterEpochFloorStoreError> {
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
    fn acquire(directory: &File) -> Result<Self, WriterEpochFloorStoreError> {
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
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) && e.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(e.into());
            }
            if Instant::now() >= deadline {
                return Err(WriterEpochFloorStoreError::StoreBusy);
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
fn read_state(directory: &File) -> Result<Option<DurableState>, WriterEpochFloorStoreError> {
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
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e.into())
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata()?;
    validate_file(&before)?;
    validate_named_file(directory, "state.json", &before)?;
    if before.len() == 0 || before.len() > MAX_STATE_BYTES {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(WriterEpochFloorStoreError::UnsafeStore("fileChanged"));
    }
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| WriterEpochFloorStoreError::InvalidState)?;
    if encode_state(&state)? != bytes {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), WriterEpochFloorStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(WriterEpochFloorStoreError::InvalidState);
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|e| WriterEpochFloorStoreError::Io(std::io::Error::other(e.to_string())))?;
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
            return Err(WriterEpochFloorStoreError::Io(
                std::io::Error::last_os_error(),
            ));
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
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), WriterEpochFloorStoreError> {
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
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
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
fn validate_directory(m: &Metadata) -> Result<(), WriterEpochFloorStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
        return Err(WriterEpochFloorStoreError::UnsafeStore(
            "directoryPermissions",
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_file(m: &Metadata) -> Result<(), WriterEpochFloorStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.permissions().mode() & 0o7777 != 0o600
    {
        return Err(WriterEpochFloorStoreError::UnsafeStore("filePermissions"));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), WriterEpochFloorStoreError> {
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
        return Err(WriterEpochFloorStoreError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
    {
        return Err(WriterEpochFloorStoreError::UnsafeStore("fileChanged"));
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
fn c_name(name: &str) -> Result<std::ffi::CString, WriterEpochFloorStoreError> {
    std::ffi::CString::new(name).map_err(|_| WriterEpochFloorStoreError::InvalidInput)
}
fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
