//! Single-host Unix store for one-time remote-cursor CAS caller challenges.
//!
//! Challenges are checked against a process-monotonic deadline and consumed
//! durably before a capability is returned. This crate has no networking,
//! signing, private-key, trusted-wall-clock, or snapshot-rollback facility.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const CHALLENGE_STORE_SCHEMA: &str = "bloch.products.remote-cursor-cas-challenge-store.v1";
const MAX_STATE_BYTES: u64 = 128 * 1024;
const MAX_OUTSTANDING: usize = 64;
const MAX_HISTORY: usize = 128;
const MAX_LIFETIME: Duration = Duration::from_secs(300);
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug)]
pub struct ChallengeAudience<'a> {
    pub caller_policy_sha256: &'a str,
    pub remote_cursor_policy_sha256: &'a str,
    pub state_identity: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableChallenge {
    serial: u64,
    nonce: String,
    caller_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    state_identity: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    store_id: String,
    next_serial: u64,
    outstanding: Vec<DurableChallenge>,
    consumed_sha256: Vec<String>,
}

/// Opaque in-process lease for a freshly issued nonce.
///
/// It deliberately cannot be serialized. A restart makes all outstanding
/// leases unusable; recovery must explicitly invalidate them before issuing
/// replacements.
#[derive(Debug)]
pub struct IssuedCasChallenge {
    store_id: String,
    serial: u64,
    nonce: String,
    caller_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    state_identity: String,
    monotonic_deadline: Instant,
}

impl IssuedCasChallenge {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn ensure_monotonic_freshness(&self) -> Result<(), ChallengeStoreError> {
        if Instant::now() >= self.monotonic_deadline {
            Err(ChallengeStoreError::Expired)
        } else {
            Ok(())
        }
    }
}

/// Opaque proof that this store durably consumed one exact issued nonce.
#[derive(Debug)]
pub struct ConsumedCasChallenge {
    nonce: String,
    caller_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    state_identity: String,
    consumption_sha256: String,
    monotonic_deadline: Instant,
}

impl ConsumedCasChallenge {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn caller_policy_sha256(&self) -> &str {
        &self.caller_policy_sha256
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn consumption_sha256(&self) -> &str {
        &self.consumption_sha256
    }

    /// Fails closed when the original issued lease reaches its deadline.
    pub fn ensure_monotonic_freshness(&self) -> Result<(), ChallengeStoreError> {
        if Instant::now() >= self.monotonic_deadline {
            Err(ChallengeStoreError::Expired)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum ChallengeStoreError {
    #[error("challenge store input is invalid")]
    InvalidInput,
    #[error("challenge store is missing")]
    StateMissing,
    #[error("challenge store is already provisioned")]
    AlreadyProvisioned,
    #[error("challenge store state is invalid or non-canonical")]
    InvalidState,
    #[error("challenge store is busy")]
    StoreBusy,
    #[error("challenge capacity is exhausted")]
    CapacityExhausted,
    #[error("challenge is expired")]
    Expired,
    #[error("challenge audience or nonce does not match")]
    ChallengeMismatch,
    #[error("challenge is not outstanding (already consumed or invalidated)")]
    NotOutstanding,
    #[error("unsafe challenge store: {0}")]
    UnsafeStore(&'static str),
    #[error("challenge storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("challenge store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(unix)]
pub fn provision_challenge_store(store: &Path) -> Result<(), ChallengeStoreError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(store) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(ChallengeStoreError::AlreadyProvisioned)
        } else {
            Err(error.into())
        };
    }
    let directory = open_directory(store)?;
    sync_parent_directory(store)?;
    let lock = create_file_exclusive(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    lock.sync_all()?;
    directory.sync_all()?;
    let _lock = StoreLock::acquire(&directory)?;
    let state = DurableState {
        schema: CHALLENGE_STORE_SCHEMA.into(),
        store_id: random_hex(32)?,
        next_serial: 1,
        outstanding: Vec::new(),
        consumed_sha256: Vec::new(),
    };
    atomic_replace(&directory, &encode_state(&state)?, None)?;
    ensure_published(&directory, &state)?;
    verify_store_path(store, &directory)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn provision_challenge_store(_store: &Path) -> Result<(), ChallengeStoreError> {
    Err(ChallengeStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn issue_challenge(
    store: &Path,
    audience: ChallengeAudience<'_>,
    lifetime: Duration,
) -> Result<IssuedCasChallenge, ChallengeStoreError> {
    validate_audience(audience)?;
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        return Err(ChallengeStoreError::InvalidInput);
    }
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let mut state = read_state(&directory)?.ok_or(ChallengeStoreError::StateMissing)?;
    if state.outstanding.len() >= MAX_OUTSTANDING {
        return Err(ChallengeStoreError::CapacityExhausted);
    }
    let deadline = Instant::now()
        .checked_add(lifetime)
        .ok_or(ChallengeStoreError::InvalidInput)?;
    let serial = state.next_serial;
    state.next_serial = state
        .next_serial
        .checked_add(1)
        .ok_or(ChallengeStoreError::CapacityExhausted)?;
    let nonce = random_hex(32)?;
    state.outstanding.push(DurableChallenge {
        serial,
        nonce: nonce.clone(),
        caller_policy_sha256: audience.caller_policy_sha256.into(),
        remote_cursor_policy_sha256: audience.remote_cursor_policy_sha256.into(),
        state_identity: audience.state_identity.into(),
    });
    atomic_replace(&directory, &encode_state(&state)?, Some(deadline))?;
    ensure_published(&directory, &state)?;
    verify_store_path(store, &directory)?;
    if Instant::now() >= deadline {
        return Err(ChallengeStoreError::Expired);
    }
    let issued = IssuedCasChallenge {
        store_id: state.store_id,
        serial,
        nonce,
        caller_policy_sha256: audience.caller_policy_sha256.into(),
        remote_cursor_policy_sha256: audience.remote_cursor_policy_sha256.into(),
        state_identity: audience.state_identity.into(),
        monotonic_deadline: deadline,
    };
    issued.ensure_monotonic_freshness()?;
    Ok(issued)
}

#[cfg(not(unix))]
pub fn issue_challenge(
    _store: &Path,
    _audience: ChallengeAudience<'_>,
    _lifetime: Duration,
) -> Result<IssuedCasChallenge, ChallengeStoreError> {
    Err(ChallengeStoreError::UnsupportedPlatform)
}

/// Atomically and durably consumes the exact nonce before returning proof.
#[cfg(unix)]
pub fn consume_challenge(
    store: &Path,
    audience: ChallengeAudience<'_>,
    issued: IssuedCasChallenge,
    presented_nonce: &str,
) -> Result<ConsumedCasChallenge, ChallengeStoreError> {
    validate_audience(audience)?;
    issued.ensure_monotonic_freshness()?;
    if issued.nonce != presented_nonce
        || issued.caller_policy_sha256 != audience.caller_policy_sha256
        || issued.remote_cursor_policy_sha256 != audience.remote_cursor_policy_sha256
        || issued.state_identity != audience.state_identity
    {
        return Err(ChallengeStoreError::ChallengeMismatch);
    }
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let mut state = read_state(&directory)?.ok_or(ChallengeStoreError::StateMissing)?;
    if state.store_id != issued.store_id {
        return Err(ChallengeStoreError::ChallengeMismatch);
    }
    let Some(index) = state.outstanding.iter().position(|candidate| {
        candidate.serial == issued.serial
            && candidate.nonce == issued.nonce
            && candidate.caller_policy_sha256 == issued.caller_policy_sha256
            && candidate.remote_cursor_policy_sha256 == issued.remote_cursor_policy_sha256
            && candidate.state_identity == issued.state_identity
    }) else {
        return Err(ChallengeStoreError::NotOutstanding);
    };
    issued.ensure_monotonic_freshness()?;
    let removed = state.outstanding.remove(index);
    let consumption_sha256 = challenge_hash(&state.store_id, &removed)?;
    state.consumed_sha256.push(consumption_sha256.clone());
    if state.consumed_sha256.len() > MAX_HISTORY {
        let excess = state.consumed_sha256.len() - MAX_HISTORY;
        state.consumed_sha256.drain(..excess);
    }
    atomic_replace(
        &directory,
        &encode_state(&state)?,
        Some(issued.monotonic_deadline),
    )?;
    ensure_published(&directory, &state)?;
    verify_store_path(store, &directory)?;
    issued.ensure_monotonic_freshness()?;
    Ok(ConsumedCasChallenge {
        nonce: removed.nonce,
        caller_policy_sha256: removed.caller_policy_sha256,
        remote_cursor_policy_sha256: removed.remote_cursor_policy_sha256,
        state_identity: removed.state_identity,
        consumption_sha256,
        monotonic_deadline: issued.monotonic_deadline,
    })
}

#[cfg(not(unix))]
pub fn consume_challenge(
    _store: &Path,
    _audience: ChallengeAudience<'_>,
    _issued: IssuedCasChallenge,
    _presented_nonce: &str,
) -> Result<ConsumedCasChallenge, ChallengeStoreError> {
    Err(ChallengeStoreError::UnsupportedPlatform)
}

/// Explicitly invalidates all leases, primarily for fail-closed restart recovery.
#[cfg(unix)]
pub fn invalidate_outstanding_challenges(store: &Path) -> Result<usize, ChallengeStoreError> {
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let mut state = read_state(&directory)?.ok_or(ChallengeStoreError::StateMissing)?;
    let count = state.outstanding.len();
    if count == 0 {
        return Ok(0);
    }
    let store_id = state.store_id.clone();
    let invalidated = state
        .outstanding
        .drain(..)
        .map(|challenge| challenge_hash(&store_id, &challenge))
        .collect::<Result<Vec<_>, _>>()?;
    state.consumed_sha256.extend(invalidated);
    if state.consumed_sha256.len() > MAX_HISTORY {
        let excess = state.consumed_sha256.len() - MAX_HISTORY;
        state.consumed_sha256.drain(..excess);
    }
    atomic_replace(&directory, &encode_state(&state)?, None)?;
    ensure_published(&directory, &state)?;
    verify_store_path(store, &directory)?;
    Ok(count)
}

#[cfg(not(unix))]
pub fn invalidate_outstanding_challenges(_store: &Path) -> Result<usize, ChallengeStoreError> {
    Err(ChallengeStoreError::UnsupportedPlatform)
}

fn validate_audience(audience: ChallengeAudience<'_>) -> Result<(), ChallengeStoreError> {
    if !valid_sha256(audience.caller_policy_sha256)
        || !valid_sha256(audience.remote_cursor_policy_sha256)
        || !valid_id(audience.state_identity)
    {
        return Err(ChallengeStoreError::InvalidInput);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_published(directory: &File, expected: &DurableState) -> Result<(), ChallengeStoreError> {
    let published = read_state(directory)?.ok_or(ChallengeStoreError::StateMissing)?;
    if &published != expected {
        return Err(ChallengeStoreError::InvalidState);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_nonce(value: &str) -> bool {
    valid_sha256(value)
}

fn challenge_hash(
    store_id: &str,
    challenge: &DurableChallenge,
) -> Result<String, ChallengeStoreError> {
    let bytes = serde_json::to_vec(&(store_id, challenge))
        .map_err(|_| ChallengeStoreError::InvalidState)?;
    Ok(format!("0x{}", hex_string(&Sha256::digest(bytes))))
}

fn validate_state(state: &DurableState) -> Result<(), ChallengeStoreError> {
    if state.schema != CHALLENGE_STORE_SCHEMA
        || !valid_nonce(&state.store_id)
        || state.next_serial == 0
        || state.outstanding.len() > MAX_OUTSTANDING
        || state.consumed_sha256.len() > MAX_HISTORY
        || state.consumed_sha256.iter().any(|hash| !valid_sha256(hash))
    {
        return Err(ChallengeStoreError::InvalidState);
    }
    let mut serials = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    let mut consumed = std::collections::BTreeSet::new();
    if !state
        .consumed_sha256
        .iter()
        .all(|hash| consumed.insert(hash))
    {
        return Err(ChallengeStoreError::InvalidState);
    }
    for challenge in &state.outstanding {
        if challenge.serial == 0
            || challenge.serial >= state.next_serial
            || !serials.insert(challenge.serial)
            || !valid_nonce(&challenge.nonce)
            || !nonces.insert(&challenge.nonce)
            || !valid_sha256(&challenge.caller_policy_sha256)
            || !valid_sha256(&challenge.remote_cursor_policy_sha256)
            || !valid_id(&challenge.state_identity)
        {
            return Err(ChallengeStoreError::InvalidState);
        }
    }
    Ok(())
}

fn encode_state(state: &DurableState) -> Result<Vec<u8>, ChallengeStoreError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| ChallengeStoreError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ChallengeStoreError::InvalidState);
    }
    Ok(bytes)
}

fn random_hex(bytes: usize) -> Result<String, ChallengeStoreError> {
    let mut random = vec![0_u8; bytes];
    getrandom::getrandom(&mut random)
        .map_err(|error| ChallengeStoreError::Io(std::io::Error::other(error.to_string())))?;
    Ok(format!("0x{}", hex_string(&random)))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, ChallengeStoreError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, ChallengeStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ChallengeStoreError::StateMissing
        } else {
            error.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(ChallengeStoreError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(ChallengeStoreError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ChallengeStoreError> {
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
fn verify_store_path(path: &Path, directory: &File) -> Result<(), ChallengeStoreError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(ChallengeStoreError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, ChallengeStoreError> {
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
            Err(ChallengeStoreError::StateMissing)
        } else {
            Err(error.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, ChallengeStoreError> {
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
    fn acquire(directory: &File) -> Result<Self, ChallengeStoreError> {
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
                return Err(ChallengeStoreError::StoreBusy);
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
fn read_state(directory: &File) -> Result<Option<DurableState>, ChallengeStoreError> {
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
        return Err(ChallengeStoreError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(ChallengeStoreError::UnsafeStore("fileChanged"));
    }
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| ChallengeStoreError::InvalidState)?;
    if encode_state(&state)? != bytes {
        return Err(ChallengeStoreError::InvalidState);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(
    directory: &File,
    bytes: &[u8],
    monotonic_deadline: Option<Instant>,
) -> Result<(), ChallengeStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ChallengeStoreError::InvalidState);
    }
    let temporary_name = format!(".state.json.tmp-{}", &random_hex(16)?[2..]);
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
        if monotonic_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ChallengeStoreError::Expired);
        }
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(ChallengeStoreError::Io(std::io::Error::last_os_error()));
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
fn validate_directory(metadata: &Metadata) -> Result<(), ChallengeStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ChallengeStoreError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata) -> Result<(), ChallengeStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ChallengeStoreError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), ChallengeStoreError> {
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
        return Err(ChallengeStoreError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
    {
        return Err(ChallengeStoreError::UnsafeStore("fileChanged"));
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
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, ChallengeStoreError> {
    std::ffi::CString::new(name).map_err(|_| ChallengeStoreError::InvalidInput)
}
