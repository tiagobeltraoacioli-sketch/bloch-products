//! Crash-safe single-host storage for an opaque verified replica-quorum report.
//!
//! Persistence never upgrades a quorum comparison into proof of consensus.

use bloch_local_state_remote_cursor_replica_quorum::VerifiedReplicaQuorum;
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

pub const QUORUM_REPORT_STORE_POLICY_SCHEMA: &str =
    "bloch.products.remote-cursor-quorum-report-store-policy.v1";
pub const QUORUM_REPORT_STORE_SCHEMA: &str = "bloch.products.remote-cursor-quorum-report-store.v1";
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: u64 = 256 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuorumReportStorePolicy {
    pub schema: String,
    pub policy_id: String,
    pub state_identity: String,
    pub replica_quorum_policy_sha256: String,
    pub remote_cursor_policy_sha256: String,
    pub trusted_time_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredReport {
    generation: u64,
    cursor_sha256: String,
    report_sha256: String,
    evaluated_at_unix_seconds: u64,
    canonical_report_json: String,
}

// Mirrors the upstream canonical document only to validate bytes recovered
// from disk. It cannot be converted into a verifier capability.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableReportDocument {
    schema: String,
    replica_quorum_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    trusted_time_policy_sha256: String,
    trusted_time_token_sha256: String,
    evaluated_at_unix_seconds: u64,
    quorum: u16,
    cursor: DurableCursor,
    cursor_sha256: String,
    oldest_counted_observation_unix_seconds: u64,
    freshest_observation_unix_seconds: u64,
    replica_ids: Vec<String>,
    observation_sha256s: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableCursor {
    schema: String,
    state_identity: String,
    generation: u64,
    checkpoint_sha256: String,
    checkpoint_policy_sha256: String,
    semantic_manifest_sha256: String,
    state_root_sha256: String,
    state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    store_id: String,
    store_policy_sha256: String,
    state_identity: String,
    replica_quorum_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    trusted_time_policy_sha256: String,
    latest: Option<StoredReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredQuorumReportSummary {
    pub generation: u64,
    pub cursor_sha256: String,
    pub report_sha256: String,
    pub evaluated_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreOutcome {
    Created,
    Advanced,
    ExactReplay,
}

#[derive(Debug, Error)]
pub enum QuorumReportStoreError {
    #[error("store policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("store policy pin mismatch")]
    PolicyPinMismatch,
    #[error("quorum report crosses the pinned store audience")]
    AudienceMismatch,
    #[error("quorum report would roll stored state back")]
    Rollback,
    #[error("quorum report conflicts at an already stored generation")]
    Equivocation,
    #[error("quorum report store is missing")]
    StateMissing,
    #[error("quorum report store is already provisioned")]
    AlreadyProvisioned,
    #[error("quorum report store state is invalid or non-canonical")]
    InvalidState,
    #[error("quorum report store is busy")]
    StoreBusy,
    #[error("unsafe quorum report store: {0}")]
    UnsafeStore(&'static str),
    #[error("quorum report storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("quorum report store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub fn store_policy_bytes(
    policy: &QuorumReportStorePolicy,
) -> Result<Vec<u8>, QuorumReportStoreError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| QuorumReportStoreError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(QuorumReportStoreError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn store_policy_sha256(
    policy: &QuorumReportStorePolicy,
) -> Result<String, QuorumReportStoreError> {
    Ok(hash(&store_policy_bytes(policy)?))
}

pub fn parse_store_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<QuorumReportStorePolicy, QuorumReportStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || !valid_sha256(expected_sha256) {
        return Err(QuorumReportStoreError::InvalidPolicy);
    }
    let policy: QuorumReportStorePolicy =
        serde_json::from_slice(bytes).map_err(|_| QuorumReportStoreError::InvalidPolicy)?;
    if store_policy_bytes(&policy)? != bytes {
        return Err(QuorumReportStoreError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_sha256)?;
    Ok(policy)
}

#[cfg(unix)]
pub fn provision_quorum_report_store(
    path: &Path,
    policy: &QuorumReportStorePolicy,
    expected_policy_sha256: &str,
) -> Result<(), QuorumReportStoreError> {
    use std::os::unix::fs::DirBuilderExt;
    validate_policy_pin(policy, expected_policy_sha256)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(path) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(QuorumReportStoreError::AlreadyProvisioned)
        } else {
            Err(error.into())
        };
    }
    let directory = open_directory(path)?;
    sync_parent_directory(path)?;
    let lock = create_file_exclusive(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    lock.sync_all()?;
    directory.sync_all()?;
    let _lock = StoreLock::acquire(&directory)?;
    let state = DurableState {
        schema: QUORUM_REPORT_STORE_SCHEMA.into(),
        store_id: random_hex(32)?,
        store_policy_sha256: expected_policy_sha256.into(),
        state_identity: policy.state_identity.clone(),
        replica_quorum_policy_sha256: policy.replica_quorum_policy_sha256.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        trusted_time_policy_sha256: policy.trusted_time_policy_sha256.clone(),
        latest: None,
    };
    atomic_replace(&directory, &encode_state(&state)?)?;
    ensure_published(&directory, &state)?;
    verify_store_path(path, &directory)
}

#[cfg(not(unix))]
pub fn provision_quorum_report_store(
    _path: &Path,
    _policy: &QuorumReportStorePolicy,
    _expected_policy_sha256: &str,
) -> Result<(), QuorumReportStoreError> {
    Err(QuorumReportStoreError::UnsupportedPlatform)
}

/// Persists only a verifier-created capability. Arbitrary report JSON is not accepted.
#[cfg(unix)]
pub fn persist_verified_quorum_report(
    path: &Path,
    policy: &QuorumReportStorePolicy,
    expected_policy_sha256: &str,
    report: &VerifiedReplicaQuorum,
) -> Result<StoreOutcome, QuorumReportStoreError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_report_audience(policy, report)?;
    let candidate = stored_report(report)?;
    let directory = open_store(path)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(path, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let mut state = read_state(&directory)?.ok_or(QuorumReportStoreError::StateMissing)?;
    validate_state_audience(&state, policy, expected_policy_sha256)?;
    let outcome = match state.latest.as_ref() {
        None => StoreOutcome::Created,
        Some(current) if candidate.generation < current.generation => {
            return Err(QuorumReportStoreError::Rollback);
        }
        Some(current) if candidate.generation == current.generation => {
            if &candidate == current {
                return Ok(StoreOutcome::ExactReplay);
            }
            return Err(QuorumReportStoreError::Equivocation);
        }
        Some(current)
            if candidate.evaluated_at_unix_seconds < current.evaluated_at_unix_seconds =>
        {
            return Err(QuorumReportStoreError::Rollback);
        }
        Some(_) => StoreOutcome::Advanced,
    };
    state.latest = Some(candidate);
    atomic_replace(&directory, &encode_state(&state)?)?;
    ensure_published(&directory, &state)?;
    verify_store_path(path, &directory)?;
    Ok(outcome)
}

#[cfg(not(unix))]
pub fn persist_verified_quorum_report(
    _path: &Path,
    _policy: &QuorumReportStorePolicy,
    _expected_policy_sha256: &str,
    _report: &VerifiedReplicaQuorum,
) -> Result<StoreOutcome, QuorumReportStoreError> {
    Err(QuorumReportStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn read_quorum_report_summary(
    path: &Path,
    policy: &QuorumReportStorePolicy,
    expected_policy_sha256: &str,
) -> Result<Option<StoredQuorumReportSummary>, QuorumReportStoreError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let directory = open_store(path)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(path, &directory)?;
    let state = read_state(&directory)?.ok_or(QuorumReportStoreError::StateMissing)?;
    validate_state_audience(&state, policy, expected_policy_sha256)?;
    Ok(state.latest.map(|report| StoredQuorumReportSummary {
        generation: report.generation,
        cursor_sha256: report.cursor_sha256,
        report_sha256: report.report_sha256,
        evaluated_at_unix_seconds: report.evaluated_at_unix_seconds,
    }))
}

#[cfg(not(unix))]
pub fn read_quorum_report_summary(
    _path: &Path,
    _policy: &QuorumReportStorePolicy,
    _expected_policy_sha256: &str,
) -> Result<Option<StoredQuorumReportSummary>, QuorumReportStoreError> {
    Err(QuorumReportStoreError::UnsupportedPlatform)
}

fn stored_report(report: &VerifiedReplicaQuorum) -> Result<StoredReport, QuorumReportStoreError> {
    let bytes = report.canonical_bytes();
    if bytes.is_empty() || bytes.len() > MAX_REPORT_BYTES {
        return Err(QuorumReportStoreError::InvalidState);
    }
    let canonical_report_json = std::str::from_utf8(bytes)
        .map_err(|_| QuorumReportStoreError::InvalidState)?
        .to_owned();
    let cursor_bytes = report
        .cursor()
        .canonical_bytes()
        .map_err(|_| QuorumReportStoreError::InvalidState)?;
    Ok(StoredReport {
        generation: report.cursor().generation(),
        cursor_sha256: hash(&cursor_bytes),
        report_sha256: hash(bytes),
        evaluated_at_unix_seconds: report.evaluated_at_unix_seconds(),
        canonical_report_json,
    })
}

fn validate_report_audience(
    policy: &QuorumReportStorePolicy,
    report: &VerifiedReplicaQuorum,
) -> Result<(), QuorumReportStoreError> {
    if report.cursor().state_identity() != policy.state_identity
        || report.replica_quorum_policy_sha256() != policy.replica_quorum_policy_sha256
        || report.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
        || report.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
    {
        return Err(QuorumReportStoreError::AudienceMismatch);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &QuorumReportStorePolicy,
    expected: &str,
) -> Result<(), QuorumReportStoreError> {
    if !valid_sha256(expected) || store_policy_sha256(policy)? != expected {
        return Err(QuorumReportStoreError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &QuorumReportStorePolicy) -> Result<(), QuorumReportStoreError> {
    if policy.schema != QUORUM_REPORT_STORE_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.replica_quorum_policy_sha256)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
    {
        return Err(QuorumReportStoreError::InvalidPolicy);
    }
    Ok(())
}

fn validate_state_audience(
    state: &DurableState,
    policy: &QuorumReportStorePolicy,
    pin: &str,
) -> Result<(), QuorumReportStoreError> {
    if state.store_policy_sha256 != pin
        || state.state_identity != policy.state_identity
        || state.replica_quorum_policy_sha256 != policy.replica_quorum_policy_sha256
        || state.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || state.trusted_time_policy_sha256 != policy.trusted_time_policy_sha256
    {
        return Err(QuorumReportStoreError::AudienceMismatch);
    }
    Ok(())
}

fn validate_state(state: &DurableState) -> Result<(), QuorumReportStoreError> {
    if state.schema != QUORUM_REPORT_STORE_SCHEMA
        || !valid_id(&state.store_id)
        || !valid_id(&state.state_identity)
        || !valid_sha256(&state.store_policy_sha256)
        || !valid_sha256(&state.replica_quorum_policy_sha256)
        || !valid_sha256(&state.remote_cursor_policy_sha256)
        || !valid_sha256(&state.trusted_time_policy_sha256)
    {
        return Err(QuorumReportStoreError::InvalidState);
    }
    if let Some(report) = &state.latest {
        if !valid_sha256(&report.cursor_sha256)
            || !valid_sha256(&report.report_sha256)
            || report.canonical_report_json.is_empty()
            || report.canonical_report_json.len() > MAX_REPORT_BYTES
            || hash(report.canonical_report_json.as_bytes()) != report.report_sha256
        {
            return Err(QuorumReportStoreError::InvalidState);
        }
        let document: DurableReportDocument = serde_json::from_str(&report.canonical_report_json)
            .map_err(|_| QuorumReportStoreError::InvalidState)?;
        let canonical =
            serde_json::to_vec(&document).map_err(|_| QuorumReportStoreError::InvalidState)?;
        let cursor_bytes = serde_json::to_vec(&document.cursor)
            .map_err(|_| QuorumReportStoreError::InvalidState)?;
        if canonical != report.canonical_report_json.as_bytes()
            || document.schema != "bloch.products.remote-cursor-replica-quorum-report.v1"
            || document.state_identity != state.state_identity
            || document.cursor.schema != "bloch.products.local-state-checkpoint-cursor.v2"
            || document.cursor.state_identity != state.state_identity
            || document.replica_quorum_policy_sha256 != state.replica_quorum_policy_sha256
            || document.remote_cursor_policy_sha256 != state.remote_cursor_policy_sha256
            || document.trusted_time_policy_sha256 != state.trusted_time_policy_sha256
            || document.cursor_sha256 != report.cursor_sha256
            || hash(&cursor_bytes) != report.cursor_sha256
            || document.cursor.generation != report.generation
            || document.evaluated_at_unix_seconds != report.evaluated_at_unix_seconds
        {
            return Err(QuorumReportStoreError::InvalidState);
        }
    }
    Ok(())
}

fn encode_state(state: &DurableState) -> Result<Vec<u8>, QuorumReportStoreError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| QuorumReportStoreError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(QuorumReportStoreError::InvalidState);
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
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
fn random_hex(length: usize) -> Result<String, QuorumReportStoreError> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| QuorumReportStoreError::Io(std::io::Error::other(error.to_string())))?;
    Ok(hex::encode(bytes))
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, QuorumReportStoreError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    Ok(directory)
}
#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, QuorumReportStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            QuorumReportStoreError::StateMissing
        } else {
            error.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(QuorumReportStoreError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(QuorumReportStoreError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}
#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), QuorumReportStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?
        .sync_all()?;
    Ok(())
}
#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), QuorumReportStoreError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(QuorumReportStoreError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}
#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, QuorumReportStoreError> {
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
            Err(QuorumReportStoreError::StateMissing)
        } else {
            Err(error.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, QuorumReportStoreError> {
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
    fn acquire(directory: &File) -> Result<Self, QuorumReportStoreError> {
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
                return Err(QuorumReportStoreError::StoreBusy);
            }
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
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
fn read_state(directory: &File) -> Result<Option<DurableState>, QuorumReportStoreError> {
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
        return Err(QuorumReportStoreError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(QuorumReportStoreError::UnsafeStore("fileChanged"));
    }
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| QuorumReportStoreError::InvalidState)?;
    if encode_state(&state)? != bytes {
        return Err(QuorumReportStoreError::InvalidState);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), QuorumReportStoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(QuorumReportStoreError::InvalidState);
    }
    let temporary = format!(".state.json.tmp-{}", random_hex(16)?);
    let temp_name = c_name(&temporary)?;
    let destination = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temp_name.as_ptr(),
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
                temp_name.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(QuorumReportStoreError::Io(std::io::Error::last_os_error()));
        }
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    result
}

#[cfg(unix)]
fn ensure_published(
    directory: &File,
    expected: &DurableState,
) -> Result<(), QuorumReportStoreError> {
    if read_state(directory)?.as_ref() != Some(expected) {
        return Err(QuorumReportStoreError::InvalidState);
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), QuorumReportStoreError> {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd};
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe {
            libc::close(duplicate);
        }
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
        let c_name = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        validate_file(&metadata)?;
        validate_named_file(directory, name, &metadata)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
    })();
    unsafe {
        libc::closedir(stream);
    }
    result
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), QuorumReportStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(QuorumReportStoreError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_file(metadata: &Metadata) -> Result<(), QuorumReportStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(QuorumReportStoreError::UnsafeStore("filePermissions"));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), QuorumReportStoreError> {
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
        return Err(QuorumReportStoreError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
    {
        return Err(QuorumReportStoreError::UnsafeStore("fileChanged"));
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
fn c_name(name: &str) -> Result<std::ffi::CString, QuorumReportStoreError> {
    std::ffi::CString::new(name).map_err(|_| QuorumReportStoreError::InvalidState)
}
