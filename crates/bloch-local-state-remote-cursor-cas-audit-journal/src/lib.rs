//! Single-host crash-safe audit journal for verified remote-cursor CAS results.
//!
//! Hash chaining does not make this mutable file WORM or snapshot-resistant.

use bloch_local_state_remote_cursor::VerifiedRemoteCursorCasReceipt;
use bloch_local_state_remote_cursor_cas_session::VerifiedRemoteCursorCasSession;
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

pub const CAS_AUDIT_JOURNAL_POLICY_SCHEMA: &str =
    "bloch.products.remote-cursor-cas-audit-journal-policy.v1";
pub const CAS_AUDIT_JOURNAL_SCHEMA: &str = "bloch.products.remote-cursor-cas-audit-journal.v1";
pub const CAS_AUDIT_ENTRY_SCHEMA: &str = "bloch.products.remote-cursor-cas-audit-entry.v1";
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CasAuditJournalPolicy {
    pub schema: String,
    pub policy_id: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub cas_policy_sha256: String,
    pub cas_signature_domain: String,
    pub authenticated_transport_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditedCasDecision {
    Accepted,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditEntryBody {
    schema: String,
    sequence: u64,
    previous_entry_sha256: Option<String>,
    generation: u64,
    request_sha256: String,
    transport_evidence_sha256: String,
    receipt_sha256: String,
    decision: AuditedCasDecision,
    refusal_reason_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditEntry {
    body: AuditEntryBody,
    entry_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JournalState {
    schema: String,
    journal_id: String,
    journal_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    cas_policy_sha256: String,
    cas_signature_domain: String,
    authenticated_transport_policy_sha256: String,
    entries: Vec<AuditEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntrySummary {
    pub sequence: u64,
    pub generation: u64,
    pub request_sha256: String,
    pub transport_evidence_sha256: String,
    pub receipt_sha256: String,
    pub decision: AuditedCasDecision,
    pub entry_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    ExactReplay,
}

#[derive(Debug, Error)]
pub enum CasAuditJournalError {
    #[error("CAS audit journal policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("CAS audit journal policy pin mismatch")]
    PolicyPinMismatch,
    #[error("verified capabilities cross the pinned journal audience")]
    AudienceMismatch,
    #[error("CAS audit journal append would roll back generation")]
    Rollback,
    #[error("CAS audit journal append conflicts with existing evidence")]
    Equivocation,
    #[error("CAS audit journal is missing")]
    StateMissing,
    #[error("CAS audit journal is already provisioned")]
    AlreadyProvisioned,
    #[error("CAS audit journal state is invalid or non-canonical")]
    InvalidState,
    #[error("CAS audit journal is full")]
    JournalFull,
    #[error("CAS audit journal is busy")]
    StoreBusy,
    #[error("unsafe CAS audit journal store: {0}")]
    UnsafeStore(&'static str),
    #[error("CAS audit journal is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("CAS audit journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub fn journal_policy_bytes(
    policy: &CasAuditJournalPolicy,
) -> Result<Vec<u8>, CasAuditJournalError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| CasAuditJournalError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(CasAuditJournalError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn journal_policy_sha256(
    policy: &CasAuditJournalPolicy,
) -> Result<String, CasAuditJournalError> {
    Ok(hash(&journal_policy_bytes(policy)?))
}

pub fn parse_journal_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<CasAuditJournalPolicy, CasAuditJournalError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || !valid_sha256(expected_sha256) {
        return Err(CasAuditJournalError::InvalidPolicy);
    }
    let policy: CasAuditJournalPolicy =
        serde_json::from_slice(bytes).map_err(|_| CasAuditJournalError::InvalidPolicy)?;
    if journal_policy_bytes(&policy)? != bytes {
        return Err(CasAuditJournalError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_sha256)?;
    Ok(policy)
}

#[cfg(unix)]
pub fn provision_cas_audit_journal(
    path: &Path,
    policy: &CasAuditJournalPolicy,
    expected_policy_sha256: &str,
) -> Result<(), CasAuditJournalError> {
    use std::os::unix::fs::DirBuilderExt;
    validate_policy_pin(policy, expected_policy_sha256)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(path) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(CasAuditJournalError::AlreadyProvisioned)
        } else {
            Err(error.into())
        };
    }
    let directory = open_directory(path)?;
    sync_parent_directory(path)?;
    let lock = create_file_exclusive(&directory, "journal.lock")?;
    validate_file(&lock.metadata()?)?;
    lock.sync_all()?;
    directory.sync_all()?;
    let _lock = JournalLock::acquire(&directory)?;
    let state = JournalState {
        schema: CAS_AUDIT_JOURNAL_SCHEMA.into(),
        journal_id: random_hex(32)?,
        journal_policy_sha256: expected_policy_sha256.into(),
        state_identity: policy.state_identity.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        cas_policy_sha256: policy.cas_policy_sha256.clone(),
        cas_signature_domain: policy.cas_signature_domain.clone(),
        authenticated_transport_policy_sha256: policy.authenticated_transport_policy_sha256.clone(),
        entries: Vec::new(),
    };
    atomic_replace(&directory, &encode_state(&state)?)?;
    ensure_published(&directory, &state)?;
    verify_store_path(path, &directory)
}

#[cfg(not(unix))]
pub fn provision_cas_audit_journal(
    _path: &Path,
    _policy: &CasAuditJournalPolicy,
    _expected_policy_sha256: &str,
) -> Result<(), CasAuditJournalError> {
    Err(CasAuditJournalError::UnsupportedPlatform)
}

/// Appends only verifier-produced receipt and transport capabilities.
#[cfg(unix)]
pub fn append_verified_cas_event(
    path: &Path,
    policy: &CasAuditJournalPolicy,
    expected_policy_sha256: &str,
    session: &VerifiedRemoteCursorCasSession,
) -> Result<AppendOutcome, CasAuditJournalError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_capability(policy, session)?;
    let candidate = candidate_entry(session)?;
    let directory = open_store(path)?;
    let _lock = JournalLock::acquire(&directory)?;
    verify_store_path(path, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let mut state = read_state(&directory)?.ok_or(CasAuditJournalError::StateMissing)?;
    validate_state_audience(&state, policy, expected_policy_sha256)?;

    if let Some(existing) = state
        .entries
        .iter()
        .find(|entry| entry.body.request_sha256 == candidate.request_sha256)
    {
        if existing.body.generation == candidate.generation
            && existing.body.transport_evidence_sha256 == candidate.transport_evidence_sha256
            && existing.body.receipt_sha256 == candidate.receipt_sha256
            && existing.body.decision == candidate.decision
            && existing.body.refusal_reason_code == candidate.refusal_reason_code
        {
            return Ok(AppendOutcome::ExactReplay);
        }
        return Err(CasAuditJournalError::Equivocation);
    }

    if let Some(last) = state.entries.last() {
        if candidate.generation < last.body.generation {
            return Err(CasAuditJournalError::Rollback);
        }
        if candidate.generation == last.body.generation
            && candidate.decision == AuditedCasDecision::Accepted
            && state.entries.iter().any(|entry| {
                entry.body.generation == candidate.generation
                    && entry.body.decision == AuditedCasDecision::Accepted
            })
        {
            return Err(CasAuditJournalError::Equivocation);
        }
    }
    if state.entries.len() >= MAX_ENTRIES {
        return Err(CasAuditJournalError::JournalFull);
    }
    let body = AuditEntryBody {
        schema: CAS_AUDIT_ENTRY_SCHEMA.into(),
        sequence: state.entries.len() as u64,
        previous_entry_sha256: state.entries.last().map(|entry| entry.entry_sha256.clone()),
        generation: candidate.generation,
        request_sha256: candidate.request_sha256,
        transport_evidence_sha256: candidate.transport_evidence_sha256,
        receipt_sha256: candidate.receipt_sha256,
        decision: candidate.decision,
        refusal_reason_code: candidate.refusal_reason_code,
    };
    let entry = AuditEntry {
        entry_sha256: hash(&entry_body_bytes(&body)?),
        body,
    };
    state.entries.push(entry);
    atomic_replace(&directory, &encode_state(&state)?)?;
    ensure_published(&directory, &state)?;
    verify_store_path(path, &directory)?;
    Ok(AppendOutcome::Appended)
}

#[cfg(not(unix))]
pub fn append_verified_cas_event(
    _path: &Path,
    _policy: &CasAuditJournalPolicy,
    _expected_policy_sha256: &str,
    _session: &VerifiedRemoteCursorCasSession,
) -> Result<AppendOutcome, CasAuditJournalError> {
    Err(CasAuditJournalError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn read_cas_audit_entries(
    path: &Path,
    policy: &CasAuditJournalPolicy,
    expected_policy_sha256: &str,
) -> Result<Vec<AuditEntrySummary>, CasAuditJournalError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let directory = open_store(path)?;
    let _lock = JournalLock::acquire(&directory)?;
    verify_store_path(path, &directory)?;
    let state = read_state(&directory)?.ok_or(CasAuditJournalError::StateMissing)?;
    validate_state_audience(&state, policy, expected_policy_sha256)?;
    Ok(state
        .entries
        .into_iter()
        .map(|entry| AuditEntrySummary {
            sequence: entry.body.sequence,
            generation: entry.body.generation,
            request_sha256: entry.body.request_sha256,
            transport_evidence_sha256: entry.body.transport_evidence_sha256,
            receipt_sha256: entry.body.receipt_sha256,
            decision: entry.body.decision,
            entry_sha256: entry.entry_sha256,
        })
        .collect())
}

#[cfg(not(unix))]
pub fn read_cas_audit_entries(
    _path: &Path,
    _policy: &CasAuditJournalPolicy,
    _expected_policy_sha256: &str,
) -> Result<Vec<AuditEntrySummary>, CasAuditJournalError> {
    Err(CasAuditJournalError::UnsupportedPlatform)
}

struct CandidateEntry {
    generation: u64,
    request_sha256: String,
    transport_evidence_sha256: String,
    receipt_sha256: String,
    decision: AuditedCasDecision,
    refusal_reason_code: Option<String>,
}

fn candidate_entry(
    session: &VerifiedRemoteCursorCasSession,
) -> Result<CandidateEntry, CasAuditJournalError> {
    let receipt = session.receipt();
    let (decision, refusal_reason_code) = match receipt {
        VerifiedRemoteCursorCasReceipt::Accepted(_) => (AuditedCasDecision::Accepted, None),
        VerifiedRemoteCursorCasReceipt::Refused(value) => (
            AuditedCasDecision::Refused,
            Some(value.reason_code().to_owned()),
        ),
    };
    Ok(CandidateEntry {
        generation: receipt.successor().generation(),
        request_sha256: receipt.request_sha256().into(),
        transport_evidence_sha256: session.transport_evidence_sha256().into(),
        receipt_sha256: receipt.receipt_sha256().into(),
        decision,
        refusal_reason_code,
    })
}

fn validate_capability(
    policy: &CasAuditJournalPolicy,
    session: &VerifiedRemoteCursorCasSession,
) -> Result<(), CasAuditJournalError> {
    let receipt = session.receipt();
    if receipt.state_identity() != policy.state_identity
        || receipt.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
        || receipt.remote_cursor_policy_sha256() != policy.cas_policy_sha256
        || receipt.signature_domain() != policy.cas_signature_domain
        || session.transport_policy_sha256() != policy.authenticated_transport_policy_sha256
        || session.request_sha256() != receipt.request_sha256()
        || session.receipt_sha256() != receipt.receipt_sha256()
    {
        return Err(CasAuditJournalError::AudienceMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &CasAuditJournalPolicy) -> Result<(), CasAuditJournalError> {
    if policy.schema != CAS_AUDIT_JOURNAL_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.state_identity)
        || !valid_id(&policy.cas_signature_domain)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || !valid_sha256(&policy.cas_policy_sha256)
        || policy.remote_cursor_policy_sha256 != policy.cas_policy_sha256
        || !valid_sha256(&policy.authenticated_transport_policy_sha256)
    {
        return Err(CasAuditJournalError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &CasAuditJournalPolicy,
    expected: &str,
) -> Result<(), CasAuditJournalError> {
    if !valid_sha256(expected) || journal_policy_sha256(policy)? != expected {
        return Err(CasAuditJournalError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_state_audience(
    state: &JournalState,
    policy: &CasAuditJournalPolicy,
    pin: &str,
) -> Result<(), CasAuditJournalError> {
    if state.journal_policy_sha256 != pin
        || state.state_identity != policy.state_identity
        || state.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || state.cas_policy_sha256 != policy.cas_policy_sha256
        || state.cas_signature_domain != policy.cas_signature_domain
        || state.authenticated_transport_policy_sha256
            != policy.authenticated_transport_policy_sha256
    {
        return Err(CasAuditJournalError::AudienceMismatch);
    }
    Ok(())
}

fn entry_body_bytes(body: &AuditEntryBody) -> Result<Vec<u8>, CasAuditJournalError> {
    serde_json::to_vec(body).map_err(|_| CasAuditJournalError::InvalidState)
}

fn validate_state(state: &JournalState) -> Result<(), CasAuditJournalError> {
    if state.schema != CAS_AUDIT_JOURNAL_SCHEMA
        || !valid_id(&state.journal_id)
        || !valid_id(&state.state_identity)
        || !valid_id(&state.cas_signature_domain)
        || !valid_sha256(&state.journal_policy_sha256)
        || !valid_sha256(&state.remote_cursor_policy_sha256)
        || !valid_sha256(&state.cas_policy_sha256)
        || state.remote_cursor_policy_sha256 != state.cas_policy_sha256
        || !valid_sha256(&state.authenticated_transport_policy_sha256)
        || state.entries.len() > MAX_ENTRIES
    {
        return Err(CasAuditJournalError::InvalidState);
    }
    let mut previous: Option<&str> = None;
    let mut generation: Option<u64> = None;
    let mut accepted_generations = std::collections::BTreeSet::new();
    let mut requests = std::collections::BTreeSet::new();
    for (index, entry) in state.entries.iter().enumerate() {
        if entry.body.schema != CAS_AUDIT_ENTRY_SCHEMA
            || entry.body.sequence != index as u64
            || entry.body.previous_entry_sha256.as_deref() != previous
            || !valid_sha256(&entry.body.request_sha256)
            || !valid_sha256(&entry.body.transport_evidence_sha256)
            || !valid_sha256(&entry.body.receipt_sha256)
            || !valid_sha256(&entry.entry_sha256)
            || hash(&entry_body_bytes(&entry.body)?) != entry.entry_sha256
            || !requests.insert(entry.body.request_sha256.as_str())
            || generation.is_some_and(|current| entry.body.generation < current)
        {
            return Err(CasAuditJournalError::InvalidState);
        }
        match entry.body.decision {
            AuditedCasDecision::Accepted => {
                if entry.body.refusal_reason_code.is_some()
                    || !accepted_generations.insert(entry.body.generation)
                {
                    return Err(CasAuditJournalError::InvalidState);
                }
            }
            AuditedCasDecision::Refused => {
                if !entry
                    .body
                    .refusal_reason_code
                    .as_deref()
                    .is_some_and(valid_id)
                {
                    return Err(CasAuditJournalError::InvalidState);
                }
            }
        }
        generation = Some(entry.body.generation);
        previous = Some(&entry.entry_sha256);
    }
    Ok(())
}

fn encode_state(state: &JournalState) -> Result<Vec<u8>, CasAuditJournalError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| CasAuditJournalError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(CasAuditJournalError::JournalFull);
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
fn random_hex(length: usize) -> Result<String, CasAuditJournalError> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| CasAuditJournalError::Io(std::io::Error::other(error.to_string())))?;
    Ok(hex::encode(bytes))
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, CasAuditJournalError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "journal.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "journal.lock", &lock.metadata()?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, CasAuditJournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CasAuditJournalError::StateMissing
        } else {
            error.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(CasAuditJournalError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(CasAuditJournalError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), CasAuditJournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?
        .sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), CasAuditJournalError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(CasAuditJournalError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, CasAuditJournalError> {
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
            Err(CasAuditJournalError::StateMissing)
        } else {
            Err(error.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, CasAuditJournalError> {
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
struct JournalLock {
    file: File,
}
#[cfg(unix)]
impl JournalLock {
    fn acquire(directory: &File) -> Result<Self, CasAuditJournalError> {
        use std::os::fd::AsRawFd;
        let file = open_existing_file(directory, "journal.lock")?;
        validate_file(&file.metadata()?)?;
        validate_named_file(directory, "journal.lock", &file.metadata()?)?;
        let deadline = Instant::now() + MAX_LOCK_WAIT;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                validate_file(&file.metadata()?)?;
                validate_named_file(directory, "journal.lock", &file.metadata()?)?;
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK)
                && error.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Err(CasAuditJournalError::StoreBusy);
            }
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
    }
}
#[cfg(unix)]
impl Drop for JournalLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
fn read_state(directory: &File) -> Result<Option<JournalState>, CasAuditJournalError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name("journal.json")?;
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
    validate_named_file(directory, "journal.json", &before)?;
    if before.len() == 0 || before.len() > MAX_STATE_BYTES {
        return Err(CasAuditJournalError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "journal.json", &after)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(CasAuditJournalError::UnsafeStore("fileChanged"));
    }
    let state: JournalState =
        serde_json::from_slice(&bytes).map_err(|_| CasAuditJournalError::InvalidState)?;
    if encode_state(&state)? != bytes {
        return Err(CasAuditJournalError::InvalidState);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), CasAuditJournalError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(CasAuditJournalError::JournalFull);
    }
    let temporary = format!(".journal.json.tmp-{}", random_hex(16)?);
    let temp_name = c_name(&temporary)?;
    let destination = c_name("journal.json")?;
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
        validate_file(&file.metadata()?)?;
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
            return Err(CasAuditJournalError::Io(std::io::Error::last_os_error()));
        }
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0) };
    }
    result
}

#[cfg(unix)]
fn ensure_published(directory: &File, expected: &JournalState) -> Result<(), CasAuditJournalError> {
    if read_state(directory)?.as_ref() != Some(expected) {
        return Err(CasAuditJournalError::InvalidState);
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), CasAuditJournalError> {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd};
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
        let Some(suffix) = name.strip_prefix(".journal.json.tmp-") else {
            continue;
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), CasAuditJournalError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CasAuditJournalError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata) -> Result<(), CasAuditJournalError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(CasAuditJournalError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    expected: &Metadata,
) -> Result<(), CasAuditJournalError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let reopened = unsafe { File::from_raw_fd(fd) };
    let metadata = reopened.metadata()?;
    validate_file(&metadata)?;
    if !same_object(expected, &metadata) {
        return Err(CasAuditJournalError::UnsafeStore("fileChanged"));
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
fn c_name(name: &str) -> Result<std::ffi::CString, CasAuditJournalError> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return Err(CasAuditJournalError::UnsafeStore("fileName"));
    }
    std::ffi::CString::new(name).map_err(|_| CasAuditJournalError::UnsafeStore("fileName"))
}
