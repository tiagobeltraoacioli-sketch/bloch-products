//! Local, verifiable retention for authenticated outbox audit artifacts.
//!
//! Every entry is a private, create-once file whose canonical digest commits
//! to the preceding entry. Verification still requires the audit trust policy
//! and its SHA-256 pin from outside the ledger. This is local tamper evidence,
//! not WORM storage, distributed/HA coordination, or proof of L2 finality.

use bloch_indexer_audit::{
    AuditError, AuditExpectation, AuditTrustPolicy, VerifiedAuditArtifact,
    audit_trust_policy_sha256, export_audit_artifact, parse_audit_trust_policy,
    verify_audit_artifact, verify_detached_signature,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

mod checkpoint;

pub use checkpoint::{
    MAX_RETENTION_CHECKPOINT_BYTES, MAX_RETENTION_CHECKPOINT_POLICY_BYTES,
    RETENTION_CHECKPOINT_POLICY_SCHEMA, RETENTION_CHECKPOINT_SCHEMA, RetentionCheckpointError,
    RetentionCheckpointPolicy, RetentionCheckpointSigner, VerifiedRetentionCheckpoint,
    canonical_retention_checkpoint_policy_bytes, export_retention_checkpoint,
    parse_retention_checkpoint_policy, retention_checkpoint_policy_sha256,
    retention_checkpoint_signature_message, verify_retention_checkpoint,
    verify_retention_checkpoint_against_ledger,
};

pub const RETENTION_ENTRY_SCHEMA: &str = "bloch.data.outbox-audit-retention-entry.v1";
pub const MAX_RETENTION_ENTRIES: usize = 100_000;
pub const MAX_RETENTION_ENTRY_BYTES: u64 = 2 * 1024 * 1024;
const GENESIS_ENTRY_SHA256: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedAuditEntry {
    pub sequence: u64,
    pub previous_entry_sha256: String,
    pub entry_sha256: String,
    pub policy_sha256: String,
    pub signer_id: String,
    pub artifact: VerifiedAuditArtifact,
}

/// Independently retained ledger boundary. Supplying it detects valid-entry
/// truncation or reordering followed by recomputation of unkeyed chain hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionExpectation {
    pub entry_count: u64,
    pub head_sha256: String,
}

#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("secure local audit retention is unsupported on this platform")]
    Unsupported,
    #[error("unsafe ledger: {0}")]
    UnsafeLedger(&'static str),
    #[error("ledger contains an invalid entry name")]
    InvalidEntryName,
    #[error("ledger exceeds its {0}-entry limit")]
    TooManyEntries(usize),
    #[error("retention entry exceeds its {maximum}-byte limit: {actual} bytes")]
    EntryTooLarge { actual: u64, maximum: u64 },
    #[error("retention entry is invalid: {0}")]
    InvalidEntry(&'static str),
    #[error("retention entry is not canonical")]
    NonCanonicalEntry,
    #[error("retention chain is discontinuous")]
    ChainDiscontinuity,
    #[error("another writer won the create-once append race")]
    ConcurrentAppend,
    #[error("audit verification failed: {0}")]
    Audit(#[from] AuditError),
    #[error("retention JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("retention I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EntryDocument {
    schema: String,
    sequence: u64,
    previous_entry_sha256: String,
    policy_sha256: String,
    signer_id: String,
    artifact_sha256: String,
    artifact: Value,
    signature_ed25519: String,
    entry_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryCommitment<'a> {
    schema: &'static str,
    sequence: u64,
    previous_entry_sha256: &'a str,
    policy_sha256: &'a str,
    signer_id: &'a str,
    artifact_sha256: &'a str,
    artifact: &'a Value,
    signature_ed25519: &'a str,
}

/// Verifies and appends one authenticated artifact. The entry file is created
/// with `O_EXCL`; concurrent callers cannot replace the winner.
pub fn append_audit_entry(
    ledger: &Path,
    artifact_bytes: &[u8],
    expected_artifact: Option<&AuditExpectation>,
    signer_id: &str,
    signature_bytes: &[u8],
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<RetainedAuditEntry, RetentionError> {
    #[cfg(not(unix))]
    {
        let _ = (
            ledger,
            artifact_bytes,
            expected_artifact,
            signer_id,
            signature_bytes,
            policy_bytes,
            expected_policy_sha256,
        );
        return Err(RetentionError::Unsupported);
    }
    #[cfg(unix)]
    {
        let directory = open_secure_ledger(ledger)?;
        let policy = parse_audit_trust_policy(policy_bytes, expected_policy_sha256)?;
        let artifact = verify_audit_artifact(artifact_bytes, expected_artifact)?;
        verify_detached_signature(&artifact, signer_id, signature_bytes, &policy)?;

        let existing = verify_open_ledger(&directory, &policy, expected_policy_sha256)?;
        let sequence = u64::try_from(existing.len())
            .map_err(|_| RetentionError::TooManyEntries(MAX_RETENTION_ENTRIES))?
            .checked_add(1)
            .ok_or(RetentionError::TooManyEntries(MAX_RETENTION_ENTRIES))?;
        if sequence as usize > MAX_RETENTION_ENTRIES {
            return Err(RetentionError::TooManyEntries(MAX_RETENTION_ENTRIES));
        }
        let previous = existing
            .last()
            .map_or(GENESIS_ENTRY_SHA256, |entry| entry.entry_sha256.as_str());
        let canonical_artifact = export_audit_artifact(&artifact.checkpoint)?;
        let artifact_value: Value = serde_json::from_slice(&canonical_artifact)?;
        let signature = format!("0x{}", hex::encode(signature_bytes));
        let policy_sha256 = audit_trust_policy_sha256(&policy)?;
        let mut document = EntryDocument {
            schema: RETENTION_ENTRY_SCHEMA.into(),
            sequence,
            previous_entry_sha256: previous.into(),
            policy_sha256,
            signer_id: signer_id.into(),
            artifact_sha256: artifact.canonical_sha256.clone(),
            artifact: artifact_value,
            signature_ed25519: signature,
            entry_sha256: String::new(),
        };
        document.entry_sha256 = commitment_sha256(&document)?;
        let mut bytes = serde_json::to_vec(&document)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RETENTION_ENTRY_BYTES {
            return Err(RetentionError::EntryTooLarge {
                actual: bytes.len() as u64,
                maximum: MAX_RETENTION_ENTRY_BYTES,
            });
        }
        create_entry(&directory, sequence, &bytes)?;
        verify_ledger_path(ledger, &directory)?;
        directory.sync_all()?;
        Ok(retained(&document, artifact))
    }
}

/// Replays the complete chain and re-verifies every artifact and detached
/// signature against the independently pinned policy.
pub fn verify_audit_ledger(
    ledger: &Path,
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<Vec<RetainedAuditEntry>, RetentionError> {
    verify_audit_ledger_with_expectation(ledger, policy_bytes, expected_policy_sha256, None)
}

/// Replays the ledger and additionally compares its count and head digest to
/// an independently retained boundary when supplied.
pub fn verify_audit_ledger_with_expectation(
    ledger: &Path,
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
    expected_ledger: Option<&RetentionExpectation>,
) -> Result<Vec<RetainedAuditEntry>, RetentionError> {
    #[cfg(not(unix))]
    {
        let _ = (
            ledger,
            policy_bytes,
            expected_policy_sha256,
            expected_ledger,
        );
        Err(RetentionError::Unsupported)
    }
    #[cfg(unix)]
    {
        let directory = open_secure_ledger(ledger)?;
        let policy = parse_audit_trust_policy(policy_bytes, expected_policy_sha256)?;
        let entries = verify_open_ledger(&directory, &policy, expected_policy_sha256)?;
        if let Some(expected) = expected_ledger {
            let count = u64::try_from(entries.len())
                .map_err(|_| RetentionError::TooManyEntries(MAX_RETENTION_ENTRIES))?;
            let head = entries
                .last()
                .map_or(GENESIS_ENTRY_SHA256, |entry| entry.entry_sha256.as_str());
            if expected.entry_count != count
                || !valid_sha256(&expected.head_sha256)
                || expected.head_sha256 != head
            {
                return Err(RetentionError::InvalidEntry("ledgerExpectation"));
            }
        }
        verify_ledger_path(ledger, &directory)?;
        Ok(entries)
    }
}

fn commitment_sha256(document: &EntryDocument) -> Result<String, RetentionError> {
    let bytes = serde_json::to_vec(&EntryCommitment {
        schema: RETENTION_ENTRY_SCHEMA,
        sequence: document.sequence,
        previous_entry_sha256: &document.previous_entry_sha256,
        policy_sha256: &document.policy_sha256,
        signer_id: &document.signer_id,
        artifact_sha256: &document.artifact_sha256,
        artifact: &document.artifact,
        signature_ed25519: &document.signature_ed25519,
    })?;
    Ok(sha256_hex(&bytes))
}

fn verify_document(
    document: &EntryDocument,
    raw: &[u8],
    expected_sequence: u64,
    previous: &str,
    policy: &AuditTrustPolicy,
    expected_policy_sha256: &str,
) -> Result<RetainedAuditEntry, RetentionError> {
    if document.schema != RETENTION_ENTRY_SCHEMA {
        return Err(RetentionError::InvalidEntry("schema"));
    }
    if document.sequence != expected_sequence || document.previous_entry_sha256 != previous {
        return Err(RetentionError::ChainDiscontinuity);
    }
    if document.policy_sha256 != expected_policy_sha256
        || document.policy_sha256 != audit_trust_policy_sha256(policy)?
    {
        return Err(RetentionError::InvalidEntry("policySha256"));
    }
    if document.entry_sha256 != commitment_sha256(document)? {
        return Err(RetentionError::InvalidEntry("entrySha256"));
    }
    let mut canonical = serde_json::to_vec(document)?;
    canonical.push(b'\n');
    if raw != canonical {
        return Err(RetentionError::NonCanonicalEntry);
    }
    let artifact_bytes = serde_json::to_vec(&document.artifact)?;
    let artifact = verify_audit_artifact(&artifact_bytes, None)?;
    if document.artifact_sha256 != artifact.canonical_sha256 {
        return Err(RetentionError::InvalidEntry("artifactSha256"));
    }
    let signature = decode_signature(&document.signature_ed25519)?;
    verify_detached_signature(&artifact, &document.signer_id, &signature, policy)?;
    Ok(retained(document, artifact))
}

fn retained(document: &EntryDocument, artifact: VerifiedAuditArtifact) -> RetainedAuditEntry {
    RetainedAuditEntry {
        sequence: document.sequence,
        previous_entry_sha256: document.previous_entry_sha256.clone(),
        entry_sha256: document.entry_sha256.clone(),
        policy_sha256: document.policy_sha256.clone(),
        signer_id: document.signer_id.clone(),
        artifact,
    }
}

fn decode_signature(value: &str) -> Result<[u8; 64], RetentionError> {
    if value.len() != 130
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RetentionError::InvalidEntry("signatureEd25519"));
    }
    hex::decode(&value[2..])
        .map_err(|_| RetentionError::InvalidEntry("signatureEd25519"))?
        .try_into()
        .map_err(|_| RetentionError::InvalidEntry("signatureEd25519"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn entry_name(sequence: u64) -> String {
    format!("{sequence:020}.json")
}

#[cfg(unix)]
fn parse_entry_name(name: &str) -> Result<u64, RetentionError> {
    if name.len() != 25
        || &name[20..] != ".json"
        || !name[..20].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RetentionError::InvalidEntryName);
    }
    name[..20]
        .parse()
        .map_err(|_| RetentionError::InvalidEntryName)
}

#[cfg(unix)]
fn verify_open_ledger(
    directory: &File,
    policy: &AuditTrustPolicy,
    expected_policy_sha256: &str,
) -> Result<Vec<RetainedAuditEntry>, RetentionError> {
    let names = directory_entry_names(directory)?;
    if names.len() > MAX_RETENTION_ENTRIES {
        return Err(RetentionError::TooManyEntries(MAX_RETENTION_ENTRIES));
    }
    let mut sequences = Vec::with_capacity(names.len());
    for name in names {
        sequences.push((parse_entry_name(&name)?, name));
    }
    sequences.sort_unstable_by_key(|(sequence, _)| *sequence);
    let mut retained_entries = Vec::with_capacity(sequences.len());
    let mut previous = GENESIS_ENTRY_SHA256.to_string();
    for (offset, (sequence, name)) in sequences.into_iter().enumerate() {
        let expected_sequence = offset as u64 + 1;
        if sequence != expected_sequence {
            return Err(RetentionError::ChainDiscontinuity);
        }
        let bytes = read_entry(directory, &name)?;
        let document: EntryDocument = serde_json::from_slice(&bytes)?;
        let retained = verify_document(
            &document,
            &bytes,
            expected_sequence,
            &previous,
            policy,
            expected_policy_sha256,
        )?;
        previous = retained.entry_sha256.clone();
        retained_entries.push(retained);
    }
    Ok(retained_entries)
}

#[cfg(unix)]
fn open_secure_ledger(path: &Path) -> Result<File, RetentionError> {
    use std::os::unix::fs::OpenOptionsExt;
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(RetentionError::UnsafeLedger("directoryType"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&directory.metadata()?)?;
    if !same_object(&link, &directory.metadata()?) {
        return Err(RetentionError::UnsafeLedger("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), RetentionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RetentionError::UnsafeLedger("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_ledger_path(path: &Path, directory: &File) -> Result<(), RetentionError> {
    let link = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if link.file_type().is_symlink() || !same_object(&link, &opened) {
        return Err(RetentionError::UnsafeLedger("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn directory_entry_names(directory: &File) -> Result<Vec<String>, RetentionError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    let duplicated = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        unsafe { libc::close(duplicated) };
        return Err(std::io::Error::last_os_error().into());
    }
    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            if error.raw_os_error() == Some(0) {
                return Ok(names);
            }
            return Err(error.into());
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| RetentionError::InvalidEntryName)?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )
))]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, RetentionError> {
    std::ffi::CString::new(name).map_err(|_| RetentionError::InvalidEntryName)
}

#[cfg(unix)]
fn read_entry(directory: &File, name: &str) -> Result<Vec<u8>, RetentionError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let name = c_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o077 != 0
    {
        return Err(RetentionError::UnsafeLedger("entryPermissions"));
    }
    if before.len() == 0 || before.len() > MAX_RETENTION_ENTRY_BYTES {
        return Err(RetentionError::EntryTooLarge {
            actual: before.len(),
            maximum: MAX_RETENTION_ENTRY_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_RETENTION_ENTRY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if !same_file_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(RetentionError::UnsafeLedger("entryChanged"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(unix)]
fn create_entry(directory: &File, sequence: u64, bytes: &[u8]) -> Result<(), RetentionError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(&entry_name(sequence))?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(RetentionError::ConcurrentAppend);
        }
        return Err(error.into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
