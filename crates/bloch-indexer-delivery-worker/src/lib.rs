//! Crash-recoverable, transport-neutral delivery spool.
//!
//! This worker coordinates the durable claim, an externally signed delivery,
//! transport request/response codecs, and authenticated durable receipt ACK.
//! It opens no socket and owns no private key. Every spool artifact is private,
//! canonical, create-once, and bound to one exact claim and pinned trust policy.
//! The spool is local single-host coordination, not distributed/HA storage.

use bloch_indexer_core::{
    delivery::{ClaimOutcome, DeliveryClaim, ResolutionOutcome},
    storage::{DurableState, StorageError, claim_and_persist, retry_and_persist},
};
use bloch_indexer_delivery_protocol::{
    ProtocolError, TrustPolicy, canonical_record_bytes, trust_policy_sha256,
    verify_accepted_receipt_for_claim, verify_delivery,
};
use bloch_indexer_delivery_transport::{
    TransportError, decode_request, decode_response, encode_request,
};
use bloch_indexer_receipt_ack::{
    AuthenticatedAcknowledgement, ReceiptAckError, acknowledge_authenticated_receipt_and_persist,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use thiserror::Error;

pub const JOB_SCHEMA: &str = "bloch.data.delivery-spool-job.v1";
pub const COMPLETION_SCHEMA: &str = "bloch.data.delivery-spool-completion.v1";
pub const MAX_SPOOL_FILE_BYTES: u64 = 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const LOCK_WAIT: Duration = Duration::from_millis(500);
const LOCK_POLL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareOutcome {
    Ready(SpoolJob),
    Unavailable { retry_at_unix_seconds: u64 },
    Empty,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpoolJob {
    pub schema: String,
    pub job_id: String,
    pub request_id: String,
    pub claim: DeliveryClaim,
    pub record_sha256: String,
    pub trust_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Completion {
    schema: String,
    job_id: String,
    disposition: String,
    resolved_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActiveIntent {
    claim_token: String,
    trust_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RetryIntent {
    job_id: String,
    resolved_at_unix_seconds: u64,
    retry_delay_seconds: u64,
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("secure delivery spool is unsupported on this platform")]
    Unsupported,
    #[error("unsafe spool: {0}")]
    UnsafeSpool(&'static str),
    #[error("spool artifact already exists with different content")]
    ArtifactConflict,
    #[error("spool job is incomplete: {0}")]
    Incomplete(&'static str),
    #[error("spool job is already terminal")]
    Terminal,
    #[error("delivery spool job is busy")]
    Busy,
    #[error("spool artifact exceeds its byte limit")]
    ArtifactTooLarge,
    #[error("spool artifact is invalid or non-canonical")]
    InvalidArtifact,
    #[error("spool job does not match the exact claim, record, or policy")]
    JobMismatch,
    #[error("durable state failed: {0}")]
    Storage(#[from] StorageError),
    #[error("delivery protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("transport codec failed: {0}")]
    Transport(#[from] TransportError),
    #[error("authenticated acknowledgement failed: {0}")]
    ReceiptAck(#[from] ReceiptAckError),
    #[error("spool I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("spool JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Durably claims the next record, then materializes its deterministic spool
/// job. Repeating with the same token recovers a crash between those steps.
pub fn prepare_next(
    state: &mut DurableState,
    snapshot_path: &Path,
    spool: &Path,
    now_unix_seconds: u64,
    lease_seconds: u64,
    claim_token: &str,
    policy: &TrustPolicy,
) -> Result<PrepareOutcome, WorkerError> {
    let directory = open_secure_spool(spool)?;
    let _active_lock = JobLock::acquire(&directory, "active")?;
    let policy_digest = trust_policy_sha256(policy)?;
    if let Some(active_job) = read_optional_json::<SpoolJob>(&directory, "active.job.json")? {
        validate_job(&active_job, &active_job.job_id, policy)?;
        if !exists(&directory, &name(&active_job.job_id, "completion.json"))? {
            if active_job.claim.token != claim_token {
                return Err(WorkerError::JobMismatch);
            }
            return Ok(PrepareOutcome::Ready(active_job));
        }
        let _ = load_completion(&directory, &active_job.job_id)?;
        remove_at(&directory, "active.job.json")?;
        remove_at(&directory, "active.intent.json")?;
        directory.sync_all()?;
    }
    let intent = ActiveIntent {
        claim_token: claim_token.into(),
        trust_policy_sha256: policy_digest.clone(),
    };
    if let Some(existing) = read_optional_json::<ActiveIntent>(&directory, "active.intent.json")? {
        if existing != intent {
            return Err(WorkerError::JobMismatch);
        }
    } else {
        put_json_once(&directory, "active.intent.json", &intent)?;
    }
    let (claim, record) = match claim_and_persist(
        state,
        snapshot_path,
        now_unix_seconds,
        lease_seconds,
        claim_token,
    )? {
        ClaimOutcome::Claimed { claim, record, .. } => (claim, *record),
        ClaimOutcome::Unavailable {
            retry_at_unix_seconds,
        } => {
            return Ok(PrepareOutcome::Unavailable {
                retry_at_unix_seconds,
            });
        }
        ClaimOutcome::Empty => {
            remove_at(&directory, "active.intent.json")?;
            directory.sync_all()?;
            return Ok(PrepareOutcome::Empty);
        }
    };
    let record_digest = sha256(&canonical_record_bytes(&record)?);
    let job_id = job_id(&claim, &record_digest, &policy_digest);
    let job = SpoolJob {
        schema: JOB_SCHEMA.into(),
        request_id: format!("spool-{job_id}"),
        job_id,
        claim,
        record_sha256: record_digest,
        trust_policy_sha256: policy_digest,
    };
    let _lock = JobLock::acquire(&directory, &job.job_id)?;
    put_json_once(&directory, &name(&job.job_id, "job.json"), &job)?;
    put_json_once(&directory, "active.job.json", &job)?;
    verify_spool_path(spool, &directory)?;
    Ok(PrepareOutcome::Ready(job))
}

/// Accepts an already signed delivery, verifies its exact job binding, and
/// writes the transport request. Neither this function nor the crate signs.
pub fn stage_signed_delivery(
    spool: &Path,
    job_id: &str,
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<Vec<u8>, WorkerError> {
    validate_job_id(job_id)?;
    let directory = open_secure_spool(spool)?;
    let _lock = JobLock::acquire(&directory, job_id)?;
    reject_terminal(&directory, job_id)?;
    let job: SpoolJob = read_json(&directory, &name(job_id, "job.json"))?;
    validate_job(&job, job_id, policy)?;
    let verified = verify_delivery(delivery_bytes, policy)?;
    if verified.record().id != job.claim.record_id
        || verified.attempt() != job.claim.attempt
        || verified.generation() != job.claim.generation
        || sha256(&canonical_record_bytes(verified.record())?) != job.record_sha256
    {
        return Err(WorkerError::JobMismatch);
    }
    let request = encode_request(&job.request_id, delivery_bytes, policy)?;
    put_once(&directory, &name(job_id, "delivery.json"), delivery_bytes)?;
    put_once(&directory, &name(job_id, "request.json"), &request)?;
    verify_spool_path(spool, &directory)?;
    Ok(request)
}

/// Imports response bytes obtained by caller-owned transport and persists the
/// authenticated response and extracted receipt as create-once evidence.
pub fn accept_response(
    spool: &Path,
    job_id: &str,
    response_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<(), WorkerError> {
    validate_job_id(job_id)?;
    let directory = open_secure_spool(spool)?;
    let _lock = JobLock::acquire(&directory, job_id)?;
    reject_terminal(&directory, job_id)?;
    let job: SpoolJob = read_json(&directory, &name(job_id, "job.json"))?;
    validate_job(&job, job_id, policy)?;
    let delivery = read_required(&directory, &name(job_id, "delivery.json"))?;
    let request = read_required(&directory, &name(job_id, "request.json"))?;
    let decoded_request = decode_request(&request, policy)?;
    if decoded_request.request_id() != job.request_id
        || decoded_request.delivery_bytes() != delivery
    {
        return Err(WorkerError::JobMismatch);
    }
    let response = decode_response(response_bytes, &job.request_id, &delivery, policy)?;
    verify_accepted_receipt_for_claim(response.receipt_bytes(), &delivery, policy, &job.claim)?;
    put_once(&directory, &name(job_id, "response.json"), response_bytes)?;
    put_once(
        &directory,
        &name(job_id, "receipt.json"),
        response.receipt_bytes(),
    )?;
    verify_spool_path(spool, &directory)?;
    Ok(())
}

/// Authenticates the persisted evidence once more and durably ACKs the exact
/// claim. A crash after durable ACK is recovered through idempotent replay.
pub fn acknowledge(
    state: &mut DurableState,
    snapshot_path: &Path,
    spool: &Path,
    job_id: &str,
    now_unix_seconds: u64,
    policy: &TrustPolicy,
) -> Result<AuthenticatedAcknowledgement, WorkerError> {
    validate_job_id(job_id)?;
    let directory = open_secure_spool(spool)?;
    let _lock = JobLock::acquire(&directory, job_id)?;
    let job: SpoolJob = read_json(&directory, &name(job_id, "job.json"))?;
    validate_job(&job, job_id, policy)?;
    let already_completed = if let Some(completion) =
        read_optional_json::<Completion>(&directory, &name(job_id, "completion.json"))?
    {
        validate_completion(&completion, job_id)?;
        if completion.disposition != "acknowledged" {
            return Err(WorkerError::Terminal);
        }
        true
    } else {
        false
    };
    let delivery = read_required(&directory, &name(job_id, "delivery.json"))?;
    let receipt = read_required(&directory, &name(job_id, "receipt.json"))?;
    let result = acknowledge_authenticated_receipt_and_persist(
        state,
        snapshot_path,
        &job.claim,
        now_unix_seconds,
        &delivery,
        &receipt,
        policy,
    )?;
    if !already_completed {
        put_json_once(
            &directory,
            &name(job_id, "completion.json"),
            &Completion {
                schema: COMPLETION_SCHEMA.into(),
                job_id: job_id.into(),
                disposition: "acknowledged".into(),
                resolved_at_unix_seconds: now_unix_seconds,
            },
        )?;
    }
    verify_spool_path(spool, &directory)?;
    Ok(result)
}

/// Explicitly abandons an incomplete transport attempt and schedules retry.
/// A received authenticated response must be ACKed and cannot be discarded.
pub fn schedule_retry(
    state: &mut DurableState,
    snapshot_path: &Path,
    spool: &Path,
    job_id: &str,
    now_unix_seconds: u64,
    retry_delay_seconds: u64,
    policy: &TrustPolicy,
) -> Result<ResolutionOutcome, WorkerError> {
    validate_job_id(job_id)?;
    let directory = open_secure_spool(spool)?;
    let _lock = JobLock::acquire(&directory, job_id)?;
    reject_terminal(&directory, job_id)?;
    let job: SpoolJob = read_json(&directory, &name(job_id, "job.json"))?;
    validate_job(&job, job_id, policy)?;
    if exists(&directory, &name(job_id, "response.json"))? {
        return Err(WorkerError::Terminal);
    }
    put_json_once(
        &directory,
        &name(job_id, "retry-intent.json"),
        &RetryIntent {
            job_id: job_id.into(),
            resolved_at_unix_seconds: now_unix_seconds,
            retry_delay_seconds,
        },
    )?;
    let outcome = retry_and_persist(
        state,
        snapshot_path,
        &job.claim,
        now_unix_seconds,
        retry_delay_seconds,
    )?;
    put_json_once(
        &directory,
        &name(job_id, "completion.json"),
        &Completion {
            schema: COMPLETION_SCHEMA.into(),
            job_id: job_id.into(),
            disposition: "retry_scheduled".into(),
            resolved_at_unix_seconds: now_unix_seconds,
        },
    )?;
    verify_spool_path(spool, &directory)?;
    Ok(outcome)
}

fn validate_job(
    job: &SpoolJob,
    expected_id: &str,
    policy: &TrustPolicy,
) -> Result<(), WorkerError> {
    if job.schema != JOB_SCHEMA
        || job.job_id != expected_id
        || job.request_id != format!("spool-{expected_id}")
        || job.trust_policy_sha256 != trust_policy_sha256(policy)?
        || job.job_id != job_id(&job.claim, &job.record_sha256, &job.trust_policy_sha256)
    {
        return Err(WorkerError::JobMismatch);
    }
    Ok(())
}

fn job_id(claim: &DeliveryClaim, record_digest: &str, policy_digest: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"bloch.data.delivery-spool-job-id.v1\0");
    hash.update(claim.record_id.as_bytes());
    hash.update(claim.token.as_bytes());
    hash.update(claim.attempt.to_be_bytes());
    hash.update(claim.generation.to_be_bytes());
    hash.update(claim.claimed_at_unix_seconds.to_be_bytes());
    hash.update(claim.expires_at_unix_seconds.to_be_bytes());
    hash.update(record_digest.as_bytes());
    hash.update(policy_digest.as_bytes());
    hex::encode(hash.finalize())
}

fn validate_job_id(value: &str) -> Result<(), WorkerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WorkerError::JobMismatch);
    }
    Ok(())
}

fn name(job_id: &str, suffix: &str) -> String {
    format!("{job_id}.{suffix}")
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn reject_terminal(directory: &File, job_id: &str) -> Result<(), WorkerError> {
    if exists(directory, &name(job_id, "completion.json"))? {
        let _ = load_completion(directory, job_id)?;
        Err(WorkerError::Terminal)
    } else {
        Ok(())
    }
}

fn load_completion(directory: &File, job_id: &str) -> Result<Completion, WorkerError> {
    let completion: Completion = read_json(directory, &name(job_id, "completion.json"))?;
    validate_completion(&completion, job_id)?;
    Ok(completion)
}

fn validate_completion(completion: &Completion, job_id: &str) -> Result<(), WorkerError> {
    if completion.schema != COMPLETION_SCHEMA
        || completion.job_id != job_id
        || completion.resolved_at_unix_seconds == 0
        || !matches!(
            completion.disposition.as_str(),
            "acknowledged" | "retry_scheduled"
        )
    {
        return Err(WorkerError::InvalidArtifact);
    }
    Ok(())
}

#[cfg(unix)]
fn open_secure_spool(path: &Path) -> Result<File, WorkerError> {
    use std::os::unix::{
        fs::OpenOptionsExt,
        fs::{DirBuilderExt, MetadataExt},
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).or_else(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(WorkerError::UnsafeSpool("directoryType"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() < 2
    {
        return Err(WorkerError::UnsafeSpool("directoryPermissions"));
    }
    if !same_object(&link, &metadata) {
        return Err(WorkerError::UnsafeSpool("directoryReplaced"));
    }
    verify_spool_path(path, &directory)?;
    Ok(directory)
}

#[cfg(not(unix))]
fn open_secure_spool(_: &Path) -> Result<File, WorkerError> {
    Err(WorkerError::Unsupported)
}

#[cfg(unix)]
fn open_at(directory: &File, filename: &str, create: bool) -> Result<File, std::io::Error> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
    };
    let filename = CString::new(filename)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let flags = if create {
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC
    } else {
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    };
    let descriptor =
        unsafe { libc::openat(directory.as_raw_fd(), filename.as_ptr(), flags, 0o600) };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn put_once(directory: &File, filename: &str, bytes: &[u8]) -> Result<(), WorkerError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SPOOL_FILE_BYTES {
        return Err(WorkerError::ArtifactTooLarge);
    }
    use std::{ffi::CString, os::fd::AsRawFd};
    let temporary = format!(
        ".{filename}.tmp.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut file = open_at(directory, &temporary, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let temporary_c = CString::new(temporary.as_str()).expect("generated filename has no NUL");
    let destination_c = CString::new(filename).map_err(|_| WorkerError::UnsafeSpool("filename"))?;
    let linked = unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            temporary_c.as_ptr(),
            directory.as_raw_fd(),
            destination_c.as_ptr(),
            0,
        )
    };
    let link_error = std::io::Error::last_os_error();
    let cleanup_result = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_c.as_ptr(), 0) };
    let cleanup = if cleanup_result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    };
    if linked != 0 {
        let error = link_error;
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = cleanup;
            return Err(error.into());
        }
        cleanup?;
        return if read_required(directory, filename)? == bytes {
            Ok(())
        } else {
            Err(WorkerError::ArtifactConflict)
        };
    }
    cleanup?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_at(directory: &File, filename: &str) -> Result<(), WorkerError> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let filename = CString::new(filename).map_err(|_| WorkerError::UnsafeSpool("filename"))?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_at(_: &File, _: &str) -> Result<(), WorkerError> {
    Err(WorkerError::Unsupported)
}

fn put_json_once<T: Serialize>(
    directory: &File,
    filename: &str,
    value: &T,
) -> Result<(), WorkerError> {
    put_once(directory, filename, &serde_json::to_vec(value)?)
}

fn read_required(directory: &File, filename: &str) -> Result<Vec<u8>, WorkerError> {
    use std::os::unix::fs::MetadataExt;
    let mut file = open_at(directory, filename, false).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WorkerError::Incomplete("artifact")
        } else {
            error.into()
        }
    })?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o077 != 0
        || before.len() == 0
        || before.len() > MAX_SPOOL_FILE_BYTES
    {
        return Err(WorkerError::UnsafeSpool("artifactMetadata"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if !stable_metadata(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(WorkerError::UnsafeSpool("artifactChangedDuringRead"));
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned + Serialize>(
    directory: &File,
    filename: &str,
) -> Result<T, WorkerError> {
    let bytes = read_required(directory, filename)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| WorkerError::InvalidArtifact)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(WorkerError::InvalidArtifact);
    }
    Ok(value)
}

fn read_optional_json<T: DeserializeOwned + Serialize>(
    directory: &File,
    filename: &str,
) -> Result<Option<T>, WorkerError> {
    if !exists(directory, filename)? {
        return Ok(None);
    }
    read_json(directory, filename).map(Some)
}

fn exists(directory: &File, filename: &str) -> Result<bool, WorkerError> {
    match open_at(directory, filename, false) {
        Ok(file) => {
            drop(file);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

struct JobLock(File);

impl JobLock {
    #[cfg(unix)]
    fn acquire(directory: &File, job_id: &str) -> Result<Self, WorkerError> {
        let filename = name(job_id, "lock");
        let file = match open_at(directory, &filename, true) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                open_at(directory, &filename, false)?
            }
            Err(error) => return Err(error.into()),
        };
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(WorkerError::UnsafeSpool("lockMetadata"));
        }
        use std::os::fd::AsRawFd;
        let started = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.kind(), std::io::ErrorKind::WouldBlock)
                || started.elapsed() >= LOCK_WAIT
            {
                return if matches!(error.kind(), std::io::ErrorKind::WouldBlock) {
                    Err(WorkerError::Busy)
                } else {
                    Err(error.into())
                };
            }
            std::thread::sleep(LOCK_POLL);
        }
        Ok(Self(file))
    }
    #[cfg(not(unix))]
    fn acquire(_: &File, _: &str) -> Result<Self, WorkerError> {
        Err(WorkerError::Unsupported)
    }
}

#[cfg(unix)]
fn verify_spool_path(path: &Path, directory: &File) -> Result<(), WorkerError> {
    let link = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if link.file_type().is_symlink() || !link.is_dir() || !same_object(&link, &opened) {
        return Err(WorkerError::UnsafeSpool("directoryReplaced"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_spool_path(_: &Path, _: &File) -> Result<(), WorkerError> {
    Err(WorkerError::Unsupported)
}

#[cfg(unix)]
fn same_object(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn stable_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(before, after)
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.nlink() == after.nlink()
}

impl Drop for JobLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
