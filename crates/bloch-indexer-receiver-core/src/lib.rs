//! Durable, transport-neutral receiver for authenticated indexer deliveries.
//!
//! This crate verifies canonical transport requests against an independently
//! pinned trust policy, persists an idempotent acceptance intent, and exposes
//! the exact receipt message for an external signer. Importing a valid
//! signature durably stores the canonical receipt before returning a canonical
//! transport response. It owns no private keys, opens no sockets, makes no
//! finality claim, and never acknowledges sender state.

use bloch_indexer_delivery_protocol::{
    TrustPolicy, VerifiedDelivery, build_receipt_signature_message, encode_accepted_receipt,
    trust_policy_sha256, verify_accepted_receipt,
};
use bloch_indexer_delivery_transport::{VerifiedRequest, decode_request, encode_response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

pub const ACCEPTANCE_SCHEMA: &str = "bloch.data.receiver-acceptance.v1";
pub const COMPLETION_SCHEMA: &str = "bloch.data.receiver-completion.v1";
pub const OUTCOME_SCHEMA: &str = "bloch.data.receiver-record-outcome.v1";
pub const MAX_STATE_BYTES: u64 = 768 * 1024;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcceptance {
    request_id: String,
    receipt_signature_message: Vec<u8>,
    record_id: String,
    delivery_sha256: String,
    attempt: u32,
    generation: u64,
}

impl PreparedAcceptance {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn receipt_signature_message(&self) -> &[u8] {
        &self.receipt_signature_message
    }
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
    pub fn delivery_sha256(&self) -> &str {
        &self.delivery_sha256
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverResponse {
    request_id: String,
    receipt_bytes: Vec<u8>,
    response_bytes: Vec<u8>,
}

impl ReceiverResponse {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptanceStatus {
    AwaitingSignature(PreparedAcceptance),
    Completed(ReceiverResponse),
}

#[derive(Debug, Error)]
pub enum ReceiverError {
    #[error("receiver trust policy does not match its pinned digest")]
    PolicyPinMismatch,
    #[error("receiver identifier is not trusted by the pinned policy")]
    UntrustedReceiver,
    #[error("authenticated transport request is invalid")]
    InvalidRequest,
    #[error("external receipt signature is invalid")]
    InvalidSignature,
    #[error("durable acceptance conflicts with the authenticated delivery")]
    AcceptanceConflict,
    #[error("durable receiver state is invalid")]
    InvalidState,
    #[error("unsafe receiver store: {0}")]
    UnsafeStore(&'static str),
    #[error("receiver store is busy")]
    StoreBusy,
    #[error("secure receiver persistence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("receiver store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AcceptanceDocument {
    schema: String,
    policy_sha256: String,
    receiver_id: String,
    record_id: String,
    delivery_sha256: String,
    attempt: u32,
    generation: u64,
    sender_id: String,
    record_outcome_sha256: String,
    canonical_delivery_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordOutcomeDocument {
    schema: String,
    policy_sha256: String,
    record_id: String,
    canonical_record_sha256: String,
    result: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CompletionDocument {
    schema: String,
    acceptance_sha256: String,
    canonical_receipt_hex: String,
}

/// Verifies and durably admits one authenticated delivery. Repeating the same
/// record/delivery/attempt/generation returns the same signing bytes; a stored
/// completed receipt is returned without requiring another signature.
pub fn prepare_acceptance(
    store: &Path,
    request_bytes: &[u8],
    policy: &TrustPolicy,
    expected_policy_sha256: &str,
    receiver_id: &str,
) -> Result<AcceptanceStatus, ReceiverError> {
    #[cfg(not(unix))]
    {
        let _ = (
            store,
            request_bytes,
            policy,
            expected_policy_sha256,
            receiver_id,
        );
        return Err(ReceiverError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        let policy_sha256 = validate_policy_pin(policy, expected_policy_sha256, receiver_id)?;
        let request =
            decode_request(request_bytes, policy).map_err(|_| ReceiverError::InvalidRequest)?;
        let outcome = outcome_document(&request, policy_sha256.clone())?;
        let outcome_bytes =
            serde_json::to_vec(&outcome).map_err(|_| ReceiverError::InvalidState)?;
        let acceptance =
            acceptance_document(&request, policy_sha256, receiver_id, hash(&outcome_bytes));
        let acceptance_bytes =
            serde_json::to_vec(&acceptance).map_err(|_| ReceiverError::InvalidState)?;
        let key = acceptance_key(request.delivery());
        let directory = open_secure_store(store)?;
        let _lock = StoreLock::acquire(&directory)?;
        verify_store_path(store, &directory)?;
        persist_or_verify_outcome(&directory, &outcome, &outcome_bytes)?;
        let acceptance_name = format!("{key}.acceptance.json");
        match read_optional(&directory, &acceptance_name)? {
            Some(existing) if existing != acceptance_bytes => {
                return Err(ReceiverError::AcceptanceConflict);
            }
            Some(_) => {}
            None => create_once(&directory, &acceptance_name, &acceptance_bytes)?,
        }
        validate_acceptance_bytes(&acceptance_bytes, &acceptance, policy)?;
        status_from_documents(
            &directory,
            &request,
            policy,
            receiver_id,
            &key,
            &acceptance_bytes,
        )
    }
}

/// Imports an externally generated Ed25519 signature. The signature and
/// canonical receipt are verified before a create-once completion is stored.
/// A crash after persistence is recoverable with [`prepare_acceptance`].
pub fn import_acceptance_signature(
    store: &Path,
    request_bytes: &[u8],
    signature: &[u8],
    policy: &TrustPolicy,
    expected_policy_sha256: &str,
    receiver_id: &str,
) -> Result<ReceiverResponse, ReceiverError> {
    if let AcceptanceStatus::Completed(response) = prepare_acceptance(
        store,
        request_bytes,
        policy,
        expected_policy_sha256,
        receiver_id,
    )? {
        return Ok(response);
    }
    #[cfg(not(unix))]
    {
        let _ = signature;
        Err(ReceiverError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let request =
            decode_request(request_bytes, policy).map_err(|_| ReceiverError::InvalidRequest)?;
        let receipt = encode_accepted_receipt(
            &policy.destination_domain,
            &policy.network,
            receiver_id,
            request.delivery(),
            signature,
        )
        .map_err(|_| ReceiverError::InvalidSignature)?;
        verify_accepted_receipt(&receipt, request.delivery_bytes(), policy)
            .map_err(|_| ReceiverError::InvalidSignature)?;
        let policy_sha256 = validate_policy_pin(policy, expected_policy_sha256, receiver_id)?;
        let outcome = outcome_document(&request, policy_sha256.clone())?;
        let outcome_bytes =
            serde_json::to_vec(&outcome).map_err(|_| ReceiverError::InvalidState)?;
        let acceptance =
            acceptance_document(&request, policy_sha256, receiver_id, hash(&outcome_bytes));
        let acceptance_bytes =
            serde_json::to_vec(&acceptance).map_err(|_| ReceiverError::InvalidState)?;
        let completion = CompletionDocument {
            schema: COMPLETION_SCHEMA.into(),
            acceptance_sha256: hash(&acceptance_bytes),
            canonical_receipt_hex: encode_hex(&receipt),
        };
        let completion_bytes =
            serde_json::to_vec(&completion).map_err(|_| ReceiverError::InvalidState)?;
        let key = acceptance_key(request.delivery());
        let directory = open_secure_store(store)?;
        let _lock = StoreLock::acquire(&directory)?;
        verify_store_path(store, &directory)?;
        persist_or_verify_outcome(&directory, &outcome, &outcome_bytes)?;
        let acceptance_name = format!("{key}.acceptance.json");
        if read_optional(&directory, &acceptance_name)?.as_deref()
            != Some(acceptance_bytes.as_slice())
        {
            return Err(ReceiverError::AcceptanceConflict);
        }
        let completion_name = format!("{key}.completion.json");
        match read_optional(&directory, &completion_name)? {
            Some(existing) if existing != completion_bytes => {
                return Err(ReceiverError::AcceptanceConflict);
            }
            Some(_) => {}
            None => create_once(&directory, &completion_name, &completion_bytes)?,
        }
        response(&request, receipt, policy)
    }
}

fn validate_policy_pin(
    policy: &TrustPolicy,
    expected: &str,
    receiver_id: &str,
) -> Result<String, ReceiverError> {
    let actual = trust_policy_sha256(policy).map_err(|_| ReceiverError::PolicyPinMismatch)?;
    if actual != expected {
        return Err(ReceiverError::PolicyPinMismatch);
    }
    if !policy
        .receivers
        .iter()
        .any(|receiver| receiver.signer_id == receiver_id)
    {
        return Err(ReceiverError::UntrustedReceiver);
    }
    Ok(actual)
}

fn outcome_document(
    request: &VerifiedRequest,
    policy_sha256: String,
) -> Result<RecordOutcomeDocument, ReceiverError> {
    let canonical_record =
        serde_json::to_vec(request.delivery().record()).map_err(|_| ReceiverError::InvalidState)?;
    Ok(RecordOutcomeDocument {
        schema: OUTCOME_SCHEMA.into(),
        policy_sha256,
        record_id: request.delivery().record().id.clone(),
        canonical_record_sha256: hash(&canonical_record),
        result: "accepted".into(),
    })
}

fn acceptance_document(
    request: &VerifiedRequest,
    policy_sha256: String,
    receiver_id: &str,
    record_outcome_sha256: String,
) -> AcceptanceDocument {
    let delivery = request.delivery();
    AcceptanceDocument {
        schema: ACCEPTANCE_SCHEMA.into(),
        policy_sha256,
        receiver_id: receiver_id.into(),
        record_id: delivery.record().id.clone(),
        delivery_sha256: delivery.sha256().into(),
        attempt: delivery.attempt(),
        generation: delivery.generation(),
        sender_id: delivery.sender_id().into(),
        record_outcome_sha256,
        canonical_delivery_hex: encode_hex(request.delivery_bytes()),
    }
}

fn acceptance_key(delivery: &VerifiedDelivery) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(delivery.record().id.as_bytes());
    input.extend_from_slice(delivery.sha256().as_bytes());
    input.extend_from_slice(&delivery.attempt().to_be_bytes());
    input.extend_from_slice(&delivery.generation().to_be_bytes());
    hex::encode(Sha256::digest(input))
}

#[cfg(unix)]
fn persist_or_verify_outcome(
    directory: &File,
    outcome: &RecordOutcomeDocument,
    bytes: &[u8],
) -> Result<(), ReceiverError> {
    let name = format!(
        "{}.outcome.json",
        hex::encode(Sha256::digest(outcome.record_id.as_bytes()))
    );
    match read_optional(directory, &name)? {
        Some(existing) if existing != bytes => Err(ReceiverError::AcceptanceConflict),
        Some(existing) => {
            let stored: RecordOutcomeDocument = canonical_document(&existing)?;
            if stored.schema != OUTCOME_SCHEMA || stored.result != "accepted" {
                return Err(ReceiverError::InvalidState);
            }
            Ok(())
        }
        None => create_once(directory, &name, bytes),
    }
}

#[cfg(unix)]
fn status_from_documents(
    directory: &File,
    request: &VerifiedRequest,
    policy: &TrustPolicy,
    receiver_id: &str,
    key: &str,
    acceptance_bytes: &[u8],
) -> Result<AcceptanceStatus, ReceiverError> {
    let completion_name = format!("{key}.completion.json");
    if let Some(bytes) = read_optional(directory, &completion_name)? {
        let completion: CompletionDocument = canonical_document(&bytes)?;
        if completion.schema != COMPLETION_SCHEMA
            || completion.acceptance_sha256 != hash(acceptance_bytes)
        {
            return Err(ReceiverError::InvalidState);
        }
        let receipt = decode_hex(&completion.canonical_receipt_hex)?;
        verify_accepted_receipt(&receipt, request.delivery_bytes(), policy)
            .map_err(|_| ReceiverError::InvalidState)?;
        return Ok(AcceptanceStatus::Completed(response(
            request, receipt, policy,
        )?));
    }
    let delivery = request.delivery();
    let message = build_receipt_signature_message(
        &policy.destination_domain,
        &policy.network,
        receiver_id,
        delivery.sha256(),
        &delivery.record().id,
        delivery.attempt(),
        delivery.generation(),
    )
    .map_err(|_| ReceiverError::InvalidState)?;
    Ok(AcceptanceStatus::AwaitingSignature(PreparedAcceptance {
        request_id: request.request_id().into(),
        receipt_signature_message: message,
        record_id: delivery.record().id.clone(),
        delivery_sha256: delivery.sha256().into(),
        attempt: delivery.attempt(),
        generation: delivery.generation(),
    }))
}

fn validate_acceptance_bytes(
    bytes: &[u8],
    expected: &AcceptanceDocument,
    policy: &TrustPolicy,
) -> Result<(), ReceiverError> {
    let document: AcceptanceDocument = canonical_document(bytes)?;
    if document != *expected || document.schema != ACCEPTANCE_SCHEMA {
        return Err(ReceiverError::InvalidState);
    }
    let delivery = decode_hex(&document.canonical_delivery_hex)?;
    let verified = bloch_indexer_delivery_protocol::verify_delivery(&delivery, policy)
        .map_err(|_| ReceiverError::InvalidState)?;
    if verified.record().id != document.record_id
        || verified.sha256() != document.delivery_sha256
        || verified.attempt() != document.attempt
        || verified.generation() != document.generation
        || verified.sender_id() != document.sender_id
    {
        return Err(ReceiverError::InvalidState);
    }
    Ok(())
}

fn response(
    request: &VerifiedRequest,
    receipt: Vec<u8>,
    policy: &TrustPolicy,
) -> Result<ReceiverResponse, ReceiverError> {
    let response_bytes = encode_response(
        request.request_id(),
        &receipt,
        request.delivery_bytes(),
        policy,
    )
    .map_err(|_| ReceiverError::InvalidState)?;
    Ok(ReceiverResponse {
        request_id: request.request_id().into(),
        receipt_bytes: receipt,
        response_bytes,
    })
}

fn canonical_document<T>(bytes: &[u8]) -> Result<T, ReceiverError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ReceiverError::InvalidState);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| ReceiverError::InvalidState)?;
    if serde_json::to_vec(&value).map_err(|_| ReceiverError::InvalidState)? != bytes {
        return Err(ReceiverError::InvalidState);
    }
    Ok(value)
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
fn decode_hex(value: &str) -> Result<Vec<u8>, ReceiverError> {
    let value = value
        .strip_prefix("0x")
        .ok_or(ReceiverError::InvalidState)?;
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() as u64 > MAX_STATE_BYTES * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(ReceiverError::InvalidState);
    }
    hex::decode(value).map_err(|_| ReceiverError::InvalidState)
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
struct StoreLock {
    file: File,
}

#[cfg(unix)]
impl StoreLock {
    fn acquire(directory: &File) -> Result<Self, ReceiverError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(".receiver.lock")?;
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
                        return Err(ReceiverError::StoreBusy);
                    }
                    std::thread::sleep(
                        LOCK_RETRY_INTERVAL.min(MAX_LOCK_WAIT.saturating_sub(started.elapsed())),
                    );
                }
                Some(libc::EINTR) => {
                    if started.elapsed() >= MAX_LOCK_WAIT {
                        return Err(ReceiverError::StoreBusy);
                    }
                }
                _ => return Err(error.into()),
            }
        }
        validate_named_file(directory, ".receiver.lock", &file.metadata()?)?;
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
fn open_secure_store(path: &Path) -> Result<File, ReceiverError> {
    use std::os::unix::fs::OpenOptionsExt;
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(ReceiverError::UnsafeStore("directoryType"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&file.metadata()?)?;
    if !same_object(&link, &file.metadata()?) {
        return Err(ReceiverError::UnsafeStore("directoryChanged"));
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), ReceiverError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !same_object(&link, &directory.metadata()?) {
        return Err(ReceiverError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&directory.metadata()?)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), ReceiverError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ReceiverError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata, require_nonempty: bool) -> Result<(), ReceiverError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || (require_nonempty && metadata.len() == 0)
        || metadata.len() > MAX_STATE_BYTES
    {
        return Err(ReceiverError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, ReceiverError> {
    std::ffi::CString::new(name).map_err(|_| ReceiverError::UnsafeStore("fileName"))
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), ReceiverError> {
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
        return Err(ReceiverError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || device_id(status.st_dev) != Some(u128::from(metadata.dev()))
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
        || status.st_mode & 0o077 != 0
        || status.st_uid != unsafe { libc::geteuid() }
    {
        return Err(ReceiverError::UnsafeStore("fileChanged"));
    }
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::unnecessary_fallible_conversions)]
fn device_id(device: libc::dev_t) -> Option<u128> {
    u128::try_from(device).ok()
}

#[cfg(unix)]
fn unchanged_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(before, after)
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(unix)]
fn read_optional(directory: &File, name: &str) -> Result<Option<Vec<u8>>, ReceiverError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let cname = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            cname.as_ptr(),
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
    let before = file.metadata()?;
    validate_file(&before, true)?;
    validate_named_file(directory, name, &before)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || !unchanged_file(&before, &after) {
        return Err(ReceiverError::UnsafeStore("fileChanged"));
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn create_once(directory: &File, name: &str, bytes: &[u8]) -> Result<(), ReceiverError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ReceiverError::InvalidState);
    }
    let destination = c_name(name)?;
    let temporary_name = format!(".{name}.tmp-{}-{}", std::process::id(), random_nonce());
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
            libc::linkat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(ReceiverError::AcceptanceConflict);
            }
            return Err(error.into());
        }
        if unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
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
fn random_nonce() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    time ^ ((std::process::id() as u128) << 64) ^ NEXT.fetch_add(1, Ordering::Relaxed) as u128
}
