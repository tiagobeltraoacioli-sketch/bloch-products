//! Durable, local, idempotent allocation records for Bloch Pay reconciliation.
//!
//! Persistence is not settlement qualification, authorization to credit,
//! custody, or authorization to move or release funds.

use bloch_pay_reconciliation::{
    AuthenticatedPaymentObservation, ReconciliationReport, report_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

mod checkpoint;
pub use checkpoint::*;

pub const STATE_SCHEMA: &str = "bloch.pay.allocation-store.v1";
pub const RECEIPT_SCHEMA: &str = "bloch.pay.allocation-receipt.v1";
pub const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_ALLOCATIONS: usize = 100_000;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AllocationKind {
    Matched,
    Late,
    Unmatched,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AllocationRequest {
    pub allocation_id: String,
    pub kind: AllocationKind,
    pub invoice_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AllocationReceipt {
    schema: String,
    allocation_id: String,
    reconciliation_policy_sha256: String,
    report_sha256: String,
    observation_id: String,
    observation_sha256: String,
    observer_id: String,
    observer_policy_sha256: String,
    network: String,
    transaction_id: String,
    event_index: u32,
    kind: AllocationKind,
    invoice_id: Option<String>,
    settlement_qualified: bool,
    credit_authorized: bool,
    funds_released: bool,
}

impl AllocationReceipt {
    pub fn allocation_id(&self) -> &str {
        &self.allocation_id
    }
    pub fn policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }
    pub fn reconciliation_policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }
    pub fn report_sha256(&self) -> &str {
        &self.report_sha256
    }
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }
    pub fn observation_sha256(&self) -> &str {
        &self.observation_sha256
    }
    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn observer_policy_sha256(&self) -> &str {
        &self.observer_policy_sha256
    }
    pub fn settlement_qualified(&self) -> bool {
        self.settlement_qualified
    }
    pub fn credit_authorized(&self) -> bool {
        self.credit_authorized
    }
    pub fn funds_released(&self) -> bool {
        self.funds_released
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoreDocument {
    schema: String,
    generation: u64,
    allocations: Vec<AllocationReceipt>,
}

#[derive(Debug, Error)]
pub enum AllocationError {
    #[error("allocation request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("authenticated report evidence is inconsistent")]
    InvalidReportEvidence,
    #[error("authorized invoice evidence is inconsistent")]
    InvalidInvoiceAuthorizationEvidence,
    #[error("observation is not allocated as requested by the report")]
    ReportMismatch,
    #[error("allocation conflicts with durable state")]
    AllocationConflict,
    #[error("observation identity was already allocated")]
    DuplicateObservation,
    #[error("network transaction event was already allocated")]
    DuplicateNetworkEvent,
    #[error("allocation store is full")]
    StoreFull,
    #[error("allocation store is busy")]
    StoreBusy,
    #[error("durable allocation state is invalid")]
    InvalidState,
    #[error("unsafe allocation store: {0}")]
    UnsafeStore(&'static str),
    #[error("secure allocation persistence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("allocation store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Requires both authenticated observation evidence and independently pinned
/// invoice-authorization evidence before recording an allocation. The report
/// digest retained by the receipt binds the complete authorization evidence.
pub fn allocate_with_authorized_invoices(
    store: &Path,
    request: &AllocationRequest,
    report: &ReconciliationReport,
    authenticated: &AuthenticatedPaymentObservation,
    expected_invoice_authorization_policy_sha256: &str,
) -> Result<AllocationReceipt, AllocationError> {
    if !valid_sha256(expected_invoice_authorization_policy_sha256)
        || !report.invoices_authorized()
        || report.invoice_authorization_evidence().len() != report.invoices().len()
        || report
            .invoice_authorization_evidence()
            .iter()
            .zip(report.invoices())
            .any(|(evidence, invoice)| {
                !evidence.authorized()
                    || evidence.invoice_id() != invoice.invoice_id()
                    || evidence.canonical_invoice_sha256().is_none()
                    || evidence.issuer_id().is_none()
                    || evidence.authorization_policy_sha256()
                        != Some(expected_invoice_authorization_policy_sha256)
                    || evidence.reconciliation_policy_sha256() != Some(report.policy_sha256())
                    || evidence.authorized_at_unix_seconds().is_none()
            })
    {
        return Err(AllocationError::InvalidInvoiceAuthorizationEvidence);
    }
    if let Some(invoice_id) = request.invoice_id.as_deref()
        && report
            .invoice_authorization_evidence()
            .binary_search_by(|evidence| evidence.invoice_id().cmp(invoice_id))
            .is_err()
    {
        return Err(AllocationError::InvalidInvoiceAuthorizationEvidence);
    }
    allocate(store, request, report, authenticated)
}

/// Durably records one allocation. An exact replay returns the byte-identical
/// receipt already in the store. Conflicting identity reuse fails closed.
pub fn allocate(
    store: &Path,
    request: &AllocationRequest,
    report: &ReconciliationReport,
    authenticated: &AuthenticatedPaymentObservation,
) -> Result<AllocationReceipt, AllocationError> {
    #[cfg(not(unix))]
    {
        let _ = (store, request, report, authenticated);
        return Err(AllocationError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        validate_request(request)?;
        let observation = authenticated.observation();
        validate_report_allocation(request, report, &observation.observation_id)?;
        if !report.observations_authenticated() {
            return Err(AllocationError::InvalidReportEvidence);
        }
        let evidence = report
            .observation_evidence()
            .binary_search_by(|item| item.observation_id().cmp(&observation.observation_id))
            .ok()
            .and_then(|index| report.observation_evidence().get(index))
            .ok_or(AllocationError::InvalidReportEvidence)?;
        if !evidence.authenticated()
            || evidence.canonical_observation_sha256()
                != Some(authenticated.canonical_observation_sha256())
            || evidence.observer_id() != Some(authenticated.observer_id())
            || evidence.observer_policy_sha256() != Some(authenticated.observer_policy_sha256())
            || evidence.reconciliation_policy_sha256()
                != Some(authenticated.reconciliation_policy_sha256())
            || evidence.reconciliation_policy_sha256() != Some(report.policy_sha256())
        {
            return Err(AllocationError::InvalidReportEvidence);
        }
        let report_bytes =
            report_bytes(report).map_err(|_| AllocationError::InvalidReportEvidence)?;
        let receipt = AllocationReceipt {
            schema: RECEIPT_SCHEMA.into(),
            allocation_id: request.allocation_id.clone(),
            reconciliation_policy_sha256: authenticated.reconciliation_policy_sha256().into(),
            report_sha256: hash(&report_bytes),
            observation_id: observation.observation_id.clone(),
            observation_sha256: authenticated.canonical_observation_sha256().into(),
            observer_id: authenticated.observer_id().into(),
            observer_policy_sha256: authenticated.observer_policy_sha256().into(),
            network: observation.network.clone(),
            transaction_id: observation.transaction_id.clone(),
            event_index: observation.event_index,
            kind: request.kind,
            invoice_id: request.invoice_id.clone(),
            settlement_qualified: false,
            credit_authorized: false,
            funds_released: false,
        };
        let directory = open_or_create_store(store)?;
        let _lock = StoreLock::acquire(&directory)?;
        verify_store_path(store, &directory)?;
        let mut document = read_state(&directory)?.unwrap_or(StoreDocument {
            schema: STATE_SCHEMA.into(),
            generation: 0,
            allocations: Vec::new(),
        });
        validate_state(&document)?;
        if let Some(existing) = document
            .allocations
            .iter()
            .find(|item| item.allocation_id == receipt.allocation_id)
        {
            return if existing == &receipt {
                Ok(existing.clone())
            } else {
                Err(AllocationError::AllocationConflict)
            };
        }
        if document
            .allocations
            .iter()
            .any(|item| item.observation_id == receipt.observation_id)
        {
            return Err(AllocationError::DuplicateObservation);
        }
        if document.allocations.iter().any(|item| {
            item.network == receipt.network
                && item.transaction_id == receipt.transaction_id
                && item.event_index == receipt.event_index
        }) {
            return Err(AllocationError::DuplicateNetworkEvent);
        }
        if document.allocations.len() >= MAX_ALLOCATIONS {
            return Err(AllocationError::StoreFull);
        }
        document.generation = document
            .generation
            .checked_add(1)
            .ok_or(AllocationError::StoreFull)?;
        document.allocations.push(receipt.clone());
        document
            .allocations
            .sort_by(|a, b| a.allocation_id.cmp(&b.allocation_id));
        let bytes = serde_json::to_vec(&document).map_err(|_| AllocationError::InvalidState)?;
        atomic_replace(&directory, "allocations.json", &bytes)?;
        Ok(receipt)
    }
}

fn validate_request(request: &AllocationRequest) -> Result<(), AllocationError> {
    if !valid_id(&request.allocation_id) {
        return Err(AllocationError::InvalidRequest("allocationId"));
    }
    match request.kind {
        AllocationKind::Matched | AllocationKind::Late
            if request.invoice_id.as_deref().is_some_and(valid_id) =>
        {
            Ok(())
        }
        AllocationKind::Unmatched if request.invoice_id.is_none() => Ok(()),
        _ => Err(AllocationError::InvalidRequest("invoiceId")),
    }
}

fn validate_report_allocation(
    request: &AllocationRequest,
    report: &ReconciliationReport,
    observation_id: &str,
) -> Result<(), AllocationError> {
    let found = match request.kind {
        AllocationKind::Unmatched => report
            .unmatched_observation_ids()
            .iter()
            .any(|id| id == observation_id),
        AllocationKind::Matched => report.invoices().iter().any(|invoice| {
            Some(invoice.invoice_id()) == request.invoice_id.as_deref()
                && invoice
                    .matched_observation_ids()
                    .iter()
                    .any(|id| id == observation_id)
        }),
        AllocationKind::Late => report.invoices().iter().any(|invoice| {
            Some(invoice.invoice_id()) == request.invoice_id.as_deref()
                && invoice
                    .late_observation_ids()
                    .iter()
                    .any(|id| id == observation_id)
        }),
    };
    if found {
        Ok(())
    } else {
        Err(AllocationError::ReportMismatch)
    }
}

fn validate_state(state: &StoreDocument) -> Result<(), AllocationError> {
    if state.schema != STATE_SCHEMA
        || state.allocations.len() > MAX_ALLOCATIONS
        || state.generation != state.allocations.len() as u64
    {
        return Err(AllocationError::InvalidState);
    }
    let mut previous: Option<&str> = None;
    let mut observations = std::collections::BTreeSet::new();
    let mut events = std::collections::BTreeSet::new();
    for item in &state.allocations {
        if item.schema != RECEIPT_SCHEMA
            || !valid_id(&item.allocation_id)
            || !valid_id(&item.observation_id)
            || !valid_id(&item.network)
            || !valid_id(&item.transaction_id)
            || !valid_id(&item.observer_id)
            || match item.kind {
                AllocationKind::Matched | AllocationKind::Late => {
                    !item.invoice_id.as_deref().is_some_and(valid_id)
                }
                AllocationKind::Unmatched => item.invoice_id.is_some(),
            }
            || !valid_sha256(&item.reconciliation_policy_sha256)
            || !valid_sha256(&item.report_sha256)
            || !valid_sha256(&item.observation_sha256)
            || !valid_sha256(&item.observer_policy_sha256)
            || item.settlement_qualified
            || item.credit_authorized
            || item.funds_released
            || previous.is_some_and(|id| id >= item.allocation_id.as_str())
            || !observations.insert(&item.observation_id)
            || !events.insert((&item.network, &item.transaction_id, item.event_index))
        {
            return Err(AllocationError::InvalidState);
        }
        previous = Some(&item.allocation_id);
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
        && !value[2..].bytes().all(|b| b == b'0')
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
    fn acquire(directory: &File) -> Result<Self, AllocationError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(".allocation.lock")?;
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
                        return Err(AllocationError::StoreBusy);
                    }
                    std::thread::sleep(
                        LOCK_RETRY_INTERVAL.min(MAX_LOCK_WAIT.saturating_sub(started.elapsed())),
                    );
                }
                Some(libc::EINTR) if started.elapsed() < MAX_LOCK_WAIT => {}
                Some(libc::EINTR) => return Err(AllocationError::StoreBusy),
                _ => return Err(error.into()),
            }
        }
        validate_named_file(directory, ".allocation.lock", &file.metadata()?)?;
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
fn open_or_create_store(path: &Path) -> Result<File, AllocationError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(AllocationError::UnsafeStore("directoryType"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&file.metadata()?)?;
    if !same_object(&link, &file.metadata()?) {
        return Err(AllocationError::UnsafeStore("directoryChanged"));
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), AllocationError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !same_object(&link, &directory.metadata()?) {
        return Err(AllocationError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&directory.metadata()?)
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<(), AllocationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AllocationError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata, require_nonempty: bool) -> Result<(), AllocationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || (require_nonempty && metadata.len() == 0)
        || metadata.len() > MAX_STATE_BYTES
    {
        return Err(AllocationError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, AllocationError> {
    std::ffi::CString::new(name).map_err(|_| AllocationError::UnsafeStore("fileName"))
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), AllocationError> {
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
        return Err(AllocationError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
        || status.st_mode & 0o077 != 0
        || status.st_uid != unsafe { libc::geteuid() }
    {
        return Err(AllocationError::UnsafeStore("fileChanged"));
    }
    Ok(())
}

#[cfg(unix)]
fn read_state(directory: &File) -> Result<Option<StoreDocument>, AllocationError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name("allocations.json")?;
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
    validate_named_file(directory, "allocations.json", &metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(AllocationError::UnsafeStore("fileChanged"));
    }
    let document: StoreDocument =
        serde_json::from_slice(&bytes).map_err(|_| AllocationError::InvalidState)?;
    if serde_json::to_vec(&document).map_err(|_| AllocationError::InvalidState)? != bytes {
        return Err(AllocationError::InvalidState);
    }
    Ok(Some(document))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, name: &str, bytes: &[u8]) -> Result<(), AllocationError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(AllocationError::StoreFull);
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
            return Err(AllocationError::Io(std::io::Error::last_os_error()));
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
fn temporary_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
