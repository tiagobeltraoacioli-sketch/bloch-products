//! Durable reference storage core for a remote cursor control plane.
//!
//! This is a Unix-only, single-host storage primitive. It performs no
//! networking or signing and never receives private keys. External authorities
//! must independently sign the exact decision returned here.

use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    RemoteCursorCasDecision, RemoteCursorCasMode, ValidatedRemoteCursorCasRequest,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

pub const CONTROL_PLANE_STATE_SCHEMA: &str = "bloch.products.remote-cursor-control-plane-state.v1";
pub const MAX_RECORDED_REQUESTS: usize = 4096;
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordedDecision {
    request_id: String,
    request_sha256: String,
    decision: RemoteCursorCasDecision,
    resulting_cursor: Option<CheckpointCursor>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    current_cursor: Option<CheckpointCursor>,
    decisions: Vec<RecordedDecision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneDecision {
    request_id: String,
    request_sha256: String,
    decision: RemoteCursorCasDecision,
    resulting_cursor: Option<CheckpointCursor>,
}

impl ControlPlaneDecision {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn decision(&self) -> &RemoteCursorCasDecision {
        &self.decision
    }
    pub fn resulting_cursor(&self) -> Option<&CheckpointCursor> {
        self.resulting_cursor.as_ref()
    }
    pub fn signed_receipt_created(&self) -> bool {
        false
    }
    pub fn remote_authority_independence_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("control-plane input is invalid")]
    InvalidInput,
    #[error("control-plane state is missing")]
    StateMissing,
    #[error("control-plane store is already provisioned")]
    AlreadyProvisioned,
    #[error("control-plane durable state is invalid or non-canonical")]
    InvalidState,
    #[error("request ID was already used for different request bytes")]
    RequestIdConflict,
    #[error("control-plane request history is full")]
    HistoryFull,
    #[error("control-plane store is busy")]
    StoreBusy,
    #[error("unsafe control-plane store: {0}")]
    UnsafeStore(&'static str),
    #[error("control-plane storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("control-plane store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Explicitly provisions an empty control-plane epoch.
///
/// Operational request paths never create directories, locks, or state. A
/// missing/deleted store therefore cannot silently reopen bootstrap.
#[cfg(unix)]
pub fn provision_control_plane_store(
    store: &Path,
    state_identity: &str,
    remote_cursor_policy_sha256: &str,
    signature_domain: &str,
) -> Result<(), ControlPlaneError> {
    use std::os::unix::fs::DirBuilderExt;
    if !valid_id(state_identity)
        || !valid_sha256(remote_cursor_policy_sha256)
        || !valid_id(signature_domain)
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if let Err(error) = builder.create(store) {
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(ControlPlaneError::AlreadyProvisioned)
        } else {
            Err(error.into())
        };
    }
    let directory = open_directory(store)?;
    sync_parent_directory(store)?;
    let lock = create_file_exclusive(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    directory.sync_all()?;
    let _lock = StoreLock::acquire(&directory)?;
    let state = DurableState {
        schema: CONTROL_PLANE_STATE_SCHEMA.into(),
        state_identity: state_identity.into(),
        remote_cursor_policy_sha256: remote_cursor_policy_sha256.into(),
        signature_domain: signature_domain.into(),
        current_cursor: None,
        decisions: Vec::new(),
    };
    atomic_replace(
        &directory,
        &serde_json::to_vec(&state).map_err(|_| ControlPlaneError::InvalidState)?,
    )?;
    let published = read_state(&directory)?.ok_or(ControlPlaneError::StateMissing)?;
    if published != state {
        return Err(ControlPlaneError::InvalidState);
    }
    verify_store_path(store, &directory)
}

#[cfg(not(unix))]
pub fn provision_control_plane_store(
    _store: &Path,
    _state_identity: &str,
    _remote_cursor_policy_sha256: &str,
    _signature_domain: &str,
) -> Result<(), ControlPlaneError> {
    Err(ControlPlaneError::UnsupportedPlatform)
}

/// Applies one already-validated request under the durable store lock.
///
/// The returned material is unsigned. Callers may submit its exact decision to
/// external authorities together with the original canonical request bytes.
#[cfg(unix)]
pub fn apply_request(
    store: &Path,
    expected_state_identity: &str,
    request: &ValidatedRemoteCursorCasRequest,
) -> Result<ControlPlaneDecision, ControlPlaneError> {
    if !valid_id(expected_state_identity) || request.state_identity() != expected_state_identity {
        return Err(ControlPlaneError::InvalidInput);
    }
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let mut state = read_state(&directory)?.ok_or(ControlPlaneError::StateMissing)?;
    validate_state(&state)?;
    if state.state_identity != expected_state_identity {
        return Err(ControlPlaneError::InvalidInput);
    }
    if state.remote_cursor_policy_sha256 != request.remote_cursor_policy_sha256()
        || state.signature_domain != request.signature_domain()
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    if let Some(recorded) = state
        .decisions
        .iter()
        .find(|recorded| recorded.request_id == request.request_id())
    {
        if recorded.request_sha256 != request.request_sha256() {
            return Err(ControlPlaneError::RequestIdConflict);
        }
        if matches!(recorded.decision, RemoteCursorCasDecision::Accepted)
            && recorded.resulting_cursor.as_ref() != Some(request.successor())
        {
            return Err(ControlPlaneError::InvalidState);
        }
        if let RemoteCursorCasDecision::Refused { reason_code } = &recorded.decision
            && reason_code != refusal_reason(request.mode())
        {
            return Err(ControlPlaneError::InvalidState);
        }
        return Ok(decision(recorded));
    }
    if state.decisions.len() >= MAX_RECORDED_REQUESTS {
        return Err(ControlPlaneError::HistoryFull);
    }

    let accepted = match request.mode() {
        RemoteCursorCasMode::CreateOnceBootstrap => state.current_cursor.is_none(),
        RemoteCursorCasMode::CompareAndSwap => {
            state.current_cursor.as_ref() == request.expected_current()
        }
    };
    let (decision_value, resulting_cursor) = if accepted {
        let successor = request.successor().clone();
        state.current_cursor = Some(successor.clone());
        (RemoteCursorCasDecision::Accepted, Some(successor))
    } else {
        let reason_code = refusal_reason(request.mode());
        (
            RemoteCursorCasDecision::Refused {
                reason_code: reason_code.into(),
            },
            None,
        )
    };
    let recorded = RecordedDecision {
        request_id: request.request_id().into(),
        request_sha256: request.request_sha256().into(),
        decision: decision_value,
        resulting_cursor,
    };
    state.decisions.push(recorded.clone());
    let bytes = serde_json::to_vec(&state).map_err(|_| ControlPlaneError::InvalidState)?;
    atomic_replace(&directory, &bytes)?;
    let published = read_state(&directory)?.ok_or(ControlPlaneError::StateMissing)?;
    if published != state {
        return Err(ControlPlaneError::InvalidState);
    }
    verify_store_path(store, &directory)?;
    Ok(decision(&recorded))
}

#[cfg(not(unix))]
pub fn apply_request(
    _store: &Path,
    _expected_state_identity: &str,
    _request: &ValidatedRemoteCursorCasRequest,
) -> Result<ControlPlaneDecision, ControlPlaneError> {
    Err(ControlPlaneError::UnsupportedPlatform)
}

/// Reads the current cursor without creating state.
#[cfg(unix)]
pub fn load_current_cursor(
    store: &Path,
    expected_state_identity: &str,
    expected_remote_cursor_policy_sha256: &str,
    expected_signature_domain: &str,
) -> Result<Option<CheckpointCursor>, ControlPlaneError> {
    if !valid_id(expected_state_identity)
        || !valid_sha256(expected_remote_cursor_policy_sha256)
        || !valid_id(expected_signature_domain)
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(ControlPlaneError::StateMissing)?;
    validate_state(&state)?;
    if state.state_identity != expected_state_identity
        || state.remote_cursor_policy_sha256 != expected_remote_cursor_policy_sha256
        || state.signature_domain != expected_signature_domain
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    Ok(state.current_cursor)
}

#[cfg(not(unix))]
pub fn load_current_cursor(
    _store: &Path,
    _expected_state_identity: &str,
    _expected_remote_cursor_policy_sha256: &str,
    _expected_signature_domain: &str,
) -> Result<Option<CheckpointCursor>, ControlPlaneError> {
    Err(ControlPlaneError::UnsupportedPlatform)
}

fn decision(recorded: &RecordedDecision) -> ControlPlaneDecision {
    ControlPlaneDecision {
        request_id: recorded.request_id.clone(),
        request_sha256: recorded.request_sha256.clone(),
        decision: recorded.decision.clone(),
        resulting_cursor: recorded.resulting_cursor.clone(),
    }
}

fn refusal_reason(mode: RemoteCursorCasMode) -> &'static str {
    match mode {
        RemoteCursorCasMode::CreateOnceBootstrap => "already_initialized",
        RemoteCursorCasMode::CompareAndSwap => "compare_and_swap_conflict",
    }
}

fn validate_state(state: &DurableState) -> Result<(), ControlPlaneError> {
    if state.schema != CONTROL_PLANE_STATE_SCHEMA
        || !valid_id(&state.state_identity)
        || !valid_sha256(&state.remote_cursor_policy_sha256)
        || !valid_id(&state.signature_domain)
        || state.decisions.len() > MAX_RECORDED_REQUESTS
        || state
            .current_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.state_identity() != state.state_identity)
    {
        return Err(ControlPlaneError::InvalidState);
    }
    if let Some(cursor) = &state.current_cursor {
        validate_cursor(cursor)?;
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut last_accepted: Option<&CheckpointCursor> = None;
    for recorded in &state.decisions {
        if !valid_id(&recorded.request_id)
            || !valid_sha256(&recorded.request_sha256)
            || !ids.insert(recorded.request_id.as_str())
        {
            return Err(ControlPlaneError::InvalidState);
        }
        match (&recorded.decision, &recorded.resulting_cursor) {
            (RemoteCursorCasDecision::Accepted, Some(cursor)) => {
                validate_cursor(cursor)?;
                if cursor.state_identity() != state.state_identity {
                    return Err(ControlPlaneError::InvalidState);
                }
                last_accepted = Some(cursor);
            }
            (RemoteCursorCasDecision::Refused { reason_code }, None) if valid_id(reason_code) => {}
            _ => return Err(ControlPlaneError::InvalidState),
        }
    }
    if last_accepted != state.current_cursor.as_ref() {
        return Err(ControlPlaneError::InvalidState);
    }
    Ok(())
}

fn validate_cursor(cursor: &CheckpointCursor) -> Result<(), ControlPlaneError> {
    let bytes = cursor
        .canonical_bytes()
        .map_err(|_| ControlPlaneError::InvalidState)?;
    parse_cursor(&bytes).map_err(|_| ControlPlaneError::InvalidState)?;
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, ControlPlaneError> {
    let directory = open_directory(path)?;
    let lock = open_existing_file(&directory, "store.lock")?;
    validate_file(&lock.metadata()?)?;
    validate_named_file(&directory, "store.lock", &lock.metadata()?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, ControlPlaneError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ControlPlaneError::StateMissing
        } else {
            error.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(ControlPlaneError::UnsafeStore("directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = directory.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(ControlPlaneError::UnsafeStore("directoryChanged"));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ControlPlaneError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_path)?;
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn verify_store_path(path: &Path, directory: &File) -> Result<(), ControlPlaneError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(ControlPlaneError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}

#[cfg(unix)]
fn open_existing_file(directory: &File, name: &str) -> Result<File, ControlPlaneError> {
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
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_exclusive(directory: &File, name: &str) -> Result<File, ControlPlaneError> {
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
    fn acquire(directory: &File) -> Result<Self, ControlPlaneError> {
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
                return Err(ControlPlaneError::StoreBusy);
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
fn read_state(directory: &File) -> Result<Option<DurableState>, ControlPlaneError> {
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
        return Err(ControlPlaneError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_file(&after)?;
    validate_named_file(directory, "state.json", &after)?;
    if !same_snapshot(&before, &after)
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
    {
        return Err(ControlPlaneError::UnsafeStore("fileChanged"));
    }
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| ControlPlaneError::InvalidState)?;
    if serde_json::to_vec(&state).map_err(|_| ControlPlaneError::InvalidState)? != bytes {
        return Err(ControlPlaneError::InvalidState);
    }
    validate_state(&state)?;
    Ok(Some(state))
}

#[cfg(unix)]
fn atomic_replace(directory: &File, bytes: &[u8]) -> Result<(), ControlPlaneError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ControlPlaneError::InvalidState);
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| ControlPlaneError::Io(std::io::Error::other(error.to_string())))?;
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
            return Err(ControlPlaneError::Io(std::io::Error::last_os_error()));
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
fn cleanup_stale_temporary_files(directory: &File) -> Result<(), ControlPlaneError> {
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
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
fn validate_directory(metadata: &Metadata) -> Result<(), ControlPlaneError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ControlPlaneError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &Metadata) -> Result<(), ControlPlaneError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ControlPlaneError::UnsafeStore("filePermissions"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_named_file(
    directory: &File,
    name: &str,
    metadata: &Metadata,
) -> Result<(), ControlPlaneError> {
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
        return Err(ControlPlaneError::UnsafeStore("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
        || status.st_nlink != 1
    {
        return Err(ControlPlaneError::UnsafeStore("fileChanged"));
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
fn c_name(name: &str) -> Result<std::ffi::CString, ControlPlaneError> {
    std::ffi::CString::new(name).map_err(|_| ControlPlaneError::InvalidInput)
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
