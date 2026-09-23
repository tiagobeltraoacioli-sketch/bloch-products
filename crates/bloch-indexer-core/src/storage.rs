//! Durable, fail-closed snapshots for the canonical indexer.
//!
//! A snapshot is self-checksummed and replaced atomically in the destination
//! directory. The checksum detects torn writes and accidental corruption; it
//! is not an authenticity signature and callers must protect the directory.

use crate::{
    ApplyOutcome, BlockAnchor, CanonicalBlock, CanonicalIndexer, ChainIdentity, IndexerError,
    delivery::{ClaimOutcome, DeliveryClaim, DeliveryError, OutboxDelivery, ResolutionOutcome},
    outbox::{OutboxError, OutboxQueue, build_outbox},
    validate_block,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

const SNAPSHOT_SCHEMA: &str = "bloch.data.indexer-snapshot.v2";
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("unsafe snapshot path: {0}")]
    UnsafePath(&'static str),
    #[error("snapshot I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    #[error("snapshot checksum mismatch")]
    ChecksumMismatch,
    #[error("indexer state is invalid: {0}")]
    Indexer(#[from] IndexerError),
    #[error("outbox state is invalid: {0}")]
    Outbox(#[from] OutboxError),
    #[error("outbox delivery state is invalid: {0}")]
    Delivery(#[from] DeliveryError),
}

#[derive(Clone, Debug)]
pub struct DurableState {
    pub indexer: CanonicalIndexer,
    pub outbox: OutboxQueue,
    pub delivery: OutboxDelivery,
}

impl DurableState {
    pub fn new(indexer: CanonicalIndexer) -> Self {
        Self {
            indexer,
            outbox: OutboxQueue::new(),
            delivery: OutboxDelivery::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Snapshot {
    schema: String,
    payload: SnapshotPayload,
    payload_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SnapshotPayload {
    network: ChainIdentity,
    anchor: BlockAnchor,
    maximum_reorg_depth: usize,
    canonical_blocks: Vec<CanonicalBlock>,
    seen_blocks: Vec<CanonicalBlock>,
    outbox: OutboxQueue,
    delivery: OutboxDelivery,
}

/// Atomically persists the complete canonical and collision-detection state.
pub fn write_snapshot(state: &DurableState, path: &Path) -> Result<(), StorageError> {
    validate_durable_state(state)?;
    let indexer = &state.indexer;
    let payload = SnapshotPayload {
        network: indexer.network.clone(),
        anchor: indexer.anchor.clone(),
        maximum_reorg_depth: indexer.maximum_reorg_depth,
        canonical_blocks: indexer.blocks.values().cloned().collect(),
        seen_blocks: indexer.seen_blocks.values().cloned().collect(),
        outbox: state.outbox.clone(),
        delivery: state.delivery.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let snapshot = Snapshot {
        schema: SNAPSHOT_SCHEMA.into(),
        payload,
        payload_sha256: format!("0x{}", hex::encode(Sha256::digest(payload_bytes))),
    };
    let mut bytes = serde_json::to_vec_pretty(&snapshot)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(StorageError::InvalidSnapshot("snapshotSize"));
    }
    atomic_replace(path, &bytes)
}

/// Loads a snapshot only after checksum and all indexer invariants validate.
pub fn load_snapshot(path: &Path) -> Result<DurableState, StorageError> {
    let bytes = read_snapshot(path)?;
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    if snapshot.schema != SNAPSHOT_SCHEMA {
        return Err(StorageError::InvalidSnapshot("schema"));
    }
    let payload_bytes = serde_json::to_vec(&snapshot.payload)?;
    let expected = format!("0x{}", hex::encode(Sha256::digest(payload_bytes)));
    if snapshot.payload_sha256 != expected {
        return Err(StorageError::ChecksumMismatch);
    }
    restore(snapshot.payload)
}

/// Applies and persists as one durable transition. In-memory state changes only
/// after the replacement snapshot has been fsynced and renamed successfully.
pub fn apply_and_persist(
    state: &mut DurableState,
    block: CanonicalBlock,
    path: &Path,
) -> Result<ApplyOutcome, StorageError> {
    let mut candidate = state.clone();
    let previous_tip_hash = candidate.indexer.tip().1.to_owned();
    let removed_blocks = if block.height <= candidate.indexer.tip().0 {
        candidate
            .indexer
            .blocks
            .range(block.height..)
            .rev()
            .map(|(_, block)| block.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let outcome = candidate.indexer.apply(block.clone())?;
    if matches!(outcome, ApplyOutcome::Idempotent { .. }) {
        return Ok(outcome);
    }
    let batch = build_outbox(
        &candidate.indexer.network,
        &previous_tip_hash,
        &block,
        &removed_blocks,
    )?;
    candidate.outbox.enqueue(batch)?;
    write_snapshot(&candidate, path)?;
    *state = candidate;
    Ok(outcome)
}

/// Claims the first unacknowledged record and persists the lease before the
/// caller is allowed to perform external delivery.
pub fn claim_and_persist(
    state: &mut DurableState,
    path: &Path,
    now_unix_seconds: u64,
    lease_seconds: u64,
    claim_token: &str,
) -> Result<ClaimOutcome, StorageError> {
    let mut candidate = state.clone();
    let outcome = candidate.delivery.claim_next(
        &candidate.outbox,
        now_unix_seconds,
        lease_seconds,
        claim_token,
    )?;
    write_snapshot(&candidate, path)?;
    *state = candidate;
    Ok(outcome)
}

/// Persists acknowledgement before advancing the in-memory delivery cursor.
pub fn acknowledge_and_persist(
    state: &mut DurableState,
    path: &Path,
    claim: &DeliveryClaim,
    now_unix_seconds: u64,
) -> Result<ResolutionOutcome, StorageError> {
    let mut candidate = state.clone();
    let outcome = candidate
        .delivery
        .acknowledge(&candidate.outbox, claim, now_unix_seconds)?;
    write_snapshot(&candidate, path)?;
    *state = candidate;
    Ok(outcome)
}

/// Releases a claim into a bounded retry delay and persists that schedule.
pub fn retry_and_persist(
    state: &mut DurableState,
    path: &Path,
    claim: &DeliveryClaim,
    now_unix_seconds: u64,
    retry_delay_seconds: u64,
) -> Result<ResolutionOutcome, StorageError> {
    let mut candidate = state.clone();
    let outcome = candidate.delivery.schedule_retry(
        &candidate.outbox,
        claim,
        now_unix_seconds,
        retry_delay_seconds,
    )?;
    write_snapshot(&candidate, path)?;
    *state = candidate;
    Ok(outcome)
}

fn restore(payload: SnapshotPayload) -> Result<DurableState, StorageError> {
    let mut restored = CanonicalIndexer::new(
        payload.network.clone(),
        payload.anchor.clone(),
        payload.maximum_reorg_depth,
    )?;

    for block in payload.canonical_blocks {
        match restored.apply(block)? {
            ApplyOutcome::Applied { .. } => {}
            _ => return Err(StorageError::InvalidSnapshot("canonicalBlocks")),
        }
    }

    let canonical_hashes = restored
        .blocks
        .values()
        .map(|block| (block.block_hash.clone(), block.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeMap::new();
    for block in payload.seen_blocks {
        validate_block(&block)?;
        if block.network != restored.network
            || block.height <= restored.anchor.height
            || block.block_hash == restored.anchor.block_hash
        {
            return Err(StorageError::InvalidSnapshot("seenBlocks"));
        }
        if seen.insert(block.block_hash.clone(), block).is_some() {
            return Err(StorageError::InvalidSnapshot("duplicateSeenBlock"));
        }
    }
    if canonical_hashes
        .iter()
        .any(|(hash, block)| seen.get(hash) != Some(block))
    {
        return Err(StorageError::InvalidSnapshot("missingCanonicalBlock"));
    }
    restored.seen_blocks = seen;
    let state = DurableState {
        indexer: restored,
        outbox: payload.outbox,
        delivery: payload.delivery,
    };
    validate_durable_state(&state)?;
    Ok(state)
}

fn validate_durable_state(state: &DurableState) -> Result<(), StorageError> {
    state.outbox.validate()?;
    state.delivery.validate(&state.outbox)?;
    let (_, tip_hash) = state.indexer.tip();
    match state.outbox.batches.as_slice() {
        [] if tip_hash != state.indexer.anchor.block_hash => {
            Err(StorageError::InvalidSnapshot("missingOutboxHistory"))
        }
        [] => Ok(()),
        batches => {
            let first = batches
                .first()
                .ok_or(StorageError::InvalidSnapshot("outbox"))?;
            let last = batches
                .last()
                .ok_or(StorageError::InvalidSnapshot("outbox"))?;
            if first.previous_tip_hash != state.indexer.anchor.block_hash
                || last.new_tip_hash != tip_hash
                || batches
                    .iter()
                    .flat_map(|batch| &batch.records)
                    .any(|record| record.network != state.indexer.network)
            {
                return Err(StorageError::InvalidSnapshot("outboxContinuity"));
            }
            Ok(())
        }
    }
}

fn read_snapshot(path: &Path) -> Result<Vec<u8>, StorageError> {
    #[cfg(unix)]
    return read_snapshot_unix(path);
    #[cfg(not(unix))]
    return read_snapshot_portable(path);
}

#[cfg(unix)]
fn read_snapshot_unix(path: &Path) -> Result<Vec<u8>, StorageError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = open_parent(path)?;
    // SAFETY: arguments remain live for the call; a successful descriptor is
    // uniquely owned and immediately wrapped in `File`.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(StorageError::UnsafePath("notRegularFile"));
        }
        return Err(StorageError::Io(error));
    }
    // SAFETY: openat returned this uniquely owned descriptor.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file.metadata()?;
    validate_file_metadata(&before)?;
    if !before.is_file() || before.len() > MAX_SNAPSHOT_BYTES {
        return Err(StorageError::InvalidSnapshot("snapshotFile"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::take(&mut file, MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || !unchanged_file(&before, &after) {
        return Err(StorageError::UnsafePath("fileChangedDuringRead"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_snapshot_portable(path: &Path) -> Result<Vec<u8>, StorageError> {
    validate_parent(path)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_SNAPSHOT_BYTES {
        return Err(StorageError::InvalidSnapshot("snapshotFile"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::take(&mut file, MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || before.len() != after.len() {
        return Err(StorageError::UnsafePath("fileChangedDuringRead"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn unchanged_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    #[cfg(unix)]
    return atomic_replace_unix(path, bytes);
    #[cfg(not(unix))]
    return atomic_replace_portable(path, bytes);
}

#[cfg(unix)]
fn atomic_replace_unix(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, destination) = open_parent(path)?;
    validate_destination_at(&parent, &destination)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StorageError::UnsafePath("invalidFileName"))?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary = CString::new(format!(".{name}.tmp-{}-{nonce}", std::process::id()))
        .map_err(|_| StorageError::UnsafePath("invalidFileName"))?;
    // SAFETY: the live directory descriptor and C string are valid. O_EXCL
    // gives unique ownership of a successful descriptor.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(StorageError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned this uniquely owned descriptor.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // SAFETY: both names are valid relative to the same live directory.
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(StorageError::Io(std::io::Error::last_os_error()));
        }
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // SAFETY: best-effort cleanup of the known temporary name.
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

#[cfg(unix)]
fn validate_destination_at(parent: &File, name: &std::ffi::CStr) -> Result<(), StorageError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    let mut status = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: status is writable and the name and descriptor are valid.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(StorageError::Io(error));
    }
    // SAFETY: fstatat initialized status on success.
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(StorageError::UnsafePath("destinationNotRegularFile"));
    }
    if status.st_nlink != 1 {
        return Err(StorageError::UnsafePath("linkCount"));
    }
    if status.st_mode & 0o077 != 0 {
        return Err(StorageError::UnsafePath("filePermissions"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn atomic_replace_portable(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    validate_parent(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StorageError::UnsafePath("destinationNotRegularFile"));
        }
        validate_file_metadata(&metadata)?;
    }
    let parent = path
        .parent()
        .ok_or(StorageError::UnsafePath("missingParent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StorageError::UnsafePath("invalidFileName"))?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.tmp-{}-{nonce}", std::process::id()));
    let result = write_and_replace(&temporary, path, parent, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn write_and_replace(
    temporary: &Path,
    destination: &Path,
    parent: &Path,
    bytes: &[u8],
) -> Result<(), StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn open_parent(path: &Path) -> Result<(File, std::ffi::CString), StorageError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let parent_path = path
        .parent()
        .ok_or(StorageError::UnsafePath("missingParent"))?;
    let before = fs::symlink_metadata(parent_path)?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(StorageError::UnsafePath("invalidParent"));
    }
    use std::os::unix::fs::MetadataExt;
    if before.mode() & 0o022 != 0 {
        return Err(StorageError::UnsafePath("writableParent"));
    }
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(parent_path)?;
    let after = parent.metadata()?;
    if !unchanged_file(&before, &after) {
        return Err(StorageError::UnsafePath("parentChangedDuringOpen"));
    }
    let name = path
        .file_name()
        .ok_or(StorageError::UnsafePath("invalidFileName"))?;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| StorageError::UnsafePath("invalidFileName"))?;
    Ok((parent, name))
}

#[cfg(not(unix))]
fn validate_parent(path: &Path) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or(StorageError::UnsafePath("missingParent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath("invalidParent"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return Err(StorageError::UnsafePath("writableParent"));
        }
    }
    Ok(())
}

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(StorageError::UnsafePath("linkCount"));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(StorageError::UnsafePath("filePermissions"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BLOCK_SCHEMA, CanonicalEvent};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn round_trip_recovers_tip_and_permanent_collision_history() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let mut state = DurableState::new(indexer());
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();
        apply_and_persist(&mut state, block(102, '3', '2'), &path).unwrap();
        apply_and_persist(&mut state, block(101, '4', '1'), &path).unwrap();

        let mut recovered = load_snapshot(&path).unwrap();
        assert_eq!(recovered.indexer.tip(), (101, hash('4').as_str()));
        let mut collision = block(102, '3', '4');
        collision.timestamp_unix_seconds += 1;
        assert!(matches!(
            recovered.indexer.apply(collision),
            Err(IndexerError::HashCollision)
        ));
    }

    #[test]
    fn truncation_and_corruption_fail_closed() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let indexer = indexer();
        let state = DurableState::new(indexer);
        write_snapshot(&state, &path).unwrap();
        let bytes = fs::read(&path).unwrap();

        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::InvalidJson(_))
        ));

        write_snapshot(&state, &path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["maximumReorgDepth"] = serde_json::json!(9);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::ChecksumMismatch)
        ));
    }

    #[test]
    fn checksum_valid_but_incomplete_state_is_refused() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let mut state = DurableState::new(indexer());
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();

        let mut snapshot: Snapshot = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        snapshot.payload.seen_blocks.clear();
        snapshot.payload_sha256 = format!(
            "0x{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(&snapshot.payload).unwrap()
            ))
        );
        fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::InvalidSnapshot("missingCanonicalBlock"))
        ));
    }

    #[test]
    fn canonical_state_and_outbox_cannot_be_persisted_independently() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");

        let mut missing_history = DurableState::new(indexer());
        missing_history.indexer.apply(block(101, '2', '1')).unwrap();
        assert!(matches!(
            write_snapshot(&missing_history, &path),
            Err(StorageError::InvalidSnapshot("missingOutboxHistory"))
        ));

        let mut divergent = DurableState::new(indexer());
        divergent.indexer.apply(block(101, '2', '1')).unwrap();
        divergent
            .outbox
            .enqueue(
                build_outbox(
                    &divergent.indexer.network,
                    &hash('1'),
                    &block(101, '4', '1'),
                    &[],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            write_snapshot(&divergent, &path),
            Err(StorageError::InvalidSnapshot("outboxContinuity"))
        ));
    }

    #[test]
    fn duplicate_json_keys_are_refused() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let duplicated = br#"{
          "schema":"bloch.data.indexer-snapshot.v1",
          "schema":"bloch.data.indexer-snapshot.v1",
          "payload":{},
          "payloadSha256":"0x00"
        }"#;
        fs::write(&path, duplicated).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::InvalidJson(_))
        ));
    }

    #[test]
    fn snapshot_v1_is_not_implicitly_migrated() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        write_snapshot(&DurableState::new(indexer()), &path).unwrap();

        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        snapshot["schema"] = serde_json::json!("bloch.data.indexer-snapshot.v1");
        fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::InvalidSnapshot("schema"))
        ));
    }

    #[test]
    fn durable_transition_replaces_snapshot_and_recovers_new_tip() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let mut state = DurableState::new(indexer());
        write_snapshot(&state, &path).unwrap();
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();
        assert_eq!(
            load_snapshot(&path).unwrap().indexer.tip(),
            (101, hash('2').as_str())
        );
        assert_eq!(load_snapshot(&path).unwrap().outbox.batches.len(), 1);
        assert!(directory.read_dir().unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
    }

    #[test]
    fn reorg_state_and_outbox_recover_together_and_replay_is_silent() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let mut state = DurableState::new(indexer());
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();
        apply_and_persist(&mut state, block(102, '3', '2'), &path).unwrap();
        apply_and_persist(&mut state, block(101, '4', '1'), &path).unwrap();

        let mut recovered = load_snapshot(&path).unwrap();
        assert_eq!(recovered.indexer.tip(), (101, hash('4').as_str()));
        assert_eq!(recovered.outbox.batches.len(), 3);
        assert_eq!(recovered.outbox.batches.last().unwrap().records.len(), 3);

        let before = fs::read(&path).unwrap();
        assert!(matches!(
            apply_and_persist(&mut recovered, block(101, '4', '1'), &path).unwrap(),
            ApplyOutcome::Idempotent { .. }
        ));
        assert_eq!(recovered.outbox.batches.len(), 3);
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn claim_retry_and_ack_progress_survive_recovery() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let mut state = DurableState::new(indexer());
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();
        apply_and_persist(&mut state, block(102, '3', '2'), &path).unwrap();

        let claim =
            match claim_and_persist(&mut state, &path, 1_800_000_000, 30, &hash('a')).unwrap() {
                ClaimOutcome::Claimed { claim, .. } => claim,
                outcome => panic!("expected claim, got {outcome:?}"),
            };
        let mut recovered = load_snapshot(&path).unwrap();
        assert_eq!(recovered.delivery.pending_position(), (0, 0));
        assert_eq!(
            retry_and_persist(&mut recovered, &path, &claim, 1_800_000_001, 10).unwrap(),
            ResolutionOutcome::Applied
        );

        let mut recovered = load_snapshot(&path).unwrap();
        assert!(matches!(
            claim_and_persist(&mut recovered, &path, 1_800_000_010, 30, &hash('b')).unwrap(),
            ClaimOutcome::Unavailable {
                retry_at_unix_seconds: 1_800_000_011
            }
        ));
        let retry = match claim_and_persist(&mut recovered, &path, 1_800_000_011, 30, &hash('b'))
            .unwrap()
        {
            ClaimOutcome::Claimed { claim, .. } => claim,
            outcome => panic!("expected retry claim, got {outcome:?}"),
        };
        acknowledge_and_persist(&mut recovered, &path, &retry, 1_800_000_012).unwrap();
        assert_eq!(
            load_snapshot(&path).unwrap().delivery.pending_position(),
            (1, 0)
        );
    }

    #[test]
    fn failed_claim_resolution_persistence_does_not_advance_cursor() {
        let directory = private_directory();
        let path = directory.join("indexer.snapshot.json");
        let missing = directory.join("missing").join("snapshot.json");
        let mut state = DurableState::new(indexer());
        apply_and_persist(&mut state, block(101, '2', '1'), &path).unwrap();
        let claim =
            match claim_and_persist(&mut state, &path, 1_800_000_000, 30, &hash('a')).unwrap() {
                ClaimOutcome::Claimed { claim, .. } => claim,
                outcome => panic!("expected claim, got {outcome:?}"),
            };
        let before = state.delivery.clone();
        assert!(acknowledge_and_persist(&mut state, &missing, &claim, 1_800_000_001).is_err());
        assert_eq!(state.delivery, before);
        assert_eq!(state.delivery.pending_position(), (0, 0));
    }

    #[test]
    fn failed_persistence_does_not_mutate_memory() {
        let directory = private_directory();
        let missing = directory.join("missing").join("snapshot.json");
        let mut state = DurableState::new(indexer());
        assert!(apply_and_persist(&mut state, block(101, '2', '1'), &missing).is_err());
        assert_eq!(state.indexer.tip(), (100, hash('1').as_str()));
        assert!(state.outbox.batches.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_hardlinks_and_permissive_files_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = private_directory();
        let path = directory.join("snapshot.json");
        write_snapshot(&DurableState::new(indexer()), &path).unwrap();
        let hard = directory.join("hard.json");
        fs::hard_link(&path, &hard).unwrap();
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::UnsafePath("linkCount"))
        ));
        fs::remove_file(hard).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_snapshot(&path),
            Err(StorageError::UnsafePath("filePermissions"))
        ));
        let symbolic = directory.join("symbolic.json");
        symlink(&path, &symbolic).unwrap();
        assert!(matches!(
            load_snapshot(&symbolic),
            Err(StorageError::UnsafePath(_))
        ));
    }

    fn private_directory() -> PathBuf {
        let nonce = DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bloch-indexer-storage-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn indexer() -> CanonicalIndexer {
        CanonicalIndexer::new(
            ChainIdentity {
                network: "bloch-l2".into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('a'),
            },
            4,
        )
        .unwrap()
    }

    fn block(height: u64, block_hash: char, parent_hash: char) -> CanonicalBlock {
        CanonicalBlock {
            schema: BLOCK_SCHEMA.into(),
            network: ChainIdentity {
                network: "bloch-l2".into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            height,
            block_hash: hash(block_hash),
            parent_hash: hash(parent_hash),
            state_root: hash('a'),
            timestamp_unix_seconds: 1_790_000_000 + height,
            events: vec![CanonicalEvent {
                transaction_hash: hash('b'),
                transaction_index: 0,
                log_index: 0,
                address: format!("0x{}", "c".repeat(40)),
                topics: vec![],
                data: "0x".into(),
            }],
        }
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }
}
