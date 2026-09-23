//! Offline comparison of separately operated audit-retention replicas.
//!
//! This module only reads and verifies local replica paths. A successful
//! comparison does not prove storage independence, WORM retention, network
//! availability, or distributed/HA coordination.

use super::{
    GENESIS_ENTRY_SHA256, RetentionCheckpointError, RetentionError, RetentionExpectation,
    VerifiedRetentionCheckpoint, verify_audit_ledger_with_expectation, verify_retention_checkpoint,
};
use serde::{Deserialize, Serialize, de};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

pub const MAX_AUDIT_REPLICAS: usize = 32;
pub const MAX_REPLICA_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_REPLICA_ID_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub struct ReplicaVerificationInput {
    pub replica_id: String,
    pub ledger: PathBuf,
    pub checkpoint_bytes: Vec<u8>,
    pub signer_id: String,
    pub signature_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReplicaStatus {
    Current,
    Stale,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedReplica {
    pub replica_id: String,
    pub status: ReplicaStatus,
    pub entry_count: u64,
    pub head_sha256: String,
    pub checkpoint_sha256: String,
    pub signer_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaSetReport {
    pub ledger_id: String,
    pub audit_policy_sha256: String,
    pub checkpoint_policy_sha256: String,
    pub required_quorum: usize,
    pub current_count: u64,
    pub current_head_sha256: String,
    pub agreeing_current_replicas: usize,
    pub replicas: Vec<VerifiedReplica>,
}

#[derive(Debug, Error)]
pub enum ReplicaSetError {
    #[error("replica set configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("replica identifier is invalid")]
    InvalidReplicaId,
    #[error("duplicate replica identifier: {0}")]
    DuplicateReplicaId(String),
    #[error("replicas {first} and {second} resolve to the same ledger directory")]
    DuplicateLedger { first: String, second: String },
    #[error("replica {replica_id} checkpoint verification failed: {source}")]
    Checkpoint {
        replica_id: String,
        #[source]
        source: RetentionCheckpointError,
    },
    #[error("replica {replica_id} ledger replay failed: {source}")]
    Replay {
        replica_id: String,
        #[source]
        source: RetentionError,
    },
    #[error("replica identity or policy substitution detected at {0}")]
    Substitution(String),
    #[error("replica history split-brain between {first} and {second} at sequence {sequence}")]
    SplitBrain {
        first: String,
        second: String,
        sequence: u64,
    },
    #[error("replica rollback or truncation detected at {0}")]
    Rollback(String),
    #[error("current-boundary quorum not met: required {required}, observed {observed}")]
    QuorumNotMet { required: usize, observed: usize },
    #[error("replica manifest is invalid: {0}")]
    InvalidManifest(String),
}

/// Strict, bounded CLI manifest. Policy material remains separately pinned and
/// is deliberately not selected by this document.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplicaManifest {
    pub required_quorum: usize,
    pub replicas: Vec<ReplicaManifestEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplicaManifestEntry {
    pub replica_id: String,
    pub ledger_path: PathBuf,
    pub checkpoint_path: PathBuf,
    pub signer_id: String,
    pub signature_path: PathBuf,
}

pub fn parse_replica_manifest(bytes: &[u8]) -> Result<ReplicaManifest, ReplicaSetError> {
    if bytes.is_empty() || bytes.len() > MAX_REPLICA_MANIFEST_BYTES {
        return Err(ReplicaSetError::InvalidManifest("size".into()));
    }
    reject_duplicate_keys(bytes)?;
    let manifest: ReplicaManifest = serde_json::from_slice(bytes)
        .map_err(|error| ReplicaSetError::InvalidManifest(error.to_string()))?;
    validate_configuration(&manifest.replicas, manifest.required_quorum)?;
    for replica in &manifest.replicas {
        validate_replica_id(&replica.replica_id)?;
        if replica.ledger_path.as_os_str().is_empty()
            || replica.checkpoint_path.as_os_str().is_empty()
            || replica.signature_path.as_os_str().is_empty()
            || replica.signer_id.is_empty()
            || replica.signer_id.len() > MAX_REPLICA_ID_BYTES
        {
            return Err(ReplicaSetError::InvalidManifest("entry".into()));
        }
    }
    Ok(manifest)
}

/// Replays every supplied ledger, verifies its signed boundary against the two
/// independent policy pins, compares every shared history prefix, and requires
/// an exact quorum at the freshest observed boundary.
#[allow(clippy::too_many_arguments)]
pub fn verify_audit_replicas(
    replicas: &[ReplicaVerificationInput],
    required_quorum: usize,
    audit_policy_bytes: &[u8],
    expected_audit_policy_sha256: &str,
    checkpoint_policy_bytes: &[u8],
    expected_checkpoint_policy_sha256: &str,
    previously_verified: Option<&VerifiedRetentionCheckpoint>,
) -> Result<ReplicaSetReport, ReplicaSetError> {
    validate_configuration(replicas, required_quorum)?;
    validate_distinct_replicas(replicas)?;

    struct Replay {
        checkpoint: VerifiedRetentionCheckpoint,
        hashes: Vec<String>,
    }
    let mut verified = Vec::with_capacity(replicas.len());
    for replica in replicas {
        let checkpoint = verify_retention_checkpoint(
            &replica.checkpoint_bytes,
            &replica.signer_id,
            &replica.signature_bytes,
            checkpoint_policy_bytes,
            expected_checkpoint_policy_sha256,
        )
        .map_err(|source| ReplicaSetError::Checkpoint {
            replica_id: replica.replica_id.clone(),
            source,
        })?;
        if checkpoint.audit_policy_sha256() != expected_audit_policy_sha256 {
            return Err(ReplicaSetError::Substitution(replica.replica_id.clone()));
        }
        let expectation = RetentionExpectation {
            entry_count: checkpoint.entry_count(),
            head_sha256: checkpoint.head_sha256().into(),
        };
        let entries = verify_audit_ledger_with_expectation(
            &replica.ledger,
            audit_policy_bytes,
            expected_audit_policy_sha256,
            Some(&expectation),
        )
        .map_err(|source| ReplicaSetError::Replay {
            replica_id: replica.replica_id.clone(),
            source,
        })?;
        let hashes: Vec<_> = entries
            .into_iter()
            .map(|entry| entry.entry_sha256)
            .collect();
        if let Some(previous) = previously_verified {
            if previous.ledger_id() != checkpoint.ledger_id()
                || previous.audit_policy_sha256() != checkpoint.audit_policy_sha256()
                || previous.checkpoint_policy_sha256() != checkpoint.checkpoint_policy_sha256()
            {
                return Err(ReplicaSetError::Substitution(replica.replica_id.clone()));
            }
            if previous.entry_count() > checkpoint.entry_count()
                || boundary_hash(&hashes, previous.entry_count()) != Some(previous.head_sha256())
            {
                return Err(ReplicaSetError::Rollback(replica.replica_id.clone()));
            }
        }
        verified.push(Replay { checkpoint, hashes });
    }

    let first = &verified[0].checkpoint;
    for (input, replay) in replicas.iter().zip(&verified).skip(1) {
        if replay.checkpoint.ledger_id() != first.ledger_id()
            || replay.checkpoint.audit_policy_sha256() != first.audit_policy_sha256()
            || replay.checkpoint.checkpoint_policy_sha256() != first.checkpoint_policy_sha256()
            || replay.checkpoint.checkpoint_domain() != first.checkpoint_domain()
        {
            return Err(ReplicaSetError::Substitution(input.replica_id.clone()));
        }
    }
    for left in 0..verified.len() {
        for right in left + 1..verified.len() {
            let shared = verified[left]
                .hashes
                .len()
                .min(verified[right].hashes.len());
            if let Some(offset) = (0..shared)
                .find(|offset| verified[left].hashes[*offset] != verified[right].hashes[*offset])
            {
                return Err(ReplicaSetError::SplitBrain {
                    first: replicas[left].replica_id.clone(),
                    second: replicas[right].replica_id.clone(),
                    sequence: offset as u64 + 1,
                });
            }
        }
    }
    let ledger_id = first.ledger_id().to_owned();
    let audit_policy_sha256 = first.audit_policy_sha256().to_owned();
    let checkpoint_policy_sha256 = first.checkpoint_policy_sha256().to_owned();

    let current_count = verified
        .iter()
        .map(|replay| replay.checkpoint.entry_count())
        .max()
        .ok_or(ReplicaSetError::InvalidConfiguration("replicas"))?;
    let current_head = verified
        .iter()
        .find(|replay| replay.checkpoint.entry_count() == current_count)
        .expect("maximum came from verified replica")
        .checkpoint
        .head_sha256()
        .to_owned();
    let agreeing = verified
        .iter()
        .filter(|replay| {
            replay.checkpoint.entry_count() == current_count
                && replay.checkpoint.head_sha256() == current_head
        })
        .count();
    if agreeing < required_quorum {
        return Err(ReplicaSetError::QuorumNotMet {
            required: required_quorum,
            observed: agreeing,
        });
    }
    let replicas = replicas
        .iter()
        .zip(verified)
        .map(|(input, replay)| VerifiedReplica {
            replica_id: input.replica_id.clone(),
            status: if replay.checkpoint.entry_count() == current_count {
                ReplicaStatus::Current
            } else {
                ReplicaStatus::Stale
            },
            entry_count: replay.checkpoint.entry_count(),
            head_sha256: replay.checkpoint.head_sha256().into(),
            checkpoint_sha256: replay.checkpoint.canonical_sha256().into(),
            signer_id: replay.checkpoint.signer_id().into(),
        })
        .collect();
    Ok(ReplicaSetReport {
        ledger_id,
        audit_policy_sha256,
        checkpoint_policy_sha256,
        required_quorum,
        current_count,
        current_head_sha256: current_head,
        agreeing_current_replicas: agreeing,
        replicas,
    })
}

fn boundary_hash(hashes: &[String], count: u64) -> Option<&str> {
    if count == 0 {
        return Some(GENESIS_ENTRY_SHA256);
    }
    let index = usize::try_from(count - 1).ok()?;
    hashes.get(index).map(String::as_str)
}

fn validate_configuration<T>(replicas: &[T], quorum: usize) -> Result<(), ReplicaSetError> {
    if replicas.len() < 2 || replicas.len() > MAX_AUDIT_REPLICAS {
        return Err(ReplicaSetError::InvalidConfiguration("replicaCount"));
    }
    if quorum < 2 || quorum > replicas.len() || quorum > MAX_AUDIT_REPLICAS {
        return Err(ReplicaSetError::InvalidConfiguration("quorum"));
    }
    Ok(())
}

fn validate_replica_id(value: &str) -> Result<(), ReplicaSetError> {
    if value.is_empty()
        || value.len() > MAX_REPLICA_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ReplicaSetError::InvalidReplicaId);
    }
    Ok(())
}

fn validate_distinct_replicas(
    replicas: &[ReplicaVerificationInput],
) -> Result<(), ReplicaSetError> {
    let mut ids = BTreeSet::new();
    let mut objects = BTreeMap::new();
    for replica in replicas {
        validate_replica_id(&replica.replica_id)?;
        if !ids.insert(replica.replica_id.clone()) {
            return Err(ReplicaSetError::DuplicateReplicaId(
                replica.replica_id.clone(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata =
                std::fs::metadata(&replica.ledger).map_err(|source| ReplicaSetError::Replay {
                    replica_id: replica.replica_id.clone(),
                    source: RetentionError::Io(source),
                })?;
            let identity = (metadata.dev(), metadata.ino());
            if let Some(first) = objects.insert(identity, replica.replica_id.clone()) {
                return Err(ReplicaSetError::DuplicateLedger {
                    first,
                    second: replica.replica_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ReplicaSetError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedValue::deserialize(&mut deserializer)
        .map_err(|error| ReplicaSetError::InvalidManifest(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ReplicaSetError::InvalidManifest(error.to_string()))
}

struct DuplicateCheckedValue;
impl<'de> Deserialize<'de> for DuplicateCheckedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}
struct DuplicateVisitor;
impl<'de> de::Visitor<'de> for DuplicateVisitor {
    type Value = DuplicateCheckedValue;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            map.next_value::<DuplicateCheckedValue>()?;
        }
        Ok(DuplicateCheckedValue)
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while seq.next_element::<DuplicateCheckedValue>()?.is_some() {}
        Ok(DuplicateCheckedValue)
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateCheckedValue::deserialize(d)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
}
