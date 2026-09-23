//! Offline quorum comparison for independently authenticated remote cursors.
//!
//! This crate performs no collection, networking, storage, consensus, leader
//! election or fencing. It only compares already verified signed observations.

use bloch_local_state_cursor::CheckpointCursor;
use bloch_local_state_remote_cursor::VerifiedRemoteCursor;
use bloch_trusted_time::VerifiedTrustedTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const REPLICA_QUORUM_POLICY_SCHEMA: &str =
    "bloch.products.remote-cursor-replica-quorum-policy.v1";
pub const REPLICA_QUORUM_REPORT_SCHEMA: &str =
    "bloch.products.remote-cursor-replica-quorum-report.v1";
pub const MAX_REPLICA_QUORUM_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_REPLICA_QUORUM_REPORT_BYTES: usize = 64 * 1024;
const MIN_REPLICAS: usize = 2;
const MAX_REPLICAS: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplicaDescriptor {
    pub replica_id: String,
    /// Operational failure-domain identity. Equality is rejected, but the
    /// truth of this declaration cannot be established by this crate.
    pub provenance_id: String,
    /// Exact signer set required on this replica's authenticated observation.
    pub signer_authority_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplicaQuorumPolicy {
    pub schema: String,
    pub policy_id: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub trusted_time_policy_sha256: String,
    pub quorum: u16,
    /// Every supplied observation must have exclusive age below this bound.
    pub max_observation_age_seconds: u64,
    /// Maximum difference between the freshest observation timestamp and an
    /// observation allowed to vote. Current-time freshness remains external.
    pub max_observation_skew_seconds: u64,
    pub replicas: Vec<ReplicaDescriptor>,
}

/// One association supplied by the collector. The replica identity is bound
/// to the independently pinned signer set before its vote is counted.
pub struct ReplicaEvidence<'a> {
    pub replica_id: &'a str,
    pub observation: &'a VerifiedRemoteCursor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QuorumReportDocument {
    schema: String,
    replica_quorum_policy_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    trusted_time_policy_sha256: String,
    trusted_time_token_sha256: String,
    evaluated_at_unix_seconds: u64,
    quorum: u16,
    cursor: CheckpointCursor,
    cursor_sha256: String,
    oldest_counted_observation_unix_seconds: u64,
    freshest_observation_unix_seconds: u64,
    replica_ids: Vec<String>,
    observation_sha256s: Vec<String>,
}

/// Opaque canonical report that a pinned threshold agreed on the complete
/// freshest cursor among the supplied, sufficiently co-temporal evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReplicaQuorum {
    document: QuorumReportDocument,
    canonical_bytes: Vec<u8>,
}

impl VerifiedReplicaQuorum {
    pub fn cursor(&self) -> &CheckpointCursor {
        &self.document.cursor
    }
    pub fn replica_quorum_policy_sha256(&self) -> &str {
        &self.document.replica_quorum_policy_sha256
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.document.remote_cursor_policy_sha256
    }
    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.document.trusted_time_policy_sha256
    }
    pub fn trusted_time_token_sha256(&self) -> &str {
        &self.document.trusted_time_token_sha256
    }
    pub fn evaluated_at_unix_seconds(&self) -> u64 {
        self.document.evaluated_at_unix_seconds
    }
    pub fn replica_ids(&self) -> &[String] {
        &self.document.replica_ids
    }
    pub fn observation_sha256s(&self) -> &[String] {
        &self.document.observation_sha256s
    }
    pub fn oldest_counted_observation_unix_seconds(&self) -> u64 {
        self.document.oldest_counted_observation_unix_seconds
    }
    pub fn freshest_observation_unix_seconds(&self) -> u64 {
        self.document.freshest_observation_unix_seconds
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn consensus_proven(&self) -> bool {
        false
    }
    pub fn linearizability_proven(&self) -> bool {
        false
    }
    pub fn replica_independence_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplicaQuorumError {
    #[error("replica quorum policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("replica quorum policy pin mismatch")]
    PolicyPinMismatch,
    #[error("replica evidence is invalid")]
    InvalidEvidence,
    #[error("replica evidence is duplicated")]
    DuplicateEvidence,
    #[error("replica provenance is not independent as declared")]
    DuplicateProvenance,
    #[error("replica signer identity does not match its pinned identity")]
    SignerMismatch,
    #[error("replica evidence crosses state or remote-policy identity")]
    IdentityMismatch,
    #[error("trusted time does not match the pinned quorum audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTimeUnavailable,
    #[error("replica evidence is from the future or outside its absolute freshness window")]
    OutsideFreshnessWindow,
    #[error("replicas report different complete cursors at one generation")]
    SplitBrain,
    #[error("freshest complete cursor does not have a sufficiently fresh quorum")]
    StaleQuorum,
    #[error("freshest quorum rolls back or conflicts with prior expectation")]
    Rollback,
}

pub fn replica_quorum_policy_bytes(
    policy: &ReplicaQuorumPolicy,
) -> Result<Vec<u8>, ReplicaQuorumError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| ReplicaQuorumError::InvalidPolicy)?;
    if bytes.len() > MAX_REPLICA_QUORUM_POLICY_BYTES {
        return Err(ReplicaQuorumError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn replica_quorum_policy_sha256(
    policy: &ReplicaQuorumPolicy,
) -> Result<String, ReplicaQuorumError> {
    Ok(hash(&replica_quorum_policy_bytes(policy)?))
}

pub fn parse_replica_quorum_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<ReplicaQuorumPolicy, ReplicaQuorumError> {
    if bytes.is_empty()
        || bytes.len() > MAX_REPLICA_QUORUM_POLICY_BYTES
        || !valid_sha256(expected_policy_sha256)
    {
        return Err(ReplicaQuorumError::InvalidPolicy);
    }
    let policy: ReplicaQuorumPolicy =
        serde_json::from_slice(bytes).map_err(|_| ReplicaQuorumError::InvalidPolicy)?;
    if replica_quorum_policy_bytes(&policy)? != bytes {
        return Err(ReplicaQuorumError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

/// Compares authenticated observations without interpreting a quorum as a
/// consensus certificate. The collector must freshly acquire every input.
pub fn verify_replica_quorum(
    evidence: &[ReplicaEvidence<'_>],
    policy: &ReplicaQuorumPolicy,
    expected_policy_sha256: &str,
    expected_previous: Option<&CheckpointCursor>,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedReplicaQuorum, ReplicaQuorumError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
    {
        return Err(ReplicaQuorumError::TrustedTimeAudienceMismatch);
    }
    let evaluated_at_unix_seconds = trusted_time
        .unix_seconds()
        .map_err(|_| ReplicaQuorumError::TrustedTimeUnavailable)?;
    if evidence.len() < usize::from(policy.quorum) || evidence.len() > policy.replicas.len() {
        return Err(ReplicaQuorumError::InvalidEvidence);
    }
    if let Some(previous) = expected_previous {
        previous
            .canonical_bytes()
            .map_err(|_| ReplicaQuorumError::InvalidEvidence)?;
        if previous.state_identity() != policy.state_identity {
            return Err(ReplicaQuorumError::IdentityMismatch);
        }
    }

    let mut replica_ids = BTreeSet::new();
    let mut observation_hashes = BTreeSet::new();
    let mut prepared = Vec::with_capacity(evidence.len());
    let mut freshest_observed_at = 0;
    for item in evidence {
        if !replica_ids.insert(item.replica_id) {
            return Err(ReplicaQuorumError::DuplicateEvidence);
        }
        if !observation_hashes.insert(item.observation.observation_sha256()) {
            return Err(ReplicaQuorumError::DuplicateEvidence);
        }
        let descriptor = policy
            .replicas
            .binary_search_by(|entry| entry.replica_id.as_str().cmp(item.replica_id))
            .ok()
            .map(|index| &policy.replicas[index])
            .ok_or(ReplicaQuorumError::InvalidEvidence)?;
        if item.observation.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
            || item.observation.cursor().state_identity() != policy.state_identity
        {
            return Err(ReplicaQuorumError::IdentityMismatch);
        }
        if item.observation.authority_ids() != descriptor.signer_authority_ids {
            return Err(ReplicaQuorumError::SignerMismatch);
        }
        let observed_at = item.observation.observed_at_unix_seconds();
        if evaluated_at_unix_seconds < observed_at
            || evaluated_at_unix_seconds - observed_at >= policy.max_observation_age_seconds
        {
            return Err(ReplicaQuorumError::OutsideFreshnessWindow);
        }
        freshest_observed_at =
            freshest_observed_at.max(item.observation.observed_at_unix_seconds());
        prepared.push((descriptor, item.observation));
    }

    // A conflict at any supplied generation is a fail-closed signal, even if
    // another generation could otherwise reach quorum.
    for (index, (_, left)) in prepared.iter().enumerate() {
        for (_, right) in prepared.iter().skip(index + 1) {
            if left.cursor().generation() == right.cursor().generation()
                && left.cursor() != right.cursor()
            {
                return Err(ReplicaQuorumError::SplitBrain);
            }
        }
    }

    let freshest_generation = prepared
        .iter()
        .map(|(_, observation)| observation.cursor().generation())
        .max()
        .ok_or(ReplicaQuorumError::InvalidEvidence)?;
    let freshest_cursor = prepared
        .iter()
        .find(|(_, observation)| observation.cursor().generation() == freshest_generation)
        .map(|(_, observation)| observation.cursor().clone())
        .ok_or(ReplicaQuorumError::InvalidEvidence)?;

    if let Some(previous) = expected_previous
        && (freshest_cursor.generation() < previous.generation()
            || (freshest_cursor.generation() == previous.generation()
                && &freshest_cursor != previous))
    {
        return Err(ReplicaQuorumError::Rollback);
    }

    let minimum_observed_at =
        freshest_observed_at.saturating_sub(policy.max_observation_skew_seconds);
    let mut counted = prepared
        .into_iter()
        .filter(|(_, observation)| {
            observation.cursor() == &freshest_cursor
                && observation.observed_at_unix_seconds() >= minimum_observed_at
        })
        .collect::<Vec<_>>();
    if counted.len() < usize::from(policy.quorum) {
        return Err(ReplicaQuorumError::StaleQuorum);
    }
    counted.sort_by(|(left, _), (right, _)| left.replica_id.cmp(&right.replica_id));
    let oldest_counted = counted
        .iter()
        .map(|(_, observation)| observation.observed_at_unix_seconds())
        .min()
        .ok_or(ReplicaQuorumError::StaleQuorum)?;
    let cursor_bytes = freshest_cursor
        .canonical_bytes()
        .map_err(|_| ReplicaQuorumError::InvalidEvidence)?;
    let document = QuorumReportDocument {
        schema: REPLICA_QUORUM_REPORT_SCHEMA.into(),
        replica_quorum_policy_sha256: expected_policy_sha256.into(),
        state_identity: policy.state_identity.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        trusted_time_policy_sha256: policy.trusted_time_policy_sha256.clone(),
        trusted_time_token_sha256: trusted_time.token_sha256().into(),
        evaluated_at_unix_seconds,
        quorum: policy.quorum,
        cursor: freshest_cursor,
        cursor_sha256: hash(&cursor_bytes),
        oldest_counted_observation_unix_seconds: oldest_counted,
        freshest_observation_unix_seconds: freshest_observed_at,
        replica_ids: counted
            .iter()
            .map(|(descriptor, _)| descriptor.replica_id.clone())
            .collect(),
        observation_sha256s: counted
            .iter()
            .map(|(_, observation)| observation.observation_sha256().into())
            .collect(),
    };
    let canonical_bytes =
        serde_json::to_vec(&document).map_err(|_| ReplicaQuorumError::InvalidEvidence)?;
    if canonical_bytes.len() > MAX_REPLICA_QUORUM_REPORT_BYTES {
        return Err(ReplicaQuorumError::InvalidEvidence);
    }
    Ok(VerifiedReplicaQuorum {
        document,
        canonical_bytes,
    })
}

fn validate_policy_pin(
    policy: &ReplicaQuorumPolicy,
    expected_policy_sha256: &str,
) -> Result<(), ReplicaQuorumError> {
    if !valid_sha256(expected_policy_sha256)
        || replica_quorum_policy_sha256(policy)? != expected_policy_sha256
    {
        return Err(ReplicaQuorumError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &ReplicaQuorumPolicy) -> Result<(), ReplicaQuorumError> {
    if policy.schema != REPLICA_QUORUM_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
        || policy.replicas.len() < MIN_REPLICAS
        || policy.replicas.len() > MAX_REPLICAS
        || usize::from(policy.quorum) < MIN_REPLICAS
        || usize::from(policy.quorum) > policy.replicas.len()
        || policy.max_observation_age_seconds == 0
        || policy.max_observation_skew_seconds == 0
    {
        return Err(ReplicaQuorumError::InvalidPolicy);
    }
    let mut previous_replica: Option<&str> = None;
    let mut provenances = BTreeSet::new();
    let mut global_signers = BTreeSet::new();
    for replica in &policy.replicas {
        if !valid_id(&replica.replica_id)
            || !valid_id(&replica.provenance_id)
            || previous_replica.is_some_and(|id| id >= replica.replica_id.as_str())
            || replica.signer_authority_ids.is_empty()
            || replica.signer_authority_ids.len() > MAX_REPLICAS
        {
            return Err(ReplicaQuorumError::InvalidPolicy);
        }
        if !provenances.insert(replica.provenance_id.as_str()) {
            return Err(ReplicaQuorumError::DuplicateProvenance);
        }
        let mut previous_signer: Option<&str> = None;
        for signer in &replica.signer_authority_ids {
            if !valid_id(signer)
                || previous_signer.is_some_and(|id| id >= signer.as_str())
                || !global_signers.insert(signer.as_str())
            {
                return Err(ReplicaQuorumError::InvalidPolicy);
            }
            previous_signer = Some(signer);
        }
        previous_replica = Some(&replica.replica_id);
    }
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

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
