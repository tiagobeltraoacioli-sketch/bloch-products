//! Threshold-authenticated checkpoint ancestry.
//!
//! A verified capability binds one already-validated `EvmAncestryEvidence`
//! object to an independently pinned policy, bundle, network, checkpoint and
//! terminal trust anchor. It authenticates parent linkage only. In particular,
//! neither an authority signature nor an upstream `finalized` label is a
//! protocol consensus-finality proof.

use crate::{
    Checkpoint, EvmAncestryEvidence, EvmBlockReference, network_identity_sha256,
    verify_evm_ancestry_evidence,
};
use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const CHECKPOINT_ANCESTRY_POLICY_SCHEMA: &str = "bloch.verify.checkpoint-ancestry-policy.v1";
pub const CHECKPOINT_ANCESTRY_EVIDENCE_SCHEMA: &str =
    "bloch.verify.authenticated-checkpoint-ancestry.v1";
const SIGNING_PREFIX: &[u8] = b"BLOCH-VERIFY-CHECKPOINT-ANCESTRY-V1\0";
const MAX_BYTES: usize = 64 * 1024;
const MAX_AUTHORITIES: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AncestryAuthority {
    pub authority_id: String,
    pub organization_id: String,
    pub control_domain: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckpointAncestryPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub expected_network_sha256: String,
    pub trusted_anchor_height: u64,
    pub trusted_anchor_block_hash: String,
    pub trusted_anchor_state_root: String,
    pub trusted_time_policy_sha256: String,
    pub trusted_time_state_identity: String,
    pub authority_threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub authorities: Vec<AncestryAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AncestrySignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AncestryEnvelope {
    schema: String,
    checkpoint_ancestry_policy_sha256: String,
    ancestry_evidence_sha256: String,
    assessed_bundle_sha256: String,
    expected_network_sha256: String,
    checkpoint_height: u64,
    checkpoint_block_hash: String,
    checkpoint_state_root: String,
    trusted_anchor_height: u64,
    trusted_anchor_block_hash: String,
    trusted_anchor_state_root: String,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedAncestryEvidence {
    envelope: AncestryEnvelope,
    signatures: Vec<AncestrySignature>,
}

pub struct CheckpointAncestryAudience<'a> {
    pub assessed_bundle_sha256: &'a str,
    pub expected_network_sha256: &'a str,
    pub expected_checkpoint: &'a Checkpoint,
}

/// Non-cloneable proof that a threshold authenticated one exact parent chain.
#[derive(Debug)]
pub struct VerifiedCheckpointAncestry {
    policy_sha256: String,
    evidence_sha256: String,
    ancestry_evidence_sha256: String,
    assessed_bundle_sha256: String,
    expected_network_sha256: String,
    checkpoint: Checkpoint,
    trusted_anchor: EvmBlockReference,
    authority_ids: Vec<String>,
    deadline_unix_seconds: u64,
    expires_at: Instant,
}

impl VerifiedCheckpointAncestry {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
    pub fn ancestry_evidence_sha256(&self) -> &str {
        &self.ancestry_evidence_sha256
    }
    pub fn assessed_bundle_sha256(&self) -> &str {
        &self.assessed_bundle_sha256
    }
    pub fn expected_network_sha256(&self) -> &str {
        &self.expected_network_sha256
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    pub fn trusted_anchor(&self) -> &EvmBlockReference {
        &self.trusted_anchor
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), CheckpointAncestryError> {
        if Instant::now() >= self.expires_at {
            Err(CheckpointAncestryError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
    /// Always false: this capability authenticates parent linkage, not finality.
    pub fn consensus_finality_authenticated(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointAncestryError {
    #[error("checkpoint-ancestry policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("checkpoint-ancestry policy pin mismatch")]
    PolicyPinMismatch,
    #[error("checkpoint-ancestry evidence is invalid or non-canonical")]
    InvalidEvidence,
    #[error("checkpoint-ancestry evidence crosses its pinned audience")]
    AudienceMismatch,
    #[error("checkpoint-ancestry evidence is outside its authenticated time window")]
    InvalidTime,
    #[error("trusted-time capability does not match the ancestry policy")]
    TrustedTimeMismatch,
    #[error("checkpoint-ancestry capability has expired")]
    ExpiredCapability,
    #[error("checkpoint-ancestry authority is untrusted")]
    UntrustedAuthority,
    #[error("checkpoint-ancestry signature is duplicated or unordered")]
    DuplicateSignature,
    #[error("checkpoint-ancestry signature is invalid")]
    InvalidSignature,
    #[error("checkpoint-ancestry signature threshold is not met")]
    ThresholdNotMet,
}

pub fn checkpoint_ancestry_policy_bytes(
    policy: &CheckpointAncestryPolicy,
) -> Result<Vec<u8>, CheckpointAncestryError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| CheckpointAncestryError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(CheckpointAncestryError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn checkpoint_ancestry_policy_sha256(
    policy: &CheckpointAncestryPolicy,
) -> Result<String, CheckpointAncestryError> {
    Ok(hash(&checkpoint_ancestry_policy_bytes(policy)?))
}

pub fn parse_checkpoint_ancestry_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<CheckpointAncestryPolicy, CheckpointAncestryError> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(CheckpointAncestryError::InvalidPolicy);
    }
    let policy: CheckpointAncestryPolicy =
        serde_json::from_slice(bytes).map_err(|_| CheckpointAncestryError::InvalidPolicy)?;
    if checkpoint_ancestry_policy_bytes(&policy)? != bytes {
        return Err(CheckpointAncestryError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_sha256)?;
    Ok(policy)
}

pub fn checkpoint_ancestry_signature_message(
    policy: &CheckpointAncestryPolicy,
    expected_policy_sha256: &str,
    ancestry: &EvmAncestryEvidence,
    audience: &CheckpointAncestryAudience<'_>,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
) -> Result<Vec<u8>, CheckpointAncestryError> {
    signing_bytes(&build_envelope(
        policy,
        expected_policy_sha256,
        ancestry,
        audience,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?)
}

pub fn create_checkpoint_ancestry_evidence(
    policy: &CheckpointAncestryPolicy,
    expected_policy_sha256: &str,
    ancestry: &EvmAncestryEvidence,
    audience: &CheckpointAncestryAudience<'_>,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    signatures: Vec<AncestrySignature>,
) -> Result<Vec<u8>, CheckpointAncestryError> {
    let envelope = build_envelope(
        policy,
        expected_policy_sha256,
        ancestry,
        audience,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?;
    validate_signature_order(&signatures)?;
    verify_signatures(policy, &signing_bytes(&envelope)?, &signatures)?;
    let bytes = serde_json::to_vec(&SignedAncestryEvidence {
        envelope,
        signatures,
    })
    .map_err(|_| CheckpointAncestryError::InvalidEvidence)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(CheckpointAncestryError::InvalidEvidence);
    }
    Ok(bytes)
}

pub fn verify_checkpoint_ancestry_evidence(
    evidence_bytes: &[u8],
    policy: &CheckpointAncestryPolicy,
    expected_policy_sha256: &str,
    ancestry: &EvmAncestryEvidence,
    audience: &CheckpointAncestryAudience<'_>,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedCheckpointAncestry, CheckpointAncestryError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if evidence_bytes.is_empty() || evidence_bytes.len() > MAX_BYTES {
        return Err(CheckpointAncestryError::InvalidEvidence);
    }
    let evidence: SignedAncestryEvidence = serde_json::from_slice(evidence_bytes)
        .map_err(|_| CheckpointAncestryError::InvalidEvidence)?;
    if serde_json::to_vec(&evidence).map_err(|_| CheckpointAncestryError::InvalidEvidence)?
        != evidence_bytes
    {
        return Err(CheckpointAncestryError::InvalidEvidence);
    }
    let expected = build_envelope(
        policy,
        expected_policy_sha256,
        ancestry,
        audience,
        evidence.envelope.attested_at_unix_seconds,
        evidence.envelope.valid_until_unix_seconds,
    )?;
    if evidence.envelope != expected {
        return Err(CheckpointAncestryError::AudienceMismatch);
    }
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.trusted_time_state_identity
    {
        return Err(CheckpointAncestryError::TrustedTimeMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| CheckpointAncestryError::InvalidTime)?;
    if now < evidence.envelope.attested_at_unix_seconds
        || now >= evidence.envelope.valid_until_unix_seconds
        || now < policy.effective_at_unix_seconds
        || now >= policy.expires_at_unix_seconds
        || now - evidence.envelope.attested_at_unix_seconds > policy.maximum_evidence_age_seconds
    {
        return Err(CheckpointAncestryError::InvalidTime);
    }
    validate_signature_order(&evidence.signatures)?;
    verify_signatures(
        policy,
        &signing_bytes(&evidence.envelope)?,
        &evidence.signatures,
    )?;
    let deadline_unix_seconds = evidence
        .envelope
        .valid_until_unix_seconds
        .min(trusted_time.valid_until_unix_seconds());
    let remaining = deadline_unix_seconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(CheckpointAncestryError::InvalidTime)?;
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(CheckpointAncestryError::InvalidTime)?;
    Ok(VerifiedCheckpointAncestry {
        policy_sha256: expected_policy_sha256.into(),
        evidence_sha256: hash(evidence_bytes),
        ancestry_evidence_sha256: evidence.envelope.ancestry_evidence_sha256,
        assessed_bundle_sha256: audience.assessed_bundle_sha256.into(),
        expected_network_sha256: audience.expected_network_sha256.into(),
        checkpoint: audience.expected_checkpoint.clone(),
        trusted_anchor: ancestry.finalized.clone(),
        authority_ids: evidence
            .signatures
            .into_iter()
            .map(|item| item.authority_id)
            .collect(),
        deadline_unix_seconds,
        expires_at,
    })
}

fn build_envelope(
    policy: &CheckpointAncestryPolicy,
    expected_policy_sha256: &str,
    ancestry: &EvmAncestryEvidence,
    audience: &CheckpointAncestryAudience<'_>,
    attested_at: u64,
    valid_until: u64,
) -> Result<AncestryEnvelope, CheckpointAncestryError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_times(policy, attested_at, valid_until)?;
    if !valid_sha256(audience.assessed_bundle_sha256)
        || !valid_sha256(audience.expected_network_sha256)
        || network_identity_sha256(&ancestry.network)
            .map_err(|_| CheckpointAncestryError::InvalidEvidence)?
            != audience.expected_network_sha256
        || policy.expected_network_sha256 != audience.expected_network_sha256
        || !same_checkpoint(&ancestry.checkpoint, audience.expected_checkpoint)
        || ancestry.finalized.height != policy.trusted_anchor_height
        || ancestry.finalized.block_hash != policy.trusted_anchor_block_hash
        || ancestry.finalized.state_root != policy.trusted_anchor_state_root
    {
        return Err(CheckpointAncestryError::AudienceMismatch);
    }
    let report = verify_evm_ancestry_evidence(ancestry)
        .map_err(|_| CheckpointAncestryError::InvalidEvidence)?;
    Ok(AncestryEnvelope {
        schema: CHECKPOINT_ANCESTRY_EVIDENCE_SCHEMA.into(),
        checkpoint_ancestry_policy_sha256: expected_policy_sha256.into(),
        ancestry_evidence_sha256: report.evidence_sha256,
        assessed_bundle_sha256: audience.assessed_bundle_sha256.into(),
        expected_network_sha256: audience.expected_network_sha256.into(),
        checkpoint_height: ancestry.checkpoint.height,
        checkpoint_block_hash: ancestry.checkpoint.block_hash.clone(),
        checkpoint_state_root: ancestry.checkpoint.state_root.clone(),
        trusted_anchor_height: ancestry.finalized.height,
        trusted_anchor_block_hash: ancestry.finalized.block_hash.clone(),
        trusted_anchor_state_root: ancestry.finalized.state_root.clone(),
        attested_at_unix_seconds: attested_at,
        valid_until_unix_seconds: valid_until,
    })
}

fn signing_bytes(envelope: &AncestryEnvelope) -> Result<Vec<u8>, CheckpointAncestryError> {
    let canonical =
        serde_json::to_vec(envelope).map_err(|_| CheckpointAncestryError::InvalidEvidence)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + canonical.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_policy_pin(
    policy: &CheckpointAncestryPolicy,
    expected: &str,
) -> Result<(), CheckpointAncestryError> {
    if !valid_sha256(expected) || checkpoint_ancestry_policy_sha256(policy)? != expected {
        return Err(CheckpointAncestryError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_times(
    policy: &CheckpointAncestryPolicy,
    attested: u64,
    valid_until: u64,
) -> Result<(), CheckpointAncestryError> {
    let lifetime = valid_until
        .checked_sub(attested)
        .ok_or(CheckpointAncestryError::InvalidTime)?;
    if lifetime == 0
        || lifetime > policy.maximum_evidence_age_seconds
        || attested < policy.effective_at_unix_seconds
        || valid_until > policy.expires_at_unix_seconds
    {
        return Err(CheckpointAncestryError::InvalidTime);
    }
    Ok(())
}

fn validate_policy(policy: &CheckpointAncestryPolicy) -> Result<(), CheckpointAncestryError> {
    if policy.schema != CHECKPOINT_ANCESTRY_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_sha256(&policy.expected_network_sha256)
        || policy.trusted_anchor_height == 0
        || !valid_sha256(&policy.trusted_anchor_block_hash)
        || !valid_sha256(&policy.trusted_anchor_state_root)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
        || !valid_id(&policy.trusted_time_state_identity)
        || policy.authority_threshold < 2
        || usize::from(policy.authority_threshold) > policy.authorities.len()
        || policy.authorities.len() > MAX_AUTHORITIES
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.maximum_evidence_age_seconds == 0
        || policy.maximum_evidence_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(CheckpointAncestryError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut organizations = BTreeSet::new();
    let mut controls = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .map_err(|_| CheckpointAncestryError::InvalidPolicy)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key).map_err(|_| CheckpointAncestryError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || !valid_id(&authority.organization_id)
            || !valid_id(&authority.control_domain)
            || previous.is_some_and(|value| value >= authority.authority_id.as_str())
            || !organizations.insert(authority.organization_id.as_str())
            || !controls.insert(authority.control_domain.as_str())
            || verifying_key.is_weak()
            || !keys.insert(key)
        {
            return Err(CheckpointAncestryError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_signature_order(
    signatures: &[AncestrySignature],
) -> Result<(), CheckpointAncestryError> {
    let mut previous: Option<&str> = None;
    for signature in signatures {
        if !valid_id(&signature.authority_id)
            || previous.is_some_and(|value| value >= signature.authority_id.as_str())
        {
            return Err(CheckpointAncestryError::DuplicateSignature);
        }
        previous = Some(&signature.authority_id);
    }
    Ok(())
}

fn verify_signatures(
    policy: &CheckpointAncestryPolicy,
    message: &[u8],
    signatures: &[AncestrySignature],
) -> Result<(), CheckpointAncestryError> {
    for signed in signatures {
        let authority = policy
            .authorities
            .iter()
            .find(|item| item.authority_id == signed.authority_id)
            .ok_or(CheckpointAncestryError::UntrustedAuthority)?;
        let key = VerifyingKey::from_bytes(
            &decode_fixed::<32>(&authority.ed25519_public_key)
                .map_err(|_| CheckpointAncestryError::InvalidPolicy)?,
        )
        .map_err(|_| CheckpointAncestryError::InvalidPolicy)?;
        let signature = decode_fixed::<64>(&signed.signature)
            .map_err(|_| CheckpointAncestryError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| CheckpointAncestryError::InvalidSignature)?;
    }
    if signatures.len() < usize::from(policy.authority_threshold) {
        return Err(CheckpointAncestryError::ThresholdNotMet);
    }
    Ok(())
}

fn same_checkpoint(left: &Checkpoint, right: &Checkpoint) -> bool {
    left.height == right.height
        && left.block_hash == right.block_hash
        && left.state_root == right.state_root
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 + 2 || !value.starts_with("0x") {
        return Err(());
    }
    hex::decode(&value[2..])
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
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
