//! Offline threshold attestations concerning an authenticated observation's block.
//!
//! A result establishes only that the configured threshold of pinned Ed25519
//! authorities signed the exact observed block as finalized. It is not native
//! consensus or ancestry proof, is never evidence of settlement, and never
//! authorizes credit or movement of funds.

use super::{AuthenticatedPaymentObservation, ReconciliationPolicy, policy_sha256};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const FINALITY_POLICY_SCHEMA: &str = "bloch.pay.finality-trust-policy.v1";
pub const FINALITY_SIGNATURE_SCHEMA: &str = "bloch.pay.finality-attestation.v1";
pub const MAX_FINALITY_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_FINALITY_ENVELOPE_BYTES: usize = 32 * 1024;
pub const MAX_FINALITY_AUTHORITIES: usize = 256;
pub const MAX_FINALITY_NETWORKS: usize = 64;
pub const MAX_FINALITY_EVIDENCE: usize = 256;

const FINALITY_PROTOCOL_DOMAIN: &[u8] = b"bloch.pay.observation-finality.signature.v1";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EVIDENCE_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FinalityNetworkRule {
    pub network: String,
    pub minimum_signatures: u16,
    pub max_evidence_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FinalityAuthority {
    pub authority_id: String,
    pub network: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FinalityTrustPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub reconciliation_policy_sha256: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub networks: Vec<FinalityNetworkRule>,
    pub authorities: Vec<FinalityAuthority>,
}

/// The exact block-finality statement presented to external key holders.
/// It contains no caller-supplied qualification boolean.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FinalityCheckpoint {
    pub finalized_block_height: u64,
    pub finalized_block_hash: String,
    pub finalized_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FinalitySignatureEnvelope {
    schema: String,
    signature_domain: String,
    finality_policy_sha256: String,
    reconciliation_policy_sha256: String,
    authority_id: String,
    network: String,
    observation_sha256: String,
    transaction_id: String,
    event_index: u32,
    observed_block_height: u64,
    observed_block_hash: String,
    finalized_block_height: u64,
    finalized_block_hash: String,
    finalized_at_unix_seconds: u64,
    signature: String,
}

/// Opaque output produced only after one pinned authority signature verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedFinalityEvidence {
    authority_id: String,
    network: String,
    observation_sha256: String,
    finality_policy_sha256: String,
    reconciliation_policy_sha256: String,
    finalized_block_height: u64,
    finalized_block_hash: String,
    finalized_at_unix_seconds: u64,
}

impl AuthenticatedFinalityEvidence {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn observation_sha256(&self) -> &str {
        &self.observation_sha256
    }
    pub fn finality_policy_sha256(&self) -> &str {
        &self.finality_policy_sha256
    }
    pub fn reconciliation_policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }
    pub fn finalized_block_height(&self) -> u64 {
        self.finalized_block_height
    }
    pub fn finalized_block_hash(&self) -> &str {
        &self.finalized_block_hash
    }
    pub fn finalized_at_unix_seconds(&self) -> u64 {
        self.finalized_at_unix_seconds
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
    pub fn credit_authorized(&self) -> bool {
        false
    }
    pub fn funds_released(&self) -> bool {
        false
    }
}

/// Opaque threshold-attestation result. This proves only that the configured
/// authority threshold signed; it is not native consensus or ancestry proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdFinalityAttestation {
    observation_sha256: String,
    network: String,
    finality_policy_sha256: String,
    reconciliation_policy_sha256: String,
    finalized_block_height: u64,
    finalized_block_hash: String,
    authority_ids: Vec<String>,
}

impl ThresholdFinalityAttestation {
    pub fn observation_sha256(&self) -> &str {
        &self.observation_sha256
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn finality_policy_sha256(&self) -> &str {
        &self.finality_policy_sha256
    }
    pub fn reconciliation_policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }
    pub fn finalized_block_height(&self) -> u64 {
        self.finalized_block_height
    }
    pub fn finalized_block_hash(&self) -> &str {
        &self.finalized_block_hash
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn attestation_threshold_met(&self) -> bool {
        true
    }
    pub fn network_finality_qualified(&self) -> bool {
        false
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
    pub fn credit_authorized(&self) -> bool {
        false
    }
    pub fn funds_released(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FinalityError {
    #[error("{kind} JSON is empty")]
    Empty { kind: &'static str },
    #[error("{kind} JSON exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid {kind} JSON: {message}")]
    InvalidJson { kind: &'static str, message: String },
    #[error("invalid finality field: {0}")]
    InvalidField(&'static str),
    #[error("input is not exact canonical JSON")]
    NonCanonicalJson,
    #[error("finality policy digest mismatch")]
    FinalityPolicyDigestMismatch,
    #[error("reconciliation policy digest mismatch")]
    ReconciliationPolicyDigestMismatch,
    #[error("finality trust context mismatch")]
    TrustContextMismatch,
    #[error("authority is not trusted for this network")]
    UntrustedAuthority,
    #[error("finality evidence does not match the authenticated observation")]
    EvidenceMismatch,
    #[error("invalid detached Ed25519 signature")]
    InvalidSignature,
    #[error("finality signature threshold was not met")]
    ThresholdNotMet,
    #[error("duplicate finality authority evidence")]
    DuplicateAuthority,
    #[error("finality authorities disagree on the checkpoint")]
    ConflictingCheckpoint,
}

pub fn canonical_finality_policy_bytes(
    policy: &FinalityTrustPolicy,
) -> Result<Vec<u8>, FinalityError> {
    validate_policy(policy)?;
    serde_json::to_vec(policy).map_err(|error| invalid_json("finality policy", error))
}

pub fn finality_policy_sha256(policy: &FinalityTrustPolicy) -> Result<String, FinalityError> {
    Ok(sha256_hex(&canonical_finality_policy_bytes(policy)?))
}

pub fn parse_finality_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<FinalityTrustPolicy, FinalityError> {
    check_size(bytes, MAX_FINALITY_POLICY_BYTES, "finality policy")?;
    require_hash(expected_sha256, "expectedFinalityPolicySha256")?;
    let policy: FinalityTrustPolicy =
        serde_json::from_slice(bytes).map_err(|error| invalid_json("finality policy", error))?;
    validate_policy(&policy)?;
    if canonical_finality_policy_bytes(&policy)? != bytes {
        return Err(FinalityError::NonCanonicalJson);
    }
    if sha256_hex(bytes) != expected_sha256 {
        return Err(FinalityError::FinalityPolicyDigestMismatch);
    }
    Ok(policy)
}

#[allow(clippy::too_many_arguments)]
pub fn finality_signing_bytes(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    authority_id: &str,
    observation: &AuthenticatedPaymentObservation,
    checkpoint: &FinalityCheckpoint,
    evaluated_at_unix_seconds: u64,
) -> Result<Vec<u8>, FinalityError> {
    let authority = validate_context(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        finality_policy,
        expected_finality_policy_sha256,
        authority_id,
        observation,
        checkpoint,
        evaluated_at_unix_seconds,
    )?;
    let source = observation.observation();
    let mut message = Vec::with_capacity(1024);
    for value in [
        FINALITY_PROTOCOL_DOMAIN,
        finality_policy.signature_domain.as_bytes(),
        expected_finality_policy_sha256.as_bytes(),
        expected_reconciliation_policy_sha256.as_bytes(),
        authority.authority_id.as_bytes(),
        source.network.as_bytes(),
        observation.canonical_observation_sha256().as_bytes(),
        source.transaction_id.as_bytes(),
        &source.event_index.to_be_bytes(),
        &source.block_height.to_be_bytes(),
        source.block_hash.as_bytes(),
        &checkpoint.finalized_block_height.to_be_bytes(),
        checkpoint.finalized_block_hash.as_bytes(),
        &checkpoint.finalized_at_unix_seconds.to_be_bytes(),
    ] {
        append(&mut message, value)?;
    }
    Ok(message)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_finality_signature_envelope(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    authority_id: &str,
    observation: &AuthenticatedPaymentObservation,
    checkpoint: &FinalityCheckpoint,
    evaluated_at_unix_seconds: u64,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, FinalityError> {
    let message = finality_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        finality_policy,
        expected_finality_policy_sha256,
        authority_id,
        observation,
        checkpoint,
        evaluated_at_unix_seconds,
    )?;
    let authority = trusted_authority(
        finality_policy,
        authority_id,
        &observation.observation().network,
    )?;
    verify_signature(authority, &message, signature_bytes)?;
    let source = observation.observation();
    let envelope = FinalitySignatureEnvelope {
        schema: FINALITY_SIGNATURE_SCHEMA.into(),
        signature_domain: finality_policy.signature_domain.clone(),
        finality_policy_sha256: expected_finality_policy_sha256.into(),
        reconciliation_policy_sha256: expected_reconciliation_policy_sha256.into(),
        authority_id: authority_id.into(),
        network: source.network.clone(),
        observation_sha256: observation.canonical_observation_sha256().into(),
        transaction_id: source.transaction_id.clone(),
        event_index: source.event_index,
        observed_block_height: source.block_height,
        observed_block_hash: source.block_hash.clone(),
        finalized_block_height: checkpoint.finalized_block_height,
        finalized_block_hash: checkpoint.finalized_block_hash.clone(),
        finalized_at_unix_seconds: checkpoint.finalized_at_unix_seconds,
        signature: format!("0x{}", hex::encode(signature_bytes)),
    };
    let bytes =
        serde_json::to_vec(&envelope).map_err(|error| invalid_json("finality envelope", error))?;
    check_size(&bytes, MAX_FINALITY_ENVELOPE_BYTES, "finality envelope")?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_finality_evidence(
    envelope_bytes: &[u8],
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    observation: &AuthenticatedPaymentObservation,
    evaluated_at_unix_seconds: u64,
) -> Result<AuthenticatedFinalityEvidence, FinalityError> {
    check_size(
        envelope_bytes,
        MAX_FINALITY_ENVELOPE_BYTES,
        "finality envelope",
    )?;
    let envelope: FinalitySignatureEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|error| invalid_json("finality envelope", error))?;
    if serde_json::to_vec(&envelope).map_err(|error| invalid_json("finality envelope", error))?
        != envelope_bytes
    {
        return Err(FinalityError::NonCanonicalJson);
    }
    if envelope.schema != FINALITY_SIGNATURE_SCHEMA {
        return Err(FinalityError::InvalidField("envelope.schema"));
    }
    let checkpoint = FinalityCheckpoint {
        finalized_block_height: envelope.finalized_block_height,
        finalized_block_hash: envelope.finalized_block_hash.clone(),
        finalized_at_unix_seconds: envelope.finalized_at_unix_seconds,
    };
    let message = finality_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        finality_policy,
        expected_finality_policy_sha256,
        &envelope.authority_id,
        observation,
        &checkpoint,
        evaluated_at_unix_seconds,
    )?;
    let source = observation.observation();
    if envelope.signature_domain != finality_policy.signature_domain
        || envelope.finality_policy_sha256 != expected_finality_policy_sha256
        || envelope.reconciliation_policy_sha256 != expected_reconciliation_policy_sha256
        || envelope.network != source.network
        || envelope.observation_sha256 != observation.canonical_observation_sha256()
        || envelope.transaction_id != source.transaction_id
        || envelope.event_index != source.event_index
        || envelope.observed_block_height != source.block_height
        || envelope.observed_block_hash != source.block_hash
    {
        return Err(FinalityError::EvidenceMismatch);
    }
    let authority = trusted_authority(finality_policy, &envelope.authority_id, &source.network)?;
    let signature = decode_hex_exact(&envelope.signature, 64, "signature")?;
    verify_signature(authority, &message, &signature)?;
    Ok(AuthenticatedFinalityEvidence {
        authority_id: envelope.authority_id,
        network: envelope.network,
        observation_sha256: envelope.observation_sha256,
        finality_policy_sha256: envelope.finality_policy_sha256,
        reconciliation_policy_sha256: envelope.reconciliation_policy_sha256,
        finalized_block_height: envelope.finalized_block_height,
        finalized_block_hash: envelope.finalized_block_hash,
        finalized_at_unix_seconds: envelope.finalized_at_unix_seconds,
    })
}

pub fn evaluate_finality_attestation_threshold(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    observation: &AuthenticatedPaymentObservation,
    evidence: &[AuthenticatedFinalityEvidence],
    evaluated_at_unix_seconds: u64,
) -> Result<ThresholdFinalityAttestation, FinalityError> {
    if evidence.is_empty() || evidence.len() > MAX_FINALITY_EVIDENCE {
        return Err(FinalityError::ThresholdNotMet);
    }
    // Revalidate every independently pinned context even though evidence is opaque.
    let source = observation.observation();
    let checkpoint = FinalityCheckpoint {
        finalized_block_height: source.block_height,
        finalized_block_hash: source.block_hash.clone(),
        finalized_at_unix_seconds: evidence[0].finalized_at_unix_seconds,
    };
    validate_base_context(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        finality_policy,
        expected_finality_policy_sha256,
        observation,
        &checkpoint,
        evaluated_at_unix_seconds,
    )?;
    let rule = network_rule(finality_policy, &source.network)?;
    let first = &evidence[0];
    let mut authority_ids = BTreeSet::new();
    for item in evidence {
        trusted_authority(finality_policy, &item.authority_id, &source.network)?;
        if !authority_ids.insert(item.authority_id.clone()) {
            return Err(FinalityError::DuplicateAuthority);
        }
        if item.network != source.network
            || item.observation_sha256 != observation.canonical_observation_sha256()
            || item.finality_policy_sha256 != expected_finality_policy_sha256
            || item.reconciliation_policy_sha256 != expected_reconciliation_policy_sha256
            || item.finalized_block_height != source.block_height
            || item.finalized_block_hash != source.block_hash
        {
            return Err(FinalityError::EvidenceMismatch);
        }
        if item.finalized_block_height != first.finalized_block_height
            || item.finalized_block_hash != first.finalized_block_hash
            || item.finalized_at_unix_seconds != first.finalized_at_unix_seconds
        {
            return Err(FinalityError::ConflictingCheckpoint);
        }
    }
    if authority_ids.len() < usize::from(rule.minimum_signatures) {
        return Err(FinalityError::ThresholdNotMet);
    }
    Ok(ThresholdFinalityAttestation {
        observation_sha256: observation.canonical_observation_sha256().into(),
        network: source.network.clone(),
        finality_policy_sha256: expected_finality_policy_sha256.into(),
        reconciliation_policy_sha256: expected_reconciliation_policy_sha256.into(),
        finalized_block_height: first.finalized_block_height,
        finalized_block_hash: first.finalized_block_hash.clone(),
        authority_ids: authority_ids.into_iter().collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_context<'a>(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &'a FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    authority_id: &str,
    observation: &AuthenticatedPaymentObservation,
    checkpoint: &FinalityCheckpoint,
    evaluated_at_unix_seconds: u64,
) -> Result<&'a FinalityAuthority, FinalityError> {
    validate_base_context(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        finality_policy,
        expected_finality_policy_sha256,
        observation,
        checkpoint,
        evaluated_at_unix_seconds,
    )?;
    trusted_authority(
        finality_policy,
        authority_id,
        &observation.observation().network,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_base_context(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    finality_policy: &FinalityTrustPolicy,
    expected_finality_policy_sha256: &str,
    observation: &AuthenticatedPaymentObservation,
    checkpoint: &FinalityCheckpoint,
    evaluated_at_unix_seconds: u64,
) -> Result<(), FinalityError> {
    require_hash(
        expected_reconciliation_policy_sha256,
        "expectedReconciliationPolicySha256",
    )?;
    require_hash(
        expected_finality_policy_sha256,
        "expectedFinalityPolicySha256",
    )?;
    let reconciliation_digest =
        policy_sha256(reconciliation_policy).map_err(|_| FinalityError::TrustContextMismatch)?;
    if reconciliation_digest != expected_reconciliation_policy_sha256
        || observation.reconciliation_policy_sha256() != expected_reconciliation_policy_sha256
    {
        return Err(FinalityError::ReconciliationPolicyDigestMismatch);
    }
    if finality_policy_sha256(finality_policy)? != expected_finality_policy_sha256 {
        return Err(FinalityError::FinalityPolicyDigestMismatch);
    }
    if finality_policy.reconciliation_policy_sha256 != expected_reconciliation_policy_sha256 {
        return Err(FinalityError::TrustContextMismatch);
    }
    if evaluated_at_unix_seconds < finality_policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= finality_policy.expires_at_unix_seconds
    {
        return Err(FinalityError::InvalidField("evaluationTime"));
    }
    let source = observation.observation();
    let rule = network_rule(finality_policy, &source.network)?;
    if checkpoint.finalized_block_height != source.block_height
        || checkpoint.finalized_block_hash != source.block_hash
        || checkpoint.finalized_at_unix_seconds < source.observed_at_unix_seconds
        || checkpoint.finalized_at_unix_seconds > evaluated_at_unix_seconds
        || evaluated_at_unix_seconds.saturating_sub(checkpoint.finalized_at_unix_seconds)
            > rule.max_evidence_age_seconds
    {
        return Err(FinalityError::EvidenceMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &FinalityTrustPolicy) -> Result<(), FinalityError> {
    if policy.schema != FINALITY_POLICY_SCHEMA {
        return Err(FinalityError::InvalidField("policy.schema"));
    }
    for (field, value) in [
        ("policyId", policy.policy_id.as_str()),
        ("signatureDomain", policy.signature_domain.as_str()),
    ] {
        if !valid_identifier(value) {
            return Err(FinalityError::InvalidField(field));
        }
    }
    require_hash(
        &policy.reconciliation_policy_sha256,
        "reconciliationPolicySha256",
    )?;
    if policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.networks.is_empty()
        || policy.networks.len() > MAX_FINALITY_NETWORKS
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_FINALITY_AUTHORITIES
    {
        return Err(FinalityError::InvalidField("policy.bounds"));
    }
    let mut prior_network: Option<&str> = None;
    for rule in &policy.networks {
        if !valid_identifier(&rule.network)
            || rule.minimum_signatures == 0
            || rule.max_evidence_age_seconds == 0
            || rule.max_evidence_age_seconds > MAX_EVIDENCE_AGE_SECONDS
            || prior_network.is_some_and(|prior| prior >= rule.network.as_str())
        {
            return Err(FinalityError::InvalidField("networkRule"));
        }
        prior_network = Some(&rule.network);
    }
    let mut prior_authority: Option<&str> = None;
    let mut keys = BTreeSet::new();
    let mut counts = BTreeMap::<&str, usize>::new();
    for authority in &policy.authorities {
        if !valid_identifier(&authority.authority_id)
            || !valid_identifier(&authority.network)
            || prior_authority.is_some_and(|prior| prior >= authority.authority_id.as_str())
            || !keys.insert(authority.ed25519_public_key.as_str())
            || policy
                .networks
                .binary_search_by(|rule| rule.network.as_str().cmp(&authority.network))
                .is_err()
        {
            return Err(FinalityError::InvalidField("authority"));
        }
        parse_public_key(&authority.ed25519_public_key)?;
        *counts.entry(&authority.network).or_default() += 1;
        prior_authority = Some(&authority.authority_id);
    }
    if policy.networks.iter().any(|rule| {
        counts.get(rule.network.as_str()).copied().unwrap_or(0)
            < usize::from(rule.minimum_signatures)
    }) {
        return Err(FinalityError::InvalidField("minimumSignatures"));
    }
    Ok(())
}

fn network_rule<'a>(
    policy: &'a FinalityTrustPolicy,
    network: &str,
) -> Result<&'a FinalityNetworkRule, FinalityError> {
    policy
        .networks
        .binary_search_by(|rule| rule.network.as_str().cmp(network))
        .map(|index| &policy.networks[index])
        .map_err(|_| FinalityError::TrustContextMismatch)
}

fn trusted_authority<'a>(
    policy: &'a FinalityTrustPolicy,
    authority_id: &str,
    network: &str,
) -> Result<&'a FinalityAuthority, FinalityError> {
    policy
        .authorities
        .iter()
        .find(|item| item.authority_id == authority_id && item.network == network)
        .ok_or(FinalityError::UntrustedAuthority)
}

fn verify_signature(
    authority: &FinalityAuthority,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), FinalityError> {
    let key = parse_public_key(&authority.ed25519_public_key)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| FinalityError::InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| FinalityError::InvalidSignature)
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, FinalityError> {
    let bytes: [u8; 32] = decode_hex_exact(value, 32, "ed25519PublicKey")?
        .try_into()
        .map_err(|_| FinalityError::InvalidField("ed25519PublicKey"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| FinalityError::InvalidField("ed25519PublicKey"))?;
    if key.is_weak() {
        return Err(FinalityError::InvalidField("ed25519PublicKey"));
    }
    Ok(key)
}

fn require_hash(value: &str, field: &'static str) -> Result<(), FinalityError> {
    let decoded = decode_hex_exact(value, 32, field)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(FinalityError::InvalidField(field));
    }
    Ok(())
}

fn decode_hex_exact(
    value: &str,
    expected_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, FinalityError> {
    if value.len() != expected_bytes.saturating_mul(2).saturating_add(2)
        || !value.starts_with("0x")
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(FinalityError::InvalidField(field));
    }
    hex::decode(&value[2..]).map_err(|_| FinalityError::InvalidField(field))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn append(target: &mut Vec<u8>, value: &[u8]) -> Result<(), FinalityError> {
    let length = u64::try_from(value.len()).map_err(|_| FinalityError::InvalidField("length"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn check_size(bytes: &[u8], maximum: usize, kind: &'static str) -> Result<(), FinalityError> {
    if bytes.is_empty() {
        return Err(FinalityError::Empty { kind });
    }
    if bytes.len() > maximum {
        return Err(FinalityError::TooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
fn invalid_json(kind: &'static str, error: serde_json::Error) -> FinalityError {
    FinalityError::InvalidJson {
        kind,
        message: error.to_string(),
    }
}
