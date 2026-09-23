//! Weighted validator-set verification for one pinned EVM/L2 checkpoint.
//!
//! Checkpoint-certificate V1 accepts only one independently pinned generation.
//! Validator-set changes use a separate, explicit dual-quorum protocol and are
//! not accepted by the checkpoint verifier. Signature quorum is not an
//! implementation of chain consensus, ancestry, independence or settlement.

use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

mod transitioned_finality;
mod validator_set_transition;

pub use transitioned_finality::{
    TRANSITIONED_CONSENSUS_FINALITY_CERTIFICATE_SCHEMA,
    TRANSITIONED_CONSENSUS_FINALITY_ENVELOPE_SCHEMA, TRANSITIONED_CONSENSUS_FINALITY_PROTOCOL,
    TransitionedConsensusFinalityError, VerifiedTransitionedConsensusFinality,
    create_transitioned_consensus_finality_certificate,
    transitioned_consensus_finality_signing_message, verify_transitioned_consensus_finality,
};

pub use validator_set_transition::{
    TRANSITIONED_VALIDATOR_SET_MODE, VALIDATOR_SET_MANIFEST_SCHEMA,
    VALIDATOR_SET_TRANSITION_CERTIFICATE_SCHEMA, VALIDATOR_SET_TRANSITION_ENVELOPE_SCHEMA,
    VALIDATOR_SET_TRANSITION_PROTOCOL, ValidatorSetManifest, ValidatorSetTransitionError,
    ValidatorSetTransitionSignatures, ValidatorSetTransitionSigningMessages,
    ValidatorSetTransitionSource, VerifiedValidatorSetTransition, consensus_validator_set_manifest,
    create_validator_set_transition_certificate, parse_validator_set_manifest,
    validator_set_manifest_sha256, validator_set_transition_signing_messages,
    verify_validator_set_transition,
};

pub const CONSENSUS_FINALITY_POLICY_SCHEMA: &str =
    "bloch.products.evm-consensus-finality-policy.v1";
pub const CONSENSUS_FINALITY_ENVELOPE_SCHEMA: &str =
    "bloch.products.evm-consensus-finality-envelope.v1";
pub const CONSENSUS_FINALITY_CERTIFICATE_SCHEMA: &str =
    "bloch.products.evm-consensus-finality-certificate.v1";
pub const PINNED_VALIDATOR_SET_MODE: &str = "pinnedV1";
pub const MAX_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_VALIDATORS: usize = 512;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-EVM-CONSENSUS-FINALITY-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Validator {
    pub validator_id: String,
    pub ed25519_public_key: String,
    pub weight: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsensusFinalityPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub network: String,
    pub chain_id: u64,
    pub genesis_block_hash: String,
    pub validator_set_mode: String,
    pub validator_set_generation: u64,
    pub quorum_weight: u64,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_checkpoint_age_seconds: u64,
    pub trusted_time_policy_sha256: String,
    pub trusted_time_state_identity: String,
    pub trusted_time_remote_cursor_policy_sha256: String,
    pub validators: Vec<Validator>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsensusCheckpoint {
    pub block_number: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finalized_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidatorSignature {
    pub validator_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FinalityEnvelope {
    schema: String,
    finality_policy_sha256: String,
    signature_domain: String,
    network: String,
    chain_id: u64,
    genesis_block_hash: String,
    validator_set_mode: String,
    validator_set_generation: u64,
    checkpoint: ConsensusCheckpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FinalityCertificate {
    schema: String,
    envelope: FinalityEnvelope,
    signatures: Vec<ValidatorSignature>,
}

/// Non-cloneable proof that one pinned weighted validator quorum signed one
/// exact statement and that it was fresh under authenticated trusted time.
#[derive(Debug)]
pub struct VerifiedConsensusFinality {
    policy_sha256: String,
    certificate_sha256: String,
    network: String,
    chain_id: u64,
    genesis_block_hash: String,
    validator_set_generation: u64,
    checkpoint: ConsensusCheckpoint,
    signed_weight: u64,
    validator_ids: Vec<String>,
    trusted_time_policy_sha256: String,
    trusted_time_token_sha256: String,
    deadline_unix_seconds: u64,
    expires_at: Instant,
}

impl VerifiedConsensusFinality {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn genesis_block_hash(&self) -> &str {
        &self.genesis_block_hash
    }
    pub fn validator_set_generation(&self) -> u64 {
        self.validator_set_generation
    }
    pub fn checkpoint(&self) -> &ConsensusCheckpoint {
        &self.checkpoint
    }
    pub fn signed_weight(&self) -> u64 {
        self.signed_weight
    }
    pub fn validator_ids(&self) -> &[String] {
        &self.validator_ids
    }
    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.trusted_time_policy_sha256
    }
    pub fn trusted_time_token_sha256(&self) -> &str {
        &self.trusted_time_token_sha256
    }
    pub fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), ConsensusFinalityError> {
        if Instant::now() >= self.expires_at {
            Err(ConsensusFinalityError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
    pub fn validator_set_transition_proven(&self) -> bool {
        false
    }
    pub fn ancestry_proven(&self) -> bool {
        false
    }
    pub fn organizational_independence_proven(&self) -> bool {
        false
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusFinalityError {
    #[error("consensus-finality policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("consensus-finality policy pin mismatch")]
    PolicyPinMismatch,
    #[error("consensus-finality certificate is invalid or non-canonical")]
    InvalidCertificate,
    #[error("certificate crosses its pinned network or validator-set audience")]
    AudienceMismatch,
    #[error("trusted time does not match the finality policy audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTimeUnavailable,
    #[error("consensus-finality policy is not currently effective")]
    PolicyNotEffective,
    #[error("checkpoint is in the future or too old")]
    StaleCheckpoint,
    #[error("validator is not in the pinned set")]
    UntrustedValidator,
    #[error("validator signature is duplicated")]
    DuplicateSignature,
    #[error("validator signature is invalid")]
    InvalidSignature,
    #[error("signed validator weight is below quorum")]
    InsufficientWeight,
    #[error("verified finality capability has expired")]
    ExpiredCapability,
}

pub fn consensus_finality_policy_bytes(
    policy: &ConsensusFinalityPolicy,
) -> Result<Vec<u8>, ConsensusFinalityError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| ConsensusFinalityError::InvalidPolicy)?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn consensus_finality_policy_sha256(
    policy: &ConsensusFinalityPolicy,
) -> Result<String, ConsensusFinalityError> {
    Ok(hash(&consensus_finality_policy_bytes(policy)?))
}

pub fn parse_consensus_finality_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<ConsensusFinalityPolicy, ConsensusFinalityError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || !valid_hash(expected_policy_sha256) {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    let policy: ConsensusFinalityPolicy =
        serde_json::from_slice(bytes).map_err(|_| ConsensusFinalityError::InvalidPolicy)?;
    if consensus_finality_policy_bytes(&policy)? != bytes {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn consensus_finality_signing_message(
    policy: &ConsensusFinalityPolicy,
    expected_policy_sha256: &str,
    checkpoint: &ConsensusCheckpoint,
) -> Result<Vec<u8>, ConsensusFinalityError> {
    let envelope = envelope(policy, expected_policy_sha256, checkpoint)?;
    signing_bytes(&envelope)
}

/// Constructs canonical certificate bytes and refuses to serialize an invalid
/// or below-quorum signature set.
pub fn create_consensus_finality_certificate(
    policy: &ConsensusFinalityPolicy,
    expected_policy_sha256: &str,
    checkpoint: &ConsensusCheckpoint,
    signatures: Vec<ValidatorSignature>,
) -> Result<Vec<u8>, ConsensusFinalityError> {
    let envelope = envelope(policy, expected_policy_sha256, checkpoint)?;
    validate_signature_order(&signatures)?;
    verify_signatures(policy, &signing_bytes(&envelope)?, &signatures)?;
    let certificate = FinalityCertificate {
        schema: CONSENSUS_FINALITY_CERTIFICATE_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes =
        serde_json::to_vec(&certificate).map_err(|_| ConsensusFinalityError::InvalidCertificate)?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(ConsensusFinalityError::InvalidCertificate);
    }
    Ok(bytes)
}

pub fn verify_consensus_finality(
    certificate_bytes: &[u8],
    policy: &ConsensusFinalityPolicy,
    expected_policy_sha256: &str,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedConsensusFinality, ConsensusFinalityError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.trusted_time_state_identity
        || trusted_time.remote_cursor_policy_sha256()
            != policy.trusted_time_remote_cursor_policy_sha256
    {
        return Err(ConsensusFinalityError::TrustedTimeAudienceMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| ConsensusFinalityError::TrustedTimeUnavailable)?;
    if now < policy.effective_at_unix_seconds || now >= policy.expires_at_unix_seconds {
        return Err(ConsensusFinalityError::PolicyNotEffective);
    }
    if certificate_bytes.is_empty() || certificate_bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(ConsensusFinalityError::InvalidCertificate);
    }
    let certificate: FinalityCertificate = serde_json::from_slice(certificate_bytes)
        .map_err(|_| ConsensusFinalityError::InvalidCertificate)?;
    if serde_json::to_vec(&certificate).map_err(|_| ConsensusFinalityError::InvalidCertificate)?
        != certificate_bytes
        || certificate.schema != CONSENSUS_FINALITY_CERTIFICATE_SCHEMA
    {
        return Err(ConsensusFinalityError::InvalidCertificate);
    }
    let expected = envelope(
        policy,
        expected_policy_sha256,
        &certificate.envelope.checkpoint,
    )?;
    if certificate.envelope != expected {
        return Err(ConsensusFinalityError::AudienceMismatch);
    }
    let checkpoint = &certificate.envelope.checkpoint;
    if checkpoint.finalized_at_unix_seconds > now
        || now - checkpoint.finalized_at_unix_seconds > policy.max_checkpoint_age_seconds
    {
        return Err(ConsensusFinalityError::StaleCheckpoint);
    }
    validate_signature_order(&certificate.signatures)?;
    let signed_weight = verify_signatures(
        policy,
        &signing_bytes(&certificate.envelope)?,
        &certificate.signatures,
    )?;
    let trusted_deadline = trusted_time.valid_until_unix_seconds();
    let deadline = policy.expires_at_unix_seconds.min(trusted_deadline);
    let remaining = deadline
        .checked_sub(now)
        .ok_or(ConsensusFinalityError::TrustedTimeUnavailable)?;
    if remaining == 0 {
        return Err(ConsensusFinalityError::PolicyNotEffective);
    }
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(ConsensusFinalityError::PolicyNotEffective)?;
    Ok(VerifiedConsensusFinality {
        policy_sha256: expected_policy_sha256.into(),
        certificate_sha256: hash(certificate_bytes),
        network: policy.network.clone(),
        chain_id: policy.chain_id,
        genesis_block_hash: policy.genesis_block_hash.clone(),
        validator_set_generation: policy.validator_set_generation,
        checkpoint: checkpoint.clone(),
        signed_weight,
        validator_ids: certificate
            .signatures
            .iter()
            .map(|signature| signature.validator_id.clone())
            .collect(),
        trusted_time_policy_sha256: trusted_time.trusted_time_policy_sha256().into(),
        trusted_time_token_sha256: trusted_time.token_sha256().into(),
        deadline_unix_seconds: deadline,
        expires_at,
    })
}

fn envelope(
    policy: &ConsensusFinalityPolicy,
    expected_policy_sha256: &str,
    checkpoint: &ConsensusCheckpoint,
) -> Result<FinalityEnvelope, ConsensusFinalityError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_checkpoint(checkpoint)?;
    Ok(FinalityEnvelope {
        schema: CONSENSUS_FINALITY_ENVELOPE_SCHEMA.into(),
        finality_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        network: policy.network.clone(),
        chain_id: policy.chain_id,
        genesis_block_hash: policy.genesis_block_hash.clone(),
        validator_set_mode: policy.validator_set_mode.clone(),
        validator_set_generation: policy.validator_set_generation,
        checkpoint: checkpoint.clone(),
    })
}

fn validate_policy(policy: &ConsensusFinalityPolicy) -> Result<(), ConsensusFinalityError> {
    if policy.schema != CONSENSUS_FINALITY_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.network)
        || policy.chain_id == 0
        || !valid_hash(&policy.genesis_block_hash)
        || policy.validator_set_mode != PINNED_VALIDATOR_SET_MODE
        || policy.validator_set_generation != 1
        || policy.validators.len() < 3
        || policy.validators.len() > MAX_VALIDATORS
        || policy.quorum_weight == 0
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_checkpoint_age_seconds == 0
        || policy.max_checkpoint_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
        || !valid_hash(&policy.trusted_time_policy_sha256)
        || !valid_id(&policy.trusted_time_state_identity)
        || !valid_hash(&policy.trusted_time_remote_cursor_policy_sha256)
    {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    let mut total = 0_u64;
    for validator in &policy.validators {
        if !valid_id(&validator.validator_id)
            || previous.is_some_and(|id| id >= validator.validator_id.as_str())
            || validator.weight == 0
            || decode_key(&validator.ed25519_public_key).is_err()
            || !keys.insert(&validator.ed25519_public_key)
        {
            return Err(ConsensusFinalityError::InvalidPolicy);
        }
        total = total
            .checked_add(validator.weight)
            .ok_or(ConsensusFinalityError::InvalidPolicy)?;
        previous = Some(&validator.validator_id);
    }
    // A strict >2/3 weighted quorum is mandatory, never merely caller-selected.
    if policy.quorum_weight > total || u128::from(policy.quorum_weight) * 3 <= u128::from(total) * 2
    {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &ConsensusFinalityPolicy,
    expected: &str,
) -> Result<(), ConsensusFinalityError> {
    if !valid_hash(expected) {
        return Err(ConsensusFinalityError::InvalidPolicy);
    }
    if consensus_finality_policy_sha256(policy)? != expected {
        return Err(ConsensusFinalityError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &ConsensusCheckpoint) -> Result<(), ConsensusFinalityError> {
    if checkpoint.block_number == 0
        || !valid_hash(&checkpoint.block_hash)
        || !valid_hash(&checkpoint.state_root)
        || !valid_hash(&checkpoint.receipts_root)
        || checkpoint.finalized_at_unix_seconds == 0
    {
        Err(ConsensusFinalityError::InvalidCertificate)
    } else {
        Ok(())
    }
}

fn validate_signature_order(
    signatures: &[ValidatorSignature],
) -> Result<(), ConsensusFinalityError> {
    let mut previous: Option<&str> = None;
    for signature in signatures {
        if !valid_id(&signature.validator_id) {
            return Err(ConsensusFinalityError::InvalidCertificate);
        }
        if previous.is_some_and(|id| id == signature.validator_id) {
            return Err(ConsensusFinalityError::DuplicateSignature);
        }
        if previous.is_some_and(|id| id > signature.validator_id.as_str()) {
            return Err(ConsensusFinalityError::InvalidCertificate);
        }
        previous = Some(&signature.validator_id);
    }
    Ok(())
}

fn verify_signatures(
    policy: &ConsensusFinalityPolicy,
    message: &[u8],
    signatures: &[ValidatorSignature],
) -> Result<u64, ConsensusFinalityError> {
    if signatures.len() > policy.validators.len() {
        return Err(ConsensusFinalityError::InvalidCertificate);
    }
    let mut weight = 0_u64;
    for signed in signatures {
        let validator = policy
            .validators
            .binary_search_by(|validator| validator.validator_id.as_str().cmp(&signed.validator_id))
            .ok()
            .map(|index| &policy.validators[index])
            .ok_or(ConsensusFinalityError::UntrustedValidator)?;
        let signature_bytes = decode_fixed::<64>(&signed.signature)
            .ok_or(ConsensusFinalityError::InvalidSignature)?;
        decode_key(&validator.ed25519_public_key)
            .map_err(|_| ConsensusFinalityError::InvalidPolicy)?
            .verify(message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| ConsensusFinalityError::InvalidSignature)?;
        weight = weight
            .checked_add(validator.weight)
            .ok_or(ConsensusFinalityError::InvalidPolicy)?;
    }
    if weight < policy.quorum_weight {
        return Err(ConsensusFinalityError::InsufficientWeight);
    }
    Ok(weight)
}

fn signing_bytes(envelope: &FinalityEnvelope) -> Result<Vec<u8>, ConsensusFinalityError> {
    let encoded =
        serde_json::to_vec(envelope).map_err(|_| ConsensusFinalityError::InvalidCertificate)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn decode_key(value: &str) -> Result<VerifyingKey, ()> {
    let bytes = decode_fixed::<32>(value).ok_or(())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ())?;
    if key.is_weak() { Err(()) } else { Ok(key) }
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let raw = value.strip_prefix("0x")?;
    if raw.len() != N * 2 || raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(raw).ok()?.try_into().ok()
}
fn valid_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
