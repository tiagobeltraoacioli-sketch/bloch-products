//! Checkpoint certificates issued by an authenticated transitioned validator set.
//!
//! This protocol is intentionally distinct from `pinnedV1`. Verification proves
//! only that the exact set authenticated by a transition capability signed an
//! exact checkpoint statement; it does not prove deployed consensus behavior.

use super::{
    ConsensusCheckpoint, ValidatorSignature, VerifiedValidatorSetTransition, decode_fixed,
    decode_key, hash, valid_id, validator_set_manifest_sha256,
};
use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const TRANSITIONED_CONSENSUS_FINALITY_ENVELOPE_SCHEMA: &str =
    "bloch.products.evm-transitioned-consensus-finality-envelope.v1";
pub const TRANSITIONED_CONSENSUS_FINALITY_CERTIFICATE_SCHEMA: &str =
    "bloch.products.evm-transitioned-consensus-finality-certificate.v1";
pub const TRANSITIONED_CONSENSUS_FINALITY_PROTOCOL: &str = "transitionedValidatorSetV1";

const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-EVM-TRANSITIONED-CONSENSUS-FINALITY-V1\0";
const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TransitionedFinalityEnvelope {
    schema: String,
    protocol: String,
    root_finality_policy_sha256: String,
    transition_certificate_sha256: String,
    transition_previous_authority_sha256: String,
    validator_set_manifest_sha256: String,
    signature_domain: String,
    network: String,
    chain_id: u64,
    genesis_block_hash: String,
    validator_set_mode: String,
    validator_set_generation: u64,
    trusted_time_policy_sha256: String,
    trusted_time_state_identity: String,
    trusted_time_remote_cursor_policy_sha256: String,
    trusted_time_token_sha256: String,
    checkpoint: ConsensusCheckpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TransitionedFinalityCertificate {
    schema: String,
    envelope: TransitionedFinalityEnvelope,
    signatures: Vec<ValidatorSignature>,
}

/// Non-cloneable evidence that the exact transitioned set signed one exact
/// checkpoint statement under one exact authenticated trusted-time token.
#[derive(Debug)]
pub struct VerifiedTransitionedConsensusFinality {
    root_finality_policy_sha256: String,
    transition_certificate_sha256: String,
    transition_previous_authority_sha256: String,
    validator_set_manifest_sha256: String,
    certificate_sha256: String,
    network: String,
    chain_id: u64,
    genesis_block_hash: String,
    validator_set_generation: u64,
    checkpoint: ConsensusCheckpoint,
    signed_weight: u64,
    validator_ids: Vec<String>,
    trusted_time_policy_sha256: String,
    trusted_time_state_identity: String,
    trusted_time_remote_cursor_policy_sha256: String,
    trusted_time_token_sha256: String,
    deadline_unix_seconds: u64,
    expires_at: Instant,
}

impl VerifiedTransitionedConsensusFinality {
    pub fn root_finality_policy_sha256(&self) -> &str {
        &self.root_finality_policy_sha256
    }
    pub fn transition_certificate_sha256(&self) -> &str {
        &self.transition_certificate_sha256
    }
    pub fn transition_previous_authority_sha256(&self) -> &str {
        &self.transition_previous_authority_sha256
    }
    pub fn validator_set_manifest_sha256(&self) -> &str {
        &self.validator_set_manifest_sha256
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
    pub fn trusted_time_state_identity(&self) -> &str {
        &self.trusted_time_state_identity
    }
    pub fn trusted_time_remote_cursor_policy_sha256(&self) -> &str {
        &self.trusted_time_remote_cursor_policy_sha256
    }
    pub fn trusted_time_token_sha256(&self) -> &str {
        &self.trusted_time_token_sha256
    }
    pub fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }
    pub fn validator_set_transition_proven(&self) -> bool {
        true
    }
    pub fn consensus_installation_proven(&self) -> bool {
        false
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), TransitionedConsensusFinalityError> {
        if Instant::now() >= self.expires_at {
            Err(TransitionedConsensusFinalityError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionedConsensusFinalityError {
    #[error("transition capability is unavailable or expired")]
    InvalidTransition,
    #[error("transitioned finality certificate is invalid or non-canonical")]
    InvalidCertificate,
    #[error("certificate crosses its authenticated transition or validator-set audience")]
    AudienceMismatch,
    #[error("trusted time does not match the transitioned validator-set audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTimeUnavailable,
    #[error("transitioned validator set is not currently effective")]
    ValidatorSetNotEffective,
    #[error("checkpoint is in the future or too old")]
    StaleCheckpoint,
    #[error("validator signature is duplicated")]
    DuplicateSignature,
    #[error("validator is not in the authenticated transitioned set")]
    UntrustedValidator,
    #[error("validator signature is invalid")]
    InvalidSignature,
    #[error("signed validator weight is below quorum")]
    InsufficientWeight,
    #[error("verified transitioned-finality capability has expired")]
    ExpiredCapability,
}

pub fn transitioned_consensus_finality_signing_message(
    transition: &VerifiedValidatorSetTransition,
    trusted_time: &VerifiedTrustedTime,
    checkpoint: &ConsensusCheckpoint,
) -> Result<Vec<u8>, TransitionedConsensusFinalityError> {
    signing_bytes(&envelope(transition, trusted_time, checkpoint)?)
}

pub fn create_transitioned_consensus_finality_certificate(
    transition: &VerifiedValidatorSetTransition,
    trusted_time: &VerifiedTrustedTime,
    checkpoint: &ConsensusCheckpoint,
    signatures: Vec<ValidatorSignature>,
) -> Result<Vec<u8>, TransitionedConsensusFinalityError> {
    let envelope = envelope(transition, trusted_time, checkpoint)?;
    validate_signature_order(&signatures)?;
    verify_signatures(transition, &signing_bytes(&envelope)?, &signatures)?;
    let certificate = TransitionedFinalityCertificate {
        schema: TRANSITIONED_CONSENSUS_FINALITY_CERTIFICATE_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes = serde_json::to_vec(&certificate)
        .map_err(|_| TransitionedConsensusFinalityError::InvalidCertificate)?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(TransitionedConsensusFinalityError::InvalidCertificate);
    }
    Ok(bytes)
}

pub fn verify_transitioned_consensus_finality(
    certificate_bytes: &[u8],
    transition: &VerifiedValidatorSetTransition,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedTransitionedConsensusFinality, TransitionedConsensusFinalityError> {
    transition
        .ensure_monotonic_freshness()
        .map_err(|_| TransitionedConsensusFinalityError::InvalidTransition)?;
    if certificate_bytes.is_empty() || certificate_bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(TransitionedConsensusFinalityError::InvalidCertificate);
    }
    let certificate: TransitionedFinalityCertificate = serde_json::from_slice(certificate_bytes)
        .map_err(|_| TransitionedConsensusFinalityError::InvalidCertificate)?;
    if serde_json::to_vec(&certificate)
        .map_err(|_| TransitionedConsensusFinalityError::InvalidCertificate)?
        != certificate_bytes
        || certificate.schema != TRANSITIONED_CONSENSUS_FINALITY_CERTIFICATE_SCHEMA
    {
        return Err(TransitionedConsensusFinalityError::InvalidCertificate);
    }
    let expected = envelope(transition, trusted_time, &certificate.envelope.checkpoint)?;
    if certificate.envelope != expected {
        return Err(TransitionedConsensusFinalityError::AudienceMismatch);
    }
    let manifest = transition.new_validator_set();
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| TransitionedConsensusFinalityError::TrustedTimeUnavailable)?;
    let checkpoint = &certificate.envelope.checkpoint;
    if checkpoint.finalized_at_unix_seconds > now
        || now - checkpoint.finalized_at_unix_seconds > manifest.max_checkpoint_age_seconds
    {
        return Err(TransitionedConsensusFinalityError::StaleCheckpoint);
    }
    validate_signature_order(&certificate.signatures)?;
    let signed_weight = verify_signatures(
        transition,
        &signing_bytes(&certificate.envelope)?,
        &certificate.signatures,
    )?;
    let deadline = transition
        .deadline_unix_seconds()
        .min(manifest.expires_at_unix_seconds)
        .min(trusted_time.valid_until_unix_seconds());
    let remaining = deadline
        .checked_sub(now)
        .filter(|value| *value != 0)
        .ok_or(TransitionedConsensusFinalityError::ValidatorSetNotEffective)?;
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(TransitionedConsensusFinalityError::ValidatorSetNotEffective)?;
    Ok(VerifiedTransitionedConsensusFinality {
        root_finality_policy_sha256: transition.root_finality_policy_sha256().into(),
        transition_certificate_sha256: transition.certificate_sha256().into(),
        transition_previous_authority_sha256: transition.previous_authority_sha256().into(),
        validator_set_manifest_sha256: transition.new_validator_set_sha256().into(),
        certificate_sha256: hash(certificate_bytes),
        network: manifest.network.clone(),
        chain_id: manifest.chain_id,
        genesis_block_hash: manifest.genesis_block_hash.clone(),
        validator_set_generation: manifest.validator_set_generation,
        checkpoint: checkpoint.clone(),
        signed_weight,
        validator_ids: certificate
            .signatures
            .into_iter()
            .map(|item| item.validator_id)
            .collect(),
        trusted_time_policy_sha256: manifest.trusted_time_policy_sha256.clone(),
        trusted_time_state_identity: manifest.trusted_time_state_identity.clone(),
        trusted_time_remote_cursor_policy_sha256: manifest
            .trusted_time_remote_cursor_policy_sha256
            .clone(),
        trusted_time_token_sha256: trusted_time.token_sha256().into(),
        deadline_unix_seconds: deadline,
        expires_at,
    })
}

fn envelope(
    transition: &VerifiedValidatorSetTransition,
    trusted_time: &VerifiedTrustedTime,
    checkpoint: &ConsensusCheckpoint,
) -> Result<TransitionedFinalityEnvelope, TransitionedConsensusFinalityError> {
    transition
        .ensure_monotonic_freshness()
        .map_err(|_| TransitionedConsensusFinalityError::InvalidTransition)?;
    super::validate_checkpoint(checkpoint)
        .map_err(|_| TransitionedConsensusFinalityError::InvalidCertificate)?;
    let manifest = transition.new_validator_set();
    if trusted_time.trusted_time_policy_sha256() != manifest.trusted_time_policy_sha256
        || trusted_time.state_identity() != manifest.trusted_time_state_identity
        || trusted_time.remote_cursor_policy_sha256()
            != manifest.trusted_time_remote_cursor_policy_sha256
    {
        return Err(TransitionedConsensusFinalityError::TrustedTimeAudienceMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| TransitionedConsensusFinalityError::TrustedTimeUnavailable)?;
    if now < manifest.effective_at_unix_seconds
        || now >= manifest.expires_at_unix_seconds
        || now >= transition.deadline_unix_seconds()
        || now >= trusted_time.valid_until_unix_seconds()
    {
        return Err(TransitionedConsensusFinalityError::ValidatorSetNotEffective);
    }
    Ok(TransitionedFinalityEnvelope {
        schema: TRANSITIONED_CONSENSUS_FINALITY_ENVELOPE_SCHEMA.into(),
        protocol: TRANSITIONED_CONSENSUS_FINALITY_PROTOCOL.into(),
        root_finality_policy_sha256: transition.root_finality_policy_sha256().into(),
        transition_certificate_sha256: transition.certificate_sha256().into(),
        transition_previous_authority_sha256: transition.previous_authority_sha256().into(),
        validator_set_manifest_sha256: validator_set_manifest_sha256(manifest)
            .map_err(|_| TransitionedConsensusFinalityError::InvalidTransition)?,
        signature_domain: manifest.signature_domain.clone(),
        network: manifest.network.clone(),
        chain_id: manifest.chain_id,
        genesis_block_hash: manifest.genesis_block_hash.clone(),
        validator_set_mode: manifest.validator_set_mode.clone(),
        validator_set_generation: manifest.validator_set_generation,
        trusted_time_policy_sha256: manifest.trusted_time_policy_sha256.clone(),
        trusted_time_state_identity: manifest.trusted_time_state_identity.clone(),
        trusted_time_remote_cursor_policy_sha256: manifest
            .trusted_time_remote_cursor_policy_sha256
            .clone(),
        trusted_time_token_sha256: trusted_time.token_sha256().into(),
        checkpoint: checkpoint.clone(),
    })
}

fn validate_signature_order(
    signatures: &[ValidatorSignature],
) -> Result<(), TransitionedConsensusFinalityError> {
    let mut previous: Option<&str> = None;
    for signature in signatures {
        if !valid_id(&signature.validator_id) {
            return Err(TransitionedConsensusFinalityError::InvalidCertificate);
        }
        if previous.is_some_and(|id| id == signature.validator_id) {
            return Err(TransitionedConsensusFinalityError::DuplicateSignature);
        }
        if previous.is_some_and(|id| id > signature.validator_id.as_str()) {
            return Err(TransitionedConsensusFinalityError::InvalidCertificate);
        }
        previous = Some(&signature.validator_id);
    }
    Ok(())
}

fn verify_signatures(
    transition: &VerifiedValidatorSetTransition,
    message: &[u8],
    signatures: &[ValidatorSignature],
) -> Result<u64, TransitionedConsensusFinalityError> {
    let manifest = transition.new_validator_set();
    if signatures.len() > manifest.validators.len() {
        return Err(TransitionedConsensusFinalityError::InvalidCertificate);
    }
    let mut weight = 0_u64;
    for signed in signatures {
        let validator = manifest
            .validators
            .binary_search_by(|validator| validator.validator_id.as_str().cmp(&signed.validator_id))
            .ok()
            .map(|index| &manifest.validators[index])
            .ok_or(TransitionedConsensusFinalityError::UntrustedValidator)?;
        let bytes = decode_fixed::<64>(&signed.signature)
            .ok_or(TransitionedConsensusFinalityError::InvalidSignature)?;
        decode_key(&validator.ed25519_public_key)
            .map_err(|_| TransitionedConsensusFinalityError::InvalidTransition)?
            .verify(message, &Signature::from_bytes(&bytes))
            .map_err(|_| TransitionedConsensusFinalityError::InvalidSignature)?;
        weight = weight
            .checked_add(validator.weight)
            .ok_or(TransitionedConsensusFinalityError::InvalidTransition)?;
    }
    if weight < manifest.quorum_weight {
        return Err(TransitionedConsensusFinalityError::InsufficientWeight);
    }
    Ok(weight)
}

fn signing_bytes(
    envelope: &TransitionedFinalityEnvelope,
) -> Result<Vec<u8>, TransitionedConsensusFinalityError> {
    let encoded = serde_json::to_vec(envelope)
        .map_err(|_| TransitionedConsensusFinalityError::InvalidCertificate)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}
