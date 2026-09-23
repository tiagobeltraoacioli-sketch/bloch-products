//! Explicit dual-quorum validator-set transition protocol.
//!
//! This module is deliberately separate from the pinned V1 checkpoint format.
//! It authenticates set-control changes; it does not prove that a deployed
//! consensus engine installed the resulting set.

use super::{
    ConsensusFinalityPolicy, Validator, ValidatorSignature, decode_fixed, decode_key, hash,
    valid_hash, valid_id, validate_policy_pin,
};
use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const VALIDATOR_SET_MANIFEST_SCHEMA: &str = "bloch.products.evm-validator-set-manifest.v1";
pub const VALIDATOR_SET_TRANSITION_ENVELOPE_SCHEMA: &str =
    "bloch.products.evm-validator-set-transition-envelope.v1";
pub const VALIDATOR_SET_TRANSITION_CERTIFICATE_SCHEMA: &str =
    "bloch.products.evm-validator-set-transition-certificate.v1";
pub const VALIDATOR_SET_TRANSITION_PROTOCOL: &str = "dualQuorumV1";
pub const TRANSITIONED_VALIDATOR_SET_MODE: &str = "transitionedV1";

const MAX_TRANSITION_BYTES: usize = 256 * 1024;
const MAX_VALIDATORS: usize = 512;
const OLD_SET_PREFIX: &[u8] = b"BLOCH-EVM-VALIDATOR-SET-TRANSITION-V1\0OLD\0";
const NEW_SET_PREFIX: &[u8] = b"BLOCH-EVM-VALIDATOR-SET-TRANSITION-V1\0NEW\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidatorSetManifest {
    pub schema: String,
    pub validator_set_id: String,
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
struct ValidatorSetTransitionEnvelope {
    schema: String,
    protocol: String,
    transition_id: String,
    root_finality_policy_sha256: String,
    previous_authority_sha256: String,
    old_validator_set_sha256: String,
    new_validator_set_sha256: String,
    signature_domain: String,
    network: String,
    chain_id: u64,
    genesis_block_hash: String,
    old_generation: u64,
    new_generation: u64,
    activates_at_unix_seconds: u64,
    authorization_expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidatorSetTransitionSignatures {
    pub old_set_signatures: Vec<ValidatorSignature>,
    pub new_set_signatures: Vec<ValidatorSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ValidatorSetTransitionCertificate {
    schema: String,
    envelope: ValidatorSetTransitionEnvelope,
    new_validator_set: ValidatorSetManifest,
    signatures: ValidatorSetTransitionSignatures,
}

#[derive(Debug)]
pub struct ValidatorSetTransitionSigningMessages {
    pub old_set_message: Vec<u8>,
    pub new_set_message: Vec<u8>,
}

/// Authenticated predecessor. A transition can start at the independently
/// pinned generation-one policy or continue from an already verified link.
#[derive(Clone, Copy)]
pub enum ValidatorSetTransitionSource<'a> {
    PinnedV1 {
        policy: &'a ConsensusFinalityPolicy,
        expected_policy_sha256: &'a str,
    },
    Verified(&'a VerifiedValidatorSetTransition),
}

/// Non-cloneable proof of one exact, contiguous, dual-quorum transition.
#[derive(Debug)]
pub struct VerifiedValidatorSetTransition {
    root_finality_policy_sha256: String,
    previous_authority_sha256: String,
    certificate_sha256: String,
    old_validator_set_sha256: String,
    new_validator_set_sha256: String,
    transition_id: String,
    new_validator_set: ValidatorSetManifest,
    old_signed_weight: u64,
    new_signed_weight: u64,
    trusted_time_token_sha256: String,
    deadline_unix_seconds: u64,
    expires_at: Instant,
}

impl VerifiedValidatorSetTransition {
    pub fn root_finality_policy_sha256(&self) -> &str {
        &self.root_finality_policy_sha256
    }
    pub fn previous_authority_sha256(&self) -> &str {
        &self.previous_authority_sha256
    }
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
    pub fn old_validator_set_sha256(&self) -> &str {
        &self.old_validator_set_sha256
    }
    pub fn new_validator_set_sha256(&self) -> &str {
        &self.new_validator_set_sha256
    }
    pub fn transition_id(&self) -> &str {
        &self.transition_id
    }
    pub fn new_validator_set(&self) -> &ValidatorSetManifest {
        &self.new_validator_set
    }
    pub fn old_signed_weight(&self) -> u64 {
        self.old_signed_weight
    }
    pub fn new_signed_weight(&self) -> u64 {
        self.new_signed_weight
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
    pub fn ensure_monotonic_freshness(&self) -> Result<(), ValidatorSetTransitionError> {
        if Instant::now() >= self.expires_at {
            Err(ValidatorSetTransitionError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidatorSetTransitionError {
    #[error("transition source is invalid, unauthenticated, or expired")]
    InvalidSource,
    #[error("validator-set manifest is invalid or non-canonical")]
    InvalidManifest,
    #[error("validator-set manifest pin mismatch")]
    ManifestPinMismatch,
    #[error("validator-set transition certificate is invalid or non-canonical")]
    InvalidCertificate,
    #[error("validator-set transition crosses its authenticated audience")]
    AudienceMismatch,
    #[error("validator-set generations are not strictly contiguous")]
    NonContiguousGeneration,
    #[error("trusted time does not match the validator-set audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTimeUnavailable,
    #[error("validator-set transition is not currently effective")]
    TransitionNotEffective,
    #[error("validator signature is duplicated")]
    DuplicateSignature,
    #[error("validator is not in the authenticated set")]
    UntrustedValidator,
    #[error("validator signature is invalid")]
    InvalidSignature,
    #[error("old validator-set signed weight is below quorum")]
    InsufficientOldWeight,
    #[error("new validator-set signed weight is below quorum")]
    InsufficientNewWeight,
    #[error("verified validator-set transition capability has expired")]
    ExpiredCapability,
}

/// Derives the canonical generation-one set manifest without changing the
/// semantics or accepted inputs of `pinnedV1` checkpoint verification.
pub fn consensus_validator_set_manifest(
    policy: &ConsensusFinalityPolicy,
    expected_policy_sha256: &str,
) -> Result<ValidatorSetManifest, ValidatorSetTransitionError> {
    validate_policy_pin(policy, expected_policy_sha256)
        .map_err(|_| ValidatorSetTransitionError::InvalidSource)?;
    let manifest = ValidatorSetManifest {
        schema: VALIDATOR_SET_MANIFEST_SCHEMA.into(),
        validator_set_id: policy.policy_id.clone(),
        signature_domain: policy.signature_domain.clone(),
        network: policy.network.clone(),
        chain_id: policy.chain_id,
        genesis_block_hash: policy.genesis_block_hash.clone(),
        validator_set_mode: super::PINNED_VALIDATOR_SET_MODE.into(),
        validator_set_generation: policy.validator_set_generation,
        quorum_weight: policy.quorum_weight,
        effective_at_unix_seconds: policy.effective_at_unix_seconds,
        expires_at_unix_seconds: policy.expires_at_unix_seconds,
        max_checkpoint_age_seconds: policy.max_checkpoint_age_seconds,
        trusted_time_policy_sha256: policy.trusted_time_policy_sha256.clone(),
        trusted_time_state_identity: policy.trusted_time_state_identity.clone(),
        trusted_time_remote_cursor_policy_sha256: policy
            .trusted_time_remote_cursor_policy_sha256
            .clone(),
        validators: policy.validators.clone(),
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validator_set_manifest_sha256(
    manifest: &ValidatorSetManifest,
) -> Result<String, ValidatorSetTransitionError> {
    validate_manifest(manifest)?;
    let bytes =
        serde_json::to_vec(manifest).map_err(|_| ValidatorSetTransitionError::InvalidManifest)?;
    if bytes.len() > super::MAX_POLICY_BYTES {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    Ok(hash(&bytes))
}

pub fn parse_validator_set_manifest(
    bytes: &[u8],
    expected_manifest_sha256: &str,
) -> Result<ValidatorSetManifest, ValidatorSetTransitionError> {
    if bytes.is_empty()
        || bytes.len() > super::MAX_POLICY_BYTES
        || !valid_hash(expected_manifest_sha256)
    {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    let manifest: ValidatorSetManifest =
        serde_json::from_slice(bytes).map_err(|_| ValidatorSetTransitionError::InvalidManifest)?;
    let canonical =
        serde_json::to_vec(&manifest).map_err(|_| ValidatorSetTransitionError::InvalidManifest)?;
    if canonical != bytes {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    if validator_set_manifest_sha256(&manifest)? != expected_manifest_sha256 {
        return Err(ValidatorSetTransitionError::ManifestPinMismatch);
    }
    Ok(manifest)
}

pub fn validator_set_transition_signing_messages(
    source: ValidatorSetTransitionSource<'_>,
    transition_id: &str,
    new_validator_set: &ValidatorSetManifest,
    authorization_expires_at_unix_seconds: u64,
) -> Result<ValidatorSetTransitionSigningMessages, ValidatorSetTransitionError> {
    let context = source_context(source)?;
    let envelope = transition_envelope(
        &context,
        transition_id,
        new_validator_set,
        authorization_expires_at_unix_seconds,
    )?;
    Ok(ValidatorSetTransitionSigningMessages {
        old_set_message: signing_bytes(OLD_SET_PREFIX, &envelope)?,
        new_set_message: signing_bytes(NEW_SET_PREFIX, &envelope)?,
    })
}

pub fn create_validator_set_transition_certificate(
    source: ValidatorSetTransitionSource<'_>,
    transition_id: &str,
    new_validator_set: &ValidatorSetManifest,
    authorization_expires_at_unix_seconds: u64,
    signatures: ValidatorSetTransitionSignatures,
) -> Result<Vec<u8>, ValidatorSetTransitionError> {
    let context = source_context(source)?;
    let envelope = transition_envelope(
        &context,
        transition_id,
        new_validator_set,
        authorization_expires_at_unix_seconds,
    )?;
    verify_transition_signatures(
        &context.old_manifest,
        new_validator_set,
        &envelope,
        &signatures,
    )?;
    let certificate = ValidatorSetTransitionCertificate {
        schema: VALIDATOR_SET_TRANSITION_CERTIFICATE_SCHEMA.into(),
        envelope,
        new_validator_set: new_validator_set.clone(),
        signatures,
    };
    let bytes = serde_json::to_vec(&certificate)
        .map_err(|_| ValidatorSetTransitionError::InvalidCertificate)?;
    if bytes.len() > MAX_TRANSITION_BYTES {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    Ok(bytes)
}

pub fn verify_validator_set_transition(
    certificate_bytes: &[u8],
    source: ValidatorSetTransitionSource<'_>,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedValidatorSetTransition, ValidatorSetTransitionError> {
    if certificate_bytes.is_empty() || certificate_bytes.len() > MAX_TRANSITION_BYTES {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    let context = source_context(source)?;
    verify_time_audience(&context.old_manifest, trusted_time)?;
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| ValidatorSetTransitionError::TrustedTimeUnavailable)?;
    if now < context.old_manifest.effective_at_unix_seconds
        || now >= context.old_manifest.expires_at_unix_seconds
    {
        return Err(ValidatorSetTransitionError::InvalidSource);
    }
    let certificate: ValidatorSetTransitionCertificate = serde_json::from_slice(certificate_bytes)
        .map_err(|_| ValidatorSetTransitionError::InvalidCertificate)?;
    if serde_json::to_vec(&certificate)
        .map_err(|_| ValidatorSetTransitionError::InvalidCertificate)?
        != certificate_bytes
        || certificate.schema != VALIDATOR_SET_TRANSITION_CERTIFICATE_SCHEMA
    {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    let expected = transition_envelope(
        &context,
        &certificate.envelope.transition_id,
        &certificate.new_validator_set,
        certificate.envelope.authorization_expires_at_unix_seconds,
    )?;
    if certificate.envelope != expected {
        return Err(ValidatorSetTransitionError::AudienceMismatch);
    }
    if now < expected.activates_at_unix_seconds
        || now >= expected.authorization_expires_at_unix_seconds
    {
        return Err(ValidatorSetTransitionError::TransitionNotEffective);
    }
    verify_time_audience(&certificate.new_validator_set, trusted_time)?;
    let (old_signed_weight, new_signed_weight) = verify_transition_signatures(
        &context.old_manifest,
        &certificate.new_validator_set,
        &certificate.envelope,
        &certificate.signatures,
    )?;
    let deadline = certificate
        .envelope
        .authorization_expires_at_unix_seconds
        .min(certificate.new_validator_set.expires_at_unix_seconds)
        .min(context.predecessor_deadline_unix_seconds)
        .min(trusted_time.valid_until_unix_seconds());
    let remaining = deadline
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(ValidatorSetTransitionError::TransitionNotEffective)?;
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(ValidatorSetTransitionError::TransitionNotEffective)?;
    Ok(VerifiedValidatorSetTransition {
        root_finality_policy_sha256: context.root_policy_sha256,
        previous_authority_sha256: context.previous_authority_sha256,
        certificate_sha256: hash(certificate_bytes),
        old_validator_set_sha256: context.old_manifest_sha256,
        new_validator_set_sha256: certificate.envelope.new_validator_set_sha256,
        transition_id: certificate.envelope.transition_id,
        new_validator_set: certificate.new_validator_set,
        old_signed_weight,
        new_signed_weight,
        trusted_time_token_sha256: trusted_time.token_sha256().into(),
        deadline_unix_seconds: deadline,
        expires_at,
    })
}

struct SourceContext {
    root_policy_sha256: String,
    previous_authority_sha256: String,
    old_manifest_sha256: String,
    old_manifest: ValidatorSetManifest,
    predecessor_deadline_unix_seconds: u64,
}

fn source_context(
    source: ValidatorSetTransitionSource<'_>,
) -> Result<SourceContext, ValidatorSetTransitionError> {
    match source {
        ValidatorSetTransitionSource::PinnedV1 {
            policy,
            expected_policy_sha256,
        } => {
            let manifest = consensus_validator_set_manifest(policy, expected_policy_sha256)?;
            let manifest_sha256 = validator_set_manifest_sha256(&manifest)?;
            Ok(SourceContext {
                root_policy_sha256: expected_policy_sha256.into(),
                previous_authority_sha256: expected_policy_sha256.into(),
                old_manifest_sha256: manifest_sha256,
                old_manifest: manifest,
                predecessor_deadline_unix_seconds: policy.expires_at_unix_seconds,
            })
        }
        ValidatorSetTransitionSource::Verified(verified) => {
            verified.ensure_monotonic_freshness()?;
            Ok(SourceContext {
                root_policy_sha256: verified.root_finality_policy_sha256.clone(),
                previous_authority_sha256: verified.certificate_sha256.clone(),
                old_manifest_sha256: verified.new_validator_set_sha256.clone(),
                old_manifest: verified.new_validator_set.clone(),
                predecessor_deadline_unix_seconds: verified.deadline_unix_seconds,
            })
        }
    }
}

fn transition_envelope(
    context: &SourceContext,
    transition_id: &str,
    new_manifest: &ValidatorSetManifest,
    authorization_expires_at_unix_seconds: u64,
) -> Result<ValidatorSetTransitionEnvelope, ValidatorSetTransitionError> {
    validate_manifest(new_manifest)?;
    if !valid_id(transition_id) {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    let old = &context.old_manifest;
    if old.validator_set_generation.checked_add(1) != Some(new_manifest.validator_set_generation) {
        return Err(ValidatorSetTransitionError::NonContiguousGeneration);
    }
    if new_manifest.validator_set_mode != TRANSITIONED_VALIDATOR_SET_MODE
        || old.signature_domain != new_manifest.signature_domain
        || old.network != new_manifest.network
        || old.chain_id != new_manifest.chain_id
        || old.genesis_block_hash != new_manifest.genesis_block_hash
        || old.trusted_time_policy_sha256 != new_manifest.trusted_time_policy_sha256
        || old.trusted_time_state_identity != new_manifest.trusted_time_state_identity
        || old.trusted_time_remote_cursor_policy_sha256
            != new_manifest.trusted_time_remote_cursor_policy_sha256
    {
        return Err(ValidatorSetTransitionError::AudienceMismatch);
    }
    if new_manifest.effective_at_unix_seconds < old.effective_at_unix_seconds
        || new_manifest.effective_at_unix_seconds >= old.expires_at_unix_seconds
        || authorization_expires_at_unix_seconds <= new_manifest.effective_at_unix_seconds
        || authorization_expires_at_unix_seconds > old.expires_at_unix_seconds
        || authorization_expires_at_unix_seconds > new_manifest.expires_at_unix_seconds
        || authorization_expires_at_unix_seconds > context.predecessor_deadline_unix_seconds
    {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    Ok(ValidatorSetTransitionEnvelope {
        schema: VALIDATOR_SET_TRANSITION_ENVELOPE_SCHEMA.into(),
        protocol: VALIDATOR_SET_TRANSITION_PROTOCOL.into(),
        transition_id: transition_id.into(),
        root_finality_policy_sha256: context.root_policy_sha256.clone(),
        previous_authority_sha256: context.previous_authority_sha256.clone(),
        old_validator_set_sha256: context.old_manifest_sha256.clone(),
        new_validator_set_sha256: validator_set_manifest_sha256(new_manifest)?,
        signature_domain: old.signature_domain.clone(),
        network: old.network.clone(),
        chain_id: old.chain_id,
        genesis_block_hash: old.genesis_block_hash.clone(),
        old_generation: old.validator_set_generation,
        new_generation: new_manifest.validator_set_generation,
        activates_at_unix_seconds: new_manifest.effective_at_unix_seconds,
        authorization_expires_at_unix_seconds,
    })
}

fn verify_transition_signatures(
    old: &ValidatorSetManifest,
    new: &ValidatorSetManifest,
    envelope: &ValidatorSetTransitionEnvelope,
    signatures: &ValidatorSetTransitionSignatures,
) -> Result<(u64, u64), ValidatorSetTransitionError> {
    let old_message = signing_bytes(OLD_SET_PREFIX, envelope)?;
    let new_message = signing_bytes(NEW_SET_PREFIX, envelope)?;
    let old_weight = verify_set_signatures(old, &old_message, &signatures.old_set_signatures)
        .map_err(|error| match error {
            ValidatorSetTransitionError::InsufficientNewWeight => {
                ValidatorSetTransitionError::InsufficientOldWeight
            }
            other => other,
        })?;
    let new_weight = verify_set_signatures(new, &new_message, &signatures.new_set_signatures)?;
    Ok((old_weight, new_weight))
}

fn verify_set_signatures(
    manifest: &ValidatorSetManifest,
    message: &[u8],
    signatures: &[ValidatorSignature],
) -> Result<u64, ValidatorSetTransitionError> {
    if signatures.len() > manifest.validators.len() {
        return Err(ValidatorSetTransitionError::InvalidCertificate);
    }
    let mut previous: Option<&str> = None;
    let mut weight = 0_u64;
    for signed in signatures {
        if !valid_id(&signed.validator_id) {
            return Err(ValidatorSetTransitionError::InvalidCertificate);
        }
        if previous.is_some_and(|id| id == signed.validator_id) {
            return Err(ValidatorSetTransitionError::DuplicateSignature);
        }
        if previous.is_some_and(|id| id > signed.validator_id.as_str()) {
            return Err(ValidatorSetTransitionError::InvalidCertificate);
        }
        let validator = manifest
            .validators
            .binary_search_by(|validator| validator.validator_id.as_str().cmp(&signed.validator_id))
            .ok()
            .map(|index| &manifest.validators[index])
            .ok_or(ValidatorSetTransitionError::UntrustedValidator)?;
        let signature = decode_fixed::<64>(&signed.signature)
            .ok_or(ValidatorSetTransitionError::InvalidSignature)?;
        decode_key(&validator.ed25519_public_key)
            .map_err(|_| ValidatorSetTransitionError::InvalidManifest)?
            .verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| ValidatorSetTransitionError::InvalidSignature)?;
        weight = weight
            .checked_add(validator.weight)
            .ok_or(ValidatorSetTransitionError::InvalidManifest)?;
        previous = Some(&signed.validator_id);
    }
    if weight < manifest.quorum_weight {
        return Err(ValidatorSetTransitionError::InsufficientNewWeight);
    }
    Ok(weight)
}

fn validate_manifest(manifest: &ValidatorSetManifest) -> Result<(), ValidatorSetTransitionError> {
    if manifest.schema != VALIDATOR_SET_MANIFEST_SCHEMA
        || !valid_id(&manifest.validator_set_id)
        || !valid_id(&manifest.signature_domain)
        || !valid_id(&manifest.network)
        || manifest.chain_id == 0
        || !valid_hash(&manifest.genesis_block_hash)
        || !matches!(
            manifest.validator_set_mode.as_str(),
            super::PINNED_VALIDATOR_SET_MODE | TRANSITIONED_VALIDATOR_SET_MODE
        )
        || manifest.validator_set_generation == 0
        || manifest.validators.len() < 3
        || manifest.validators.len() > MAX_VALIDATORS
        || manifest.quorum_weight == 0
        || manifest.effective_at_unix_seconds >= manifest.expires_at_unix_seconds
        || manifest.max_checkpoint_age_seconds == 0
        || manifest.max_checkpoint_age_seconds
            > manifest.expires_at_unix_seconds - manifest.effective_at_unix_seconds
        || !valid_hash(&manifest.trusted_time_policy_sha256)
        || !valid_id(&manifest.trusted_time_state_identity)
        || !valid_hash(&manifest.trusted_time_remote_cursor_policy_sha256)
    {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    if (manifest.validator_set_generation == 1)
        != (manifest.validator_set_mode == super::PINNED_VALIDATOR_SET_MODE)
    {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    let mut total = 0_u64;
    for validator in &manifest.validators {
        if !valid_id(&validator.validator_id)
            || previous.is_some_and(|id| id >= validator.validator_id.as_str())
            || validator.weight == 0
            || decode_key(&validator.ed25519_public_key).is_err()
            || !keys.insert(&validator.ed25519_public_key)
        {
            return Err(ValidatorSetTransitionError::InvalidManifest);
        }
        total = total
            .checked_add(validator.weight)
            .ok_or(ValidatorSetTransitionError::InvalidManifest)?;
        previous = Some(&validator.validator_id);
    }
    if manifest.quorum_weight > total
        || u128::from(manifest.quorum_weight) * 3 <= u128::from(total) * 2
    {
        return Err(ValidatorSetTransitionError::InvalidManifest);
    }
    Ok(())
}

fn verify_time_audience(
    manifest: &ValidatorSetManifest,
    trusted_time: &VerifiedTrustedTime,
) -> Result<(), ValidatorSetTransitionError> {
    if trusted_time.trusted_time_policy_sha256() != manifest.trusted_time_policy_sha256
        || trusted_time.state_identity() != manifest.trusted_time_state_identity
        || trusted_time.remote_cursor_policy_sha256()
            != manifest.trusted_time_remote_cursor_policy_sha256
    {
        Err(ValidatorSetTransitionError::TrustedTimeAudienceMismatch)
    } else {
        Ok(())
    }
}

fn signing_bytes(
    prefix: &[u8],
    envelope: &ValidatorSetTransitionEnvelope,
) -> Result<Vec<u8>, ValidatorSetTransitionError> {
    let encoded = serde_json::to_vec(envelope)
        .map_err(|_| ValidatorSetTransitionError::InvalidCertificate)?;
    let mut bytes = Vec::with_capacity(prefix.len() + 8 + encoded.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}
