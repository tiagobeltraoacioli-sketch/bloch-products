//! Threshold-authenticated, transport-neutral external anti-rollback anchors.
//!
//! No persistence, network transport, authority independence or external
//! counter implementation is provided by this crate.

use bloch_trusted_time::{
    TrustedTimeBoundary, TrustedTimeError, VerifiedTrustedTime, parse_trusted_time_boundary,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const EXTERNAL_ANCHOR_POLICY_SCHEMA: &str =
    "bloch.products.trusted-time-external-anchor-policy.v1";
pub const EXTERNAL_ANCHOR_ENVELOPE_SCHEMA: &str =
    "bloch.products.trusted-time-external-anchor-envelope.v1";
pub const EXTERNAL_ANCHOR_DOCUMENT_SCHEMA: &str =
    "bloch.products.trusted-time-external-anchor-document.v1";
pub const EXTERNAL_ANCHOR_EXPECTATION_SCHEMA: &str =
    "bloch.products.trusted-time-external-anchor-expectation.v1";
pub const MAX_EXTERNAL_ANCHOR_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES: usize = 128 * 1024;
pub const MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES: usize = 4 * 1024;
const MAX_AUTHORITIES: usize = 16;
const MAX_BOUNDARY_BYTES: usize = 1024;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-TRUSTED-TIME-EXTERNAL-ANCHOR-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalAnchorAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalAnchorPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub state_identity: String,
    pub trusted_time_policy_sha256: String,
    pub remote_cursor_policy_sha256: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_anchor_lifetime_seconds: u64,
    pub authorities: Vec<ExternalAnchorAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalAnchorSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExternalAnchorEnvelope {
    schema: String,
    external_anchor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    trusted_time_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    generation: u64,
    trusted_time_boundary_sha256: String,
    canonical_trusted_time_boundary_hex: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    challenge_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExternalAnchorDocument {
    schema: String,
    envelope: ExternalAnchorEnvelope,
    signatures: Vec<ExternalAnchorSignature>,
}

/// Minimum generation and boundary that the independent system must retain.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalAnchorExpectation {
    schema: String,
    external_anchor_policy_sha256: String,
    state_identity: String,
    trusted_time_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    generation: u64,
    boundary_sha256: String,
    boundary_not_before_unix_seconds: u64,
}

impl ExternalAnchorExpectation {
    pub fn external_anchor_policy_sha256(&self) -> &str {
        &self.external_anchor_policy_sha256
    }

    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }

    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.trusted_time_policy_sha256
    }

    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn boundary_sha256(&self) -> &str {
        &self.boundary_sha256
    }

    pub fn boundary_not_before_unix_seconds(&self) -> u64 {
        self.boundary_not_before_unix_seconds
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExternalAnchorError> {
        validate_expectation(self)?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| ExternalAnchorError::InvalidExpectation)?;
        if bytes.len() > MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES {
            return Err(ExternalAnchorError::InvalidExpectation);
        }
        Ok(bytes)
    }
}

/// Opaque proof that the configured threshold authenticated one fresh anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalAnchor {
    policy_sha256: String,
    state_identity: String,
    trusted_time_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    generation: u64,
    boundary_sha256: String,
    canonical_boundary: Vec<u8>,
    boundary_not_before_unix_seconds: u64,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    challenge_nonce: String,
    authority_ids: Vec<String>,
    document_sha256: String,
    monotonic_deadline: Instant,
}

impl VerifiedExternalAnchor {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.trusted_time_policy_sha256
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn boundary_sha256(&self) -> &str {
        &self.boundary_sha256
    }
    pub fn canonical_boundary(&self) -> &[u8] {
        &self.canonical_boundary
    }
    pub fn boundary_not_before_unix_seconds(&self) -> u64 {
        self.boundary_not_before_unix_seconds
    }
    pub fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    pub fn challenge_nonce(&self) -> &str {
        &self.challenge_nonce
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn document_sha256(&self) -> &str {
        &self.document_sha256
    }

    /// Fails closed at the earlier of the anchor expiry and trusted-time expiry.
    pub fn ensure_monotonic_freshness(&self) -> Result<(), ExternalAnchorError> {
        if Instant::now() >= self.monotonic_deadline {
            Err(ExternalAnchorError::OutsideValidityWindow)
        } else {
            Ok(())
        }
    }

    pub fn retention_expectation(&self) -> ExternalAnchorExpectation {
        ExternalAnchorExpectation {
            schema: EXTERNAL_ANCHOR_EXPECTATION_SCHEMA.into(),
            external_anchor_policy_sha256: self.policy_sha256.clone(),
            state_identity: self.state_identity.clone(),
            trusted_time_policy_sha256: self.trusted_time_policy_sha256.clone(),
            remote_cursor_policy_sha256: self.remote_cursor_policy_sha256.clone(),
            generation: self.generation,
            boundary_sha256: self.boundary_sha256.clone(),
            boundary_not_before_unix_seconds: self.boundary_not_before_unix_seconds,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExternalAnchorError {
    #[error("external anchor policy is invalid")]
    InvalidPolicy,
    #[error("external anchor policy pin mismatch")]
    PolicyPinMismatch,
    #[error("external anchor document is invalid or non-canonical")]
    InvalidDocument,
    #[error("external anchor retention expectation is invalid or non-canonical")]
    InvalidExpectation,
    #[error("external anchor audience does not match verified trusted time")]
    AudienceMismatch,
    #[error("external anchor challenge nonce does not match")]
    NonceMismatch,
    #[error("external anchor is outside its validity window")]
    OutsideValidityWindow,
    #[error("external anchor generation or boundary rolled back")]
    RollbackDetected,
    #[error("external anchor authority is not trusted")]
    UntrustedAuthority,
    #[error("external anchor signature is invalid")]
    InvalidSignature,
    #[error("external anchor signature threshold is not met")]
    ThresholdNotMet,
    #[error("verified trusted time is unavailable or expired")]
    TrustedTimeUnavailable,
}

pub fn external_anchor_policy_bytes(
    policy: &ExternalAnchorPolicy,
) -> Result<Vec<u8>, ExternalAnchorError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| ExternalAnchorError::InvalidPolicy)?;
    if bytes.len() > MAX_EXTERNAL_ANCHOR_POLICY_BYTES {
        return Err(ExternalAnchorError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn external_anchor_policy_sha256(
    policy: &ExternalAnchorPolicy,
) -> Result<String, ExternalAnchorError> {
    Ok(hash(&external_anchor_policy_bytes(policy)?))
}

pub fn parse_external_anchor_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<ExternalAnchorPolicy, ExternalAnchorError> {
    if bytes.is_empty() || bytes.len() > MAX_EXTERNAL_ANCHOR_POLICY_BYTES {
        return Err(ExternalAnchorError::InvalidPolicy);
    }
    let policy: ExternalAnchorPolicy =
        serde_json::from_slice(bytes).map_err(|_| ExternalAnchorError::InvalidPolicy)?;
    if external_anchor_policy_bytes(&policy)? != bytes {
        return Err(ExternalAnchorError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

/// Parses retained state against independently configured pins and audience.
///
/// The bytes are canonical but not self-authenticating. Their durable storage
/// and authenticated delivery remain the independent system's responsibility.
pub fn parse_external_anchor_expectation(
    bytes: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_state_identity: &str,
    expected_trusted_time_policy_sha256: &str,
    expected_remote_cursor_policy_sha256: &str,
) -> Result<ExternalAnchorExpectation, ExternalAnchorError> {
    if bytes.is_empty() || bytes.len() > MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES {
        return Err(ExternalAnchorError::InvalidExpectation);
    }
    let expectation: ExternalAnchorExpectation =
        serde_json::from_slice(bytes).map_err(|_| ExternalAnchorError::InvalidExpectation)?;
    if expectation.canonical_bytes()? != bytes {
        return Err(ExternalAnchorError::InvalidExpectation);
    }
    if !valid_sha256(expected_external_anchor_policy_sha256)
        || !valid_id(expected_state_identity)
        || !valid_sha256(expected_trusted_time_policy_sha256)
        || !valid_sha256(expected_remote_cursor_policy_sha256)
        || expectation.external_anchor_policy_sha256 != expected_external_anchor_policy_sha256
        || expectation.state_identity != expected_state_identity
        || expectation.trusted_time_policy_sha256 != expected_trusted_time_policy_sha256
        || expectation.remote_cursor_policy_sha256 != expected_remote_cursor_policy_sha256
    {
        return Err(ExternalAnchorError::AudienceMismatch);
    }
    Ok(expectation)
}

/// Domain-separated bytes that each independent anchor authority signs.
#[allow(clippy::too_many_arguments)]
pub fn external_anchor_signature_message(
    policy: &ExternalAnchorPolicy,
    expected_policy_sha256: &str,
    generation: u64,
    boundary: &TrustedTimeBoundary,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    challenge_nonce: &str,
) -> Result<Vec<u8>, ExternalAnchorError> {
    signing_bytes(&envelope(
        policy,
        expected_policy_sha256,
        generation,
        boundary,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        challenge_nonce,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub fn create_external_anchor_document(
    policy: &ExternalAnchorPolicy,
    expected_policy_sha256: &str,
    generation: u64,
    boundary: &TrustedTimeBoundary,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    challenge_nonce: &str,
    signatures: &[ExternalAnchorSignature],
) -> Result<Vec<u8>, ExternalAnchorError> {
    let envelope = envelope(
        policy,
        expected_policy_sha256,
        generation,
        boundary,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        challenge_nonce,
    )?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let document = ExternalAnchorDocument {
        schema: EXTERNAL_ANCHOR_DOCUMENT_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes = serde_json::to_vec(&document).map_err(|_| ExternalAnchorError::InvalidDocument)?;
    if bytes.len() > MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    Ok(bytes)
}

pub fn verify_external_anchor(
    document_bytes: &[u8],
    policy: &ExternalAnchorPolicy,
    expected_policy_sha256: &str,
    expected_challenge_nonce: &str,
    trusted_time: &VerifiedTrustedTime,
    retained: Option<&ExternalAnchorExpectation>,
) -> Result<VerifiedExternalAnchor, ExternalAnchorError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if document_bytes.is_empty() || document_bytes.len() > MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    let document: ExternalAnchorDocument =
        serde_json::from_slice(document_bytes).map_err(|_| ExternalAnchorError::InvalidDocument)?;
    if serde_json::to_vec(&document).map_err(|_| ExternalAnchorError::InvalidDocument)?
        != document_bytes
        || document.schema != EXTERNAL_ANCHOR_DOCUMENT_SCHEMA
    {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    validate_envelope(&document.envelope, policy, expected_policy_sha256)?;
    if !valid_nonce(expected_challenge_nonce)
        || document.envelope.challenge_nonce != expected_challenge_nonce
    {
        return Err(ExternalAnchorError::NonceMismatch);
    }
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
    {
        return Err(ExternalAnchorError::AudienceMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| ExternalAnchorError::TrustedTimeUnavailable)?;
    if now < policy.effective_at_unix_seconds
        || now >= policy.expires_at_unix_seconds
        || now < document.envelope.issued_at_unix_seconds
        || now >= document.envelope.expires_at_unix_seconds
    {
        return Err(ExternalAnchorError::OutsideValidityWindow);
    }
    let remaining_anchor = document
        .envelope
        .expires_at_unix_seconds
        .checked_sub(now)
        .ok_or(ExternalAnchorError::OutsideValidityWindow)?;
    let remaining_time = trusted_time
        .valid_until_unix_seconds()
        .checked_sub(now)
        .ok_or(ExternalAnchorError::TrustedTimeUnavailable)?;
    let remaining = remaining_anchor.min(remaining_time);
    if remaining == 0 {
        return Err(ExternalAnchorError::OutsideValidityWindow);
    }
    let monotonic_deadline = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(ExternalAnchorError::OutsideValidityWindow)?;
    let boundary_bytes = decode_boundary(&document.envelope)?;
    let boundary = parse_trusted_time_boundary(&boundary_bytes, &policy.trusted_time_policy_sha256)
        .map_err(|_| ExternalAnchorError::InvalidDocument)?;
    if trusted_time.attested_at_unix_seconds() < boundary.not_before_unix_seconds() {
        return Err(ExternalAnchorError::RollbackDetected);
    }
    if let Some(retained) = retained {
        if retained.external_anchor_policy_sha256 != expected_policy_sha256
            || retained.state_identity != policy.state_identity
            || retained.trusted_time_policy_sha256 != policy.trusted_time_policy_sha256
            || retained.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        {
            return Err(ExternalAnchorError::AudienceMismatch);
        }
        let generation = document.envelope.generation;
        let floor = boundary.not_before_unix_seconds();
        if generation < retained.generation
            || floor < retained.boundary_not_before_unix_seconds
            || (generation == retained.generation
                && (document.envelope.trusted_time_boundary_sha256 != retained.boundary_sha256
                    || floor != retained.boundary_not_before_unix_seconds))
        {
            return Err(ExternalAnchorError::RollbackDetected);
        }
    }
    let message = signing_bytes(&document.envelope)?;
    verify_signatures(policy, &message, &document.signatures)?;
    Ok(VerifiedExternalAnchor {
        policy_sha256: expected_policy_sha256.into(),
        state_identity: document.envelope.state_identity,
        trusted_time_policy_sha256: document.envelope.trusted_time_policy_sha256,
        remote_cursor_policy_sha256: document.envelope.remote_cursor_policy_sha256,
        generation: document.envelope.generation,
        boundary_sha256: document.envelope.trusted_time_boundary_sha256,
        canonical_boundary: boundary_bytes,
        boundary_not_before_unix_seconds: boundary.not_before_unix_seconds(),
        issued_at_unix_seconds: document.envelope.issued_at_unix_seconds,
        expires_at_unix_seconds: document.envelope.expires_at_unix_seconds,
        challenge_nonce: document.envelope.challenge_nonce,
        authority_ids: document
            .signatures
            .into_iter()
            .map(|item| item.authority_id)
            .collect(),
        document_sha256: hash(document_bytes),
        monotonic_deadline,
    })
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    policy: &ExternalAnchorPolicy,
    expected_policy_sha256: &str,
    generation: u64,
    boundary: &TrustedTimeBoundary,
    issued_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<ExternalAnchorEnvelope, ExternalAnchorError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let boundary_bytes = boundary.canonical_bytes().map_err(map_time_error)?;
    if boundary_bytes.len() > MAX_BOUNDARY_BYTES
        || boundary.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || generation == 0
        || !valid_nonce(nonce)
        || issued_at < policy.effective_at_unix_seconds
        || expires_at <= issued_at
        || expires_at > policy.expires_at_unix_seconds
        || expires_at - issued_at > policy.max_anchor_lifetime_seconds
    {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    Ok(ExternalAnchorEnvelope {
        schema: EXTERNAL_ANCHOR_ENVELOPE_SCHEMA.into(),
        external_anchor_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        trusted_time_policy_sha256: policy.trusted_time_policy_sha256.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        generation,
        trusted_time_boundary_sha256: hash(&boundary_bytes),
        canonical_trusted_time_boundary_hex: hex::encode(boundary_bytes),
        issued_at_unix_seconds: issued_at,
        expires_at_unix_seconds: expires_at,
        challenge_nonce: nonce.into(),
    })
}

fn validate_envelope(
    envelope: &ExternalAnchorEnvelope,
    policy: &ExternalAnchorPolicy,
    expected_policy_sha256: &str,
) -> Result<(), ExternalAnchorError> {
    if envelope.schema != EXTERNAL_ANCHOR_ENVELOPE_SCHEMA
        || envelope.external_anchor_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || envelope.trusted_time_policy_sha256 != policy.trusted_time_policy_sha256
        || envelope.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || envelope.generation == 0
        || !valid_sha256(&envelope.trusted_time_boundary_sha256)
        || !valid_nonce(&envelope.challenge_nonce)
        || envelope.issued_at_unix_seconds < policy.effective_at_unix_seconds
        || envelope.expires_at_unix_seconds <= envelope.issued_at_unix_seconds
        || envelope.expires_at_unix_seconds > policy.expires_at_unix_seconds
        || envelope.expires_at_unix_seconds - envelope.issued_at_unix_seconds
            > policy.max_anchor_lifetime_seconds
    {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    decode_boundary(envelope).map(|_| ())
}

fn decode_boundary(envelope: &ExternalAnchorEnvelope) -> Result<Vec<u8>, ExternalAnchorError> {
    if envelope.canonical_trusted_time_boundary_hex.is_empty()
        || envelope.canonical_trusted_time_boundary_hex.len() > MAX_BOUNDARY_BYTES * 2
        || !envelope
            .canonical_trusted_time_boundary_hex
            .len()
            .is_multiple_of(2)
        || envelope
            .canonical_trusted_time_boundary_hex
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    let bytes = hex::decode(&envelope.canonical_trusted_time_boundary_hex)
        .map_err(|_| ExternalAnchorError::InvalidDocument)?;
    if hash(&bytes) != envelope.trusted_time_boundary_sha256 {
        return Err(ExternalAnchorError::InvalidDocument);
    }
    Ok(bytes)
}

fn signing_bytes(envelope: &ExternalAnchorEnvelope) -> Result<Vec<u8>, ExternalAnchorError> {
    let encoded = serde_json::to_vec(envelope).map_err(|_| ExternalAnchorError::InvalidDocument)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn verify_signatures(
    policy: &ExternalAnchorPolicy,
    message: &[u8],
    signatures: &[ExternalAnchorSignature],
) -> Result<(), ExternalAnchorError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(ExternalAnchorError::ThresholdNotMet);
    }
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
        {
            return Err(ExternalAnchorError::InvalidDocument);
        }
        let authority = policy
            .authorities
            .binary_search_by(|item| item.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(ExternalAnchorError::UntrustedAuthority)?;
        let key = VerifyingKey::from_bytes(
            &decode_fixed::<32>(&authority.ed25519_public_key)
                .ok_or(ExternalAnchorError::InvalidPolicy)?,
        )
        .map_err(|_| ExternalAnchorError::InvalidPolicy)?;
        let signature =
            decode_fixed::<64>(&detached.signature).ok_or(ExternalAnchorError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| ExternalAnchorError::InvalidSignature)?;
        previous = Some(&detached.authority_id);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &ExternalAnchorPolicy,
    expected: &str,
) -> Result<(), ExternalAnchorError> {
    validate_policy(policy)?;
    if !valid_sha256(expected) || external_anchor_policy_sha256(policy)? != expected {
        return Err(ExternalAnchorError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &ExternalAnchorPolicy) -> Result<(), ExternalAnchorError> {
    if policy.schema != EXTERNAL_ANCHOR_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || policy.threshold == 0
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_anchor_lifetime_seconds == 0
        || policy.max_anchor_lifetime_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(ExternalAnchorError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        let key_bytes = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(ExternalAnchorError::InvalidPolicy)?;
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| ExternalAnchorError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.is_weak()
            || !keys.insert(key.to_bytes())
        {
            return Err(ExternalAnchorError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_expectation(
    expectation: &ExternalAnchorExpectation,
) -> Result<(), ExternalAnchorError> {
    if expectation.schema != EXTERNAL_ANCHOR_EXPECTATION_SCHEMA
        || !valid_sha256(&expectation.external_anchor_policy_sha256)
        || !valid_id(&expectation.state_identity)
        || !valid_sha256(&expectation.trusted_time_policy_sha256)
        || !valid_sha256(&expectation.remote_cursor_policy_sha256)
        || expectation.generation == 0
        || !valid_sha256(&expectation.boundary_sha256)
    {
        return Err(ExternalAnchorError::InvalidExpectation);
    }
    Ok(())
}

fn map_time_error(_: TrustedTimeError) -> ExternalAnchorError {
    ExternalAnchorError::InvalidDocument
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let raw = value.strip_prefix("0x")?;
    if raw.len() != N * 2 || raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(raw).ok()?.try_into().ok()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_nonce(value: &str) -> bool {
    valid_sha256(value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
