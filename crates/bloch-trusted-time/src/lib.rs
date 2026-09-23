//! Threshold-authenticated, transport-neutral trusted-time tokens.
//!
//! The verifier performs no network or disk I/O and holds no private keys.
//! A successful result proves that the configured threshold signed one
//! canonical, nonce-bound interval. Authority independence, secure boundary
//! persistence and clock accuracy remain operational properties.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::Instant;
use thiserror::Error;

pub const TRUSTED_TIME_POLICY_SCHEMA: &str = "bloch.products.trusted-time-policy.v1";
pub const TRUSTED_TIME_ENVELOPE_SCHEMA: &str = "bloch.products.trusted-time-envelope.v1";
pub const TRUSTED_TIME_TOKEN_SCHEMA: &str = "bloch.products.trusted-time-token.v1";
pub const TRUSTED_TIME_BOUNDARY_SCHEMA: &str = "bloch.products.trusted-time-boundary.v1";
pub const MAX_TRUSTED_TIME_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TRUSTED_TIME_TOKEN_BYTES: usize = 64 * 1024;
const MAX_AUTHORITIES: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-TRUSTED-TIME-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedTimeAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedTimePolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_token_lifetime_seconds: u64,
    pub authorities: Vec<TrustedTimeAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedTimeSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedTimeEnvelope {
    schema: String,
    trusted_time_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    request_nonce: String,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedTimeToken {
    schema: String,
    envelope: TrustedTimeEnvelope,
    signatures: Vec<TrustedTimeSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BoundaryDocument {
    schema: String,
    trusted_time_policy_sha256: String,
    not_before_unix_seconds: u64,
}

/// Canonical rollback floor. Its storage must itself be rollback-resistant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedTimeBoundary(BoundaryDocument);

impl TrustedTimeBoundary {
    pub fn not_before_unix_seconds(&self) -> u64 {
        self.0.not_before_unix_seconds
    }

    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.0.trusted_time_policy_sha256
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustedTimeError> {
        serde_json::to_vec(&self.0).map_err(|_| TrustedTimeError::InvalidBoundary)
    }
}

/// Opaque capability whose time advances only by the process monotonic clock.
#[derive(Debug)]
pub struct VerifiedTrustedTime {
    policy_sha256: String,
    token_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    verified_at: Instant,
    expires_at: Instant,
    authority_ids: Vec<String>,
}

impl VerifiedTrustedTime {
    pub fn unix_seconds(&self) -> Result<u64, TrustedTimeError> {
        if Instant::now() >= self.expires_at {
            return Err(TrustedTimeError::ExpiredCapability);
        }
        let elapsed = self.verified_at.elapsed().as_secs();
        let current = self
            .attested_at_unix_seconds
            .checked_add(elapsed)
            .ok_or(TrustedTimeError::ExpiredCapability)?;
        Ok(current)
    }

    pub fn attested_at_unix_seconds(&self) -> u64 {
        self.attested_at_unix_seconds
    }

    pub fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }

    pub fn trusted_time_policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn token_sha256(&self) -> &str {
        &self.token_sha256
    }

    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }

    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }

    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }

    pub fn rollback_boundary(&self) -> Result<TrustedTimeBoundary, TrustedTimeError> {
        Ok(TrustedTimeBoundary(BoundaryDocument {
            schema: TRUSTED_TIME_BOUNDARY_SCHEMA.into(),
            trusted_time_policy_sha256: self.policy_sha256.clone(),
            not_before_unix_seconds: self.unix_seconds()?,
        }))
    }

    pub fn authority_independence_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustedTimeError {
    #[error("trusted-time policy is invalid")]
    InvalidPolicy,
    #[error("trusted-time policy pin mismatch")]
    PolicyPinMismatch,
    #[error("trusted-time envelope is invalid")]
    InvalidEnvelope,
    #[error("trusted-time token is invalid or non-canonical")]
    InvalidToken,
    #[error("trusted-time nonce does not match")]
    NonceMismatch,
    #[error("trusted-time rollback boundary is invalid or non-canonical")]
    InvalidBoundary,
    #[error("trusted-time token is older than the rollback boundary")]
    RollbackDetected,
    #[error("trusted-time authority is not trusted")]
    UntrustedAuthority,
    #[error("trusted-time signature is invalid")]
    InvalidSignature,
    #[error("trusted-time signature threshold is not met")]
    ThresholdNotMet,
    #[error("trusted-time capability has expired")]
    ExpiredCapability,
}

pub fn trusted_time_policy_bytes(policy: &TrustedTimePolicy) -> Result<Vec<u8>, TrustedTimeError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| TrustedTimeError::InvalidPolicy)?;
    if bytes.len() > MAX_TRUSTED_TIME_POLICY_BYTES {
        return Err(TrustedTimeError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn trusted_time_policy_sha256(policy: &TrustedTimePolicy) -> Result<String, TrustedTimeError> {
    Ok(hash(&trusted_time_policy_bytes(policy)?))
}

pub fn parse_trusted_time_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<TrustedTimePolicy, TrustedTimeError> {
    if bytes.is_empty() || bytes.len() > MAX_TRUSTED_TIME_POLICY_BYTES {
        return Err(TrustedTimeError::InvalidPolicy);
    }
    let policy: TrustedTimePolicy =
        serde_json::from_slice(bytes).map_err(|_| TrustedTimeError::InvalidPolicy)?;
    if trusted_time_policy_bytes(&policy)? != bytes {
        return Err(TrustedTimeError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn parse_trusted_time_boundary(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<TrustedTimeBoundary, TrustedTimeError> {
    let document: BoundaryDocument =
        serde_json::from_slice(bytes).map_err(|_| TrustedTimeError::InvalidBoundary)?;
    if bytes.is_empty()
        || bytes.len() > 1024
        || serde_json::to_vec(&document).map_err(|_| TrustedTimeError::InvalidBoundary)? != bytes
        || document.schema != TRUSTED_TIME_BOUNDARY_SCHEMA
        || document.trusted_time_policy_sha256 != expected_policy_sha256
        || !valid_sha256(expected_policy_sha256)
    {
        return Err(TrustedTimeError::InvalidBoundary);
    }
    Ok(TrustedTimeBoundary(document))
}

/// Exact domain-separated bytes that each time authority signs.
pub fn trusted_time_signature_message(
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
) -> Result<Vec<u8>, TrustedTimeError> {
    signing_bytes(&envelope(
        policy,
        expected_policy_sha256,
        request_nonce,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?)
}

pub fn create_trusted_time_token(
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    signatures: &[TrustedTimeSignature],
) -> Result<Vec<u8>, TrustedTimeError> {
    let envelope = envelope(
        policy,
        expected_policy_sha256,
        request_nonce,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|a, b| a.authority_id.cmp(&b.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let token = TrustedTimeToken {
        schema: TRUSTED_TIME_TOKEN_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes = serde_json::to_vec(&token).map_err(|_| TrustedTimeError::InvalidToken)?;
    if bytes.len() > MAX_TRUSTED_TIME_TOKEN_BYTES {
        return Err(TrustedTimeError::InvalidToken);
    }
    Ok(bytes)
}

pub fn verify_trusted_time_token(
    token_bytes: &[u8],
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
    expected_request_nonce: &str,
    rollback_boundary: Option<&TrustedTimeBoundary>,
) -> Result<VerifiedTrustedTime, TrustedTimeError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if token_bytes.is_empty() || token_bytes.len() > MAX_TRUSTED_TIME_TOKEN_BYTES {
        return Err(TrustedTimeError::InvalidToken);
    }
    let token: TrustedTimeToken =
        serde_json::from_slice(token_bytes).map_err(|_| TrustedTimeError::InvalidToken)?;
    if serde_json::to_vec(&token).map_err(|_| TrustedTimeError::InvalidToken)? != token_bytes
        || token.schema != TRUSTED_TIME_TOKEN_SCHEMA
    {
        return Err(TrustedTimeError::InvalidToken);
    }
    validate_envelope(&token.envelope, policy, expected_policy_sha256)?;
    if !valid_nonce(expected_request_nonce)
        || token.envelope.request_nonce != expected_request_nonce
    {
        return Err(TrustedTimeError::NonceMismatch);
    }
    if let Some(boundary) = rollback_boundary {
        if boundary.trusted_time_policy_sha256() != expected_policy_sha256 {
            return Err(TrustedTimeError::InvalidBoundary);
        }
        if token.envelope.attested_at_unix_seconds < boundary.not_before_unix_seconds() {
            return Err(TrustedTimeError::RollbackDetected);
        }
    }
    let message = signing_bytes(&token.envelope)?;
    verify_signatures(policy, &message, &token.signatures)?;
    let verified_at = Instant::now();
    let lifetime = token
        .envelope
        .valid_until_unix_seconds
        .checked_sub(token.envelope.attested_at_unix_seconds)
        .ok_or(TrustedTimeError::InvalidEnvelope)?;
    let expires_at = verified_at
        .checked_add(std::time::Duration::from_secs(lifetime))
        .ok_or(TrustedTimeError::InvalidEnvelope)?;
    Ok(VerifiedTrustedTime {
        policy_sha256: expected_policy_sha256.into(),
        token_sha256: hash(token_bytes),
        state_identity: token.envelope.state_identity,
        remote_cursor_policy_sha256: token.envelope.remote_cursor_policy_sha256,
        attested_at_unix_seconds: token.envelope.attested_at_unix_seconds,
        valid_until_unix_seconds: token.envelope.valid_until_unix_seconds,
        verified_at,
        expires_at,
        authority_ids: token
            .signatures
            .into_iter()
            .map(|signature| signature.authority_id)
            .collect(),
    })
}

fn envelope(
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    attested_at: u64,
    valid_until: u64,
) -> Result<TrustedTimeEnvelope, TrustedTimeError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if !valid_nonce(request_nonce)
        || attested_at < policy.effective_at_unix_seconds
        || valid_until > policy.expires_at_unix_seconds
        || attested_at >= valid_until
        || valid_until - attested_at > policy.max_token_lifetime_seconds
    {
        return Err(TrustedTimeError::InvalidEnvelope);
    }
    Ok(TrustedTimeEnvelope {
        schema: TRUSTED_TIME_ENVELOPE_SCHEMA.into(),
        trusted_time_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        request_nonce: request_nonce.into(),
        attested_at_unix_seconds: attested_at,
        valid_until_unix_seconds: valid_until,
    })
}

fn validate_envelope(
    envelope: &TrustedTimeEnvelope,
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
) -> Result<(), TrustedTimeError> {
    if envelope.schema != TRUSTED_TIME_ENVELOPE_SCHEMA
        || envelope.trusted_time_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || envelope.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
    {
        return Err(TrustedTimeError::InvalidEnvelope);
    }
    envelope_for_validation(policy, envelope)
}

fn envelope_for_validation(
    policy: &TrustedTimePolicy,
    envelope: &TrustedTimeEnvelope,
) -> Result<(), TrustedTimeError> {
    if !valid_nonce(&envelope.request_nonce)
        || envelope.attested_at_unix_seconds < policy.effective_at_unix_seconds
        || envelope.valid_until_unix_seconds > policy.expires_at_unix_seconds
        || envelope.attested_at_unix_seconds >= envelope.valid_until_unix_seconds
        || envelope.valid_until_unix_seconds - envelope.attested_at_unix_seconds
            > policy.max_token_lifetime_seconds
    {
        return Err(TrustedTimeError::InvalidEnvelope);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &TrustedTimePolicy,
    expected_policy_sha256: &str,
) -> Result<(), TrustedTimeError> {
    if !valid_sha256(expected_policy_sha256)
        || trusted_time_policy_sha256(policy)? != expected_policy_sha256
    {
        return Err(TrustedTimeError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &TrustedTimePolicy) -> Result<(), TrustedTimeError> {
    if policy.schema != TRUSTED_TIME_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || policy.threshold == 0
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_token_lifetime_seconds == 0
        || policy.max_token_lifetime_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(TrustedTimeError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        let bytes = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(TrustedTimeError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| TrustedTimeError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.is_weak()
            || !keys.insert(key.to_bytes())
        {
            return Err(TrustedTimeError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn signing_bytes(envelope: &TrustedTimeEnvelope) -> Result<Vec<u8>, TrustedTimeError> {
    let encoded = serde_json::to_vec(envelope).map_err(|_| TrustedTimeError::InvalidEnvelope)?;
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn verify_signatures(
    policy: &TrustedTimePolicy,
    message: &[u8],
    signatures: &[TrustedTimeSignature],
) -> Result<(), TrustedTimeError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(TrustedTimeError::ThresholdNotMet);
    }
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
        {
            return Err(TrustedTimeError::InvalidToken);
        }
        let authority = policy
            .authorities
            .binary_search_by(|authority| authority.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(TrustedTimeError::UntrustedAuthority)?;
        let key = VerifyingKey::from_bytes(
            &decode_fixed::<32>(&authority.ed25519_public_key)
                .ok_or(TrustedTimeError::InvalidPolicy)?,
        )
        .map_err(|_| TrustedTimeError::InvalidPolicy)?;
        let signature =
            decode_fixed::<64>(&detached.signature).ok_or(TrustedTimeError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| TrustedTimeError::InvalidSignature)?;
        previous = Some(&detached.authority_id);
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

fn valid_nonce(value: &str) -> bool {
    value.len() >= 32
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    value
        .strip_prefix("0x")
        .and_then(|value| hex::decode(value).ok())?
        .try_into()
        .ok()
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
