//! Threshold caller authorization for an exact remote cursor CAS request.
//!
//! This crate performs no network I/O and never handles private keys.  A
//! successful verification returns an opaque capability bound to one canonical
//! CAS request, one caller policy pin, one remote policy pin and one state
//! identity.

use bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest;
use bloch_local_state_remote_cursor_challenge_store::ConsumedCasChallenge;
use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const CALLER_AUTH_POLICY_SCHEMA: &str = "bloch.products.remote-cursor-cas-caller-policy.v1";
pub const CALLER_AUTH_ENVELOPE_SCHEMA: &str =
    "bloch.products.remote-cursor-cas-caller-authorization-envelope.v1";
pub const CALLER_AUTHORIZATION_SCHEMA: &str =
    "bloch.products.remote-cursor-cas-caller-authorization.v1";
pub const MAX_CALLER_AUTH_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_CALLER_AUTHORIZATION_BYTES: usize = 256 * 1024;
const MAX_AUTHORITIES: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-REMOTE-CURSOR-CAS-CALLER-AUTH-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CallerAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CallerAuthorizationPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_authorization_age_seconds: u64,
    pub max_authorization_lifetime_seconds: u64,
    pub authorities: Vec<CallerAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CallerSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthorizationEnvelope {
    schema: String,
    caller_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_sha256: String,
    canonical_request_hex: String,
    authorization_nonce: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Authorization {
    schema: String,
    envelope: AuthorizationEnvelope,
    signatures: Vec<CallerSignature>,
}

/// Opaque proof that a threshold authorized one exact canonical CAS request.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedRemoteCursorCasCallerAuthorization {
    caller_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_sha256: String,
    canonical_request: Vec<u8>,
    authorization_nonce: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    authority_ids: Vec<String>,
    authorization_sha256: String,
    monotonic_deadline: Instant,
}

impl VerifiedRemoteCursorCasCallerAuthorization {
    pub fn caller_policy_sha256(&self) -> &str {
        &self.caller_policy_sha256
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn signature_domain(&self) -> &str {
        &self.signature_domain
    }
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }
    pub fn authorization_nonce(&self) -> &str {
        &self.authorization_nonce
    }
    pub fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn authorization_sha256(&self) -> &str {
        &self.authorization_sha256
    }

    /// Fails closed once the deadline fixed during verification is reached.
    /// No caller-supplied wall-clock value is accepted here.
    pub fn ensure_monotonic_freshness(&self) -> Result<(), CallerAuthorizationError> {
        if Instant::now() >= self.monotonic_deadline {
            Err(CallerAuthorizationError::OutsideFreshnessWindow)
        } else {
            Ok(())
        }
    }
}

/// Linear proof that an authenticated CAS request also consumed its exact
/// server-issued challenge durably.
#[derive(Debug)]
pub struct ReplayProtectedRemoteCursorCasCallerAuthorization {
    authorization: VerifiedRemoteCursorCasCallerAuthorization,
    challenge: ConsumedCasChallenge,
}

impl ReplayProtectedRemoteCursorCasCallerAuthorization {
    pub fn caller_policy_sha256(&self) -> &str {
        self.authorization.caller_policy_sha256()
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        self.authorization.remote_cursor_policy_sha256()
    }
    pub fn state_identity(&self) -> &str {
        self.authorization.state_identity()
    }
    pub fn request_sha256(&self) -> &str {
        self.authorization.request_sha256()
    }
    pub fn canonical_request(&self) -> &[u8] {
        self.authorization.canonical_request()
    }
    pub fn challenge_consumption_sha256(&self) -> &str {
        self.challenge.consumption_sha256()
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), CallerAuthorizationError> {
        self.authorization.ensure_monotonic_freshness()?;
        self.challenge
            .ensure_monotonic_freshness()
            .map_err(|_| CallerAuthorizationError::ChallengeExpired)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CallerAuthorizationError {
    #[error("caller authorization policy is invalid")]
    InvalidPolicy,
    #[error("caller authorization policy pin mismatch")]
    PolicyPinMismatch,
    #[error("caller authorization is invalid or non-canonical")]
    InvalidAuthorization,
    #[error("caller authorization does not bind the expected request")]
    RequestMismatch,
    #[error("trusted-time capability does not bind the authorization audience")]
    TrustedTimeAudienceMismatch,
    #[error("caller authorization nonce does not match")]
    NonceMismatch,
    #[error("consumed challenge does not bind the verified authorization")]
    ChallengeMismatch,
    #[error("consumed challenge monotonic deadline has expired")]
    ChallengeExpired,
    #[error("caller authorization is outside its validity or freshness window")]
    OutsideFreshnessWindow,
    #[error("caller authorization signature threshold is not met")]
    ThresholdNotMet,
    #[error("caller authorization authority is not trusted")]
    UntrustedAuthority,
    #[error("caller authorization signature is invalid")]
    InvalidSignature,
}

pub fn caller_authorization_policy_bytes(
    policy: &CallerAuthorizationPolicy,
) -> Result<Vec<u8>, CallerAuthorizationError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| CallerAuthorizationError::InvalidPolicy)?;
    if bytes.len() > MAX_CALLER_AUTH_POLICY_BYTES {
        return Err(CallerAuthorizationError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn caller_authorization_policy_sha256(
    policy: &CallerAuthorizationPolicy,
) -> Result<String, CallerAuthorizationError> {
    Ok(hash(&caller_authorization_policy_bytes(policy)?))
}

/// Parses canonical policy bytes and verifies the independently configured pin.
pub fn parse_caller_authorization_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<CallerAuthorizationPolicy, CallerAuthorizationError> {
    if bytes.is_empty() || bytes.len() > MAX_CALLER_AUTH_POLICY_BYTES {
        return Err(CallerAuthorizationError::InvalidPolicy);
    }
    let policy: CallerAuthorizationPolicy =
        serde_json::from_slice(bytes).map_err(|_| CallerAuthorizationError::InvalidPolicy)?;
    if caller_authorization_policy_bytes(&policy)? != bytes {
        return Err(CallerAuthorizationError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn caller_authorization_signature_message(
    request: &ValidatedRemoteCursorCasRequest,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
    authorization_nonce: &str,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<Vec<u8>, CallerAuthorizationError> {
    signing_bytes(&envelope(
        request,
        policy,
        expected_policy_sha256,
        authorization_nonce,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
    )?)
}

pub fn create_caller_authorization(
    request: &ValidatedRemoteCursorCasRequest,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
    authorization_nonce: &str,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    signatures: &[CallerSignature],
) -> Result<Vec<u8>, CallerAuthorizationError> {
    let envelope = envelope(
        request,
        policy,
        expected_policy_sha256,
        authorization_nonce,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
    )?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let authorization = Authorization {
        schema: CALLER_AUTHORIZATION_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes = serde_json::to_vec(&authorization)
        .map_err(|_| CallerAuthorizationError::InvalidAuthorization)?;
    if bytes.len() > MAX_CALLER_AUTHORIZATION_BYTES {
        return Err(CallerAuthorizationError::InvalidAuthorization);
    }
    Ok(bytes)
}

/// Compatibility verifier for callers which already possess a qualified wall
/// clock. Production compositions should prefer
/// [`verify_caller_authorization_with_trusted_time`].
pub fn verify_caller_authorization(
    authorization_bytes: &[u8],
    expected_request: &ValidatedRemoteCursorCasRequest,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
    expected_authorization_nonce: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedRemoteCursorCasCallerAuthorization, CallerAuthorizationError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if authorization_bytes.is_empty() || authorization_bytes.len() > MAX_CALLER_AUTHORIZATION_BYTES
    {
        return Err(CallerAuthorizationError::InvalidAuthorization);
    }
    let authorization: Authorization = serde_json::from_slice(authorization_bytes)
        .map_err(|_| CallerAuthorizationError::InvalidAuthorization)?;
    if serde_json::to_vec(&authorization)
        .map_err(|_| CallerAuthorizationError::InvalidAuthorization)?
        != authorization_bytes
        || authorization.schema != CALLER_AUTHORIZATION_SCHEMA
    {
        return Err(CallerAuthorizationError::InvalidAuthorization);
    }
    validate_envelope(&authorization.envelope, policy, expected_policy_sha256)?;
    if !valid_nonce(expected_authorization_nonce)
        || authorization.envelope.authorization_nonce != expected_authorization_nonce
    {
        return Err(CallerAuthorizationError::NonceMismatch);
    }
    if authorization.envelope.request_sha256 != expected_request.request_sha256()
        || authorization.envelope.canonical_request_hex
            != hex::encode(expected_request.canonical_bytes())
        || authorization.envelope.remote_cursor_policy_sha256
            != expected_request.remote_cursor_policy_sha256()
        || authorization.envelope.state_identity != expected_request.state_identity()
    {
        return Err(CallerAuthorizationError::RequestMismatch);
    }
    validate_freshness(&authorization.envelope, policy, evaluated_at_unix_seconds)?;
    let remaining_lifetime = authorization
        .envelope
        .expires_at_unix_seconds
        .checked_sub(evaluated_at_unix_seconds)
        .ok_or(CallerAuthorizationError::OutsideFreshnessWindow)?;
    let elapsed_age = evaluated_at_unix_seconds
        .checked_sub(authorization.envelope.issued_at_unix_seconds)
        .ok_or(CallerAuthorizationError::OutsideFreshnessWindow)?;
    let remaining_age = policy
        .max_authorization_age_seconds
        .checked_sub(elapsed_age)
        .ok_or(CallerAuthorizationError::OutsideFreshnessWindow)?;
    let remaining = remaining_lifetime.min(remaining_age);
    if remaining == 0 {
        return Err(CallerAuthorizationError::OutsideFreshnessWindow);
    }
    let monotonic_deadline = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(CallerAuthorizationError::OutsideFreshnessWindow)?;
    let message = signing_bytes(&authorization.envelope)?;
    verify_signatures(policy, &message, &authorization.signatures)?;
    Ok(VerifiedRemoteCursorCasCallerAuthorization {
        caller_policy_sha256: expected_policy_sha256.into(),
        remote_cursor_policy_sha256: authorization.envelope.remote_cursor_policy_sha256,
        signature_domain: authorization.envelope.signature_domain,
        state_identity: authorization.envelope.state_identity,
        request_sha256: authorization.envelope.request_sha256,
        canonical_request: expected_request.canonical_bytes().to_vec(),
        authorization_nonce: authorization.envelope.authorization_nonce,
        issued_at_unix_seconds: authorization.envelope.issued_at_unix_seconds,
        expires_at_unix_seconds: authorization.envelope.expires_at_unix_seconds,
        authority_ids: authorization
            .signatures
            .into_iter()
            .map(|item| item.authority_id)
            .collect(),
        authorization_sha256: hash(authorization_bytes),
        monotonic_deadline,
    })
}

/// Verifies an authorization using only the time supplied by an opaque,
/// audience-bound trusted-time capability.
///
/// This entry point accepts no operator-provided wall-clock value. The time
/// capability must bind the same state identity and remote-cursor policy as
/// the exact CAS request and caller policy.
pub fn verify_caller_authorization_with_trusted_time(
    authorization_bytes: &[u8],
    expected_request: &ValidatedRemoteCursorCasRequest,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
    expected_authorization_nonce: &str,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedRemoteCursorCasCallerAuthorization, CallerAuthorizationError> {
    if trusted_time.state_identity() != expected_request.state_identity()
        || trusted_time.remote_cursor_policy_sha256()
            != expected_request.remote_cursor_policy_sha256()
        || policy.state_identity != expected_request.state_identity()
        || policy.remote_cursor_policy_sha256 != expected_request.remote_cursor_policy_sha256()
    {
        return Err(CallerAuthorizationError::TrustedTimeAudienceMismatch);
    }
    let evaluated_at = trusted_time
        .unix_seconds()
        .map_err(|_| CallerAuthorizationError::OutsideFreshnessWindow)?;
    verify_caller_authorization(
        authorization_bytes,
        expected_request,
        policy,
        expected_policy_sha256,
        expected_authorization_nonce,
        evaluated_at,
    )
}

/// Consumes both linear capabilities and returns the only authorization type
/// accepted by the reference control plane.
pub fn bind_consumed_challenge(
    authorization: VerifiedRemoteCursorCasCallerAuthorization,
    challenge: ConsumedCasChallenge,
) -> Result<ReplayProtectedRemoteCursorCasCallerAuthorization, CallerAuthorizationError> {
    authorization.ensure_monotonic_freshness()?;
    challenge
        .ensure_monotonic_freshness()
        .map_err(|_| CallerAuthorizationError::ChallengeExpired)?;
    if authorization.authorization_nonce() != challenge.nonce()
        || authorization.caller_policy_sha256() != challenge.caller_policy_sha256()
        || authorization.remote_cursor_policy_sha256() != challenge.remote_cursor_policy_sha256()
        || authorization.state_identity() != challenge.state_identity()
    {
        return Err(CallerAuthorizationError::ChallengeMismatch);
    }
    Ok(ReplayProtectedRemoteCursorCasCallerAuthorization {
        authorization,
        challenge,
    })
}

fn envelope(
    request: &ValidatedRemoteCursorCasRequest,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<AuthorizationEnvelope, CallerAuthorizationError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if request.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
        || request.state_identity() != policy.state_identity
        || !valid_nonce(nonce)
    {
        return Err(CallerAuthorizationError::InvalidAuthorization);
    }
    if issued_at < policy.effective_at_unix_seconds
        || issued_at > policy.expires_at_unix_seconds
        || expires_at < issued_at
        || expires_at > policy.expires_at_unix_seconds
        || expires_at - issued_at > policy.max_authorization_lifetime_seconds
    {
        return Err(CallerAuthorizationError::OutsideFreshnessWindow);
    }
    Ok(AuthorizationEnvelope {
        schema: CALLER_AUTH_ENVELOPE_SCHEMA.into(),
        caller_policy_sha256: expected_policy_sha256.into(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        request_sha256: request.request_sha256().into(),
        canonical_request_hex: hex::encode(request.canonical_bytes()),
        authorization_nonce: nonce.into(),
        issued_at_unix_seconds: issued_at,
        expires_at_unix_seconds: expires_at,
    })
}

fn validate_envelope(
    envelope: &AuthorizationEnvelope,
    policy: &CallerAuthorizationPolicy,
    expected_policy_sha256: &str,
) -> Result<(), CallerAuthorizationError> {
    if envelope.schema != CALLER_AUTH_ENVELOPE_SCHEMA
        || envelope.caller_policy_sha256 != expected_policy_sha256
        || envelope.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || !valid_sha256(&envelope.request_sha256)
        || !valid_nonce(&envelope.authorization_nonce)
        || envelope.canonical_request_hex.is_empty()
        || envelope.canonical_request_hex.len() > 2 * 64 * 1024
        || hex::decode(&envelope.canonical_request_hex).is_err()
    {
        return Err(CallerAuthorizationError::InvalidAuthorization);
    }
    if envelope.issued_at_unix_seconds < policy.effective_at_unix_seconds
        || envelope.issued_at_unix_seconds > policy.expires_at_unix_seconds
        || envelope.expires_at_unix_seconds < envelope.issued_at_unix_seconds
        || envelope.expires_at_unix_seconds > policy.expires_at_unix_seconds
        || envelope.expires_at_unix_seconds - envelope.issued_at_unix_seconds
            > policy.max_authorization_lifetime_seconds
    {
        return Err(CallerAuthorizationError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn validate_freshness(
    envelope: &AuthorizationEnvelope,
    policy: &CallerAuthorizationPolicy,
    now: u64,
) -> Result<(), CallerAuthorizationError> {
    if now < envelope.issued_at_unix_seconds
        || now >= envelope.expires_at_unix_seconds
        || now - envelope.issued_at_unix_seconds >= policy.max_authorization_age_seconds
    {
        return Err(CallerAuthorizationError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn signing_bytes(envelope: &AuthorizationEnvelope) -> Result<Vec<u8>, CallerAuthorizationError> {
    let bytes =
        serde_json::to_vec(envelope).map_err(|_| CallerAuthorizationError::InvalidAuthorization)?;
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + bytes.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&bytes);
    Ok(message)
}

fn verify_signatures(
    policy: &CallerAuthorizationPolicy,
    message: &[u8],
    signatures: &[CallerSignature],
) -> Result<(), CallerAuthorizationError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(CallerAuthorizationError::ThresholdNotMet);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
            || !seen.insert(detached.authority_id.as_str())
        {
            return Err(CallerAuthorizationError::InvalidAuthorization);
        }
        let authority = policy
            .authorities
            .binary_search_by(|item| item.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(CallerAuthorizationError::UntrustedAuthority)?;
        let key: [u8; 32] = decode_fixed(&authority.ed25519_public_key)
            .ok_or(CallerAuthorizationError::InvalidPolicy)?;
        let key =
            VerifyingKey::from_bytes(&key).map_err(|_| CallerAuthorizationError::InvalidPolicy)?;
        let signature: [u8; 64] =
            decode_fixed(&detached.signature).ok_or(CallerAuthorizationError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| CallerAuthorizationError::InvalidSignature)?;
        previous = Some(&detached.authority_id);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &CallerAuthorizationPolicy,
    expected: &str,
) -> Result<(), CallerAuthorizationError> {
    validate_policy(policy)?;
    if !valid_sha256(expected) || caller_authorization_policy_sha256(policy)? != expected {
        return Err(CallerAuthorizationError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &CallerAuthorizationPolicy) -> Result<(), CallerAuthorizationError> {
    if policy.schema != CALLER_AUTH_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || policy.threshold == 0
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_authorization_age_seconds == 0
        || policy.max_authorization_lifetime_seconds == 0
    {
        return Err(CallerAuthorizationError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    for authority in &policy.authorities {
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .and_then(|key| VerifyingKey::from_bytes(&key).ok());
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.as_ref().is_none_or(VerifyingKey::is_weak)
            || !public_keys.insert(authority.ed25519_public_key.as_str())
        {
            return Err(CallerAuthorizationError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
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
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_sha256(value: &str) -> bool {
    valid_nonce(value)
}
