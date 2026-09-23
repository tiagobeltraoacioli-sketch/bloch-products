//! Threshold-authenticated evidence for one exact TLS transport exchange.
//!
//! This crate verifies claims made by configured transport attestors. It does
//! not open sockets, perform TLS, inspect a live handshake, or prove that the
//! attestors are independent.

use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const TRANSPORT_POLICY_SCHEMA: &str = "bloch.products.authenticated-transport-policy.v1";
pub const TRANSPORT_EVIDENCE_ENVELOPE_SCHEMA: &str =
    "bloch.products.authenticated-transport-evidence-envelope.v1";
pub const TRANSPORT_EVIDENCE_SCHEMA: &str = "bloch.products.authenticated-transport-evidence.v1";
pub const MAX_TRANSPORT_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TRANSPORT_EVIDENCE_BYTES: usize = 128 * 1024;
const MAX_AUTHORITIES: usize = 16;
const MAX_PINS: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-AUTHENTICATED-TRANSPORT-EVIDENCE-V1\0";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TransportPurpose {
    TrustedTime,
    RemoteCursor,
    RemoteCursorCas,
    ExternalTimeAnchor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransportAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticatedTransportPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub service_id: String,
    pub purpose: TransportPurpose,
    pub state_identity: String,
    pub trusted_time_policy_sha256: String,
    pub remote_cursor_policy_sha256: String,
    pub endpoint_dns_name: String,
    pub endpoint_port: u16,
    pub tls_version: String,
    pub alpn: String,
    pub allowed_cipher_suites: Vec<String>,
    pub server_spki_sha256: Vec<String>,
    pub client_spki_sha256: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_evidence_age_seconds: u64,
    pub max_round_trip_millis: u64,
    pub max_response_bytes: u64,
    pub authorities: Vec<TransportAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransportEvidenceSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TransportEvidenceEnvelope {
    schema: String,
    transport_policy_sha256: String,
    signature_domain: String,
    service_id: String,
    purpose: TransportPurpose,
    state_identity: String,
    trusted_time_policy_sha256: String,
    remote_cursor_policy_sha256: String,
    endpoint_dns_name: String,
    endpoint_port: u16,
    tls_version: String,
    alpn: String,
    cipher_suite: String,
    server_spki_sha256: String,
    client_spki_sha256: String,
    request_nonce: String,
    request_sha256: String,
    response_sha256: String,
    response_bytes: u64,
    round_trip_millis: u64,
    observed_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TransportEvidenceDocument {
    schema: String,
    envelope: TransportEvidenceEnvelope,
    signatures: Vec<TransportEvidenceSignature>,
}

#[derive(Clone, Copy, Debug)]
pub struct TransportEvidenceParameters<'a> {
    pub request_nonce: &'a str,
    pub request_sha256: &'a str,
    pub response_sha256: &'a str,
    pub response_bytes: u64,
    pub round_trip_millis: u64,
    pub observed_at_unix_seconds: u64,
    pub cipher_suite: &'a str,
    pub server_spki_sha256: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct TransportEvidenceExpectation<'a> {
    pub purpose: TransportPurpose,
    pub request_nonce: &'a str,
    pub request_sha256: &'a str,
    pub response_sha256: &'a str,
    pub response_bytes: u64,
}

/// Opaque proof that configured attestors authenticated one exact exchange.
#[derive(Debug)]
pub struct VerifiedAuthenticatedTransportEvidence {
    policy_sha256: String,
    service_id: String,
    purpose: TransportPurpose,
    request_sha256: String,
    response_sha256: String,
    evidence_sha256: String,
    authority_ids: Vec<String>,
    monotonic_deadline: Instant,
}

impl VerifiedAuthenticatedTransportEvidence {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn service_id(&self) -> &str {
        &self.service_id
    }
    pub fn purpose(&self) -> TransportPurpose {
        self.purpose
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn response_sha256(&self) -> &str {
        &self.response_sha256
    }
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), TransportEvidenceError> {
        if Instant::now() >= self.monotonic_deadline {
            Err(TransportEvidenceError::OutsideValidityWindow)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportEvidenceError {
    #[error("authenticated transport policy is invalid")]
    InvalidPolicy,
    #[error("authenticated transport policy pin mismatch")]
    PolicyPinMismatch,
    #[error("authenticated transport evidence is invalid or non-canonical")]
    InvalidEvidence,
    #[error("authenticated transport evidence does not bind the expected exchange")]
    ExchangeMismatch,
    #[error("authenticated transport evidence audience does not match trusted time")]
    AudienceMismatch,
    #[error("authenticated transport evidence is outside its validity window")]
    OutsideValidityWindow,
    #[error("authenticated transport evidence signature threshold is not met")]
    ThresholdNotMet,
    #[error("authenticated transport evidence authority is not trusted")]
    UntrustedAuthority,
    #[error("authenticated transport evidence signature is invalid")]
    InvalidSignature,
}

pub fn authenticated_transport_policy_bytes(
    policy: &AuthenticatedTransportPolicy,
) -> Result<Vec<u8>, TransportEvidenceError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| TransportEvidenceError::InvalidPolicy)?;
    if bytes.len() > MAX_TRANSPORT_POLICY_BYTES {
        return Err(TransportEvidenceError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn authenticated_transport_policy_sha256(
    policy: &AuthenticatedTransportPolicy,
) -> Result<String, TransportEvidenceError> {
    Ok(hash(&authenticated_transport_policy_bytes(policy)?))
}

pub fn parse_authenticated_transport_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<AuthenticatedTransportPolicy, TransportEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSPORT_POLICY_BYTES {
        return Err(TransportEvidenceError::InvalidPolicy);
    }
    let policy: AuthenticatedTransportPolicy =
        serde_json::from_slice(bytes).map_err(|_| TransportEvidenceError::InvalidPolicy)?;
    if authenticated_transport_policy_bytes(&policy)? != bytes {
        return Err(TransportEvidenceError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn transport_evidence_signature_message(
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
    parameters: TransportEvidenceParameters<'_>,
) -> Result<Vec<u8>, TransportEvidenceError> {
    signing_bytes(&envelope(policy, expected_policy_sha256, parameters)?)
}

pub fn create_authenticated_transport_evidence(
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
    parameters: TransportEvidenceParameters<'_>,
    signatures: &[TransportEvidenceSignature],
) -> Result<Vec<u8>, TransportEvidenceError> {
    let envelope = envelope(policy, expected_policy_sha256, parameters)?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let document = TransportEvidenceDocument {
        schema: TRANSPORT_EVIDENCE_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes =
        serde_json::to_vec(&document).map_err(|_| TransportEvidenceError::InvalidEvidence)?;
    if bytes.len() > MAX_TRANSPORT_EVIDENCE_BYTES {
        return Err(TransportEvidenceError::InvalidEvidence);
    }
    Ok(bytes)
}

pub fn verify_authenticated_transport_evidence(
    evidence_bytes: &[u8],
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
    expectation: TransportEvidenceExpectation<'_>,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedAuthenticatedTransportEvidence, TransportEvidenceError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if evidence_bytes.is_empty() || evidence_bytes.len() > MAX_TRANSPORT_EVIDENCE_BYTES {
        return Err(TransportEvidenceError::InvalidEvidence);
    }
    let document: TransportEvidenceDocument = serde_json::from_slice(evidence_bytes)
        .map_err(|_| TransportEvidenceError::InvalidEvidence)?;
    if serde_json::to_vec(&document).map_err(|_| TransportEvidenceError::InvalidEvidence)?
        != evidence_bytes
        || document.schema != TRANSPORT_EVIDENCE_SCHEMA
    {
        return Err(TransportEvidenceError::InvalidEvidence);
    }
    validate_envelope(&document.envelope, policy, expected_policy_sha256)?;
    if expectation.purpose != policy.purpose
        || !valid_sha256(expectation.request_nonce)
        || !valid_sha256(expectation.request_sha256)
        || !valid_sha256(expectation.response_sha256)
        || document.envelope.request_nonce != expectation.request_nonce
        || document.envelope.request_sha256 != expectation.request_sha256
        || document.envelope.response_sha256 != expectation.response_sha256
        || document.envelope.response_bytes != expectation.response_bytes
    {
        return Err(TransportEvidenceError::ExchangeMismatch);
    }
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
    {
        return Err(TransportEvidenceError::AudienceMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| TransportEvidenceError::OutsideValidityWindow)?;
    if now < policy.effective_at_unix_seconds
        || now >= policy.expires_at_unix_seconds
        || now < document.envelope.observed_at_unix_seconds
    {
        return Err(TransportEvidenceError::OutsideValidityWindow);
    }
    let age = now - document.envelope.observed_at_unix_seconds;
    if age >= policy.max_evidence_age_seconds {
        return Err(TransportEvidenceError::OutsideValidityWindow);
    }
    let remaining_age = policy.max_evidence_age_seconds - age;
    let remaining_policy = policy.expires_at_unix_seconds - now;
    let remaining_time = trusted_time
        .valid_until_unix_seconds()
        .checked_sub(now)
        .ok_or(TransportEvidenceError::OutsideValidityWindow)?;
    let remaining = remaining_age.min(remaining_policy).min(remaining_time);
    if remaining == 0 {
        return Err(TransportEvidenceError::OutsideValidityWindow);
    }
    let message = signing_bytes(&document.envelope)?;
    verify_signatures(policy, &message, &document.signatures)?;
    let monotonic_deadline = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(TransportEvidenceError::OutsideValidityWindow)?;
    Ok(VerifiedAuthenticatedTransportEvidence {
        policy_sha256: expected_policy_sha256.into(),
        service_id: policy.service_id.clone(),
        purpose: policy.purpose,
        request_sha256: document.envelope.request_sha256,
        response_sha256: document.envelope.response_sha256,
        evidence_sha256: hash(evidence_bytes),
        authority_ids: document
            .signatures
            .into_iter()
            .map(|item| item.authority_id)
            .collect(),
        monotonic_deadline,
    })
}

fn envelope(
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
    parameters: TransportEvidenceParameters<'_>,
) -> Result<TransportEvidenceEnvelope, TransportEvidenceError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if !valid_sha256(parameters.request_nonce)
        || !valid_sha256(parameters.request_sha256)
        || !valid_sha256(parameters.response_sha256)
        || !valid_sha256(parameters.server_spki_sha256)
        || parameters.response_bytes > policy.max_response_bytes
        || parameters.round_trip_millis == 0
        || parameters.round_trip_millis > policy.max_round_trip_millis
        || parameters.observed_at_unix_seconds < policy.effective_at_unix_seconds
        || parameters.observed_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy
            .allowed_cipher_suites
            .binary_search_by(|item| item.as_str().cmp(parameters.cipher_suite))
            .is_err()
        || policy
            .server_spki_sha256
            .binary_search_by(|item| item.as_str().cmp(parameters.server_spki_sha256))
            .is_err()
    {
        return Err(TransportEvidenceError::InvalidEvidence);
    }
    Ok(TransportEvidenceEnvelope {
        schema: TRANSPORT_EVIDENCE_ENVELOPE_SCHEMA.into(),
        transport_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        service_id: policy.service_id.clone(),
        purpose: policy.purpose,
        state_identity: policy.state_identity.clone(),
        trusted_time_policy_sha256: policy.trusted_time_policy_sha256.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        endpoint_dns_name: policy.endpoint_dns_name.clone(),
        endpoint_port: policy.endpoint_port,
        tls_version: policy.tls_version.clone(),
        alpn: policy.alpn.clone(),
        cipher_suite: parameters.cipher_suite.into(),
        server_spki_sha256: parameters.server_spki_sha256.into(),
        client_spki_sha256: policy.client_spki_sha256.clone(),
        request_nonce: parameters.request_nonce.into(),
        request_sha256: parameters.request_sha256.into(),
        response_sha256: parameters.response_sha256.into(),
        response_bytes: parameters.response_bytes,
        round_trip_millis: parameters.round_trip_millis,
        observed_at_unix_seconds: parameters.observed_at_unix_seconds,
    })
}

fn validate_envelope(
    envelope: &TransportEvidenceEnvelope,
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
) -> Result<(), TransportEvidenceError> {
    if envelope.schema != TRANSPORT_EVIDENCE_ENVELOPE_SCHEMA
        || envelope.transport_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.service_id != policy.service_id
        || envelope.purpose != policy.purpose
        || envelope.state_identity != policy.state_identity
        || envelope.trusted_time_policy_sha256 != policy.trusted_time_policy_sha256
        || envelope.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || envelope.endpoint_dns_name != policy.endpoint_dns_name
        || envelope.endpoint_port != policy.endpoint_port
        || envelope.tls_version != policy.tls_version
        || envelope.alpn != policy.alpn
        || envelope.client_spki_sha256 != policy.client_spki_sha256
        || !valid_sha256(&envelope.request_nonce)
        || !valid_sha256(&envelope.request_sha256)
        || !valid_sha256(&envelope.response_sha256)
        || envelope.response_bytes > policy.max_response_bytes
        || envelope.round_trip_millis == 0
        || envelope.round_trip_millis > policy.max_round_trip_millis
        || envelope.observed_at_unix_seconds < policy.effective_at_unix_seconds
        || envelope.observed_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy
            .allowed_cipher_suites
            .binary_search(&envelope.cipher_suite)
            .is_err()
        || policy
            .server_spki_sha256
            .binary_search(&envelope.server_spki_sha256)
            .is_err()
    {
        return Err(TransportEvidenceError::InvalidEvidence);
    }
    Ok(())
}

fn signing_bytes(envelope: &TransportEvidenceEnvelope) -> Result<Vec<u8>, TransportEvidenceError> {
    let encoded =
        serde_json::to_vec(envelope).map_err(|_| TransportEvidenceError::InvalidEvidence)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn verify_signatures(
    policy: &AuthenticatedTransportPolicy,
    message: &[u8],
    signatures: &[TransportEvidenceSignature],
) -> Result<(), TransportEvidenceError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(TransportEvidenceError::ThresholdNotMet);
    }
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
        {
            return Err(TransportEvidenceError::InvalidEvidence);
        }
        let authority = policy
            .authorities
            .binary_search_by(|item| item.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(TransportEvidenceError::UntrustedAuthority)?;
        let key = VerifyingKey::from_bytes(
            &decode_fixed::<32>(&authority.ed25519_public_key)
                .ok_or(TransportEvidenceError::InvalidPolicy)?,
        )
        .map_err(|_| TransportEvidenceError::InvalidPolicy)?;
        let signature = decode_fixed::<64>(&detached.signature)
            .ok_or(TransportEvidenceError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| TransportEvidenceError::InvalidSignature)?;
        previous = Some(&detached.authority_id);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &AuthenticatedTransportPolicy,
    expected: &str,
) -> Result<(), TransportEvidenceError> {
    validate_policy(policy)?;
    if !valid_sha256(expected) || authenticated_transport_policy_sha256(policy)? != expected {
        return Err(TransportEvidenceError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &AuthenticatedTransportPolicy) -> Result<(), TransportEvidenceError> {
    if policy.schema != TRANSPORT_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.service_id)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || !valid_dns_name(&policy.endpoint_dns_name)
        || policy.endpoint_port == 0
        || policy.tls_version != "TLSv1.3"
        || !valid_token(&policy.alpn)
        || policy.allowed_cipher_suites.is_empty()
        || policy.allowed_cipher_suites.len() > MAX_PINS
        || policy.server_spki_sha256.is_empty()
        || policy.server_spki_sha256.len() > MAX_PINS
        || !valid_sha256(&policy.client_spki_sha256)
        || policy.threshold == 0
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_evidence_age_seconds == 0
        || policy.max_round_trip_millis == 0
        || policy.max_response_bytes == 0
    {
        return Err(TransportEvidenceError::InvalidPolicy);
    }
    validate_sorted_unique(&policy.allowed_cipher_suites, valid_token)?;
    validate_sorted_unique(&policy.server_spki_sha256, valid_sha256)?;
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        let raw = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(TransportEvidenceError::InvalidPolicy)?;
        let key =
            VerifyingKey::from_bytes(&raw).map_err(|_| TransportEvidenceError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.is_weak()
            || !keys.insert(key.to_bytes())
        {
            return Err(TransportEvidenceError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_sorted_unique<F>(values: &[String], valid: F) -> Result<(), TransportEvidenceError>
where
    F: Fn(&str) -> bool,
{
    let mut previous: Option<&str> = None;
    for value in values {
        if !valid(value) || previous.is_some_and(|item| item >= value.as_str()) {
            return Err(TransportEvidenceError::InvalidPolicy);
        }
        previous = Some(value);
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}
