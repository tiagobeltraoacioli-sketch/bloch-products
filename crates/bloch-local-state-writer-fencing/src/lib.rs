//! Offline verification for threshold-signed writer fencing leases.
//!
//! Verification is not leader election, consensus, linearizable issuance or
//! rollback-resistant storage. Those remain mandatory operational controls.

use bloch_trusted_time::VerifiedTrustedTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const WRITER_FENCING_POLICY_SCHEMA: &str = "bloch.products.writer-fencing-policy.v1";
pub const WRITER_FENCING_ENVELOPE_SCHEMA: &str = "bloch.products.writer-fencing-envelope.v1";
pub const WRITER_FENCING_CERTIFICATE_SCHEMA: &str = "bloch.products.writer-fencing-certificate.v1";
pub const MAX_WRITER_FENCING_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_WRITER_FENCING_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_AUTHORITIES: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-WRITER-FENCING-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FencingAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WriterFencingPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub cas_service_id: String,
    pub cas_policy_sha256: String,
    pub trusted_time_policy_sha256: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_lease_lifetime_seconds: u64,
    pub authorities: Vec<FencingAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FencingSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterLeaseParameters<'a> {
    pub writer_id: &'a str,
    pub epoch: u64,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FencingEnvelope {
    schema: String,
    writer_fencing_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    cas_service_id: String,
    cas_policy_sha256: String,
    writer_id: String,
    epoch: u64,
    effective_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FencingCertificate {
    schema: String,
    envelope: FencingEnvelope,
    signatures: Vec<FencingSignature>,
}

/// Non-cloneable authority to write as one writer at one fencing epoch.
#[derive(Debug)]
pub struct VerifiedWriterLease {
    policy_sha256: String,
    certificate_sha256: String,
    state_identity: String,
    remote_cursor_policy_sha256: String,
    cas_service_id: String,
    cas_policy_sha256: String,
    writer_id: String,
    epoch: u64,
    effective_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    deadline_unix_seconds: u64,
    expires_at: Instant,
    authority_ids: Vec<String>,
}

impl VerifiedWriterLease {
    pub fn writer_fencing_policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn cas_service_id(&self) -> &str {
        &self.cas_service_id
    }
    pub fn cas_policy_sha256(&self) -> &str {
        &self.cas_policy_sha256
    }
    pub fn writer_id(&self) -> &str {
        &self.writer_id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn effective_at_unix_seconds(&self) -> u64 {
        self.effective_at_unix_seconds
    }
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    pub fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), WriterFencingError> {
        if self.is_expired() {
            Err(WriterFencingError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
    pub fn leader_election_proven(&self) -> bool {
        false
    }
    pub fn consensus_proven(&self) -> bool {
        false
    }
    pub fn linearizable_issuer_proven(&self) -> bool {
        false
    }
    pub fn floor_persistence_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WriterFencingError {
    #[error("writer-fencing policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("writer-fencing policy pin mismatch")]
    PolicyPinMismatch,
    #[error("writer-fencing certificate is invalid or non-canonical")]
    InvalidCertificate,
    #[error("writer-fencing certificate crosses its pinned audience")]
    AudienceMismatch,
    #[error("trusted time does not match the writer-fencing audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTimeUnavailable,
    #[error("writer-fencing policy is not currently effective")]
    PolicyNotEffective,
    #[error("writer-fencing lease is not currently effective")]
    LeaseNotEffective,
    #[error("writer-fencing capability has expired")]
    ExpiredCapability,
    #[error("writer-fencing epoch does not advance the independent floor")]
    EpochRollback,
    #[error("writer-fencing authority is not trusted")]
    UntrustedAuthority,
    #[error("writer-fencing signature is duplicated")]
    DuplicateSignature,
    #[error("writer-fencing signature is invalid")]
    InvalidSignature,
    #[error("writer-fencing signature threshold is not met")]
    ThresholdNotMet,
}

pub fn writer_fencing_policy_bytes(
    policy: &WriterFencingPolicy,
) -> Result<Vec<u8>, WriterFencingError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| WriterFencingError::InvalidPolicy)?;
    if bytes.len() > MAX_WRITER_FENCING_POLICY_BYTES {
        return Err(WriterFencingError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn writer_fencing_policy_sha256(
    policy: &WriterFencingPolicy,
) -> Result<String, WriterFencingError> {
    Ok(hash(&writer_fencing_policy_bytes(policy)?))
}

pub fn parse_writer_fencing_policy(
    bytes: &[u8],
    expected_pin: &str,
) -> Result<WriterFencingPolicy, WriterFencingError> {
    if bytes.is_empty()
        || bytes.len() > MAX_WRITER_FENCING_POLICY_BYTES
        || !valid_sha256(expected_pin)
    {
        return Err(WriterFencingError::InvalidPolicy);
    }
    let policy: WriterFencingPolicy =
        serde_json::from_slice(bytes).map_err(|_| WriterFencingError::InvalidPolicy)?;
    if writer_fencing_policy_bytes(&policy)? != bytes {
        return Err(WriterFencingError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_pin)?;
    Ok(policy)
}

/// Exact domain-separated bytes every fencing authority signs.
pub fn writer_fencing_signature_message(
    policy: &WriterFencingPolicy,
    expected_policy_sha256: &str,
    parameters: WriterLeaseParameters<'_>,
) -> Result<Vec<u8>, WriterFencingError> {
    let envelope = build_envelope(policy, expected_policy_sha256, parameters)?;
    signing_bytes(&envelope)
}

pub fn create_writer_fencing_certificate(
    policy: &WriterFencingPolicy,
    expected_policy_sha256: &str,
    parameters: WriterLeaseParameters<'_>,
    signatures: Vec<FencingSignature>,
) -> Result<Vec<u8>, WriterFencingError> {
    let envelope = build_envelope(policy, expected_policy_sha256, parameters)?;
    validate_signature_order(&signatures)?;
    verify_signatures(policy, &signing_bytes(&envelope)?, &signatures)?;
    let certificate = FencingCertificate {
        schema: WRITER_FENCING_CERTIFICATE_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes =
        serde_json::to_vec(&certificate).map_err(|_| WriterFencingError::InvalidCertificate)?;
    if bytes.len() > MAX_WRITER_FENCING_CERTIFICATE_BYTES {
        return Err(WriterFencingError::InvalidCertificate);
    }
    Ok(bytes)
}

/// Verifies a newly acquired lease against an independently retained epoch.
/// The supplied floor must come from rollback-resistant storage; this function
/// does not store or advance it.
pub fn verify_successor_writer_lease(
    certificate_bytes: &[u8],
    policy: &WriterFencingPolicy,
    expected_policy_sha256: &str,
    independent_epoch_floor: u64,
    trusted_time: &VerifiedTrustedTime,
) -> Result<VerifiedWriterLease, WriterFencingError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
    {
        return Err(WriterFencingError::TrustedTimeAudienceMismatch);
    }
    let now = trusted_time
        .unix_seconds()
        .map_err(|_| WriterFencingError::TrustedTimeUnavailable)?;
    if now < policy.effective_at_unix_seconds || now >= policy.expires_at_unix_seconds {
        return Err(WriterFencingError::PolicyNotEffective);
    }
    if certificate_bytes.is_empty()
        || certificate_bytes.len() > MAX_WRITER_FENCING_CERTIFICATE_BYTES
    {
        return Err(WriterFencingError::InvalidCertificate);
    }
    let certificate: FencingCertificate = serde_json::from_slice(certificate_bytes)
        .map_err(|_| WriterFencingError::InvalidCertificate)?;
    if serde_json::to_vec(&certificate).map_err(|_| WriterFencingError::InvalidCertificate)?
        != certificate_bytes
        || certificate.schema != WRITER_FENCING_CERTIFICATE_SCHEMA
    {
        return Err(WriterFencingError::InvalidCertificate);
    }
    let envelope = &certificate.envelope;
    if envelope.schema != WRITER_FENCING_ENVELOPE_SCHEMA
        || envelope.writer_fencing_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || envelope.remote_cursor_policy_sha256 != policy.remote_cursor_policy_sha256
        || envelope.cas_service_id != policy.cas_service_id
        || envelope.cas_policy_sha256 != policy.cas_policy_sha256
    {
        return Err(WriterFencingError::AudienceMismatch);
    }
    validate_lease_fields(
        policy,
        &envelope.writer_id,
        envelope.epoch,
        envelope.effective_at_unix_seconds,
        envelope.expires_at_unix_seconds,
    )?;
    if envelope.epoch <= independent_epoch_floor {
        return Err(WriterFencingError::EpochRollback);
    }
    if now < envelope.effective_at_unix_seconds || now >= envelope.expires_at_unix_seconds {
        return Err(WriterFencingError::LeaseNotEffective);
    }
    validate_signature_order(&certificate.signatures)?;
    let message = signing_bytes(envelope)?;
    verify_signatures(policy, &message, &certificate.signatures)?;
    let remaining = envelope.expires_at_unix_seconds - now;
    let trusted_remaining = trusted_time
        .valid_until_unix_seconds()
        .checked_sub(now)
        .ok_or(WriterFencingError::TrustedTimeUnavailable)?;
    let lifetime = remaining.min(trusted_remaining);
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(lifetime))
        .ok_or(WriterFencingError::LeaseNotEffective)?;
    Ok(VerifiedWriterLease {
        policy_sha256: expected_policy_sha256.into(),
        certificate_sha256: hash(certificate_bytes),
        state_identity: envelope.state_identity.clone(),
        remote_cursor_policy_sha256: envelope.remote_cursor_policy_sha256.clone(),
        cas_service_id: envelope.cas_service_id.clone(),
        cas_policy_sha256: envelope.cas_policy_sha256.clone(),
        writer_id: envelope.writer_id.clone(),
        epoch: envelope.epoch,
        effective_at_unix_seconds: envelope.effective_at_unix_seconds,
        expires_at_unix_seconds: envelope.expires_at_unix_seconds,
        deadline_unix_seconds: now + lifetime,
        expires_at,
        authority_ids: certificate
            .signatures
            .iter()
            .map(|s| s.authority_id.clone())
            .collect(),
    })
}

fn build_envelope(
    policy: &WriterFencingPolicy,
    expected_pin: &str,
    parameters: WriterLeaseParameters<'_>,
) -> Result<FencingEnvelope, WriterFencingError> {
    validate_policy_pin(policy, expected_pin)?;
    validate_lease_fields(
        policy,
        parameters.writer_id,
        parameters.epoch,
        parameters.effective_at_unix_seconds,
        parameters.expires_at_unix_seconds,
    )?;
    Ok(FencingEnvelope {
        schema: WRITER_FENCING_ENVELOPE_SCHEMA.into(),
        writer_fencing_policy_sha256: expected_pin.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        remote_cursor_policy_sha256: policy.remote_cursor_policy_sha256.clone(),
        cas_service_id: policy.cas_service_id.clone(),
        cas_policy_sha256: policy.cas_policy_sha256.clone(),
        writer_id: parameters.writer_id.into(),
        epoch: parameters.epoch,
        effective_at_unix_seconds: parameters.effective_at_unix_seconds,
        expires_at_unix_seconds: parameters.expires_at_unix_seconds,
    })
}

fn validate_policy(policy: &WriterFencingPolicy) -> Result<(), WriterFencingError> {
    if policy.schema != WRITER_FENCING_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.state_identity)
        || !valid_sha256(&policy.remote_cursor_policy_sha256)
        || !valid_id(&policy.cas_service_id)
        || !valid_sha256(&policy.cas_policy_sha256)
        || !valid_sha256(&policy.trusted_time_policy_sha256)
        || policy.threshold < 2
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.authorities.len() > MAX_AUTHORITIES
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_lease_lifetime_seconds == 0
        || policy.max_lease_lifetime_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(WriterFencingError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|p| p >= authority.authority_id.as_str())
            || decode_key(&authority.ed25519_public_key).is_err()
            || !keys.insert(&authority.ed25519_public_key)
        {
            return Err(WriterFencingError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &WriterFencingPolicy,
    expected: &str,
) -> Result<(), WriterFencingError> {
    if !valid_sha256(expected) {
        return Err(WriterFencingError::InvalidPolicy);
    }
    if writer_fencing_policy_sha256(policy)? != expected {
        return Err(WriterFencingError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_lease_fields(
    policy: &WriterFencingPolicy,
    writer_id: &str,
    epoch: u64,
    effective: u64,
    expires: u64,
) -> Result<(), WriterFencingError> {
    if !valid_id(writer_id)
        || epoch == 0
        || effective < policy.effective_at_unix_seconds
        || expires > policy.expires_at_unix_seconds
        || effective >= expires
        || expires - effective > policy.max_lease_lifetime_seconds
    {
        return Err(WriterFencingError::InvalidCertificate);
    }
    Ok(())
}

fn validate_signature_order(signatures: &[FencingSignature]) -> Result<(), WriterFencingError> {
    let mut previous: Option<&str> = None;
    for signature in signatures {
        if !valid_id(&signature.authority_id) {
            return Err(WriterFencingError::InvalidCertificate);
        }
        if previous.is_some_and(|p| p == signature.authority_id) {
            return Err(WriterFencingError::DuplicateSignature);
        }
        if previous.is_some_and(|p| p > signature.authority_id.as_str()) {
            return Err(WriterFencingError::InvalidCertificate);
        }
        previous = Some(&signature.authority_id);
    }
    Ok(())
}

fn verify_signatures(
    policy: &WriterFencingPolicy,
    message: &[u8],
    signatures: &[FencingSignature],
) -> Result<(), WriterFencingError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(WriterFencingError::ThresholdNotMet);
    }
    let mut valid = 0usize;
    for signed in signatures {
        let authority = policy
            .authorities
            .binary_search_by(|a| a.authority_id.as_str().cmp(&signed.authority_id))
            .ok()
            .map(|i| &policy.authorities[i])
            .ok_or(WriterFencingError::UntrustedAuthority)?;
        let key = decode_key(&authority.ed25519_public_key)
            .map_err(|_| WriterFencingError::InvalidPolicy)?;
        let signature_bytes =
            decode_fixed::<64>(&signed.signature).ok_or(WriterFencingError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| WriterFencingError::InvalidSignature)?;
        valid += 1;
    }
    if valid < usize::from(policy.threshold) {
        return Err(WriterFencingError::ThresholdNotMet);
    }
    Ok(())
}

fn signing_bytes(envelope: &FencingEnvelope) -> Result<Vec<u8>, WriterFencingError> {
    let encoded =
        serde_json::to_vec(envelope).map_err(|_| WriterFencingError::InvalidCertificate)?;
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + encoded.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    message.extend_from_slice(&encoded);
    Ok(message)
}
fn decode_key(value: &str) -> Result<VerifyingKey, ()> {
    let bytes = decode_fixed::<32>(value).ok_or(())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ())?;
    if key.is_weak() {
        return Err(());
    }
    Ok(key)
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
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
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
