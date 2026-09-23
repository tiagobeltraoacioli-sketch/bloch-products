//! Authenticated observations of a cursor held by an external control plane.
//!
//! This crate defines and verifies an offline protocol. It performs no network
//! I/O, stores nothing, receives no private key and does not prove that an
//! authority, service or storage system is independent or highly available.

use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

mod cas;
pub use cas::*;

pub const REMOTE_CURSOR_POLICY_SCHEMA: &str = "bloch.products.remote-monotonic-cursor-policy.v1";
pub const REMOTE_CURSOR_ENVELOPE_SCHEMA: &str =
    "bloch.products.remote-monotonic-cursor-envelope.v1";
pub const REMOTE_CURSOR_OBSERVATION_SCHEMA: &str =
    "bloch.products.remote-monotonic-cursor-observation.v1";
pub const MAX_REMOTE_CURSOR_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_REMOTE_CURSOR_OBSERVATION_BYTES: usize = 64 * 1024;
const MAX_AUTHORITIES: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-REMOTE-MONOTONIC-CURSOR-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteCursorAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteCursorPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub state_identity: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_observation_age_seconds: u64,
    pub authorities: Vec<RemoteCursorAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteCursorSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteCursorEnvelope {
    schema: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_nonce: String,
    observed_at_unix_seconds: u64,
    cursor_sha256: String,
    cursor: CheckpointCursor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteCursorObservation {
    schema: String,
    envelope: RemoteCursorEnvelope,
    signatures: Vec<RemoteCursorSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteCursor {
    cursor: CheckpointCursor,
    remote_cursor_policy_sha256: String,
    observation_sha256: String,
    observed_at_unix_seconds: u64,
    authority_ids: Vec<String>,
}

impl VerifiedRemoteCursor {
    /// Exact authenticated cursor suitable as the independent expectation for
    /// local startup admission. Independence remains an operational property.
    pub fn cursor(&self) -> &CheckpointCursor {
        &self.cursor
    }
    pub fn remote_cursor_policy_sha256(&self) -> &str {
        &self.remote_cursor_policy_sha256
    }
    pub fn observation_sha256(&self) -> &str {
        &self.observation_sha256
    }
    pub fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn authority_independence_proven(&self) -> bool {
        false
    }
    pub fn remote_monotonicity_proven(&self) -> bool {
        false
    }
    pub fn high_availability_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteCursorError {
    #[error("remote cursor trust policy is invalid")]
    InvalidPolicy,
    #[error("remote cursor trust policy pin mismatch")]
    PolicyPinMismatch,
    #[error("remote cursor envelope is invalid")]
    InvalidEnvelope,
    #[error("remote cursor observation is invalid or non-canonical")]
    InvalidObservation,
    #[error("remote cursor request nonce does not match")]
    NonceMismatch,
    #[error("remote cursor observation is outside the validity or freshness window")]
    OutsideFreshnessWindow,
    #[error("remote cursor authority is not trusted")]
    UntrustedAuthority,
    #[error("remote cursor signature is invalid")]
    InvalidSignature,
    #[error("remote cursor signature threshold is not met")]
    ThresholdNotMet,
}

pub fn remote_cursor_policy_bytes(
    policy: &RemoteCursorPolicy,
) -> Result<Vec<u8>, RemoteCursorError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| RemoteCursorError::InvalidPolicy)?;
    if bytes.len() > MAX_REMOTE_CURSOR_POLICY_BYTES {
        return Err(RemoteCursorError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn remote_cursor_policy_sha256(
    policy: &RemoteCursorPolicy,
) -> Result<String, RemoteCursorError> {
    Ok(hash(&remote_cursor_policy_bytes(policy)?))
}

pub fn parse_remote_cursor_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<RemoteCursorPolicy, RemoteCursorError> {
    if bytes.is_empty()
        || bytes.len() > MAX_REMOTE_CURSOR_POLICY_BYTES
        || !valid_sha256(expected_policy_sha256)
    {
        return Err(RemoteCursorError::InvalidPolicy);
    }
    let policy: RemoteCursorPolicy =
        serde_json::from_slice(bytes).map_err(|_| RemoteCursorError::InvalidPolicy)?;
    if remote_cursor_policy_bytes(&policy)? != bytes {
        return Err(RemoteCursorError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

/// Exact domain-separated bytes every external cursor authority signs.
pub fn remote_cursor_signature_message(
    cursor: &CheckpointCursor,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    observed_at_unix_seconds: u64,
) -> Result<Vec<u8>, RemoteCursorError> {
    signing_bytes(&envelope(
        cursor,
        policy,
        expected_policy_sha256,
        request_nonce,
        observed_at_unix_seconds,
    )?)
}

/// Assembles a canonical response after checking the complete signature set.
pub fn create_remote_cursor_observation(
    cursor: &CheckpointCursor,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    observed_at_unix_seconds: u64,
    signatures: &[RemoteCursorSignature],
) -> Result<Vec<u8>, RemoteCursorError> {
    let envelope = envelope(
        cursor,
        policy,
        expected_policy_sha256,
        request_nonce,
        observed_at_unix_seconds,
    )?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let observation = RemoteCursorObservation {
        schema: REMOTE_CURSOR_OBSERVATION_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes =
        serde_json::to_vec(&observation).map_err(|_| RemoteCursorError::InvalidObservation)?;
    if bytes.len() > MAX_REMOTE_CURSOR_OBSERVATION_BYTES {
        return Err(RemoteCursorError::InvalidObservation);
    }
    Ok(bytes)
}

/// Verifies a fresh response against a nonce generated by the fetch caller.
pub fn verify_remote_cursor_observation(
    observation_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    expected_request_nonce: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedRemoteCursor, RemoteCursorError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if observation_bytes.is_empty() || observation_bytes.len() > MAX_REMOTE_CURSOR_OBSERVATION_BYTES
    {
        return Err(RemoteCursorError::InvalidObservation);
    }
    let observation: RemoteCursorObservation = serde_json::from_slice(observation_bytes)
        .map_err(|_| RemoteCursorError::InvalidObservation)?;
    if serde_json::to_vec(&observation).map_err(|_| RemoteCursorError::InvalidObservation)?
        != observation_bytes
        || observation.schema != REMOTE_CURSOR_OBSERVATION_SCHEMA
    {
        return Err(RemoteCursorError::InvalidObservation);
    }
    validate_envelope(&observation.envelope, policy, expected_policy_sha256)?;
    if !valid_nonce(expected_request_nonce)
        || observation.envelope.request_nonce != expected_request_nonce
    {
        return Err(RemoteCursorError::NonceMismatch);
    }
    validate_freshness(
        policy,
        observation.envelope.observed_at_unix_seconds,
        evaluated_at_unix_seconds,
    )?;
    let message = signing_bytes(&observation.envelope)?;
    verify_signatures(policy, &message, &observation.signatures)?;
    Ok(VerifiedRemoteCursor {
        cursor: observation.envelope.cursor,
        remote_cursor_policy_sha256: expected_policy_sha256.into(),
        observation_sha256: hash(observation_bytes),
        observed_at_unix_seconds: observation.envelope.observed_at_unix_seconds,
        authority_ids: observation
            .signatures
            .into_iter()
            .map(|signature| signature.authority_id)
            .collect(),
    })
}

fn envelope(
    cursor: &CheckpointCursor,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    request_nonce: &str,
    observed_at_unix_seconds: u64,
) -> Result<RemoteCursorEnvelope, RemoteCursorError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_issue_time(policy, observed_at_unix_seconds)?;
    if cursor.state_identity() != policy.state_identity || !valid_nonce(request_nonce) {
        return Err(RemoteCursorError::InvalidEnvelope);
    }
    let cursor_bytes = cursor
        .canonical_bytes()
        .map_err(|_| RemoteCursorError::InvalidEnvelope)?;
    let envelope = RemoteCursorEnvelope {
        schema: REMOTE_CURSOR_ENVELOPE_SCHEMA.into(),
        remote_cursor_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        request_nonce: request_nonce.into(),
        observed_at_unix_seconds,
        cursor_sha256: hash(&cursor_bytes),
        cursor: cursor.clone(),
    };
    validate_envelope(&envelope, policy, expected_policy_sha256)?;
    Ok(envelope)
}

fn validate_envelope(
    envelope: &RemoteCursorEnvelope,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<(), RemoteCursorError> {
    if envelope.schema != REMOTE_CURSOR_ENVELOPE_SCHEMA
        || envelope.remote_cursor_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || envelope.cursor.state_identity() != policy.state_identity
        || !valid_nonce(&envelope.request_nonce)
        || !valid_sha256(&envelope.cursor_sha256)
    {
        return Err(RemoteCursorError::InvalidEnvelope);
    }
    let cursor_bytes = envelope
        .cursor
        .canonical_bytes()
        .map_err(|_| RemoteCursorError::InvalidEnvelope)?;
    parse_cursor(&cursor_bytes).map_err(|_| RemoteCursorError::InvalidEnvelope)?;
    if hash(&cursor_bytes) != envelope.cursor_sha256 {
        return Err(RemoteCursorError::InvalidEnvelope);
    }
    validate_issue_time(policy, envelope.observed_at_unix_seconds)
}

fn validate_policy_pin(
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<(), RemoteCursorError> {
    if !valid_sha256(expected_policy_sha256)
        || remote_cursor_policy_sha256(policy)? != expected_policy_sha256
    {
        return Err(RemoteCursorError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &RemoteCursorPolicy) -> Result<(), RemoteCursorError> {
    if policy.schema != REMOTE_CURSOR_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.state_identity)
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || usize::from(policy.threshold) == 0
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_observation_age_seconds == 0
        || policy.max_observation_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(RemoteCursorError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    for authority in &policy.authorities {
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(RemoteCursorError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| RemoteCursorError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.is_weak()
            || !public_keys.insert(key.to_bytes())
        {
            return Err(RemoteCursorError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_issue_time(
    policy: &RemoteCursorPolicy,
    observed_at: u64,
) -> Result<(), RemoteCursorError> {
    if observed_at < policy.effective_at_unix_seconds
        || observed_at > policy.expires_at_unix_seconds
    {
        return Err(RemoteCursorError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn validate_freshness(
    policy: &RemoteCursorPolicy,
    observed_at: u64,
    evaluated_at: u64,
) -> Result<(), RemoteCursorError> {
    validate_issue_time(policy, observed_at)?;
    if evaluated_at < observed_at
        || evaluated_at > policy.expires_at_unix_seconds
        || evaluated_at - observed_at > policy.max_observation_age_seconds
    {
        return Err(RemoteCursorError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn signing_bytes(envelope: &RemoteCursorEnvelope) -> Result<Vec<u8>, RemoteCursorError> {
    let envelope = serde_json::to_vec(envelope).map_err(|_| RemoteCursorError::InvalidEnvelope)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + envelope.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(envelope.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&envelope);
    Ok(bytes)
}

fn verify_signatures(
    policy: &RemoteCursorPolicy,
    message: &[u8],
    signatures: &[RemoteCursorSignature],
) -> Result<(), RemoteCursorError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(RemoteCursorError::ThresholdNotMet);
    }
    let mut previous: Option<&str> = None;
    let mut seen = BTreeSet::new();
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
            || !seen.insert(detached.authority_id.as_str())
        {
            return Err(RemoteCursorError::InvalidObservation);
        }
        let authority = policy
            .authorities
            .binary_search_by(|authority| authority.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(RemoteCursorError::UntrustedAuthority)?;
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(RemoteCursorError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| RemoteCursorError::InvalidPolicy)?;
        let signature =
            decode_fixed::<64>(&detached.signature).ok_or(RemoteCursorError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| RemoteCursorError::InvalidSignature)?;
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
    let bytes = value
        .strip_prefix("0x")
        .and_then(|value| hex::decode(value).ok())?;
    bytes.try_into().ok()
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NONCE: &str = "fetch_nonce_0123456789abcdef0123456789abcdef";

    fn cursor(identity: &str) -> CheckpointCursor {
        let h = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
        let bytes = format!(
            "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{identity}\",\"generation\":7,\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
            h(1),
            h(2),
            h(3),
            h(4),
            h(5)
        );
        parse_cursor(bytes.as_bytes()).unwrap()
    }

    fn policy() -> (RemoteCursorPolicy, Vec<SigningKey>, String) {
        let keys = vec![
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
            SigningKey::from_bytes(&[53; 32]),
        ];
        let policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-cursor-policy-a".into(),
            signature_domain: "bloch-control-plane-prod".into(),
            state_identity: "data:tenant-a:lifecycle".into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_observation_age_seconds: 60,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let pin = remote_cursor_policy_sha256(&policy).unwrap();
        (policy, keys, pin)
    }

    fn observation() -> (Vec<u8>, RemoteCursorPolicy, String, CheckpointCursor) {
        let cursor = cursor("data:tenant-a:lifecycle");
        let (policy, keys, pin) = policy();
        let message = remote_cursor_signature_message(&cursor, &policy, &pin, NONCE, 200).unwrap();
        let signatures = keys[..2]
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let observation =
            create_remote_cursor_observation(&cursor, &policy, &pin, NONCE, 200, &signatures)
                .unwrap();
        (observation, policy, pin, cursor)
    }

    #[test]
    fn verifies_fresh_threshold_response_and_exposes_exact_cursor() {
        let (observation, policy, pin, cursor) = observation();
        let verified =
            verify_remote_cursor_observation(&observation, &policy, &pin, NONCE, 250).unwrap();
        assert_eq!(verified.cursor(), &cursor);
        assert_eq!(verified.authority_ids(), &["authority-1", "authority-2"]);
        assert_eq!(verified.remote_cursor_policy_sha256(), pin);
        assert_eq!(verified.observed_at_unix_seconds(), 200);
        assert!(!verified.authority_independence_proven());
        assert!(!verified.remote_monotonicity_proven());
        assert!(!verified.high_availability_proven());
    }

    #[test]
    fn nonce_replay_stale_response_and_noncanonical_bytes_fail_closed() {
        let (observation, policy, pin, _) = observation();
        assert!(matches!(
            verify_remote_cursor_observation(
                &observation,
                &policy,
                &pin,
                "different_nonce_0123456789abcdef0123456789abcdef",
                250
            ),
            Err(RemoteCursorError::NonceMismatch)
        ));
        assert!(matches!(
            verify_remote_cursor_observation(&observation, &policy, &pin, NONCE, 261),
            Err(RemoteCursorError::OutsideFreshnessWindow)
        ));
        let mut noncanonical = observation;
        noncanonical.push(b'\n');
        assert!(matches!(
            verify_remote_cursor_observation(&noncanonical, &policy, &pin, NONCE, 250),
            Err(RemoteCursorError::InvalidObservation)
        ));
    }

    #[test]
    fn cursor_digest_tampering_and_wrong_identity_fail_closed() {
        let (observation, policy, pin, _) = observation();
        let parsed: RemoteCursorObservation = serde_json::from_slice(&observation).unwrap();
        let digest = parsed.envelope.cursor_sha256;
        let tampered = String::from_utf8(observation)
            .unwrap()
            .replacen(&digest, &format!("0x{}", "00".repeat(32)), 1)
            .into_bytes();
        assert!(matches!(
            verify_remote_cursor_observation(&tampered, &policy, &pin, NONCE, 250),
            Err(RemoteCursorError::InvalidEnvelope)
        ));
        assert!(matches!(
            remote_cursor_signature_message(
                &cursor("pay:merchant-a:adjustment"),
                &policy,
                &pin,
                NONCE,
                200
            ),
            Err(RemoteCursorError::InvalidEnvelope)
        ));
    }

    #[test]
    fn threshold_signatures_and_policy_pins_are_strict() {
        let cursor = cursor("data:tenant-a:lifecycle");
        let (mut policy, keys, pin) = policy();
        let message = remote_cursor_signature_message(&cursor, &policy, &pin, NONCE, 200).unwrap();
        let one = [RemoteCursorSignature {
            authority_id: "authority-1".into(),
            signature: format!("0x{}", hex::encode(keys[0].sign(&message).to_bytes())),
        }];
        assert!(matches!(
            create_remote_cursor_observation(&cursor, &policy, &pin, NONCE, 200, &one),
            Err(RemoteCursorError::ThresholdNotMet)
        ));
        let bytes = remote_cursor_policy_bytes(&policy).unwrap();
        assert_eq!(parse_remote_cursor_policy(&bytes, &pin).unwrap(), policy);
        policy.authorities.swap(0, 1);
        assert!(matches!(
            remote_cursor_policy_bytes(&policy),
            Err(RemoteCursorError::InvalidPolicy)
        ));
        assert!(matches!(
            parse_remote_cursor_policy(&bytes, &format!("0x{}", "00".repeat(32))),
            Err(RemoteCursorError::PolicyPinMismatch)
        ));
    }
}
