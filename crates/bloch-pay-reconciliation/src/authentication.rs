//! Offline authentication of exact canonical payment observations.
//!
//! This module verifies public-key signatures only. It never handles private
//! keys, performs network I/O, or treats an authenticated observation as
//! finality, settlement, or authorization to credit an account.

use super::{PaymentObservation, ReconciliationPolicy, canonical_observation_bytes, policy_sha256};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const OBSERVER_POLICY_SCHEMA: &str = "bloch.pay.observer-trust-policy.v1";
pub const OBSERVATION_SIGNATURE_SCHEMA: &str = "bloch.pay.observation-signature.v1";
pub const MAX_OBSERVER_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_OBSERVATION_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_CANONICAL_OBSERVATION_BYTES: usize = 16 * 1024;
pub const MAX_OBSERVERS: usize = 256;

const SIGNATURE_PROTOCOL_DOMAIN: &[u8] = b"bloch.pay.payment-observation.signature.v1";
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedObserver {
    pub observer_id: String,
    pub source_id: String,
    pub network: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObserverTrustPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub reconciliation_policy_sha256: String,
    pub tenant_id: String,
    pub merchant_id: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub observers: Vec<TrustedObserver>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObservationSignatureEnvelope {
    schema: String,
    signature_domain: String,
    observer_policy_sha256: String,
    reconciliation_policy_sha256: String,
    tenant_id: String,
    merchant_id: String,
    network: String,
    source_id: String,
    observer_id: String,
    observation_sha256: String,
    signature: String,
}

/// Result of public-key authentication. The private fields prevent callers
/// from constructing an authenticated value without successful verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPaymentObservation {
    observation: PaymentObservation,
    observer_id: String,
    observer_policy_sha256: String,
    reconciliation_policy_sha256: String,
    canonical_observation_sha256: String,
}

impl AuthenticatedPaymentObservation {
    pub fn observation(&self) -> &PaymentObservation {
        &self.observation
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    pub fn observer_policy_sha256(&self) -> &str {
        &self.observer_policy_sha256
    }

    pub fn reconciliation_policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }

    pub fn canonical_observation_sha256(&self) -> &str {
        &self.canonical_observation_sha256
    }

    /// Authentication never establishes network finality.
    pub fn finality_qualified(&self) -> bool {
        false
    }

    /// Authentication never establishes settlement.
    pub fn settlement_qualified(&self) -> bool {
        false
    }

    /// Authentication never authorizes credit or movement of funds.
    pub fn credit_authorized(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObservationAuthenticationError {
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
    #[error("invalid observer authentication field: {0}")]
    InvalidField(&'static str),
    #[error("input is not exact canonical JSON")]
    NonCanonicalJson,
    #[error("observer trust policy digest mismatch")]
    ObserverPolicyDigestMismatch,
    #[error("reconciliation policy digest mismatch")]
    ReconciliationPolicyDigestMismatch,
    #[error("observer trust context does not match the reconciliation policy")]
    TrustContextMismatch,
    #[error("observer is not authorized for this source and network")]
    UntrustedObserver,
    #[error("observation digest mismatch")]
    ObservationDigestMismatch,
    #[error("invalid detached Ed25519 signature")]
    InvalidSignature,
    #[error("invalid payment observation: {0}")]
    InvalidObservation(String),
}

pub fn canonical_observer_policy_bytes(
    policy: &ObserverTrustPolicy,
) -> Result<Vec<u8>, ObservationAuthenticationError> {
    validate_observer_policy(policy)?;
    serde_json::to_vec(policy).map_err(|error| invalid_json("observer policy", error))
}

pub fn observer_policy_sha256(
    policy: &ObserverTrustPolicy,
) -> Result<String, ObservationAuthenticationError> {
    Ok(sha256_hex(&canonical_observer_policy_bytes(policy)?))
}

/// Parses only byte-exact canonical policy JSON matching an independently
/// supplied SHA-256 pin.
pub fn parse_observer_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<ObserverTrustPolicy, ObservationAuthenticationError> {
    check_size(bytes, MAX_OBSERVER_POLICY_BYTES, "observer policy")?;
    require_hash(expected_sha256, "expectedObserverPolicySha256")?;
    let policy: ObserverTrustPolicy =
        serde_json::from_slice(bytes).map_err(|error| invalid_json("observer policy", error))?;
    validate_observer_policy(&policy)?;
    if canonical_observer_policy_bytes(&policy)? != bytes {
        return Err(ObservationAuthenticationError::NonCanonicalJson);
    }
    if sha256_hex(bytes) != expected_sha256 {
        return Err(ObservationAuthenticationError::ObserverPolicyDigestMismatch);
    }
    Ok(policy)
}

/// Strictly parses exact canonical observation JSON under a reconciliation
/// policy. Duplicate/unknown fields and trailing non-canonical bytes fail.
pub fn parse_payment_observation(
    bytes: &[u8],
    reconciliation_policy: &ReconciliationPolicy,
    evaluated_at_unix_seconds: u64,
) -> Result<PaymentObservation, ObservationAuthenticationError> {
    check_size(
        bytes,
        MAX_CANONICAL_OBSERVATION_BYTES,
        "payment observation",
    )?;
    let observation: PaymentObservation = serde_json::from_slice(bytes)
        .map_err(|error| invalid_json("payment observation", error))?;
    let canonical = canonical_observation_bytes(
        reconciliation_policy,
        &observation,
        evaluated_at_unix_seconds,
    )
    .map_err(|error| ObservationAuthenticationError::InvalidObservation(error.to_string()))?;
    if canonical != bytes {
        return Err(ObservationAuthenticationError::NonCanonicalJson);
    }
    Ok(observation)
}

/// Returns the exact domain-separated bytes an external Ed25519 holder signs.
/// Both policy digests must come from an independently provisioned pin.
#[allow(clippy::too_many_arguments)]
pub fn observation_signing_bytes(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    observer_policy: &ObserverTrustPolicy,
    expected_observer_policy_sha256: &str,
    observer_id: &str,
    observation: &PaymentObservation,
    evaluated_at_unix_seconds: u64,
) -> Result<Vec<u8>, ObservationAuthenticationError> {
    let (observer, canonical_observation) = validate_signing_context(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        observer_policy,
        expected_observer_policy_sha256,
        observer_id,
        observation,
        evaluated_at_unix_seconds,
    )?;
    let mut message = Vec::with_capacity(canonical_observation.len() + 768);
    append(&mut message, SIGNATURE_PROTOCOL_DOMAIN)?;
    append(&mut message, observer_policy.signature_domain.as_bytes())?;
    append(&mut message, expected_observer_policy_sha256.as_bytes())?;
    append(
        &mut message,
        expected_reconciliation_policy_sha256.as_bytes(),
    )?;
    append(&mut message, observer_policy.tenant_id.as_bytes())?;
    append(&mut message, observer_policy.merchant_id.as_bytes())?;
    append(&mut message, observer.network.as_bytes())?;
    append(&mut message, observer.source_id.as_bytes())?;
    append(&mut message, observer.observer_id.as_bytes())?;
    append(&mut message, &canonical_observation)?;
    Ok(message)
}

/// Encodes a detached raw 64-byte Ed25519 signature with its complete public
/// verification context. The observation itself remains detached.
#[allow(clippy::too_many_arguments)]
pub fn encode_observation_signature_envelope(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    observer_policy: &ObserverTrustPolicy,
    expected_observer_policy_sha256: &str,
    observer_id: &str,
    observation: &PaymentObservation,
    evaluated_at_unix_seconds: u64,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, ObservationAuthenticationError> {
    let message = observation_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        observer_policy,
        expected_observer_policy_sha256,
        observer_id,
        observation,
        evaluated_at_unix_seconds,
    )?;
    let observer = trusted_observer(observer_policy, observer_id, observation)?;
    verify_signature(observer, &message, signature_bytes)?;
    let canonical_observation = canonical_observation_bytes(
        reconciliation_policy,
        observation,
        evaluated_at_unix_seconds,
    )
    .map_err(|error| ObservationAuthenticationError::InvalidObservation(error.to_string()))?;
    let envelope = ObservationSignatureEnvelope {
        schema: OBSERVATION_SIGNATURE_SCHEMA.into(),
        signature_domain: observer_policy.signature_domain.clone(),
        observer_policy_sha256: expected_observer_policy_sha256.into(),
        reconciliation_policy_sha256: expected_reconciliation_policy_sha256.into(),
        tenant_id: observer_policy.tenant_id.clone(),
        merchant_id: observer_policy.merchant_id.clone(),
        network: observation.network.clone(),
        source_id: observation.source_id.clone(),
        observer_id: observer_id.into(),
        observation_sha256: sha256_hex(&canonical_observation),
        signature: format!("0x{}", hex::encode(signature_bytes)),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| invalid_json("observation signature envelope", error))?;
    check_size(
        &bytes,
        MAX_OBSERVATION_ENVELOPE_BYTES,
        "observation signature envelope",
    )?;
    Ok(bytes)
}

/// Verifies a strict canonical envelope and its detached observation against
/// both independent policy pins.
#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_observation(
    envelope_bytes: &[u8],
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    observer_policy: &ObserverTrustPolicy,
    expected_observer_policy_sha256: &str,
    observation: &PaymentObservation,
    evaluated_at_unix_seconds: u64,
) -> Result<AuthenticatedPaymentObservation, ObservationAuthenticationError> {
    check_size(
        envelope_bytes,
        MAX_OBSERVATION_ENVELOPE_BYTES,
        "observation signature envelope",
    )?;
    let envelope: ObservationSignatureEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|error| invalid_json("observation signature envelope", error))?;
    let canonical_envelope = serde_json::to_vec(&envelope)
        .map_err(|error| invalid_json("observation signature envelope", error))?;
    if canonical_envelope != envelope_bytes {
        return Err(ObservationAuthenticationError::NonCanonicalJson);
    }
    if envelope.schema != OBSERVATION_SIGNATURE_SCHEMA {
        return Err(ObservationAuthenticationError::InvalidField(
            "envelope.schema",
        ));
    }
    let message = observation_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        observer_policy,
        expected_observer_policy_sha256,
        &envelope.observer_id,
        observation,
        evaluated_at_unix_seconds,
    )?;
    let expected_context = envelope.signature_domain == observer_policy.signature_domain
        && envelope.observer_policy_sha256 == expected_observer_policy_sha256
        && envelope.reconciliation_policy_sha256 == expected_reconciliation_policy_sha256
        && envelope.tenant_id == reconciliation_policy.tenant_id
        && envelope.merchant_id == reconciliation_policy.merchant_id
        && envelope.network == observation.network
        && envelope.source_id == observation.source_id;
    if !expected_context {
        return Err(ObservationAuthenticationError::TrustContextMismatch);
    }
    let canonical_observation = canonical_observation_bytes(
        reconciliation_policy,
        observation,
        evaluated_at_unix_seconds,
    )
    .map_err(|error| ObservationAuthenticationError::InvalidObservation(error.to_string()))?;
    let observation_digest = sha256_hex(&canonical_observation);
    if envelope.observation_sha256 != observation_digest {
        return Err(ObservationAuthenticationError::ObservationDigestMismatch);
    }
    let observer = trusted_observer(observer_policy, &envelope.observer_id, observation)?;
    let signature = decode_hex_exact(&envelope.signature, 64, "signature")?;
    verify_signature(observer, &message, &signature)?;
    Ok(AuthenticatedPaymentObservation {
        observation: observation.clone(),
        observer_id: envelope.observer_id,
        observer_policy_sha256: envelope.observer_policy_sha256,
        reconciliation_policy_sha256: envelope.reconciliation_policy_sha256,
        canonical_observation_sha256: observation_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_signing_context<'a>(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    observer_policy: &'a ObserverTrustPolicy,
    expected_observer_policy_sha256: &str,
    observer_id: &str,
    observation: &PaymentObservation,
    evaluated_at_unix_seconds: u64,
) -> Result<(&'a TrustedObserver, Vec<u8>), ObservationAuthenticationError> {
    require_hash(
        expected_reconciliation_policy_sha256,
        "expectedReconciliationPolicySha256",
    )?;
    require_hash(
        expected_observer_policy_sha256,
        "expectedObserverPolicySha256",
    )?;
    let actual_reconciliation = policy_sha256(reconciliation_policy)
        .map_err(|error| ObservationAuthenticationError::InvalidObservation(error.to_string()))?;
    if actual_reconciliation != expected_reconciliation_policy_sha256 {
        return Err(ObservationAuthenticationError::ReconciliationPolicyDigestMismatch);
    }
    let actual_observer = observer_policy_sha256(observer_policy)?;
    if actual_observer != expected_observer_policy_sha256 {
        return Err(ObservationAuthenticationError::ObserverPolicyDigestMismatch);
    }
    validate_policy_context(reconciliation_policy, observer_policy)?;
    if evaluated_at_unix_seconds < observer_policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= observer_policy.expires_at_unix_seconds
    {
        return Err(ObservationAuthenticationError::InvalidField(
            "evaluationTime",
        ));
    }
    let canonical_observation = canonical_observation_bytes(
        reconciliation_policy,
        observation,
        evaluated_at_unix_seconds,
    )
    .map_err(|error| ObservationAuthenticationError::InvalidObservation(error.to_string()))?;
    if canonical_observation.len() > MAX_CANONICAL_OBSERVATION_BYTES {
        return Err(ObservationAuthenticationError::TooLarge {
            kind: "payment observation",
            actual: canonical_observation.len(),
            maximum: MAX_CANONICAL_OBSERVATION_BYTES,
        });
    }
    let observer = trusted_observer(observer_policy, observer_id, observation)?;
    Ok((observer, canonical_observation))
}

fn trusted_observer<'a>(
    policy: &'a ObserverTrustPolicy,
    observer_id: &str,
    observation: &PaymentObservation,
) -> Result<&'a TrustedObserver, ObservationAuthenticationError> {
    policy
        .observers
        .iter()
        .find(|observer| {
            observer.observer_id == observer_id
                && observer.source_id == observation.source_id
                && observer.network == observation.network
        })
        .ok_or(ObservationAuthenticationError::UntrustedObserver)
}

fn validate_observer_policy(
    policy: &ObserverTrustPolicy,
) -> Result<(), ObservationAuthenticationError> {
    if policy.schema != OBSERVER_POLICY_SCHEMA {
        return Err(ObservationAuthenticationError::InvalidField(
            "policy.schema",
        ));
    }
    for (field, value) in [
        ("policyId", policy.policy_id.as_str()),
        ("signatureDomain", policy.signature_domain.as_str()),
        ("tenantId", policy.tenant_id.as_str()),
        ("merchantId", policy.merchant_id.as_str()),
    ] {
        if !valid_identifier(value) {
            return Err(ObservationAuthenticationError::InvalidField(field));
        }
    }
    require_hash(
        &policy.reconciliation_policy_sha256,
        "reconciliationPolicySha256",
    )?;
    if policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds {
        return Err(ObservationAuthenticationError::InvalidField("policyTime"));
    }
    if policy.observers.is_empty() || policy.observers.len() > MAX_OBSERVERS {
        return Err(ObservationAuthenticationError::InvalidField("observers"));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut previous_id: Option<&str> = None;
    for observer in &policy.observers {
        if !valid_identifier(&observer.observer_id)
            || !valid_identifier(&observer.source_id)
            || !valid_identifier(&observer.network)
        {
            return Err(ObservationAuthenticationError::InvalidField("observer"));
        }
        parse_public_key(&observer.ed25519_public_key)?;
        if previous_id.is_some_and(|previous| previous >= observer.observer_id.as_str())
            || !ids.insert(observer.observer_id.as_str())
            || !keys.insert(observer.ed25519_public_key.as_str())
        {
            return Err(ObservationAuthenticationError::InvalidField(
                "duplicateObserver",
            ));
        }
        previous_id = Some(observer.observer_id.as_str());
    }
    Ok(())
}

fn validate_policy_context(
    reconciliation_policy: &ReconciliationPolicy,
    observer_policy: &ObserverTrustPolicy,
) -> Result<(), ObservationAuthenticationError> {
    if observer_policy.reconciliation_policy_sha256
        != policy_sha256(reconciliation_policy).map_err(|error| {
            ObservationAuthenticationError::InvalidObservation(error.to_string())
        })?
        || observer_policy.tenant_id != reconciliation_policy.tenant_id
        || observer_policy.merchant_id != reconciliation_policy.merchant_id
        || observer_policy.observers.iter().any(|observer| {
            reconciliation_policy
                .allowed_source_ids
                .binary_search(&observer.source_id)
                .is_err()
                || !reconciliation_policy
                    .routes
                    .iter()
                    .any(|route| route.network == observer.network)
        })
    {
        return Err(ObservationAuthenticationError::TrustContextMismatch);
    }
    Ok(())
}

fn verify_signature(
    observer: &TrustedObserver,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ObservationAuthenticationError> {
    let key = parse_public_key(&observer.ed25519_public_key)?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| ObservationAuthenticationError::InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| ObservationAuthenticationError::InvalidSignature)
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, ObservationAuthenticationError> {
    let bytes: [u8; 32] = decode_hex_exact(value, 32, "ed25519PublicKey")?
        .try_into()
        .map_err(|_| ObservationAuthenticationError::InvalidField("ed25519PublicKey"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ObservationAuthenticationError::InvalidField("ed25519PublicKey"))?;
    if key.is_weak() {
        return Err(ObservationAuthenticationError::InvalidField(
            "ed25519PublicKey",
        ));
    }
    Ok(key)
}

fn require_hash(value: &str, field: &'static str) -> Result<(), ObservationAuthenticationError> {
    decode_hex_exact(value, 32, field).map(|_| ())
}

fn decode_hex_exact(
    value: &str,
    expected_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, ObservationAuthenticationError> {
    if value.len() != expected_bytes.saturating_mul(2).saturating_add(2)
        || !value.starts_with("0x")
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ObservationAuthenticationError::InvalidField(field));
    }
    hex::decode(&value[2..]).map_err(|_| ObservationAuthenticationError::InvalidField(field))
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

fn append(target: &mut Vec<u8>, value: &[u8]) -> Result<(), ObservationAuthenticationError> {
    let length = u64::try_from(value.len())
        .map_err(|_| ObservationAuthenticationError::InvalidField("length"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn check_size(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<(), ObservationAuthenticationError> {
    if bytes.is_empty() {
        return Err(ObservationAuthenticationError::Empty { kind });
    }
    if bytes.len() > maximum {
        return Err(ObservationAuthenticationError::TooLarge {
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

fn invalid_json(kind: &'static str, error: serde_json::Error) -> ObservationAuthenticationError {
    ObservationAuthenticationError::InvalidJson {
        kind,
        message: error.to_string(),
    }
}
