//! Bounded, offline export and verification for compacted outbox checkpoints.
//!
//! The artifact digest detects accidental corruption and provides stable bytes
//! for review. It is not an authenticity claim. Authenticity is established
//! only when a detached Ed25519 signature is verified against a policy whose
//! digest was provisioned independently. Neither path establishes L2 finality.

use bloch_indexer_core::{
    ChainIdentity,
    outbox::{OutboxCheckpoint, validate_outbox_checkpoint},
    validate_chain_identity,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;

pub const AUDIT_ARTIFACT_SCHEMA: &str = "bloch.data.outbox-checkpoint-audit.v1";
pub const AUDIT_TRUST_POLICY_SCHEMA: &str = "bloch.data.outbox-audit-trust-policy.v1";
pub const MAX_AUDIT_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_AUDIT_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_AUDIT_SIGNERS: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"bloch.data.outbox-checkpoint-audit.signature.v1";
const MAX_TEXT_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAuditArtifact {
    pub checkpoint: OutboxCheckpoint,
    pub canonical_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditExpectation {
    pub network: ChainIdentity,
    pub anchor_tip_hash: String,
    pub compacted_tip_hash: String,
    pub batch_count: u64,
    pub record_count: u64,
    pub chain_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSigner {
    pub signer_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditTrustPolicy {
    /// Operator-selected boundary, such as `bloch-prod-outbox-audit-1`.
    pub audit_domain: String,
    pub network: ChainIdentity,
    pub anchor_tip_hash: String,
    pub signers: Vec<AuditSigner>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit artifact is empty")]
    Empty,
    #[error("audit artifact exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("audit trust policy is empty")]
    PolicyEmpty,
    #[error("audit trust policy exceeds the {maximum}-byte limit: {actual} bytes")]
    PolicyTooLarge { actual: usize, maximum: usize },
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("invalid audit artifact field: {0}")]
    InvalidArtifact(&'static str),
    #[error("invalid audit trust policy field: {0}")]
    InvalidPolicy(&'static str),
    #[error("audit artifact canonical digest mismatch")]
    ArtifactDigestMismatch,
    #[error("audit trust policy canonical digest mismatch")]
    PolicyDigestMismatch,
    #[error("audit artifact does not match the caller's expected checkpoint")]
    ExpectationMismatch,
    #[error("audit artifact does not match the pinned trust context")]
    TrustContextMismatch,
    #[error("untrusted audit signer")]
    UntrustedSigner,
    #[error("invalid detached Ed25519 signature")]
    InvalidSignature,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditArtifactDocument {
    schema: String,
    checkpoint: OutboxCheckpoint,
    canonical_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalAuditDocument<'a> {
    schema: &'static str,
    checkpoint: &'a OutboxCheckpoint,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditTrustPolicyDocument {
    schema: String,
    audit_domain: String,
    network: ChainIdentity,
    anchor_tip_hash: String,
    signers: Vec<AuditSignerDocument>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditSignerDocument {
    signer_id: String,
    ed25519_public_key: String,
}

/// Exports compact JSON whose digest covers the versioned checkpoint exactly.
pub fn export_audit_artifact(checkpoint: &OutboxCheckpoint) -> Result<Vec<u8>, AuditError> {
    validate_checkpoint(checkpoint)?;
    let canonical = canonical_audit_bytes(checkpoint)?;
    let document = AuditArtifactDocument {
        schema: AUDIT_ARTIFACT_SCHEMA.into(),
        checkpoint: checkpoint.clone(),
        canonical_sha256: sha256_hex(&canonical),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| AuditError::InvalidJson(error.to_string()))?;
    if bytes.len() > MAX_AUDIT_ARTIFACT_BYTES {
        return Err(AuditError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_AUDIT_ARTIFACT_BYTES,
        });
    }
    Ok(bytes)
}

/// Strictly parses and validates an artifact, optionally against independently
/// provisioned exact expectations. A successful result is not proof of origin.
pub fn verify_audit_artifact(
    bytes: &[u8],
    expected: Option<&AuditExpectation>,
) -> Result<VerifiedAuditArtifact, AuditError> {
    check_size(bytes, MAX_AUDIT_ARTIFACT_BYTES, false)?;
    reject_duplicate_keys(bytes)?;
    let document: AuditArtifactDocument = serde_json::from_slice(bytes)
        .map_err(|error| AuditError::InvalidJson(error.to_string()))?;
    if document.schema != AUDIT_ARTIFACT_SCHEMA {
        return Err(AuditError::InvalidArtifact("schema"));
    }
    validate_checkpoint(&document.checkpoint)?;
    let canonical = canonical_audit_bytes(&document.checkpoint)?;
    let digest = sha256_hex(&canonical);
    if document.canonical_sha256 != digest {
        return Err(AuditError::ArtifactDigestMismatch);
    }
    if let Some(expected) = expected {
        validate_expectation(expected)?;
        let checkpoint = &document.checkpoint;
        if checkpoint.network != expected.network
            || checkpoint.anchor_tip_hash != expected.anchor_tip_hash
            || checkpoint.compacted_tip_hash != expected.compacted_tip_hash
            || checkpoint.batch_count != expected.batch_count
            || checkpoint.record_count != expected.record_count
            || checkpoint.chain_hash != expected.chain_hash
        {
            return Err(AuditError::ExpectationMismatch);
        }
    }
    Ok(VerifiedAuditArtifact {
        checkpoint: document.checkpoint,
        canonical_sha256: digest,
    })
}

/// Parses a policy only if its canonical SHA-256 equals the independently
/// supplied pin. Source field and signer order do not affect canonical bytes.
pub fn parse_audit_trust_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<AuditTrustPolicy, AuditError> {
    check_size(bytes, MAX_AUDIT_POLICY_BYTES, true)?;
    reject_duplicate_keys(bytes)?;
    let document: AuditTrustPolicyDocument = serde_json::from_slice(bytes)
        .map_err(|error| AuditError::InvalidJson(error.to_string()))?;
    if document.schema != AUDIT_TRUST_POLICY_SCHEMA {
        return Err(AuditError::InvalidPolicy("schema"));
    }
    let mut policy = AuditTrustPolicy {
        audit_domain: document.audit_domain,
        network: document.network,
        anchor_tip_hash: document.anchor_tip_hash,
        signers: document
            .signers
            .into_iter()
            .map(|signer| AuditSigner {
                signer_id: signer.signer_id,
                ed25519_public_key: signer.ed25519_public_key,
            })
            .collect(),
    };
    policy.signers.sort_by(|left, right| {
        left.signer_id
            .cmp(&right.signer_id)
            .then_with(|| left.ed25519_public_key.cmp(&right.ed25519_public_key))
    });
    validate_policy(&policy)?;
    let expected =
        decode_hex(expected_sha256, 32).map_err(|_| AuditError::InvalidPolicy("expectedSha256"))?;
    let canonical = canonical_audit_trust_policy_bytes(&policy)?;
    if Sha256::digest(canonical).as_slice() != expected.as_slice() {
        return Err(AuditError::PolicyDigestMismatch);
    }
    Ok(policy)
}

pub fn canonical_audit_trust_policy_bytes(
    policy: &AuditTrustPolicy,
) -> Result<Vec<u8>, AuditError> {
    validate_policy(policy)?;
    let mut signers = policy.signers.clone();
    signers.sort_by(|left, right| {
        left.signer_id
            .cmp(&right.signer_id)
            .then_with(|| left.ed25519_public_key.cmp(&right.ed25519_public_key))
    });
    let document = AuditTrustPolicyDocument {
        schema: AUDIT_TRUST_POLICY_SCHEMA.into(),
        audit_domain: policy.audit_domain.clone(),
        network: policy.network.clone(),
        anchor_tip_hash: policy.anchor_tip_hash.clone(),
        signers: signers
            .into_iter()
            .map(|signer| AuditSignerDocument {
                signer_id: signer.signer_id,
                ed25519_public_key: signer.ed25519_public_key,
            })
            .collect(),
    };
    serde_json::to_vec(&document).map_err(|error| AuditError::InvalidJson(error.to_string()))
}

pub fn audit_trust_policy_sha256(policy: &AuditTrustPolicy) -> Result<String, AuditError> {
    Ok(sha256_hex(&canonical_audit_trust_policy_bytes(policy)?))
}

/// Returns the exact offline bytes an external Ed25519 signer must sign.
pub fn detached_signature_message(
    artifact: &VerifiedAuditArtifact,
    signer_id: &str,
    policy: &AuditTrustPolicy,
) -> Result<Vec<u8>, AuditError> {
    validate_verified_artifact(artifact)?;
    validate_policy(policy)?;
    validate_identifier(signer_id).map_err(AuditError::InvalidPolicy)?;
    if artifact.checkpoint.network != policy.network
        || artifact.checkpoint.anchor_tip_hash != policy.anchor_tip_hash
    {
        return Err(AuditError::TrustContextMismatch);
    }
    if !policy
        .signers
        .iter()
        .any(|signer| signer.signer_id == signer_id)
    {
        return Err(AuditError::UntrustedSigner);
    }
    let mut message = Vec::with_capacity(512);
    push_field(&mut message, SIGNATURE_DOMAIN);
    push_field(&mut message, audit_trust_policy_sha256(policy)?.as_bytes());
    push_field(&mut message, policy.audit_domain.as_bytes());
    push_field(&mut message, signer_id.as_bytes());
    push_field(&mut message, artifact.canonical_sha256.as_bytes());
    push_field(&mut message, artifact.checkpoint.network.network.as_bytes());
    message.extend_from_slice(&artifact.checkpoint.network.chain_id.to_be_bytes());
    push_field(
        &mut message,
        artifact.checkpoint.network.genesis_hash.as_bytes(),
    );
    push_field(&mut message, artifact.checkpoint.anchor_tip_hash.as_bytes());
    push_field(
        &mut message,
        artifact.checkpoint.compacted_tip_hash.as_bytes(),
    );
    message.extend_from_slice(&artifact.checkpoint.batch_count.to_be_bytes());
    message.extend_from_slice(&artifact.checkpoint.record_count.to_be_bytes());
    push_field(&mut message, artifact.checkpoint.chain_hash.as_bytes());
    Ok(message)
}

/// Verifies raw 64-byte detached signature bytes. The signature and signer ID
/// are external to the audit artifact, so the artifact cannot choose its key.
pub fn verify_detached_signature(
    artifact: &VerifiedAuditArtifact,
    signer_id: &str,
    signature_bytes: &[u8],
    policy: &AuditTrustPolicy,
) -> Result<(), AuditError> {
    let message = detached_signature_message(artifact, signer_id, policy)?;
    let signer = policy
        .signers
        .iter()
        .find(|candidate| candidate.signer_id == signer_id)
        .ok_or(AuditError::UntrustedSigner)?;
    let public_key = decode_hex(&signer.ed25519_public_key, 32)
        .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| AuditError::InvalidSignature)?;
    key.verify_strict(&message, &signature)
        .map_err(|_| AuditError::InvalidSignature)
}

fn canonical_audit_bytes(checkpoint: &OutboxCheckpoint) -> Result<Vec<u8>, AuditError> {
    serde_json::to_vec(&CanonicalAuditDocument {
        schema: AUDIT_ARTIFACT_SCHEMA,
        checkpoint,
    })
    .map_err(|error| AuditError::InvalidJson(error.to_string()))
}

fn validate_checkpoint(checkpoint: &OutboxCheckpoint) -> Result<(), AuditError> {
    validate_outbox_checkpoint(checkpoint).map_err(|_| AuditError::InvalidArtifact("checkpoint"))
}

fn validate_expectation(expected: &AuditExpectation) -> Result<(), AuditError> {
    if validate_chain_identity(&expected.network).is_err()
        || !valid_hash(&expected.anchor_tip_hash)
        || !valid_hash(&expected.compacted_tip_hash)
        || expected.batch_count == 0
        || expected.record_count < expected.batch_count
        || !valid_hash(&expected.chain_hash)
    {
        return Err(AuditError::InvalidArtifact("expectation"));
    }
    Ok(())
}

fn validate_policy(policy: &AuditTrustPolicy) -> Result<(), AuditError> {
    if !valid_identifier(&policy.audit_domain) {
        return Err(AuditError::InvalidPolicy("auditDomain"));
    }
    if validate_chain_identity(&policy.network).is_err() {
        return Err(AuditError::InvalidPolicy("network"));
    }
    if !valid_hash(&policy.anchor_tip_hash) {
        return Err(AuditError::InvalidPolicy("anchorTipHash"));
    }
    if policy.signers.is_empty() || policy.signers.len() > MAX_AUDIT_SIGNERS {
        return Err(AuditError::InvalidPolicy("signers"));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in &policy.signers {
        validate_identifier(&signer.signer_id).map_err(AuditError::InvalidPolicy)?;
        let key = decode_hex(&signer.ed25519_public_key, 32)
            .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| AuditError::InvalidPolicy("ed25519PublicKey"))?;
        if !ids.insert(signer.signer_id.as_str())
            || !keys.insert(signer.ed25519_public_key.as_str())
        {
            return Err(AuditError::InvalidPolicy("duplicateSigner"));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), &'static str> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err("identifier")
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn valid_hash(value: &str) -> bool {
    decode_hex(value, 32).is_ok_and(|bytes| bytes.iter().any(|byte| *byte != 0))
}

fn decode_hex(value: &str, size: usize) -> Result<Vec<u8>, ()> {
    if value.len() != 2 + size * 2
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    hex::decode(&value[2..]).map_err(|_| ())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_verified_artifact(artifact: &VerifiedAuditArtifact) -> Result<(), AuditError> {
    validate_checkpoint(&artifact.checkpoint)?;
    let expected = sha256_hex(&canonical_audit_bytes(&artifact.checkpoint)?);
    if artifact.canonical_sha256 != expected {
        return Err(AuditError::ArtifactDigestMismatch);
    }
    Ok(())
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn check_size(bytes: &[u8], maximum: usize, policy: bool) -> Result<(), AuditError> {
    if bytes.is_empty() {
        return Err(if policy {
            AuditError::PolicyEmpty
        } else {
            AuditError::Empty
        });
    }
    if bytes.len() > maximum {
        return Err(if policy {
            AuditError::PolicyTooLarge {
                actual: bytes.len(),
                maximum,
            }
        } else {
            AuditError::TooLarge {
                actual: bytes.len(),
                maximum,
            }
        });
    }
    Ok(())
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), AuditError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedValue::deserialize(&mut deserializer)
        .map_err(|error| AuditError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| AuditError::InvalidJson(error.to_string()))
}

struct DuplicateCheckedValue;

impl<'de> Deserialize<'de> for DuplicateCheckedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

struct DuplicateVisitor;

impl<'de> de::Visitor<'de> for DuplicateVisitor {
    type Value = DuplicateCheckedValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            map.next_value::<DuplicateCheckedValue>()?;
        }
        Ok(DuplicateCheckedValue)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateCheckedValue>()?.is_some() {}
        Ok(DuplicateCheckedValue)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateCheckedValue::deserialize(deserializer)
    }
}
