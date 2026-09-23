//! Authenticated, path-independent boundaries for one retention ledger.

use super::{
    GENESIS_ENTRY_SHA256, RetentionError, RetentionExpectation,
    verify_audit_ledger_with_expectation,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, path::Path};
use thiserror::Error;

pub const RETENTION_CHECKPOINT_SCHEMA: &str = "bloch.data.outbox-audit-retention-checkpoint.v1";
pub const RETENTION_CHECKPOINT_POLICY_SCHEMA: &str =
    "bloch.data.outbox-audit-retention-checkpoint-policy.v1";
pub const MAX_RETENTION_CHECKPOINT_BYTES: usize = 16 * 1024;
pub const MAX_RETENTION_CHECKPOINT_POLICY_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_SIGNERS: usize = 64;
const MAX_TEXT_BYTES: usize = 128;
const SIGNATURE_DOMAIN: &[u8] = b"bloch.data.outbox-audit-retention-checkpoint.signature.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionCheckpointSigner {
    pub signer_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionCheckpointPolicy {
    /// Deployment boundary selected independently of the local ledger path.
    pub checkpoint_domain: String,
    /// Stable operator-assigned identity; never derived from a filesystem path.
    pub ledger_id: String,
    pub signers: Vec<RetentionCheckpointSigner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedRetentionCheckpoint {
    checkpoint_domain: String,
    ledger_id: String,
    audit_policy_sha256: String,
    checkpoint_policy_sha256: String,
    entry_count: u64,
    head_sha256: String,
    canonical_sha256: String,
    signer_id: String,
}

impl VerifiedRetentionCheckpoint {
    pub fn checkpoint_domain(&self) -> &str {
        &self.checkpoint_domain
    }

    pub fn ledger_id(&self) -> &str {
        &self.ledger_id
    }

    pub fn audit_policy_sha256(&self) -> &str {
        &self.audit_policy_sha256
    }

    pub fn checkpoint_policy_sha256(&self) -> &str {
        &self.checkpoint_policy_sha256
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn head_sha256(&self) -> &str {
        &self.head_sha256
    }

    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }
}

#[derive(Debug, Error)]
pub enum RetentionCheckpointError {
    #[error("retention checkpoint input is empty")]
    Empty,
    #[error("retention checkpoint input exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid retention checkpoint JSON: {0}")]
    InvalidJson(String),
    #[error("invalid retention checkpoint field: {0}")]
    InvalidCheckpoint(&'static str),
    #[error("invalid retention checkpoint policy field: {0}")]
    InvalidPolicy(&'static str),
    #[error("retention checkpoint policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("retention checkpoint canonical digest mismatch")]
    CheckpointDigestMismatch,
    #[error("retention checkpoint is not canonical JSON")]
    NonCanonicalCheckpoint,
    #[error("untrusted retention checkpoint signer")]
    UntrustedSigner,
    #[error("invalid retention checkpoint Ed25519 signature")]
    InvalidSignature,
    #[error("retention checkpoint does not describe the verified ledger")]
    LedgerMismatch,
    #[error("retention ledger rollback or history replacement detected")]
    RollbackDetected,
    #[error("retention ledger verification failed: {0}")]
    Retention(#[from] RetentionError),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointDocument {
    schema: String,
    checkpoint_domain: String,
    ledger_id: String,
    audit_policy_sha256: String,
    checkpoint_policy_sha256: String,
    entry_count: u64,
    head_sha256: String,
    canonical_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointCommitment<'a> {
    schema: &'static str,
    checkpoint_domain: &'a str,
    ledger_id: &'a str,
    audit_policy_sha256: &'a str,
    checkpoint_policy_sha256: &'a str,
    entry_count: u64,
    head_sha256: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyDocument {
    schema: String,
    checkpoint_domain: String,
    ledger_id: String,
    signers: Vec<SignerDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignerDocument {
    signer_id: String,
    ed25519_public_key: String,
}

/// Produces a bounded canonical checkpoint. It contains no signature or key.
pub fn export_retention_checkpoint(
    boundary: &RetentionExpectation,
    audit_policy_sha256: &str,
    policy: &RetentionCheckpointPolicy,
) -> Result<Vec<u8>, RetentionCheckpointError> {
    validate_policy(policy)?;
    validate_boundary(boundary)?;
    require_nonzero_hash(audit_policy_sha256, "auditPolicySha256")?;
    let policy_sha256 = retention_checkpoint_policy_sha256(policy)?;
    let commitment = CheckpointCommitment {
        schema: RETENTION_CHECKPOINT_SCHEMA,
        checkpoint_domain: &policy.checkpoint_domain,
        ledger_id: &policy.ledger_id,
        audit_policy_sha256,
        checkpoint_policy_sha256: &policy_sha256,
        entry_count: boundary.entry_count,
        head_sha256: &boundary.head_sha256,
    };
    let canonical_sha256 = sha256_hex(&json(&commitment)?);
    let document = CheckpointDocument {
        schema: RETENTION_CHECKPOINT_SCHEMA.into(),
        checkpoint_domain: policy.checkpoint_domain.clone(),
        ledger_id: policy.ledger_id.clone(),
        audit_policy_sha256: audit_policy_sha256.into(),
        checkpoint_policy_sha256: policy_sha256,
        entry_count: boundary.entry_count,
        head_sha256: boundary.head_sha256.clone(),
        canonical_sha256,
    };
    let bytes = json(&document)?;
    check_size(&bytes, MAX_RETENTION_CHECKPOINT_BYTES)?;
    Ok(bytes)
}

pub fn canonical_retention_checkpoint_policy_bytes(
    policy: &RetentionCheckpointPolicy,
) -> Result<Vec<u8>, RetentionCheckpointError> {
    validate_policy(policy)?;
    let mut signers = policy.signers.clone();
    signers.sort_by(|left, right| {
        left.signer_id
            .cmp(&right.signer_id)
            .then_with(|| left.ed25519_public_key.cmp(&right.ed25519_public_key))
    });
    json(&PolicyDocument {
        schema: RETENTION_CHECKPOINT_POLICY_SCHEMA.into(),
        checkpoint_domain: policy.checkpoint_domain.clone(),
        ledger_id: policy.ledger_id.clone(),
        signers: signers
            .into_iter()
            .map(|signer| SignerDocument {
                signer_id: signer.signer_id,
                ed25519_public_key: signer.ed25519_public_key,
            })
            .collect(),
    })
}

pub fn retention_checkpoint_policy_sha256(
    policy: &RetentionCheckpointPolicy,
) -> Result<String, RetentionCheckpointError> {
    Ok(sha256_hex(&canonical_retention_checkpoint_policy_bytes(
        policy,
    )?))
}

/// Parses a policy only when its canonical digest matches an independent pin.
pub fn parse_retention_checkpoint_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<RetentionCheckpointPolicy, RetentionCheckpointError> {
    check_size(bytes, MAX_RETENTION_CHECKPOINT_POLICY_BYTES)?;
    reject_duplicate_keys(bytes)?;
    if decode_hex(expected_sha256, 32).is_err() || expected_sha256 == GENESIS_ENTRY_SHA256 {
        return Err(RetentionCheckpointError::InvalidPolicy(
            "expectedPolicySha256",
        ));
    }
    let document: PolicyDocument = parse(bytes)?;
    if document.schema != RETENTION_CHECKPOINT_POLICY_SCHEMA {
        return Err(RetentionCheckpointError::InvalidPolicy("schema"));
    }
    let mut policy = RetentionCheckpointPolicy {
        checkpoint_domain: document.checkpoint_domain,
        ledger_id: document.ledger_id,
        signers: document
            .signers
            .into_iter()
            .map(|signer| RetentionCheckpointSigner {
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
    if retention_checkpoint_policy_sha256(&policy)? != expected_sha256 {
        return Err(RetentionCheckpointError::PolicyDigestMismatch);
    }
    Ok(policy)
}

/// Returns the exact domain-separated bytes an external signer must sign.
pub fn retention_checkpoint_signature_message(
    checkpoint_bytes: &[u8],
    signer_id: &str,
    policy: &RetentionCheckpointPolicy,
) -> Result<Vec<u8>, RetentionCheckpointError> {
    let checkpoint = parse_checkpoint(checkpoint_bytes, policy)?;
    trusted_signer(policy, signer_id)?;
    let mut message = Vec::with_capacity(512);
    push_field(&mut message, SIGNATURE_DOMAIN);
    push_field(&mut message, checkpoint.checkpoint_domain.as_bytes());
    push_field(&mut message, checkpoint.checkpoint_policy_sha256.as_bytes());
    push_field(&mut message, signer_id.as_bytes());
    push_field(&mut message, checkpoint.ledger_id.as_bytes());
    push_field(&mut message, checkpoint.audit_policy_sha256.as_bytes());
    message.extend_from_slice(&checkpoint.entry_count.to_be_bytes());
    push_field(&mut message, checkpoint.head_sha256.as_bytes());
    push_field(&mut message, checkpoint.canonical_sha256.as_bytes());
    Ok(message)
}

/// Verifies canonical bytes, an independently pinned policy, and a raw
/// detached 64-byte Ed25519 signature.
pub fn verify_retention_checkpoint(
    checkpoint_bytes: &[u8],
    signer_id: &str,
    signature_bytes: &[u8],
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<VerifiedRetentionCheckpoint, RetentionCheckpointError> {
    let policy = parse_retention_checkpoint_policy(policy_bytes, expected_policy_sha256)?;
    let document = parse_checkpoint(checkpoint_bytes, &policy)?;
    let signer = trusted_signer(&policy, signer_id)?;
    let message = retention_checkpoint_signature_message(checkpoint_bytes, signer_id, &policy)?;
    let key: [u8; 32] = decode_hex(&signer.ed25519_public_key, 32)
        .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?
        .try_into()
        .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?;
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| RetentionCheckpointError::InvalidSignature)?;
    key.verify_strict(&message, &signature)
        .map_err(|_| RetentionCheckpointError::InvalidSignature)?;
    Ok(VerifiedRetentionCheckpoint {
        checkpoint_domain: document.checkpoint_domain,
        ledger_id: document.ledger_id,
        audit_policy_sha256: document.audit_policy_sha256,
        checkpoint_policy_sha256: document.checkpoint_policy_sha256,
        entry_count: document.entry_count,
        head_sha256: document.head_sha256,
        canonical_sha256: document.canonical_sha256,
        signer_id: signer_id.into(),
    })
}

/// Verifies the signed checkpoint against a complete ledger replay. When a
/// previously verified checkpoint is supplied, its head must still be an
/// ancestor at the exact retained count, detecting rollback and replacement.
#[allow(clippy::too_many_arguments)]
pub fn verify_retention_checkpoint_against_ledger(
    ledger: &Path,
    audit_policy_bytes: &[u8],
    expected_audit_policy_sha256: &str,
    checkpoint_bytes: &[u8],
    signer_id: &str,
    signature_bytes: &[u8],
    checkpoint_policy_bytes: &[u8],
    expected_checkpoint_policy_sha256: &str,
    previously_verified: Option<&VerifiedRetentionCheckpoint>,
) -> Result<VerifiedRetentionCheckpoint, RetentionCheckpointError> {
    let checkpoint = verify_retention_checkpoint(
        checkpoint_bytes,
        signer_id,
        signature_bytes,
        checkpoint_policy_bytes,
        expected_checkpoint_policy_sha256,
    )?;
    if checkpoint.audit_policy_sha256 != expected_audit_policy_sha256 {
        return Err(RetentionCheckpointError::LedgerMismatch);
    }
    let expectation = RetentionExpectation {
        entry_count: checkpoint.entry_count,
        head_sha256: checkpoint.head_sha256.clone(),
    };
    let entries = verify_audit_ledger_with_expectation(
        ledger,
        audit_policy_bytes,
        expected_audit_policy_sha256,
        Some(&expectation),
    )
    .map_err(|error| match error {
        RetentionError::InvalidEntry("ledgerExpectation") => {
            RetentionCheckpointError::LedgerMismatch
        }
        other => RetentionCheckpointError::Retention(other),
    })?;
    if let Some(previous) = previously_verified {
        if previous.checkpoint_domain != checkpoint.checkpoint_domain
            || previous.ledger_id != checkpoint.ledger_id
            || previous.audit_policy_sha256 != checkpoint.audit_policy_sha256
            || previous.checkpoint_policy_sha256 != checkpoint.checkpoint_policy_sha256
            || previous.entry_count > checkpoint.entry_count
        {
            return Err(RetentionCheckpointError::RollbackDetected);
        }
        let prior_head = if previous.entry_count == 0 {
            GENESIS_ENTRY_SHA256
        } else {
            entries
                .get((previous.entry_count - 1) as usize)
                .map(|entry| entry.entry_sha256.as_str())
                .ok_or(RetentionCheckpointError::RollbackDetected)?
        };
        if previous.head_sha256 != prior_head {
            return Err(RetentionCheckpointError::RollbackDetected);
        }
    }
    Ok(checkpoint)
}

fn parse_checkpoint(
    bytes: &[u8],
    policy: &RetentionCheckpointPolicy,
) -> Result<CheckpointDocument, RetentionCheckpointError> {
    check_size(bytes, MAX_RETENTION_CHECKPOINT_BYTES)?;
    reject_duplicate_keys(bytes)?;
    let document: CheckpointDocument = parse(bytes)?;
    if document.schema != RETENTION_CHECKPOINT_SCHEMA {
        return Err(RetentionCheckpointError::InvalidCheckpoint("schema"));
    }
    if document.checkpoint_domain != policy.checkpoint_domain {
        return Err(RetentionCheckpointError::InvalidCheckpoint(
            "checkpointDomain",
        ));
    }
    if document.ledger_id != policy.ledger_id {
        return Err(RetentionCheckpointError::InvalidCheckpoint("ledgerId"));
    }
    require_nonzero_hash(&document.audit_policy_sha256, "auditPolicySha256")?;
    require_nonzero_hash(&document.checkpoint_policy_sha256, "checkpointPolicySha256")?;
    if document.checkpoint_policy_sha256 != retention_checkpoint_policy_sha256(policy)? {
        return Err(RetentionCheckpointError::PolicyDigestMismatch);
    }
    validate_boundary(&RetentionExpectation {
        entry_count: document.entry_count,
        head_sha256: document.head_sha256.clone(),
    })?;
    let expected = sha256_hex(&json(&CheckpointCommitment {
        schema: RETENTION_CHECKPOINT_SCHEMA,
        checkpoint_domain: &document.checkpoint_domain,
        ledger_id: &document.ledger_id,
        audit_policy_sha256: &document.audit_policy_sha256,
        checkpoint_policy_sha256: &document.checkpoint_policy_sha256,
        entry_count: document.entry_count,
        head_sha256: &document.head_sha256,
    })?);
    if document.canonical_sha256 != expected {
        return Err(RetentionCheckpointError::CheckpointDigestMismatch);
    }
    if json(&document)? != bytes {
        return Err(RetentionCheckpointError::NonCanonicalCheckpoint);
    }
    Ok(document)
}

fn validate_boundary(boundary: &RetentionExpectation) -> Result<(), RetentionCheckpointError> {
    if !valid_hash(&boundary.head_sha256)
        || (boundary.entry_count == 0 && boundary.head_sha256 != GENESIS_ENTRY_SHA256)
        || (boundary.entry_count > 0 && boundary.head_sha256 == GENESIS_ENTRY_SHA256)
    {
        return Err(RetentionCheckpointError::InvalidCheckpoint("boundary"));
    }
    Ok(())
}

fn validate_policy(policy: &RetentionCheckpointPolicy) -> Result<(), RetentionCheckpointError> {
    if !valid_identifier(&policy.checkpoint_domain) {
        return Err(RetentionCheckpointError::InvalidPolicy("checkpointDomain"));
    }
    if !valid_identifier(&policy.ledger_id) {
        return Err(RetentionCheckpointError::InvalidPolicy("ledgerId"));
    }
    if policy.signers.is_empty() || policy.signers.len() > MAX_CHECKPOINT_SIGNERS {
        return Err(RetentionCheckpointError::InvalidPolicy("signers"));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in &policy.signers {
        if !valid_identifier(&signer.signer_id) {
            return Err(RetentionCheckpointError::InvalidPolicy("signerId"));
        }
        let key: [u8; 32] = decode_hex(&signer.ed25519_public_key, 32)
            .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?
            .try_into()
            .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| RetentionCheckpointError::InvalidPolicy("ed25519PublicKey"))?;
        if !ids.insert(signer.signer_id.as_str())
            || !keys.insert(signer.ed25519_public_key.as_str())
        {
            return Err(RetentionCheckpointError::InvalidPolicy("duplicateSigner"));
        }
    }
    Ok(())
}

fn trusted_signer<'a>(
    policy: &'a RetentionCheckpointPolicy,
    signer_id: &str,
) -> Result<&'a RetentionCheckpointSigner, RetentionCheckpointError> {
    policy
        .signers
        .iter()
        .find(|signer| signer.signer_id == signer_id)
        .ok_or(RetentionCheckpointError::UntrustedSigner)
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
    decode_hex(value, 32).is_ok()
}

fn require_nonzero_hash(value: &str, field: &'static str) -> Result<(), RetentionCheckpointError> {
    let bytes =
        decode_hex(value, 32).map_err(|_| RetentionCheckpointError::InvalidCheckpoint(field))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(RetentionCheckpointError::InvalidCheckpoint(field));
    }
    Ok(())
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

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn check_size(bytes: &[u8], maximum: usize) -> Result<(), RetentionCheckpointError> {
    if bytes.is_empty() {
        return Err(RetentionCheckpointError::Empty);
    }
    if bytes.len() > maximum {
        return Err(RetentionCheckpointError::TooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, RetentionCheckpointError> {
    serde_json::to_vec(value)
        .map_err(|error| RetentionCheckpointError::InvalidJson(error.to_string()))
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, RetentionCheckpointError> {
    serde_json::from_slice(bytes)
        .map_err(|error| RetentionCheckpointError::InvalidJson(error.to_string()))
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), RetentionCheckpointError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedValue::deserialize(&mut deserializer)
        .map_err(|error| RetentionCheckpointError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| RetentionCheckpointError::InvalidJson(error.to_string()))
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
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateCheckedValue::deserialize(deserializer)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
}
