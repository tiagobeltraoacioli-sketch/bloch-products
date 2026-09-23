//! Threshold-authenticated roots for `bloch-local-state-store`.
//!
//! Signing is deliberately external. This crate constructs exact messages and
//! verifies detached Ed25519 signatures; it never receives a private key.

use bloch_local_state_store::StateRoot;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const POLICY_SCHEMA: &str = "bloch.products.local-state-checkpoint-policy.v1";
pub const MANIFEST_SCHEMA: &str = "bloch.products.local-state-checkpoint-manifest.v1";
pub const ARTIFACT_SCHEMA: &str = "bloch.products.local-state-checkpoint-artifact.v1";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024;
const MAX_AUTHORITIES: usize = 16;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-LOCAL-STATE-CHECKPOINT-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckpointAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckpointPolicy {
    pub schema: String,
    pub policy_id: String,
    pub checkpoint_domain: String,
    pub state_identity: String,
    pub threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_checkpoint_age_seconds: u64,
    pub authorities: Vec<CheckpointAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DetachedCheckpointSignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointManifest {
    schema: String,
    checkpoint_policy_sha256: String,
    checkpoint_domain: String,
    state_root: StateRoot,
    created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointArtifact {
    schema: String,
    manifest: CheckpointManifest,
    signatures: Vec<DetachedCheckpointSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRootCheckpoint {
    root: StateRoot,
    checkpoint_policy_sha256: String,
    checkpoint_sha256: String,
    created_at_unix_seconds: u64,
    authority_ids: Vec<String>,
}

impl VerifiedRootCheckpoint {
    pub fn root(&self) -> &StateRoot {
        &self.root
    }
    pub fn checkpoint_policy_sha256(&self) -> &str {
        &self.checkpoint_policy_sha256
    }
    pub fn checkpoint_sha256(&self) -> &str {
        &self.checkpoint_sha256
    }
    pub fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn authority_independence_proven(&self) -> bool {
        false
    }
    pub fn high_availability_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint policy is invalid")]
    InvalidPolicy,
    #[error("checkpoint policy pin mismatch")]
    PolicyPinMismatch,
    #[error("checkpoint manifest is invalid")]
    InvalidManifest,
    #[error("checkpoint artifact is invalid or non-canonical")]
    InvalidArtifact,
    #[error("checkpoint authority is not trusted")]
    UntrustedAuthority,
    #[error("checkpoint signature is invalid")]
    InvalidSignature,
    #[error("checkpoint signature threshold is not met")]
    ThresholdNotMet,
    #[error("checkpoint is outside the policy validity window")]
    OutsideValidityWindow,
    #[error("checkpoint does not match the independently expected root")]
    ExpectationMismatch,
}

pub fn checkpoint_policy_bytes(policy: &CheckpointPolicy) -> Result<Vec<u8>, CheckpointError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| CheckpointError::InvalidPolicy)?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(CheckpointError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn checkpoint_policy_sha256(policy: &CheckpointPolicy) -> Result<String, CheckpointError> {
    Ok(hash(&checkpoint_policy_bytes(policy)?))
}

pub fn parse_checkpoint_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<CheckpointPolicy, CheckpointError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || !valid_sha256(expected_policy_sha256) {
        return Err(CheckpointError::InvalidPolicy);
    }
    let policy: CheckpointPolicy =
        serde_json::from_slice(bytes).map_err(|_| CheckpointError::InvalidPolicy)?;
    if checkpoint_policy_bytes(&policy)? != bytes {
        return Err(CheckpointError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

/// Exact domain-separated bytes every external authority signs.
pub fn checkpoint_signature_message(
    root: &StateRoot,
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
    created_at_unix_seconds: u64,
) -> Result<Vec<u8>, CheckpointError> {
    let manifest = manifest(
        root,
        policy,
        expected_policy_sha256,
        created_at_unix_seconds,
    )?;
    signing_bytes(&manifest)
}

/// Assembles a canonical checkpoint only after verifying a threshold of
/// detached signatures. Signature entries are canonicalized by authority ID.
pub fn create_root_checkpoint(
    root: &StateRoot,
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
    created_at_unix_seconds: u64,
    signatures: &[DetachedCheckpointSignature],
) -> Result<Vec<u8>, CheckpointError> {
    let manifest = manifest(
        root,
        policy,
        expected_policy_sha256,
        created_at_unix_seconds,
    )?;
    let message = signing_bytes(&manifest)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let artifact = CheckpointArtifact {
        schema: ARTIFACT_SCHEMA.into(),
        manifest,
        signatures,
    };
    let bytes = serde_json::to_vec(&artifact).map_err(|_| CheckpointError::InvalidArtifact)?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(CheckpointError::InvalidArtifact);
    }
    Ok(bytes)
}

/// Verifies authentication, freshness and exact anti-rollback expectations.
/// The expected generation must come from outside the state-store host.
pub fn verify_root_checkpoint(
    artifact_bytes: &[u8],
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
    expected_generation: u64,
    expected_state_sha256: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedRootCheckpoint, CheckpointError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if artifact_bytes.is_empty()
        || artifact_bytes.len() > MAX_ARTIFACT_BYTES
        || !valid_sha256(expected_state_sha256)
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    let artifact: CheckpointArtifact =
        serde_json::from_slice(artifact_bytes).map_err(|_| CheckpointError::InvalidArtifact)?;
    if serde_json::to_vec(&artifact).map_err(|_| CheckpointError::InvalidArtifact)?
        != artifact_bytes
        || artifact.schema != ARTIFACT_SCHEMA
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    validate_manifest(&artifact.manifest, policy, expected_policy_sha256)?;
    validate_freshness(
        policy,
        artifact.manifest.created_at_unix_seconds,
        evaluated_at_unix_seconds,
    )?;
    if artifact.manifest.state_root.generation() != expected_generation
        || artifact.manifest.state_root.state_sha256() != expected_state_sha256
    {
        return Err(CheckpointError::ExpectationMismatch);
    }
    let message = signing_bytes(&artifact.manifest)?;
    verify_signatures(policy, &message, &artifact.signatures)?;
    Ok(VerifiedRootCheckpoint {
        root: artifact.manifest.state_root,
        checkpoint_policy_sha256: expected_policy_sha256.into(),
        checkpoint_sha256: hash(artifact_bytes),
        created_at_unix_seconds: artifact.manifest.created_at_unix_seconds,
        authority_ids: artifact
            .signatures
            .into_iter()
            .map(|signature| signature.authority_id)
            .collect(),
    })
}

fn manifest(
    root: &StateRoot,
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
    created_at_unix_seconds: u64,
) -> Result<CheckpointManifest, CheckpointError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_issue_time(policy, created_at_unix_seconds)?;
    if root.state_identity() != policy.state_identity {
        return Err(CheckpointError::ExpectationMismatch);
    }
    let manifest = CheckpointManifest {
        schema: MANIFEST_SCHEMA.into(),
        checkpoint_policy_sha256: expected_policy_sha256.into(),
        checkpoint_domain: policy.checkpoint_domain.clone(),
        state_root: root.clone(),
        created_at_unix_seconds,
    };
    validate_manifest(&manifest, policy, expected_policy_sha256)?;
    Ok(manifest)
}

fn validate_manifest(
    manifest: &CheckpointManifest,
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
) -> Result<(), CheckpointError> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.checkpoint_policy_sha256 != expected_policy_sha256
        || manifest.checkpoint_domain != policy.checkpoint_domain
        || manifest.state_root.state_identity() != policy.state_identity
        || !valid_sha256(manifest.state_root.state_sha256())
    {
        return Err(CheckpointError::InvalidManifest);
    }
    // Round-trip through the strict store parser so private root invariants are
    // not duplicated in this crate.
    bloch_local_state_store::parse_state_root(
        &manifest
            .state_root
            .canonical_bytes()
            .map_err(|_| CheckpointError::InvalidManifest)?,
    )
    .map_err(|_| CheckpointError::InvalidManifest)?;
    validate_issue_time(policy, manifest.created_at_unix_seconds)
}

fn validate_policy_pin(
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
) -> Result<(), CheckpointError> {
    if !valid_sha256(expected_policy_sha256)
        || checkpoint_policy_sha256(policy)? != expected_policy_sha256
    {
        return Err(CheckpointError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &CheckpointPolicy) -> Result<(), CheckpointError> {
    if policy.schema != POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.checkpoint_domain)
        || !valid_id(&policy.state_identity)
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || usize::from(policy.threshold) == 0
        || usize::from(policy.threshold) > policy.authorities.len()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_checkpoint_age_seconds == 0
        || policy.max_checkpoint_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(CheckpointError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    for authority in &policy.authorities {
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(CheckpointError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| CheckpointError::InvalidPolicy)?;
        if !valid_id(&authority.authority_id)
            || previous.is_some_and(|id| id >= authority.authority_id.as_str())
            || key.is_weak()
            || !public_keys.insert(key.to_bytes())
        {
            return Err(CheckpointError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_issue_time(policy: &CheckpointPolicy, timestamp: u64) -> Result<(), CheckpointError> {
    if timestamp < policy.effective_at_unix_seconds || timestamp > policy.expires_at_unix_seconds {
        return Err(CheckpointError::OutsideValidityWindow);
    }
    Ok(())
}

fn validate_freshness(
    policy: &CheckpointPolicy,
    issued_at: u64,
    evaluated_at: u64,
) -> Result<(), CheckpointError> {
    validate_issue_time(policy, issued_at)?;
    if evaluated_at < issued_at
        || evaluated_at > policy.expires_at_unix_seconds
        || evaluated_at - issued_at > policy.max_checkpoint_age_seconds
    {
        return Err(CheckpointError::OutsideValidityWindow);
    }
    Ok(())
}

fn signing_bytes(manifest: &CheckpointManifest) -> Result<Vec<u8>, CheckpointError> {
    let manifest = serde_json::to_vec(manifest).map_err(|_| CheckpointError::InvalidManifest)?;
    let mut bytes = Vec::with_capacity(SIGNING_PREFIX.len() + 8 + manifest.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest);
    Ok(bytes)
}

fn verify_signatures(
    policy: &CheckpointPolicy,
    message: &[u8],
    signatures: &[DetachedCheckpointSignature],
) -> Result<(), CheckpointError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(CheckpointError::ThresholdNotMet);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
            || !seen.insert(detached.authority_id.as_str())
        {
            return Err(CheckpointError::InvalidArtifact);
        }
        let authority = policy
            .authorities
            .binary_search_by(|authority| authority.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(CheckpointError::UntrustedAuthority)?;
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(CheckpointError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| CheckpointError::InvalidPolicy)?;
        let signature =
            decode_fixed::<64>(&detached.signature).ok_or(CheckpointError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| CheckpointError::InvalidSignature)?;
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
    use bloch_local_state_store::write_state;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn policy() -> (CheckpointPolicy, Vec<SigningKey>) {
        let keys = vec![key(1), key(2), key(3)];
        let authorities = keys
            .iter()
            .enumerate()
            .map(|(index, key)| CheckpointAuthority {
                authority_id: format!("authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect();
        (
            CheckpointPolicy {
                schema: POLICY_SCHEMA.into(),
                policy_id: "root-policy-a".into(),
                checkpoint_domain: "bloch-products-prod".into(),
                state_identity: "data:tenant-a:lifecycle".into(),
                threshold: 2,
                effective_at_unix_seconds: 100,
                expires_at_unix_seconds: 1_000,
                max_checkpoint_age_seconds: 100,
                authorities,
            },
            keys,
        )
    }

    fn root() -> StateRoot {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bloch-root-checkpoint-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let root = write_state(&path, "data:tenant-a:lifecycle", 0, b"state", None).unwrap();
        std::fs::remove_dir_all(path).unwrap();
        root
    }

    fn signed_artifact() -> (Vec<u8>, CheckpointPolicy, String, StateRoot) {
        let root = root();
        let (policy, keys) = policy();
        let pin = checkpoint_policy_sha256(&policy).unwrap();
        let message = checkpoint_signature_message(&root, &policy, &pin, 200).unwrap();
        let signatures: Vec<_> = keys[..2]
            .iter()
            .enumerate()
            .map(|(index, key)| DetachedCheckpointSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect();
        let artifact = create_root_checkpoint(&root, &policy, &pin, 200, &signatures).unwrap();
        (artifact, policy, pin, root)
    }

    #[test]
    fn verifies_threshold_checkpoint_against_exact_expectation() {
        let (artifact, policy, pin, root) = signed_artifact();
        let verified = verify_root_checkpoint(
            &artifact,
            &policy,
            &pin,
            root.generation(),
            root.state_sha256(),
            250,
        )
        .unwrap();
        assert_eq!(verified.root(), &root);
        assert_eq!(verified.authority_ids(), &["authority-1", "authority-2"]);
        assert!(!verified.authority_independence_proven());
        assert!(!verified.high_availability_proven());
    }

    #[test]
    fn insufficient_or_invalid_signatures_fail_closed() {
        let root = root();
        let (policy, keys) = policy();
        let pin = checkpoint_policy_sha256(&policy).unwrap();
        let message = checkpoint_signature_message(&root, &policy, &pin, 200).unwrap();
        let one = [DetachedCheckpointSignature {
            authority_id: "authority-1".into(),
            signature: format!("0x{}", hex::encode(keys[0].sign(&message).to_bytes())),
        }];
        assert!(matches!(
            create_root_checkpoint(&root, &policy, &pin, 200, &one),
            Err(CheckpointError::ThresholdNotMet)
        ));
        let wrong = [
            one[0].clone(),
            DetachedCheckpointSignature {
                authority_id: "authority-2".into(),
                signature: format!("0x{}", hex::encode(keys[2].sign(&message).to_bytes())),
            },
        ];
        assert!(matches!(
            create_root_checkpoint(&root, &policy, &pin, 200, &wrong),
            Err(CheckpointError::InvalidSignature)
        ));
    }

    #[test]
    fn rollback_expiry_and_noncanonical_inputs_fail_closed() {
        let (artifact, policy, pin, root) = signed_artifact();
        assert!(matches!(
            verify_root_checkpoint(&artifact, &policy, &pin, 1, root.state_sha256(), 250),
            Err(CheckpointError::ExpectationMismatch)
        ));
        assert!(matches!(
            verify_root_checkpoint(&artifact, &policy, &pin, 0, root.state_sha256(), 301),
            Err(CheckpointError::OutsideValidityWindow)
        ));
        let mut noncanonical = artifact;
        noncanonical.push(b'\n');
        assert!(matches!(
            verify_root_checkpoint(&noncanonical, &policy, &pin, 0, root.state_sha256(), 250),
            Err(CheckpointError::InvalidArtifact)
        ));
    }

    #[test]
    fn policy_requires_canonical_pin_and_sorted_distinct_authorities() {
        let (mut altered_policy, _) = policy();
        let bytes = checkpoint_policy_bytes(&altered_policy).unwrap();
        let pin = hash(&bytes);
        assert_eq!(
            parse_checkpoint_policy(&bytes, &pin).unwrap(),
            altered_policy
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(matches!(
            parse_checkpoint_policy(&noncanonical, &pin),
            Err(CheckpointError::InvalidPolicy)
        ));
        altered_policy.authorities.swap(0, 1);
        assert!(matches!(
            checkpoint_policy_bytes(&altered_policy),
            Err(CheckpointError::InvalidPolicy)
        ));

        let (mut duplicated_key_policy, _) = policy();
        duplicated_key_policy.authorities[1].ed25519_public_key = duplicated_key_policy.authorities
            [0]
        .ed25519_public_key
        .clone();
        assert!(matches!(
            checkpoint_policy_bytes(&duplicated_key_policy),
            Err(CheckpointError::InvalidPolicy)
        ));
    }
}
