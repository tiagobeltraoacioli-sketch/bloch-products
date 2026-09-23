//! Offline, authority-resigned re-bootstrap from checkpoint/cursor v1 to v2.
//!
//! This crate never infers currentness. The caller must obtain both cursor
//! digests from an independent authenticated control plane. Legacy artifacts
//! that predate canonical state-root v2 cannot be migrated automatically.

use bloch_local_state_checkpoint::{
    CheckpointPolicy, VerifiedRootCheckpoint, authenticate_retained_root_checkpoint,
    parse_checkpoint_policy,
};
use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_store::{StateRoot, parse_state_root};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const LEGACY_MANIFEST_SCHEMA: &str = "bloch.products.local-state-checkpoint-manifest.v1";
pub const LEGACY_ARTIFACT_SCHEMA: &str = "bloch.products.local-state-checkpoint-artifact.v1";
pub const LEGACY_CURSOR_SCHEMA: &str = "bloch.products.local-state-checkpoint-cursor.v1";
pub const MAX_LEGACY_CURSOR_BYTES: usize = 4096;
const LEGACY_SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-LOCAL-STATE-CHECKPOINT-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LegacyManifest {
    schema: String,
    checkpoint_policy_sha256: String,
    checkpoint_domain: String,
    state_root: StateRoot,
    created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LegacySignature {
    authority_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LegacyArtifact {
    schema: String,
    manifest: LegacyManifest,
    signatures: Vec<LegacySignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LegacyCursor {
    schema: String,
    state_identity: String,
    generation: u64,
    checkpoint_sha256: String,
    checkpoint_policy_sha256: String,
    state_root_sha256: String,
    state_sha256: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RebootstrapError {
    #[error("legacy checkpoint policy or its independent pin is invalid")]
    InvalidLegacyPolicy,
    #[error("legacy checkpoint artifact is invalid, non-canonical, or unsupported")]
    InvalidLegacyArtifact,
    #[error("legacy checkpoint signature threshold is not authenticated")]
    InvalidLegacySignatures,
    #[error("legacy cursor is invalid or non-canonical")]
    InvalidLegacyCursor,
    #[error("legacy cursor digest does not match the independently supplied digest")]
    LegacyCursorPinMismatch,
    #[error("legacy checkpoint and cursor do not match exactly")]
    LegacyEvidenceMismatch,
    #[error("new v2 checkpoint policy, artifact, or signatures are invalid")]
    InvalidNewCheckpoint,
    #[error("new v2 cursor is invalid or non-canonical")]
    InvalidNewCursor,
    #[error("new v2 cursor digest does not match the independently supplied digest")]
    NewCursorPinMismatch,
    #[error("new checkpoint and cursor do not match exactly")]
    NewEvidenceMismatch,
    #[error("v1 to v2 continuity is not exact; automated migration is refused")]
    ContinuityMismatch,
    #[error("checkpoint policy rotation requires a separate externally authorized ceremony")]
    PolicyRotationRefused,
}

/// Verifies a narrow, offline re-bootstrap and returns the exact v2 cursor
/// bytes to publish create-only. The returned bytes do not prove currentness;
/// that property comes only from the independently supplied cursor digests.
#[allow(clippy::too_many_arguments)]
pub fn rebootstrap_v1_to_v2(
    legacy_artifact_bytes: &[u8],
    legacy_policy_bytes: &[u8],
    expected_legacy_policy_sha256: &str,
    legacy_cursor_bytes: &[u8],
    expected_legacy_cursor_sha256: &str,
    new_artifact_bytes: &[u8],
    new_policy_bytes: &[u8],
    expected_new_policy_sha256: &str,
    expected_semantic_manifest_sha256: &str,
    new_cursor_bytes: &[u8],
    expected_new_cursor_sha256: &str,
) -> Result<Vec<u8>, RebootstrapError> {
    require_hash(expected_legacy_cursor_sha256)
        .map_err(|_| RebootstrapError::LegacyCursorPinMismatch)?;
    require_hash(expected_new_cursor_sha256).map_err(|_| RebootstrapError::NewCursorPinMismatch)?;
    require_hash(expected_semantic_manifest_sha256)
        .map_err(|_| RebootstrapError::InvalidNewCheckpoint)?;
    if hash(legacy_cursor_bytes) != expected_legacy_cursor_sha256 {
        return Err(RebootstrapError::LegacyCursorPinMismatch);
    }
    if hash(new_cursor_bytes) != expected_new_cursor_sha256 {
        return Err(RebootstrapError::NewCursorPinMismatch);
    }

    let legacy_policy = parse_checkpoint_policy(legacy_policy_bytes, expected_legacy_policy_sha256)
        .map_err(|_| RebootstrapError::InvalidLegacyPolicy)?;
    let legacy_root = authenticate_legacy_artifact(
        legacy_artifact_bytes,
        &legacy_policy,
        expected_legacy_policy_sha256,
    )?;
    let legacy_cursor = parse_legacy_cursor(legacy_cursor_bytes)?;
    match_legacy(
        &legacy_cursor,
        legacy_artifact_bytes,
        expected_legacy_policy_sha256,
        &legacy_root,
    )?;

    if expected_new_policy_sha256 != expected_legacy_policy_sha256 {
        return Err(RebootstrapError::PolicyRotationRefused);
    }
    let new_policy = parse_checkpoint_policy(new_policy_bytes, expected_new_policy_sha256)
        .map_err(|_| RebootstrapError::InvalidNewCheckpoint)?;
    let new_checkpoint = authenticate_retained_root_checkpoint(
        new_artifact_bytes,
        &new_policy,
        expected_new_policy_sha256,
    )
    .map_err(|_| RebootstrapError::InvalidNewCheckpoint)?;
    if new_checkpoint.semantic_manifest_sha256() != expected_semantic_manifest_sha256 {
        return Err(RebootstrapError::NewEvidenceMismatch);
    }
    let new_cursor =
        parse_cursor(new_cursor_bytes).map_err(|_| RebootstrapError::InvalidNewCursor)?;
    match_new(&new_cursor, &new_checkpoint)?;

    if new_checkpoint.root() != &legacy_root
        || new_cursor.state_identity() != legacy_cursor.state_identity
        || new_cursor.generation() != legacy_cursor.generation
        || new_cursor.state_root_sha256() != legacy_cursor.state_root_sha256
        || new_cursor.state_sha256() != legacy_cursor.state_sha256
    {
        return Err(RebootstrapError::ContinuityMismatch);
    }
    new_cursor
        .canonical_bytes()
        .map_err(|_| RebootstrapError::InvalidNewCursor)
}

fn authenticate_legacy_artifact(
    bytes: &[u8],
    policy: &CheckpointPolicy,
    expected_policy_sha256: &str,
) -> Result<StateRoot, RebootstrapError> {
    if bytes.is_empty() || bytes.len() > bloch_local_state_checkpoint::MAX_ARTIFACT_BYTES {
        return Err(RebootstrapError::InvalidLegacyArtifact);
    }
    let artifact: LegacyArtifact =
        serde_json::from_slice(bytes).map_err(|_| RebootstrapError::InvalidLegacyArtifact)?;
    if serde_json::to_vec(&artifact).map_err(|_| RebootstrapError::InvalidLegacyArtifact)? != bytes
        || artifact.schema != LEGACY_ARTIFACT_SCHEMA
        || artifact.manifest.schema != LEGACY_MANIFEST_SCHEMA
        || artifact.manifest.checkpoint_policy_sha256 != expected_policy_sha256
        || artifact.manifest.checkpoint_domain != policy.checkpoint_domain
        || artifact.manifest.state_root.state_identity() != policy.state_identity
        || artifact.manifest.created_at_unix_seconds < policy.effective_at_unix_seconds
        || artifact.manifest.created_at_unix_seconds > policy.expires_at_unix_seconds
    {
        return Err(RebootstrapError::InvalidLegacyArtifact);
    }
    let root_bytes = artifact
        .manifest
        .state_root
        .canonical_bytes()
        .map_err(|_| RebootstrapError::InvalidLegacyArtifact)?;
    parse_state_root(&root_bytes).map_err(|_| RebootstrapError::InvalidLegacyArtifact)?;
    let message = legacy_signing_bytes(&artifact.manifest)?;
    verify_legacy_signatures(policy, &message, &artifact.signatures)?;
    Ok(artifact.manifest.state_root)
}

fn legacy_signing_bytes(manifest: &LegacyManifest) -> Result<Vec<u8>, RebootstrapError> {
    let manifest =
        serde_json::to_vec(manifest).map_err(|_| RebootstrapError::InvalidLegacyArtifact)?;
    let mut bytes = Vec::with_capacity(LEGACY_SIGNING_PREFIX.len() + 8 + manifest.len());
    bytes.extend_from_slice(LEGACY_SIGNING_PREFIX);
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest);
    Ok(bytes)
}

fn verify_legacy_signatures(
    policy: &CheckpointPolicy,
    message: &[u8],
    signatures: &[LegacySignature],
) -> Result<(), RebootstrapError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(RebootstrapError::InvalidLegacySignatures);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for detached in signatures {
        if previous.is_some_and(|value| value >= detached.authority_id.as_str())
            || !seen.insert(detached.authority_id.as_str())
        {
            return Err(RebootstrapError::InvalidLegacySignatures);
        }
        let authority = policy
            .authorities
            .binary_search_by(|value| value.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(RebootstrapError::InvalidLegacySignatures)?;
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(RebootstrapError::InvalidLegacySignatures)?;
        let key = VerifyingKey::from_bytes(&key)
            .map_err(|_| RebootstrapError::InvalidLegacySignatures)?;
        let signature = decode_fixed::<64>(&detached.signature)
            .ok_or(RebootstrapError::InvalidLegacySignatures)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| RebootstrapError::InvalidLegacySignatures)?;
        previous = Some(&detached.authority_id);
    }
    Ok(())
}

fn parse_legacy_cursor(bytes: &[u8]) -> Result<LegacyCursor, RebootstrapError> {
    if bytes.is_empty() || bytes.len() > MAX_LEGACY_CURSOR_BYTES {
        return Err(RebootstrapError::InvalidLegacyCursor);
    }
    let cursor: LegacyCursor =
        serde_json::from_slice(bytes).map_err(|_| RebootstrapError::InvalidLegacyCursor)?;
    if serde_json::to_vec(&cursor).map_err(|_| RebootstrapError::InvalidLegacyCursor)? != bytes
        || cursor.schema != LEGACY_CURSOR_SCHEMA
        || cursor.state_identity.is_empty()
        || cursor.state_identity.len() > 128
        || !cursor
            .state_identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || [
            cursor.checkpoint_sha256.as_str(),
            cursor.checkpoint_policy_sha256.as_str(),
            cursor.state_root_sha256.as_str(),
            cursor.state_sha256.as_str(),
        ]
        .into_iter()
        .any(|value| require_hash(value).is_err())
    {
        return Err(RebootstrapError::InvalidLegacyCursor);
    }
    Ok(cursor)
}

fn match_legacy(
    cursor: &LegacyCursor,
    artifact_bytes: &[u8],
    policy_sha256: &str,
    root: &StateRoot,
) -> Result<(), RebootstrapError> {
    let root_bytes = root
        .canonical_bytes()
        .map_err(|_| RebootstrapError::InvalidLegacyArtifact)?;
    if cursor.checkpoint_sha256 != hash(artifact_bytes)
        || cursor.checkpoint_policy_sha256 != policy_sha256
        || cursor.state_identity != root.state_identity()
        || cursor.generation != root.generation()
        || cursor.state_root_sha256 != hash(&root_bytes)
        || cursor.state_sha256 != root.state_sha256()
    {
        return Err(RebootstrapError::LegacyEvidenceMismatch);
    }
    Ok(())
}

fn match_new(
    cursor: &CheckpointCursor,
    checkpoint: &VerifiedRootCheckpoint,
) -> Result<(), RebootstrapError> {
    let root_bytes = checkpoint
        .root()
        .canonical_bytes()
        .map_err(|_| RebootstrapError::InvalidNewCheckpoint)?;
    if cursor.checkpoint_sha256() != checkpoint.checkpoint_sha256()
        || cursor.checkpoint_policy_sha256() != checkpoint.checkpoint_policy_sha256()
        || cursor.semantic_manifest_sha256() != checkpoint.semantic_manifest_sha256()
        || cursor.state_identity() != checkpoint.root().state_identity()
        || cursor.generation() != checkpoint.root().generation()
        || cursor.state_root_sha256() != hash(&root_bytes)
        || cursor.state_sha256() != checkpoint.root().state_sha256()
    {
        return Err(RebootstrapError::NewEvidenceMismatch);
    }
    Ok(())
}

fn require_hash(value: &str) -> Result<(), ()> {
    if value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(())
    }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use bloch_local_state_checkpoint::{
        CheckpointAuthority, DetachedCheckpointSignature, POLICY_SCHEMA, checkpoint_policy_bytes,
        checkpoint_policy_sha256, checkpoint_signature_message, create_root_checkpoint,
    };
    use bloch_local_state_store::write_state;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct NewCursorWire<'a> {
        schema: &'a str,
        state_identity: &'a str,
        generation: u64,
        checkpoint_sha256: String,
        checkpoint_policy_sha256: &'a str,
        semantic_manifest_sha256: &'a str,
        state_root_sha256: String,
        state_sha256: &'a str,
    }

    struct Fixture {
        legacy_artifact: Vec<u8>,
        policy: Vec<u8>,
        policy_sha256: String,
        legacy_cursor: Vec<u8>,
        new_artifact: Vec<u8>,
        semantic_sha256: String,
        new_cursor: Vec<u8>,
    }

    #[test]
    fn rebootstrap_requires_resigned_v2_evidence_and_preserves_exact_root() {
        let fixture = fixture(b"current-state");
        let output = rebootstrap_v1_to_v2(
            &fixture.legacy_artifact,
            &fixture.policy,
            &fixture.policy_sha256,
            &fixture.legacy_cursor,
            &hash(&fixture.legacy_cursor),
            &fixture.new_artifact,
            &fixture.policy,
            &fixture.policy_sha256,
            &fixture.semantic_sha256,
            &fixture.new_cursor,
            &hash(&fixture.new_cursor),
        )
        .unwrap();
        assert_eq!(output, fixture.new_cursor);
        parse_cursor(&output).unwrap();
    }

    #[test]
    fn cursor_pins_are_never_inferred_from_local_inputs() {
        let fixture = fixture(b"current-state");
        let wrong = format!("0x{}", "f".repeat(64));
        assert_eq!(
            rebootstrap_v1_to_v2(
                &fixture.legacy_artifact,
                &fixture.policy,
                &fixture.policy_sha256,
                &fixture.legacy_cursor,
                &wrong,
                &fixture.new_artifact,
                &fixture.policy,
                &fixture.policy_sha256,
                &fixture.semantic_sha256,
                &fixture.new_cursor,
                &hash(&fixture.new_cursor),
            ),
            Err(RebootstrapError::LegacyCursorPinMismatch)
        );
    }

    #[test]
    fn a_resigned_different_root_is_not_a_migration() {
        let legacy = fixture(b"legacy-state");
        let replacement = fixture(b"replacement-state");
        assert_eq!(
            rebootstrap_v1_to_v2(
                &legacy.legacy_artifact,
                &legacy.policy,
                &legacy.policy_sha256,
                &legacy.legacy_cursor,
                &hash(&legacy.legacy_cursor),
                &replacement.new_artifact,
                &replacement.policy,
                &replacement.policy_sha256,
                &replacement.semantic_sha256,
                &replacement.new_cursor,
                &hash(&replacement.new_cursor),
            ),
            Err(RebootstrapError::ContinuityMismatch)
        );
    }

    #[test]
    fn legacy_root_v1_is_explicitly_unsupported() {
        let fixture = fixture(b"current-state");
        let value: serde_json::Value = serde_json::from_slice(&fixture.legacy_artifact).unwrap();
        let mut value = value;
        value["manifest"]["stateRoot"]["schema"] =
            serde_json::Value::String("bloch.products.local-state-root.v1".into());
        value["manifest"]["stateRoot"]
            .as_object_mut()
            .unwrap()
            .remove("previousRootSha256");
        let unsupported = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            authenticate_legacy_artifact(
                &unsupported,
                &parse_checkpoint_policy(&fixture.policy, &fixture.policy_sha256).unwrap(),
                &fixture.policy_sha256,
            ),
            Err(RebootstrapError::InvalidLegacyArtifact)
        );
    }

    fn fixture(state: &[u8]) -> Fixture {
        let keys = [
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[43; 32]),
        ];
        let policy = CheckpointPolicy {
            schema: POLICY_SCHEMA.into(),
            policy_id: "rebootstrap-policy".into(),
            checkpoint_domain: "bloch-products-prod".into(),
            state_identity: "data:tenant-a:lifecycle".into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_checkpoint_age_seconds: 100,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CheckpointAuthority {
                    authority_id: format!("authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().to_bytes())
                    ),
                })
                .collect(),
        };
        let policy_sha256 = checkpoint_policy_sha256(&policy).unwrap();
        let policy_bytes = checkpoint_policy_bytes(&policy).unwrap();
        let path = temporary_path();
        let root = write_state(&path, &policy.state_identity, 0, state, None).unwrap();
        std::fs::remove_dir_all(path).unwrap();

        let manifest = LegacyManifest {
            schema: LEGACY_MANIFEST_SCHEMA.into(),
            checkpoint_policy_sha256: policy_sha256.clone(),
            checkpoint_domain: policy.checkpoint_domain.clone(),
            state_root: root.clone(),
            created_at_unix_seconds: 200,
        };
        let legacy_message = legacy_signing_bytes(&manifest).unwrap();
        let legacy_artifact = serde_json::to_vec(&LegacyArtifact {
            schema: LEGACY_ARTIFACT_SCHEMA.into(),
            manifest,
            signatures: keys
                .iter()
                .enumerate()
                .map(|(index, key)| LegacySignature {
                    authority_id: format!("authority-{}", index + 1),
                    signature: format!("0x{}", hex::encode(key.sign(&legacy_message).to_bytes())),
                })
                .collect(),
        })
        .unwrap();
        let root_bytes = root.canonical_bytes().unwrap();
        let legacy_cursor = serde_json::to_vec(&LegacyCursor {
            schema: LEGACY_CURSOR_SCHEMA.into(),
            state_identity: root.state_identity().into(),
            generation: root.generation(),
            checkpoint_sha256: hash(&legacy_artifact),
            checkpoint_policy_sha256: policy_sha256.clone(),
            state_root_sha256: hash(&root_bytes),
            state_sha256: root.state_sha256().into(),
        })
        .unwrap();

        let semantic_sha256 = format!("0x{}", "a".repeat(64));
        let new_message =
            checkpoint_signature_message(&root, &policy, &policy_sha256, &semantic_sha256, 200)
                .unwrap();
        let signatures: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, key)| DetachedCheckpointSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&new_message).to_bytes())),
            })
            .collect();
        let new_artifact = create_root_checkpoint(
            &root,
            &policy,
            &policy_sha256,
            &semantic_sha256,
            200,
            &signatures,
        )
        .unwrap();
        let new_cursor = serde_json::to_vec(&NewCursorWire {
            schema: bloch_local_state_cursor::CURSOR_SCHEMA,
            state_identity: root.state_identity(),
            generation: root.generation(),
            checkpoint_sha256: hash(&new_artifact),
            checkpoint_policy_sha256: &policy_sha256,
            semantic_manifest_sha256: &semantic_sha256,
            state_root_sha256: hash(&root_bytes),
            state_sha256: root.state_sha256(),
        })
        .unwrap();
        Fixture {
            legacy_artifact,
            policy: policy_bytes,
            policy_sha256,
            legacy_cursor,
            new_artifact,
            semantic_sha256,
            new_cursor,
        }
    }

    fn temporary_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bloch-rebootstrap-test-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
