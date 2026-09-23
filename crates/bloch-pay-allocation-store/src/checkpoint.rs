use super::*;
use ed25519_dalek::{Signature, VerifyingKey};

pub const CHECKPOINT_POLICY_SCHEMA: &str = "bloch.pay.allocation-checkpoint-policy.v1";
pub const CHECKPOINT_MANIFEST_SCHEMA: &str = "bloch.pay.allocation-checkpoint-manifest.v1";
pub const CHECKPOINT_ARTIFACT_SCHEMA: &str = "bloch.pay.allocation-checkpoint-artifact.v1";
const SIGNING_PREFIX: &[u8] = b"BLOCH-PAY-ALLOCATION-CHECKPOINT-V1\0";
const MAX_CHECKPOINT_BYTES: usize = MAX_STATE_BYTES as usize + 16 * 1024;

/// Independently pinned authority and scope for signing local-store snapshots.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckpointTrustPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub store_identity: String,
    pub signer_id: String,
    pub ed25519_public_key: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_checkpoint_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointManifest {
    schema: String,
    checkpoint_policy_sha256: String,
    store_identity: String,
    signer_id: String,
    generation: u64,
    state_sha256: String,
    created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointArtifact {
    schema: String,
    manifest: CheckpointManifest,
    state: StoreDocument,
    signature: String,
}

/// A fully verified canonical state copy. This attests only to snapshot
/// identity and integrity; it is not evidence of HA, quorum, or consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    artifact_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    store_identity: String,
    signer_id: String,
    checkpoint_policy_sha256: String,
    generation: u64,
    state_sha256: String,
    created_at_unix_seconds: u64,
}

impl VerifiedCheckpoint {
    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }
    pub fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }
    pub fn store_identity(&self) -> &str {
        &self.store_identity
    }
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }
    pub fn checkpoint_policy_sha256(&self) -> &str {
        &self.checkpoint_policy_sha256
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }
    pub fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }
    pub fn high_availability_proven(&self) -> bool {
        false
    }
    pub fn distributed_consistency_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint policy is invalid")]
    InvalidPolicy,
    #[error("checkpoint policy pin does not match canonical policy")]
    PolicyPinMismatch,
    #[error("checkpoint is outside the pinned policy validity window")]
    OutsideValidityWindow,
    #[error("checkpoint artifact is invalid or non-canonical")]
    InvalidArtifact,
    #[error("checkpoint signature is invalid")]
    InvalidSignature,
    #[error("checkpoint does not match the independently expected generation and state digest")]
    ExpectationMismatch,
    #[error("allocation state cannot be checkpointed: {0}")]
    Store(#[from] AllocationError),
}

pub fn checkpoint_policy_bytes(policy: &CheckpointTrustPolicy) -> Result<Vec<u8>, CheckpointError> {
    validate_policy(policy)?;
    serde_json::to_vec(policy).map_err(|_| CheckpointError::InvalidPolicy)
}

pub fn checkpoint_policy_sha256(policy: &CheckpointTrustPolicy) -> Result<String, CheckpointError> {
    Ok(hash(&checkpoint_policy_bytes(policy)?))
}

/// Returns the exact bytes an external Ed25519 authority must sign.
pub fn checkpoint_signing_bytes(
    store: &Path,
    policy: &CheckpointTrustPolicy,
    expected_policy_sha256: &str,
    created_at_unix_seconds: u64,
) -> Result<Vec<u8>, CheckpointError> {
    let (manifest, _) = snapshot(
        store,
        policy,
        expected_policy_sha256,
        created_at_unix_seconds,
    )?;
    signing_bytes(policy, &manifest)
}

/// Creates a canonical self-contained artifact after verifying the detached
/// external signature. No private-key or network operation occurs here.
pub fn create_checkpoint_artifact(
    store: &Path,
    policy: &CheckpointTrustPolicy,
    expected_policy_sha256: &str,
    created_at_unix_seconds: u64,
    signature: &[u8],
) -> Result<Vec<u8>, CheckpointError> {
    let (manifest, state) = snapshot(
        store,
        policy,
        expected_policy_sha256,
        created_at_unix_seconds,
    )?;
    verify_signature(policy, &signing_bytes(policy, &manifest)?, signature)?;
    let artifact = CheckpointArtifact {
        schema: CHECKPOINT_ARTIFACT_SCHEMA.into(),
        manifest,
        state,
        signature: format!("0x{}", hex::encode(signature)),
    };
    let bytes = serde_json::to_vec(&artifact).map_err(|_| CheckpointError::InvalidArtifact)?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(CheckpointError::InvalidArtifact);
    }
    Ok(bytes)
}

/// Verifies a complete embedded state copy against its generation, digest,
/// store identity, independent policy pin, validity window, and signature.
pub fn verify_checkpoint_artifact(
    artifact_bytes: &[u8],
    policy: &CheckpointTrustPolicy,
    expected_policy_sha256: &str,
    expected_generation: u64,
    expected_state_sha256: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedCheckpoint, CheckpointError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if !valid_sha256(expected_state_sha256) {
        return Err(CheckpointError::ExpectationMismatch);
    }
    if artifact_bytes.is_empty() || artifact_bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(CheckpointError::InvalidArtifact);
    }
    let artifact: CheckpointArtifact =
        serde_json::from_slice(artifact_bytes).map_err(|_| CheckpointError::InvalidArtifact)?;
    if serde_json::to_vec(&artifact).map_err(|_| CheckpointError::InvalidArtifact)?
        != artifact_bytes
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    validate_state(&artifact.state).map_err(|_| CheckpointError::InvalidArtifact)?;
    let state_bytes =
        serde_json::to_vec(&artifact.state).map_err(|_| CheckpointError::InvalidArtifact)?;
    let manifest = &artifact.manifest;
    if artifact.schema != CHECKPOINT_ARTIFACT_SCHEMA
        || manifest.schema != CHECKPOINT_MANIFEST_SCHEMA
        || manifest.checkpoint_policy_sha256 != expected_policy_sha256
        || manifest.store_identity != policy.store_identity
        || manifest.signer_id != policy.signer_id
        || manifest.generation != artifact.state.generation
        || manifest.state_sha256 != hash(&state_bytes)
        || !valid_sha256(&manifest.state_sha256)
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    if manifest.generation != expected_generation || manifest.state_sha256 != expected_state_sha256
    {
        return Err(CheckpointError::ExpectationMismatch);
    }
    validate_time(policy, manifest.created_at_unix_seconds)?;
    if evaluated_at_unix_seconds < manifest.created_at_unix_seconds
        || evaluated_at_unix_seconds > policy.expires_at_unix_seconds
        || evaluated_at_unix_seconds - manifest.created_at_unix_seconds
            > policy.max_checkpoint_age_seconds
    {
        return Err(CheckpointError::OutsideValidityWindow);
    }
    let signature =
        decode_fixed::<64>(&artifact.signature).ok_or(CheckpointError::InvalidArtifact)?;
    verify_signature(policy, &signing_bytes(policy, manifest)?, &signature)?;
    Ok(VerifiedCheckpoint {
        artifact_bytes: artifact_bytes.to_vec(),
        state_bytes,
        store_identity: manifest.store_identity.clone(),
        signer_id: manifest.signer_id.clone(),
        checkpoint_policy_sha256: manifest.checkpoint_policy_sha256.clone(),
        generation: manifest.generation,
        state_sha256: manifest.state_sha256.clone(),
        created_at_unix_seconds: manifest.created_at_unix_seconds,
    })
}

fn snapshot(
    store: &Path,
    policy: &CheckpointTrustPolicy,
    expected_pin: &str,
    created_at: u64,
) -> Result<(CheckpointManifest, StoreDocument), CheckpointError> {
    validate_policy_pin(policy, expected_pin)?;
    validate_time(policy, created_at)?;
    #[cfg(not(unix))]
    {
        let _ = store;
        Err(AllocationError::UnsupportedPlatform.into())
    }
    #[cfg(unix)]
    {
        let directory = open_or_create_store(store)?;
        let _lock = StoreLock::acquire(&directory)?;
        verify_store_path(store, &directory)?;
        let state = read_state(&directory)?.unwrap_or(StoreDocument {
            schema: STATE_SCHEMA.into(),
            generation: 0,
            allocations: Vec::new(),
        });
        validate_state(&state)?;
        let state_bytes =
            serde_json::to_vec(&state).map_err(|_| CheckpointError::InvalidArtifact)?;
        Ok((
            CheckpointManifest {
                schema: CHECKPOINT_MANIFEST_SCHEMA.into(),
                checkpoint_policy_sha256: expected_pin.into(),
                store_identity: policy.store_identity.clone(),
                signer_id: policy.signer_id.clone(),
                generation: state.generation,
                state_sha256: hash(&state_bytes),
                created_at_unix_seconds: created_at,
            },
            state,
        ))
    }
}

fn validate_policy_pin(policy: &CheckpointTrustPolicy, pin: &str) -> Result<(), CheckpointError> {
    if !valid_sha256(pin) {
        return Err(CheckpointError::PolicyPinMismatch);
    }
    let actual = checkpoint_policy_sha256(policy)?;
    if actual != pin {
        return Err(CheckpointError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &CheckpointTrustPolicy) -> Result<(), CheckpointError> {
    let key =
        decode_fixed::<32>(&policy.ed25519_public_key).ok_or(CheckpointError::InvalidPolicy)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| CheckpointError::InvalidPolicy)?;
    if policy.schema != CHECKPOINT_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.store_identity)
        || !valid_id(&policy.signer_id)
        || key.is_weak()
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_checkpoint_age_seconds == 0
        || policy.max_checkpoint_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(CheckpointError::InvalidPolicy);
    }
    Ok(())
}

fn validate_time(policy: &CheckpointTrustPolicy, timestamp: u64) -> Result<(), CheckpointError> {
    if timestamp < policy.effective_at_unix_seconds || timestamp > policy.expires_at_unix_seconds {
        return Err(CheckpointError::OutsideValidityWindow);
    }
    Ok(())
}

fn signing_bytes(
    policy: &CheckpointTrustPolicy,
    manifest: &CheckpointManifest,
) -> Result<Vec<u8>, CheckpointError> {
    let manifest = serde_json::to_vec(manifest).map_err(|_| CheckpointError::InvalidArtifact)?;
    let domain = policy.signature_domain.as_bytes();
    let mut bytes =
        Vec::with_capacity(SIGNING_PREFIX.len() + 8 + domain.len() + 8 + manifest.len());
    bytes.extend_from_slice(SIGNING_PREFIX);
    bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest);
    Ok(bytes)
}

fn verify_signature(
    policy: &CheckpointTrustPolicy,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CheckpointError> {
    let key =
        decode_fixed::<32>(&policy.ed25519_public_key).ok_or(CheckpointError::InvalidPolicy)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| CheckpointError::InvalidPolicy)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CheckpointError::InvalidSignature)?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| CheckpointError::InvalidSignature)
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != 2 + N * 2 || !value.starts_with("0x") {
        return None;
    }
    let decoded = hex::decode(&value[2..]).ok()?;
    decoded.try_into().ok()
}
