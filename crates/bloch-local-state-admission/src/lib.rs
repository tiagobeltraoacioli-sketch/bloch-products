//! Read-only startup admission for persisted Bloch Data and Bloch Pay state.
//!
//! This composes independent checkpoint, cursor and semantic expectations. It
//! does not serialize admission with a concurrent writer; production callers
//! must provide an outer lock shared with every state/cursor writer.

use bloch_data_governance::{
    LifecycleError, LifecyclePolicy, LifecycleState, LifecycleStateExpectation,
    parse_lifecycle_policy, restore_lifecycle_state,
};
use bloch_local_state_checkpoint::{
    CheckpointError, authenticate_retained_root_checkpoint, parse_checkpoint_policy,
};
use bloch_local_state_cursor::{CheckpointCursor, CursorError, verify_admitted_checkpoint};
use bloch_local_state_store::{StoreError, load_state};
use bloch_pay_adjustments::{
    AdjustmentError, AdjustmentState, AdjustmentStateExpectation, restore_adjustment_state,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

pub const DATA_SEMANTIC_MANIFEST_SCHEMA: &str =
    "bloch.products.local-state-data-lifecycle-semantics.v1";
pub const PAY_SEMANTIC_MANIFEST_SCHEMA: &str =
    "bloch.products.local-state-pay-adjustment-semantics.v1";
pub const MAX_SEMANTIC_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataLifecycleSemanticManifest {
    pub schema: String,
    pub state_identity: String,
    pub lifecycle_policy_sha256: String,
    pub governance_policy_sha256: String,
    pub dataset_schema_sha256: String,
    pub record_sha256: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PayAdjustmentSemanticManifest {
    pub schema: String,
    pub state_identity: String,
    pub adjustment_policy_sha256: String,
    pub reconciliation_policy_sha256: String,
    pub adjustment_id: String,
    pub payment_observation_id: String,
    pub payment_observation_sha256: String,
    pub payment_amount_minor: u64,
    pub generation: u64,
}

pub struct StartupAdmission<'a> {
    pub artifact_bytes: &'a [u8],
    pub checkpoint_policy_bytes: &'a [u8],
    pub expected_checkpoint_policy_sha256: &'a str,
    pub semantic_manifest_bytes: &'a [u8],
    pub expected_semantic_manifest_sha256: &'a str,
    pub expected_cursor: &'a CheckpointCursor,
    pub cursor_store: &'a Path,
    pub state_store: &'a Path,
}

pub struct DataLifecycleAdmission<'a> {
    pub startup: StartupAdmission<'a>,
    pub lifecycle_policy_bytes: &'a [u8],
}

pub struct PayAdjustmentAdmission<'a> {
    pub startup: StartupAdmission<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEvidence {
    state_identity: String,
    generation: u64,
    state_sha256: String,
    checkpoint_sha256: String,
    checkpoint_policy_sha256: String,
    semantic_manifest_sha256: String,
}

impl AdmissionEvidence {
    pub fn state_identity(&self) -> &str {
        &self.state_identity
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }
    pub fn checkpoint_sha256(&self) -> &str {
        &self.checkpoint_sha256
    }
    pub fn checkpoint_policy_sha256(&self) -> &str {
        &self.checkpoint_policy_sha256
    }
    pub fn semantic_manifest_sha256(&self) -> &str {
        &self.semantic_manifest_sha256
    }
    pub fn concurrent_writer_excluded(&self) -> bool {
        false
    }
    pub fn regulatory_compliance_proven(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedLifecycleState {
    state: LifecycleState,
    evidence: AdmissionEvidence,
}

impl AdmittedLifecycleState {
    pub fn state(&self) -> &LifecycleState {
        &self.state
    }
    pub fn evidence(&self) -> &AdmissionEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedAdjustmentState {
    state: AdjustmentState,
    evidence: AdmissionEvidence,
}

impl AdmittedAdjustmentState {
    pub fn state(&self) -> &AdjustmentState {
        &self.state
    }
    pub fn evidence(&self) -> &AdmissionEvidence {
        &self.evidence
    }
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("semantic manifest is invalid or non-canonical")]
    InvalidSemanticManifest,
    #[error("semantic manifest does not match the independent digest pin")]
    SemanticManifestPinMismatch,
    #[error("semantic manifest does not match the authenticated state context")]
    SemanticContextMismatch,
    #[error("checkpoint authentication failed")]
    Checkpoint(#[source] CheckpointError),
    #[error("checkpoint cursor admission failed")]
    Cursor(#[source] CursorError),
    #[error("exact local state load failed")]
    Store(#[source] StoreError),
    #[error("Bloch Data lifecycle semantic restoration failed")]
    Lifecycle(#[source] LifecycleError),
    #[error("Bloch Pay adjustment semantic restoration failed")]
    Adjustment(#[source] AdjustmentError),
    #[error("state changed while startup admission was being checked")]
    StateChangedDuringAdmission,
}

pub fn data_semantic_manifest_bytes(
    manifest: &DataLifecycleSemanticManifest,
) -> Result<Vec<u8>, AdmissionError> {
    validate_data_manifest(manifest)?;
    bounded_json(manifest)
}

pub fn data_semantic_manifest_sha256(
    manifest: &DataLifecycleSemanticManifest,
) -> Result<String, AdmissionError> {
    Ok(hash(&data_semantic_manifest_bytes(manifest)?))
}

pub fn parse_data_semantic_manifest(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<DataLifecycleSemanticManifest, AdmissionError> {
    parse_manifest(bytes, expected_sha256, validate_data_manifest)
}

pub fn pay_semantic_manifest_bytes(
    manifest: &PayAdjustmentSemanticManifest,
) -> Result<Vec<u8>, AdmissionError> {
    validate_pay_manifest(manifest)?;
    bounded_json(manifest)
}

pub fn pay_semantic_manifest_sha256(
    manifest: &PayAdjustmentSemanticManifest,
) -> Result<String, AdmissionError> {
    Ok(hash(&pay_semantic_manifest_bytes(manifest)?))
}

pub fn parse_pay_semantic_manifest(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<PayAdjustmentSemanticManifest, AdmissionError> {
    parse_manifest(bytes, expected_sha256, validate_pay_manifest)
}

pub fn admit_data_lifecycle(
    admission: DataLifecycleAdmission<'_>,
) -> Result<AdmittedLifecycleState, AdmissionError> {
    let manifest = parse_data_semantic_manifest(
        admission.startup.semantic_manifest_bytes,
        admission.startup.expected_semantic_manifest_sha256,
    )?;
    let policy: LifecyclePolicy = parse_lifecycle_policy(
        admission.lifecycle_policy_bytes,
        &manifest.lifecycle_policy_sha256,
    )
    .map_err(AdmissionError::Lifecycle)?;
    let (verified, bytes) = authenticate_and_load(&admission.startup)?;
    if manifest.state_identity != verified.root().state_identity()
        || manifest.sequence != verified.root().generation()
    {
        return Err(AdmissionError::SemanticContextMismatch);
    }
    let state = restore_lifecycle_state(
        &bytes,
        &policy,
        LifecycleStateExpectation {
            lifecycle_policy_sha256: &manifest.lifecycle_policy_sha256,
            governance_policy_sha256: &manifest.governance_policy_sha256,
            dataset_schema_sha256: &manifest.dataset_schema_sha256,
            record_sha256: &manifest.record_sha256,
            sequence: manifest.sequence,
            state_sha256: verified.root().state_sha256(),
        },
    )
    .map_err(AdmissionError::Lifecycle)?;
    recheck(&admission.startup, &verified, &bytes)?;
    Ok(AdmittedLifecycleState {
        state,
        evidence: evidence(&verified),
    })
}

pub fn admit_pay_adjustment(
    admission: PayAdjustmentAdmission<'_>,
) -> Result<AdmittedAdjustmentState, AdmissionError> {
    let manifest = parse_pay_semantic_manifest(
        admission.startup.semantic_manifest_bytes,
        admission.startup.expected_semantic_manifest_sha256,
    )?;
    let (verified, bytes) = authenticate_and_load(&admission.startup)?;
    if manifest.state_identity != verified.root().state_identity()
        || manifest.generation != verified.root().generation()
    {
        return Err(AdmissionError::SemanticContextMismatch);
    }
    let state = restore_adjustment_state(
        &bytes,
        AdjustmentStateExpectation {
            adjustment_policy_sha256: &manifest.adjustment_policy_sha256,
            reconciliation_policy_sha256: &manifest.reconciliation_policy_sha256,
            adjustment_id: &manifest.adjustment_id,
            payment_observation_id: &manifest.payment_observation_id,
            payment_observation_sha256: &manifest.payment_observation_sha256,
            payment_amount_minor: manifest.payment_amount_minor,
            generation: manifest.generation,
            state_sha256: verified.root().state_sha256(),
        },
    )
    .map_err(AdmissionError::Adjustment)?;
    recheck(&admission.startup, &verified, &bytes)?;
    Ok(AdmittedAdjustmentState {
        state,
        evidence: evidence(&verified),
    })
}

fn authenticate_and_load(
    startup: &StartupAdmission<'_>,
) -> Result<
    (
        bloch_local_state_checkpoint::VerifiedRootCheckpoint,
        Vec<u8>,
    ),
    AdmissionError,
> {
    let policy = parse_checkpoint_policy(
        startup.checkpoint_policy_bytes,
        startup.expected_checkpoint_policy_sha256,
    )
    .map_err(AdmissionError::Checkpoint)?;
    let verified = authenticate_retained_root_checkpoint(
        startup.artifact_bytes,
        &policy,
        startup.expected_checkpoint_policy_sha256,
    )
    .map_err(AdmissionError::Checkpoint)?;
    if verified.semantic_manifest_sha256() != startup.expected_semantic_manifest_sha256 {
        return Err(AdmissionError::SemanticManifestPinMismatch);
    }
    verify_admitted_checkpoint(startup.cursor_store, &verified, startup.expected_cursor)
        .map_err(AdmissionError::Cursor)?;
    let bytes = load_state(startup.state_store, verified.root()).map_err(AdmissionError::Store)?;
    Ok((verified, bytes))
}

fn recheck(
    startup: &StartupAdmission<'_>,
    verified: &bloch_local_state_checkpoint::VerifiedRootCheckpoint,
    bytes: &[u8],
) -> Result<(), AdmissionError> {
    verify_admitted_checkpoint(startup.cursor_store, verified, startup.expected_cursor)
        .map_err(AdmissionError::Cursor)?;
    let current =
        load_state(startup.state_store, verified.root()).map_err(AdmissionError::Store)?;
    if current != bytes {
        return Err(AdmissionError::StateChangedDuringAdmission);
    }
    Ok(())
}

fn evidence(verified: &bloch_local_state_checkpoint::VerifiedRootCheckpoint) -> AdmissionEvidence {
    AdmissionEvidence {
        state_identity: verified.root().state_identity().into(),
        generation: verified.root().generation(),
        state_sha256: verified.root().state_sha256().into(),
        checkpoint_sha256: verified.checkpoint_sha256().into(),
        checkpoint_policy_sha256: verified.checkpoint_policy_sha256().into(),
        semantic_manifest_sha256: verified.semantic_manifest_sha256().into(),
    }
}

fn parse_manifest<T>(
    bytes: &[u8],
    expected_sha256: &str,
    validate: fn(&T) -> Result<(), AdmissionError>,
) -> Result<T, AdmissionError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_SEMANTIC_MANIFEST_BYTES {
        return Err(AdmissionError::InvalidSemanticManifest);
    }
    if !valid_sha256(expected_sha256) || hash(bytes) != expected_sha256 {
        return Err(AdmissionError::SemanticManifestPinMismatch);
    }
    let manifest =
        serde_json::from_slice(bytes).map_err(|_| AdmissionError::InvalidSemanticManifest)?;
    validate(&manifest)?;
    if serde_json::to_vec(&manifest).map_err(|_| AdmissionError::InvalidSemanticManifest)? != bytes
    {
        return Err(AdmissionError::InvalidSemanticManifest);
    }
    Ok(manifest)
}

fn bounded_json<T: Serialize>(value: &T) -> Result<Vec<u8>, AdmissionError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AdmissionError::InvalidSemanticManifest)?;
    if bytes.is_empty() || bytes.len() > MAX_SEMANTIC_MANIFEST_BYTES {
        return Err(AdmissionError::InvalidSemanticManifest);
    }
    Ok(bytes)
}

fn validate_data_manifest(manifest: &DataLifecycleSemanticManifest) -> Result<(), AdmissionError> {
    if manifest.schema != DATA_SEMANTIC_MANIFEST_SCHEMA
        || !valid_id(&manifest.state_identity)
        || !valid_sha256(&manifest.lifecycle_policy_sha256)
        || !valid_sha256(&manifest.governance_policy_sha256)
        || !valid_sha256(&manifest.dataset_schema_sha256)
        || !valid_sha256(&manifest.record_sha256)
    {
        return Err(AdmissionError::InvalidSemanticManifest);
    }
    Ok(())
}

fn validate_pay_manifest(manifest: &PayAdjustmentSemanticManifest) -> Result<(), AdmissionError> {
    if manifest.schema != PAY_SEMANTIC_MANIFEST_SCHEMA
        || !valid_id(&manifest.state_identity)
        || !valid_sha256(&manifest.adjustment_policy_sha256)
        || !valid_sha256(&manifest.reconciliation_policy_sha256)
        || !valid_id(&manifest.adjustment_id)
        || !valid_id(&manifest.payment_observation_id)
        || !valid_sha256(&manifest.payment_observation_sha256)
    {
        return Err(AdmissionError::InvalidSemanticManifest);
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

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
