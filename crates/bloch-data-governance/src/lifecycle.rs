//! Offline lifecycle authorization for already admitted JSON records.
//!
//! The state machine records signed intent and evidence identity. It never
//! performs deletion/anonymization, inspects backups, or establishes legal or
//! regulatory compliance.

use crate::{
    AuthorizedJsonIngestion, GovernancePolicy, RetentionDisposition, governance_policy_sha256,
    valid_identifier,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const LIFECYCLE_POLICY_SCHEMA: &str = "bloch.data.lifecycle-policy.v1";
pub const LIFECYCLE_TRANSITION_SCHEMA: &str = "bloch.data.lifecycle-transition.v1";
pub const LIFECYCLE_STATE_SCHEMA: &str = "bloch.data.lifecycle-state.v1";
pub const MAX_LIFECYCLE_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_LIFECYCLE_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_LIFECYCLE_ACTORS: usize = 256;
pub const MAX_LIFECYCLE_EVENTS: usize = 4_096;
const SIGNATURE_PROTOCOL_DOMAIN: &[u8] = b"BLOCH-DATA-LIFECYCLE-TRANSITION-V1\0";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActorRole {
    LegalHoldAuthority,
    DisposalAuthority,
    EvidenceRecorder,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LifecycleActor {
    pub actor_id: String,
    pub role: LifecycleActorRole,
    pub ed25519_public_key: String,
}

/// Independently pinned public authority policy. Its retention facts must
/// exactly match the governance policy admitted with the record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LifecyclePolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub governance_policy_sha256: String,
    pub dataset_schema_sha256: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub dispose_after_unix_seconds: u64,
    pub disposition: RetentionDisposition,
    pub initial_legal_hold_id: Option<String>,
    pub actors: Vec<LifecycleActor>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LifecycleAction {
    PlaceLegalHold {
        hold_id: String,
    },
    ReleaseLegalHold {
        hold_id: String,
    },
    OrderDisposal {
        order_id: String,
        disposition: RetentionDisposition,
    },
    ConfirmDisposalEvidence {
        order_id: String,
        evidence_id: String,
        evidence_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LifecycleTransitionRequest {
    pub schema: String,
    pub lifecycle_policy_sha256: String,
    pub record_sha256: String,
    pub prior_state_sha256: String,
    pub sequence: u64,
    pub occurred_at_unix_seconds: u64,
    pub actor_id: String,
    pub action: LifecycleAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    Retained,
    DisposalOrdered,
    EvidenceRecorded,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LifecycleEvent {
    sequence: u64,
    occurred_at_unix_seconds: u64,
    actor_id: String,
    action: LifecycleAction,
    request_sha256: String,
    signature: String,
}

/// Canonical audit state. Private fields prevent construction of a terminal
/// state without a verified transition.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleState {
    schema: String,
    lifecycle_policy_sha256: String,
    governance_policy_sha256: String,
    dataset_schema_sha256: String,
    record_sha256: String,
    dispose_after_unix_seconds: u64,
    disposition: RetentionDisposition,
    sequence: u64,
    phase: LifecyclePhase,
    active_legal_hold_id: Option<String>,
    disposal_order_id: Option<String>,
    evidence_id: Option<String>,
    evidence_sha256: Option<String>,
    events: Vec<LifecycleEvent>,
}

impl LifecycleState {
    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn phase(&self) -> LifecyclePhase {
        self.phase
    }
    pub fn active_legal_hold_id(&self) -> Option<&str> {
        self.active_legal_hold_id.as_deref()
    }
    pub fn disposal_order_id(&self) -> Option<&str> {
        self.disposal_order_id.as_deref()
    }
    pub fn evidence_id(&self) -> Option<&str> {
        self.evidence_id.as_deref()
    }
    pub fn evidence_sha256(&self) -> Option<&str> {
        self.evidence_sha256.as_deref()
    }
    pub fn lifecycle_policy_sha256(&self) -> &str {
        &self.lifecycle_policy_sha256
    }
    pub fn state_sha256(&self) -> Result<String, LifecycleError> {
        Ok(hash(&lifecycle_state_bytes(self)?))
    }
    pub fn physical_deletion_proven(&self) -> bool {
        false
    }
    pub fn backup_purge_proven(&self) -> bool {
        false
    }
    pub fn irreversible_anonymization_proven(&self) -> bool {
        false
    }
    pub fn regulatory_compliance_proven(&self) -> bool {
        false
    }
    pub fn external_execution_succeeded(&self) -> bool {
        false
    }
}

/// Opaque, exact-state-bound capability returned after signature verification.
#[derive(Clone, Debug)]
pub struct AuthorizedLifecycleTransition {
    request: LifecycleTransitionRequest,
    request_sha256: String,
    signature: [u8; 64],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("lifecycle input is empty")]
    Empty,
    #[error("lifecycle input exceeds its byte limit")]
    TooLarge,
    #[error("invalid lifecycle JSON: {0}")]
    InvalidJson(String),
    #[error("invalid lifecycle field: {0}")]
    InvalidField(&'static str),
    #[error("lifecycle JSON is not canonical")]
    NonCanonical,
    #[error("lifecycle policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("lifecycle policy does not match the admitted record")]
    AdmissionMismatch,
    #[error("lifecycle transition is outside the policy validity window")]
    OutsideValidityWindow,
    #[error("lifecycle actor is not authorized for this action")]
    UnauthorizedActor,
    #[error("invalid lifecycle transition signature")]
    InvalidSignature,
    #[error("lifecycle transition does not match the current state")]
    StateMismatch,
    #[error("lifecycle transition is denied by retention or legal-hold state")]
    TransitionDenied,
    #[error("cannot encode lifecycle artifact")]
    Encoding,
}

pub fn canonical_lifecycle_policy_bytes(
    policy: &LifecyclePolicy,
) -> Result<Vec<u8>, LifecycleError> {
    validate_policy(policy)?;
    serde_json::to_vec(policy).map_err(|_| LifecycleError::Encoding)
}

pub fn lifecycle_policy_sha256(policy: &LifecyclePolicy) -> Result<String, LifecycleError> {
    Ok(hash(&canonical_lifecycle_policy_bytes(policy)?))
}

pub fn parse_lifecycle_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<LifecyclePolicy, LifecycleError> {
    if bytes.is_empty() {
        return Err(LifecycleError::Empty);
    }
    if bytes.len() > MAX_LIFECYCLE_POLICY_BYTES {
        return Err(LifecycleError::TooLarge);
    }
    require_hash(expected_sha256, "expectedSha256")?;
    let policy: LifecyclePolicy = serde_json::from_slice(bytes)
        .map_err(|error| LifecycleError::InvalidJson(error.to_string()))?;
    if canonical_lifecycle_policy_bytes(&policy)? != bytes {
        return Err(LifecycleError::NonCanonical);
    }
    if hash(bytes) != expected_sha256 {
        return Err(LifecycleError::PolicyDigestMismatch);
    }
    Ok(policy)
}

pub fn initialize_lifecycle_state(
    ingestion: &AuthorizedJsonIngestion,
    governance_policy: &GovernancePolicy,
    policy: &LifecyclePolicy,
    expected_policy_sha256: &str,
    initialized_at_unix_seconds: u64,
) -> Result<LifecycleState, LifecycleError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let governance_sha = governance_policy_sha256(governance_policy)
        .map_err(|_| LifecycleError::AdmissionMismatch)?;
    if ingestion.authorization().policy_sha256() != governance_sha
        || policy.governance_policy_sha256 != governance_sha
        || ingestion.dataset_schema_sha256() != policy.dataset_schema_sha256
        || policy.dispose_after_unix_seconds
            != governance_policy.retention.dispose_after_unix_seconds
        || policy.disposition != governance_policy.retention.disposition
        || policy.initial_legal_hold_id != governance_policy.retention.legal_hold_id
    {
        return Err(LifecycleError::AdmissionMismatch);
    }
    validate_time(
        policy,
        initialized_at_unix_seconds,
        initialized_at_unix_seconds,
    )?;
    Ok(LifecycleState {
        schema: LIFECYCLE_STATE_SCHEMA.into(),
        lifecycle_policy_sha256: expected_policy_sha256.into(),
        governance_policy_sha256: governance_sha,
        dataset_schema_sha256: ingestion.dataset_schema_sha256().into(),
        record_sha256: ingestion.record_sha256().into(),
        dispose_after_unix_seconds: policy.dispose_after_unix_seconds,
        disposition: policy.disposition,
        sequence: 0,
        phase: LifecyclePhase::Retained,
        active_legal_hold_id: policy.initial_legal_hold_id.clone(),
        disposal_order_id: None,
        evidence_id: None,
        evidence_sha256: None,
        events: Vec::new(),
    })
}

/// Returns exact, length-framed bytes for an external Ed25519 signer.
pub fn lifecycle_transition_signing_bytes(
    state: &LifecycleState,
    policy: &LifecyclePolicy,
    expected_policy_sha256: &str,
    request: &LifecycleTransitionRequest,
    evaluated_at_unix_seconds: u64,
) -> Result<Vec<u8>, LifecycleError> {
    let actor = validate_transition_context(
        state,
        policy,
        expected_policy_sha256,
        request,
        evaluated_at_unix_seconds,
    )?;
    let request_bytes = canonical_request_bytes(request)?;
    let mut output = Vec::with_capacity(request_bytes.len() + 512);
    append(&mut output, SIGNATURE_PROTOCOL_DOMAIN)?;
    append(&mut output, policy.signature_domain.as_bytes())?;
    append(&mut output, expected_policy_sha256.as_bytes())?;
    append(&mut output, actor.actor_id.as_bytes())?;
    append(&mut output, &request_bytes)?;
    Ok(output)
}

pub fn authorize_lifecycle_transition(
    state: &LifecycleState,
    policy: &LifecyclePolicy,
    expected_policy_sha256: &str,
    request_bytes: &[u8],
    signature_bytes: &[u8],
    evaluated_at_unix_seconds: u64,
) -> Result<AuthorizedLifecycleTransition, LifecycleError> {
    if request_bytes.is_empty() {
        return Err(LifecycleError::Empty);
    }
    if request_bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
        return Err(LifecycleError::TooLarge);
    }
    let request: LifecycleTransitionRequest = serde_json::from_slice(request_bytes)
        .map_err(|error| LifecycleError::InvalidJson(error.to_string()))?;
    if canonical_request_bytes(&request)? != request_bytes {
        return Err(LifecycleError::NonCanonical);
    }
    let actor = validate_transition_context(
        state,
        policy,
        expected_policy_sha256,
        &request,
        evaluated_at_unix_seconds,
    )?;
    let signing_bytes = lifecycle_transition_signing_bytes(
        state,
        policy,
        expected_policy_sha256,
        &request,
        evaluated_at_unix_seconds,
    )?;
    let public_key = decode_fixed::<32>(&actor.ed25519_public_key)
        .ok_or(LifecycleError::InvalidField("ed25519PublicKey"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| LifecycleError::InvalidField("ed25519PublicKey"))?;
    if verifying_key.is_weak() {
        return Err(LifecycleError::InvalidField("ed25519PublicKey"));
    }
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| LifecycleError::InvalidSignature)?;
    verifying_key
        .verify_strict(&signing_bytes, &Signature::from_bytes(&signature))
        .map_err(|_| LifecycleError::InvalidSignature)?;
    Ok(AuthorizedLifecycleTransition {
        request,
        request_sha256: hash(request_bytes),
        signature,
    })
}

pub fn apply_authorized_lifecycle_transition(
    state: &mut LifecycleState,
    transition: AuthorizedLifecycleTransition,
) -> Result<(), LifecycleError> {
    let request = transition.request;
    if request.lifecycle_policy_sha256 != state.lifecycle_policy_sha256
        || request.record_sha256 != state.record_sha256
        || request.sequence
            != state
                .sequence
                .checked_add(1)
                .ok_or(LifecycleError::StateMismatch)?
        || request.prior_state_sha256 != state.state_sha256()?
        || state.events.len() >= MAX_LIFECYCLE_EVENTS
    {
        return Err(LifecycleError::StateMismatch);
    }
    match &request.action {
        LifecycleAction::PlaceLegalHold { hold_id } => {
            if state.phase != LifecyclePhase::Retained || state.active_legal_hold_id.is_some() {
                return Err(LifecycleError::TransitionDenied);
            }
            state.active_legal_hold_id = Some(hold_id.clone());
        }
        LifecycleAction::ReleaseLegalHold { hold_id } => {
            if state.phase != LifecyclePhase::Retained
                || state.active_legal_hold_id.as_deref() != Some(hold_id)
            {
                return Err(LifecycleError::TransitionDenied);
            }
            state.active_legal_hold_id = None;
        }
        LifecycleAction::OrderDisposal {
            order_id,
            disposition,
        } => {
            if state.phase != LifecyclePhase::Retained
                || state.active_legal_hold_id.is_some()
                || request.occurred_at_unix_seconds < state.dispose_after_unix_seconds
                || *disposition != state.disposition
            {
                return Err(LifecycleError::TransitionDenied);
            }
            state.disposal_order_id = Some(order_id.clone());
            state.phase = LifecyclePhase::DisposalOrdered;
        }
        LifecycleAction::ConfirmDisposalEvidence {
            order_id,
            evidence_id,
            evidence_sha256,
        } => {
            if state.phase != LifecyclePhase::DisposalOrdered
                || state.disposal_order_id.as_deref() != Some(order_id)
            {
                return Err(LifecycleError::TransitionDenied);
            }
            state.evidence_id = Some(evidence_id.clone());
            state.evidence_sha256 = Some(evidence_sha256.clone());
            state.phase = LifecyclePhase::EvidenceRecorded;
        }
    }
    state.sequence = request.sequence;
    state.events.push(LifecycleEvent {
        sequence: request.sequence,
        occurred_at_unix_seconds: request.occurred_at_unix_seconds,
        actor_id: request.actor_id,
        action: request.action,
        request_sha256: transition.request_sha256,
        signature: format!("0x{}", hex::encode(transition.signature)),
    });
    Ok(())
}

pub fn lifecycle_state_bytes(state: &LifecycleState) -> Result<Vec<u8>, LifecycleError> {
    serde_json::to_vec(state).map_err(|_| LifecycleError::Encoding)
}

fn validate_transition_context<'a>(
    state: &LifecycleState,
    policy: &'a LifecyclePolicy,
    expected: &str,
    request: &LifecycleTransitionRequest,
    evaluated_at: u64,
) -> Result<&'a LifecycleActor, LifecycleError> {
    validate_policy_pin(policy, expected)?;
    validate_request(request)?;
    if state.lifecycle_policy_sha256 != expected
        || state.governance_policy_sha256 != policy.governance_policy_sha256
        || state.dataset_schema_sha256 != policy.dataset_schema_sha256
        || request.lifecycle_policy_sha256 != expected
        || request.record_sha256 != state.record_sha256
        || request.prior_state_sha256 != state.state_sha256()?
        || request.sequence
            != state
                .sequence
                .checked_add(1)
                .ok_or(LifecycleError::StateMismatch)?
    {
        return Err(LifecycleError::StateMismatch);
    }
    validate_time(policy, request.occurred_at_unix_seconds, evaluated_at)?;
    let role = match request.action {
        LifecycleAction::PlaceLegalHold { .. } | LifecycleAction::ReleaseLegalHold { .. } => {
            LifecycleActorRole::LegalHoldAuthority
        }
        LifecycleAction::OrderDisposal { .. } => LifecycleActorRole::DisposalAuthority,
        LifecycleAction::ConfirmDisposalEvidence { .. } => LifecycleActorRole::EvidenceRecorder,
    };
    policy
        .actors
        .iter()
        .find(|actor| actor.actor_id == request.actor_id && actor.role == role)
        .ok_or(LifecycleError::UnauthorizedActor)
}

fn validate_policy_pin(policy: &LifecyclePolicy, expected: &str) -> Result<(), LifecycleError> {
    require_hash(expected, "expectedLifecyclePolicySha256")?;
    if lifecycle_policy_sha256(policy)? != expected {
        return Err(LifecycleError::PolicyDigestMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &LifecyclePolicy) -> Result<(), LifecycleError> {
    if policy.schema != LIFECYCLE_POLICY_SCHEMA
        || !valid_identifier(&policy.policy_id)
        || !valid_identifier(&policy.signature_domain)
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.dispose_after_unix_seconds < policy.effective_at_unix_seconds
        || policy.dispose_after_unix_seconds >= policy.expires_at_unix_seconds
        || policy.actors.is_empty()
        || policy.actors.len() > MAX_LIFECYCLE_ACTORS
    {
        return Err(LifecycleError::InvalidField("policy"));
    }
    require_hash(&policy.governance_policy_sha256, "governancePolicySha256")?;
    require_hash(&policy.dataset_schema_sha256, "datasetSchemaSha256")?;
    if let Some(hold) = &policy.initial_legal_hold_id {
        require_identifier(hold, "initialLegalHoldId")?;
    }
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for actor in &policy.actors {
        require_identifier(&actor.actor_id, "actorId")?;
        if previous.is_some_and(|value| value >= actor.actor_id.as_str())
            || !ids.insert(actor.actor_id.as_str())
        {
            return Err(LifecycleError::InvalidField("actors"));
        }
        previous = Some(actor.actor_id.as_str());
        roles.insert(actor.role);
        let key = decode_fixed::<32>(&actor.ed25519_public_key)
            .ok_or(LifecycleError::InvalidField("ed25519PublicKey"))?;
        if !public_keys.insert(key) {
            return Err(LifecycleError::InvalidField("ed25519PublicKeyReuse"));
        }
        let verifying_key = VerifyingKey::from_bytes(&key)
            .map_err(|_| LifecycleError::InvalidField("ed25519PublicKey"))?;
        if verifying_key.is_weak() {
            return Err(LifecycleError::InvalidField("ed25519PublicKey"));
        }
    }
    if ![
        LifecycleActorRole::LegalHoldAuthority,
        LifecycleActorRole::DisposalAuthority,
        LifecycleActorRole::EvidenceRecorder,
    ]
    .iter()
    .all(|role| roles.contains(role))
    {
        return Err(LifecycleError::InvalidField("actorRoles"));
    }
    Ok(())
}

fn validate_request(request: &LifecycleTransitionRequest) -> Result<(), LifecycleError> {
    if request.schema != LIFECYCLE_TRANSITION_SCHEMA || request.sequence == 0 {
        return Err(LifecycleError::InvalidField("request"));
    }
    require_hash(&request.lifecycle_policy_sha256, "lifecyclePolicySha256")?;
    require_hash(&request.record_sha256, "recordSha256")?;
    require_hash(&request.prior_state_sha256, "priorStateSha256")?;
    require_identifier(&request.actor_id, "actorId")?;
    match &request.action {
        LifecycleAction::PlaceLegalHold { hold_id }
        | LifecycleAction::ReleaseLegalHold { hold_id } => require_identifier(hold_id, "holdId")?,
        LifecycleAction::OrderDisposal { order_id, .. } => require_identifier(order_id, "orderId")?,
        LifecycleAction::ConfirmDisposalEvidence {
            order_id,
            evidence_id,
            evidence_sha256,
        } => {
            require_identifier(order_id, "orderId")?;
            require_identifier(evidence_id, "evidenceId")?;
            require_hash(evidence_sha256, "evidenceSha256")?;
        }
    }
    Ok(())
}

fn validate_time(
    policy: &LifecyclePolicy,
    occurred: u64,
    evaluated: u64,
) -> Result<(), LifecycleError> {
    if occurred < policy.effective_at_unix_seconds
        || occurred >= policy.expires_at_unix_seconds
        || occurred > evaluated
        || evaluated >= policy.expires_at_unix_seconds
    {
        return Err(LifecycleError::OutsideValidityWindow);
    }
    Ok(())
}
fn canonical_request_bytes(
    request: &LifecycleTransitionRequest,
) -> Result<Vec<u8>, LifecycleError> {
    validate_request(request)?;
    serde_json::to_vec(request).map_err(|_| LifecycleError::Encoding)
}
fn append(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LifecycleError> {
    let len = u32::try_from(value.len()).map_err(|_| LifecycleError::TooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn require_identifier(value: &str, field: &'static str) -> Result<(), LifecycleError> {
    if !valid_identifier(value) {
        return Err(LifecycleError::InvalidField(field));
    }
    Ok(())
}
fn require_hash(value: &str, field: &'static str) -> Result<(), LifecycleError> {
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value[2..].bytes().all(|b| b == b'0')
    {
        return Err(LifecycleError::InvalidField(field));
    }
    Ok(())
}
fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let raw = value.strip_prefix("0x")?;
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(raw).ok()?.try_into().ok()
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
