//! Authenticated, deterministic observations of Bloch Pay adjustment events.
//!
//! This crate never transmits refunds, holds assets, or handles private keys.

use bloch_pay_reconciliation::{
    AuthenticatedPaymentObservation, ReconciliationPolicy, policy_sha256,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const ADJUSTMENT_POLICY_SCHEMA: &str = "bloch.pay.adjustment-policy.v1";
pub const ADJUSTMENT_EVENT_SCHEMA: &str = "bloch.pay.adjustment-event.v1";
pub const ADJUSTMENT_STATE_SCHEMA: &str = "bloch.pay.adjustment-state.v1";
pub const MAX_ADJUSTMENT_EVENTS: usize = 1_024;
pub const MAX_ADJUSTMENT_POLICY_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const SIGNING_DOMAIN: &[u8] = b"BLOCH-PAY-ADJUSTMENT-EVENT-V1\0";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentEventKind {
    CancellationRequestedObserved,
    CancellationConfirmedObserved,
    DisputeOpenedObserved,
    DisputeResolvedNoRefundObserved,
    DisputeResolvedRefundExpectedObserved,
    RefundObserved,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdjustmentAuthority {
    pub authority_id: String,
    pub source_id: String,
    pub network: String,
    pub ed25519_public_key: String,
    pub allowed_event_kinds: Vec<AdjustmentEventKind>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdjustmentPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub reconciliation_policy_sha256: String,
    pub tenant_id: String,
    pub merchant_id: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_event_age_seconds: u64,
    pub authorities: Vec<AdjustmentAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdjustmentEvent {
    pub schema: String,
    pub adjustment_id: String,
    pub payment_observation_id: String,
    pub payment_observation_sha256: String,
    pub event_id: String,
    pub sequence: u64,
    pub kind: AdjustmentEventKind,
    pub source_id: String,
    pub network: String,
    pub external_reference: String,
    pub transaction_id: Option<String>,
    pub event_index: Option<u32>,
    pub amount_minor: Option<u64>,
    pub occurred_at_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedAdjustmentEvent {
    event: AdjustmentEvent,
    authority_id: String,
    policy_sha256: String,
    event_sha256: String,
}

impl AuthenticatedAdjustmentEvent {
    pub fn event(&self) -> &AdjustmentEvent {
        &self.event
    }
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn event_sha256(&self) -> &str {
        &self.event_sha256
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
    pub fn credit_authorized(&self) -> bool {
        false
    }
    pub fn funds_moved(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentStatus {
    Active,
    CancellationPending,
    Cancelled,
    Disputed,
    RefundExpected,
    RefundObserved,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AppliedEvent {
    event_id: String,
    event_sha256: String,
    external_reference: String,
    network_event: Option<String>,
    authority_id: String,
    resulting_status: AdjustmentStatus,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdjustmentState {
    schema: String,
    adjustment_policy_sha256: String,
    reconciliation_policy_sha256: String,
    adjustment_id: String,
    payment_observation_id: String,
    payment_observation_sha256: String,
    payment_amount_minor: u64,
    generation: u64,
    status: AdjustmentStatus,
    applied_events: Vec<AppliedEvent>,
    settlement_qualified: bool,
    credit_authorized: bool,
    funds_moved: bool,
}

impl AdjustmentState {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn status(&self) -> AdjustmentStatus {
        self.status
    }
    pub fn adjustment_id(&self) -> &str {
        &self.adjustment_id
    }
    pub fn payment_observation_id(&self) -> &str {
        &self.payment_observation_id
    }
    pub fn policy_sha256(&self) -> &str {
        &self.adjustment_policy_sha256
    }
    pub fn settlement_qualified(&self) -> bool {
        false
    }
    pub fn credit_authorized(&self) -> bool {
        false
    }
    pub fn funds_moved(&self) -> bool {
        false
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializing validated adjustment state cannot fail")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdjustmentError {
    #[error("invalid adjustment policy")]
    InvalidPolicy,
    #[error("adjustment policy pin mismatch")]
    PolicyPinMismatch,
    #[error("adjustment context does not match authenticated payment")]
    ContextMismatch,
    #[error("invalid adjustment event")]
    InvalidEvent,
    #[error("event authority is not authorized")]
    UnauthorizedAuthority,
    #[error("event is outside policy time bounds")]
    OutsideValidityWindow,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("event sequence is not the next generation")]
    InvalidSequence,
    #[error("event identity conflicts with applied history")]
    EventConflict,
    #[error("event transition is not valid from the current state")]
    InvalidTransition,
    #[error("observed refund exceeds the original payment amount")]
    RefundAmountExceeded,
    #[error("adjustment event limit reached")]
    EventLimit,
}

pub fn adjustment_policy_bytes(policy: &AdjustmentPolicy) -> Result<Vec<u8>, AdjustmentError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| AdjustmentError::InvalidPolicy)?;
    if bytes.len() > MAX_ADJUSTMENT_POLICY_BYTES {
        return Err(AdjustmentError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn adjustment_policy_sha256(policy: &AdjustmentPolicy) -> Result<String, AdjustmentError> {
    Ok(hash(&adjustment_policy_bytes(policy)?))
}

/// Parses only byte-exact canonical policy JSON matching an independently
/// supplied digest pin.
pub fn parse_adjustment_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<AdjustmentPolicy, AdjustmentError> {
    if bytes.is_empty() || bytes.len() > MAX_ADJUSTMENT_POLICY_BYTES {
        return Err(AdjustmentError::InvalidPolicy);
    }
    let policy: AdjustmentPolicy =
        serde_json::from_slice(bytes).map_err(|_| AdjustmentError::InvalidPolicy)?;
    if adjustment_policy_bytes(&policy)? != bytes {
        return Err(AdjustmentError::InvalidPolicy);
    }
    validate_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn adjustment_event_bytes(event: &AdjustmentEvent) -> Result<Vec<u8>, AdjustmentError> {
    validate_event(event)?;
    serde_json::to_vec(event).map_err(|_| AdjustmentError::InvalidEvent)
}

pub fn adjustment_event_signing_bytes(
    policy: &AdjustmentPolicy,
    expected_policy_sha256: &str,
    authority_id: &str,
    event: &AdjustmentEvent,
) -> Result<Vec<u8>, AdjustmentError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let authority = authority(policy, authority_id, event)?;
    let event_bytes = adjustment_event_bytes(event)?;
    signing_bytes(policy, expected_policy_sha256, authority, &event_bytes)
}

pub fn verify_adjustment_event(
    policy: &AdjustmentPolicy,
    expected_policy_sha256: &str,
    authority_id: &str,
    event: &AdjustmentEvent,
    signature: &[u8],
    evaluated_at_unix_seconds: u64,
) -> Result<AuthenticatedAdjustmentEvent, AdjustmentError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_event_time(policy, event, evaluated_at_unix_seconds)?;
    let authority = authority(policy, authority_id, event)?;
    let event_bytes = adjustment_event_bytes(event)?;
    let message = signing_bytes(policy, expected_policy_sha256, authority, &event_bytes)?;
    let public_key =
        decode_fixed::<32>(&authority.ed25519_public_key).ok_or(AdjustmentError::InvalidPolicy)?;
    let public_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AdjustmentError::InvalidPolicy)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| AdjustmentError::InvalidSignature)?;
    public_key
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| AdjustmentError::InvalidSignature)?;
    Ok(AuthenticatedAdjustmentEvent {
        event: event.clone(),
        authority_id: authority_id.into(),
        policy_sha256: expected_policy_sha256.into(),
        event_sha256: hash(&event_bytes),
    })
}

pub fn initialize_adjustment(
    policy: &AdjustmentPolicy,
    expected_policy_sha256: &str,
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    adjustment_id: &str,
    payment: &AuthenticatedPaymentObservation,
) -> Result<AdjustmentState, AdjustmentError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_reconciliation_context(
        policy,
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
    )?;
    if !valid_id(adjustment_id)
        || expected_reconciliation_policy_sha256 != payment.reconciliation_policy_sha256()
    {
        return Err(AdjustmentError::ContextMismatch);
    }
    Ok(AdjustmentState {
        schema: ADJUSTMENT_STATE_SCHEMA.into(),
        adjustment_policy_sha256: expected_policy_sha256.into(),
        reconciliation_policy_sha256: payment.reconciliation_policy_sha256().into(),
        adjustment_id: adjustment_id.into(),
        payment_observation_id: payment.observation().observation_id.clone(),
        payment_observation_sha256: payment.canonical_observation_sha256().into(),
        payment_amount_minor: payment.observation().amount_minor,
        generation: 0,
        status: AdjustmentStatus::Active,
        applied_events: Vec::new(),
        settlement_qualified: false,
        credit_authorized: false,
        funds_moved: false,
    })
}

pub fn apply_adjustment_event(
    state: &AdjustmentState,
    authenticated: &AuthenticatedAdjustmentEvent,
) -> Result<AdjustmentState, AdjustmentError> {
    validate_state(state)?;
    let event = authenticated.event();
    if state.adjustment_policy_sha256 != authenticated.policy_sha256
        || state.adjustment_id != event.adjustment_id
        || state.payment_observation_id != event.payment_observation_id
        || state.payment_observation_sha256 != event.payment_observation_sha256
    {
        return Err(AdjustmentError::ContextMismatch);
    }
    if let Some(applied) = state
        .applied_events
        .iter()
        .find(|item| item.event_id == event.event_id)
    {
        return if applied.event_sha256 == authenticated.event_sha256 {
            Ok(state.clone())
        } else {
            Err(AdjustmentError::EventConflict)
        };
    }
    let network_event = network_event(event);
    if state.applied_events.iter().any(|item| {
        item.external_reference == event.external_reference
            || network_event
                .as_ref()
                .is_some_and(|candidate| item.network_event.as_ref() == Some(candidate))
    }) {
        return Err(AdjustmentError::EventConflict);
    }
    if state.applied_events.len() >= MAX_ADJUSTMENT_EVENTS {
        return Err(AdjustmentError::EventLimit);
    }
    if event.sequence
        != state
            .generation
            .checked_add(1)
            .ok_or(AdjustmentError::EventLimit)?
    {
        return Err(AdjustmentError::InvalidSequence);
    }
    if event.kind == AdjustmentEventKind::RefundObserved
        && event
            .amount_minor
            .is_some_and(|amount| amount > state.payment_amount_minor)
    {
        return Err(AdjustmentError::RefundAmountExceeded);
    }
    let status = transition(state.status, event.kind)?;
    let mut next = state.clone();
    next.generation = event.sequence;
    next.status = status;
    next.applied_events.push(AppliedEvent {
        event_id: event.event_id.clone(),
        event_sha256: authenticated.event_sha256.clone(),
        external_reference: event.external_reference.clone(),
        network_event,
        authority_id: authenticated.authority_id.clone(),
        resulting_status: status,
    });
    Ok(next)
}

fn transition(
    status: AdjustmentStatus,
    kind: AdjustmentEventKind,
) -> Result<AdjustmentStatus, AdjustmentError> {
    use AdjustmentEventKind::*;
    use AdjustmentStatus::*;
    match (status, kind) {
        (Active, CancellationRequestedObserved) => Ok(CancellationPending),
        (Active | CancellationPending, CancellationConfirmedObserved) => Ok(Cancelled),
        (Active, DisputeOpenedObserved) => Ok(Disputed),
        (Disputed, DisputeResolvedNoRefundObserved) => Ok(Active),
        (Disputed, DisputeResolvedRefundExpectedObserved) => Ok(RefundExpected),
        (
            Active | CancellationPending | Cancelled | Disputed | RefundExpected,
            AdjustmentEventKind::RefundObserved,
        ) => Ok(AdjustmentStatus::RefundObserved),
        _ => Err(AdjustmentError::InvalidTransition),
    }
}

fn validate_policy_pin(policy: &AdjustmentPolicy, expected: &str) -> Result<(), AdjustmentError> {
    if !valid_sha256(expected) || adjustment_policy_sha256(policy)? != expected {
        return Err(AdjustmentError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &AdjustmentPolicy) -> Result<(), AdjustmentError> {
    if policy.schema != ADJUSTMENT_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_sha256(&policy.reconciliation_policy_sha256)
        || !valid_id(&policy.tenant_id)
        || !valid_id(&policy.merchant_id)
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_event_age_seconds == 0
        || policy.max_event_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
        || policy.authorities.is_empty()
        || policy.authorities.len() > 256
    {
        return Err(AdjustmentError::InvalidPolicy);
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut previous_authority: Option<&str> = None;
    for authority in &policy.authorities {
        let key = decode_fixed::<32>(&authority.ed25519_public_key)
            .ok_or(AdjustmentError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| AdjustmentError::InvalidPolicy)?;
        let kinds: BTreeSet<_> = authority.allowed_event_kinds.iter().copied().collect();
        if !valid_id(&authority.authority_id)
            || !valid_id(&authority.source_id)
            || !valid_id(&authority.network)
            || key.is_weak()
            || !ids.insert(&authority.authority_id)
            || !keys.insert(&authority.ed25519_public_key)
            || previous_authority
                .is_some_and(|previous| previous >= authority.authority_id.as_str())
            || kinds.len() != authority.allowed_event_kinds.len()
            || kinds.is_empty()
            || !authority
                .allowed_event_kinds
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(AdjustmentError::InvalidPolicy);
        }
        previous_authority = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_event(event: &AdjustmentEvent) -> Result<(), AdjustmentError> {
    let refund = event.kind == AdjustmentEventKind::RefundObserved;
    if event.schema != ADJUSTMENT_EVENT_SCHEMA
        || !valid_id(&event.adjustment_id)
        || !valid_id(&event.payment_observation_id)
        || !valid_sha256(&event.payment_observation_sha256)
        || !valid_id(&event.event_id)
        || event.sequence == 0
        || !valid_id(&event.source_id)
        || !valid_id(&event.network)
        || !valid_id(&event.external_reference)
        || (refund
            && (!event.transaction_id.as_deref().is_some_and(valid_id)
                || event.event_index.is_none()
                || !event.amount_minor.is_some_and(|value| value > 0)))
        || (!refund && event.amount_minor.is_some())
        || event.transaction_id.is_some() != event.event_index.is_some()
    {
        return Err(AdjustmentError::InvalidEvent);
    }
    Ok(())
}

fn validate_event_time(
    policy: &AdjustmentPolicy,
    event: &AdjustmentEvent,
    evaluated: u64,
) -> Result<(), AdjustmentError> {
    if event.occurred_at_unix_seconds < policy.effective_at_unix_seconds
        || event.occurred_at_unix_seconds >= policy.expires_at_unix_seconds
        || evaluated < event.occurred_at_unix_seconds
        || evaluated >= policy.expires_at_unix_seconds
        || evaluated - event.occurred_at_unix_seconds > policy.max_event_age_seconds
    {
        return Err(AdjustmentError::OutsideValidityWindow);
    }
    Ok(())
}

fn validate_reconciliation_context(
    policy: &AdjustmentPolicy,
    reconciliation: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
) -> Result<(), AdjustmentError> {
    if !valid_sha256(expected_reconciliation_policy_sha256)
        || policy_sha256(reconciliation).map_err(|_| AdjustmentError::ContextMismatch)?
            != expected_reconciliation_policy_sha256
        || policy.reconciliation_policy_sha256 != expected_reconciliation_policy_sha256
        || policy.tenant_id != reconciliation.tenant_id
        || policy.merchant_id != reconciliation.merchant_id
        || policy.effective_at_unix_seconds < reconciliation.effective_at_unix_seconds
        || policy.expires_at_unix_seconds > reconciliation.expires_at_unix_seconds
        || policy.authorities.iter().any(|authority| {
            reconciliation
                .allowed_source_ids
                .binary_search(&authority.source_id)
                .is_err()
                || !reconciliation
                    .routes
                    .iter()
                    .any(|route| route.network == authority.network)
        })
    {
        return Err(AdjustmentError::ContextMismatch);
    }
    Ok(())
}

fn authority<'a>(
    policy: &'a AdjustmentPolicy,
    id: &str,
    event: &AdjustmentEvent,
) -> Result<&'a AdjustmentAuthority, AdjustmentError> {
    policy
        .authorities
        .iter()
        .find(|item| {
            item.authority_id == id
                && item.source_id == event.source_id
                && item.network == event.network
                && item.allowed_event_kinds.binary_search(&event.kind).is_ok()
        })
        .ok_or(AdjustmentError::UnauthorizedAuthority)
}

fn signing_bytes(
    policy: &AdjustmentPolicy,
    pin: &str,
    authority: &AdjustmentAuthority,
    event: &[u8],
) -> Result<Vec<u8>, AdjustmentError> {
    let fields: [&[u8]; 5] = [
        policy.signature_domain.as_bytes(),
        pin.as_bytes(),
        policy.reconciliation_policy_sha256.as_bytes(),
        authority.authority_id.as_bytes(),
        event,
    ];
    let mut out = SIGNING_DOMAIN.to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

fn validate_state(state: &AdjustmentState) -> Result<(), AdjustmentError> {
    if state.schema != ADJUSTMENT_STATE_SCHEMA
        || !valid_sha256(&state.adjustment_policy_sha256)
        || !valid_sha256(&state.reconciliation_policy_sha256)
        || !valid_sha256(&state.payment_observation_sha256)
        || !valid_id(&state.adjustment_id)
        || !valid_id(&state.payment_observation_id)
        || state.payment_amount_minor == 0
        || state.generation != state.applied_events.len() as u64
        || state.applied_events.len() > MAX_ADJUSTMENT_EVENTS
        || state.settlement_qualified
        || state.credit_authorized
        || state.funds_moved
    {
        return Err(AdjustmentError::ContextMismatch);
    }
    Ok(())
}

fn network_event(event: &AdjustmentEvent) -> Option<String> {
    event
        .transaction_id
        .as_ref()
        .zip(event.event_index)
        .map(|(transaction, index)| format!("{}:{transaction}:{index}", event.network))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        && !value[2..].bytes().all(|b| b == b'0')
}
fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 + 2 || !value.starts_with("0x") {
        return None;
    }
    hex::decode(&value[2..]).ok()?.try_into().ok()
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
