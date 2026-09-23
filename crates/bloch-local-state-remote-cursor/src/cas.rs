use crate::{
    RemoteCursorError, RemoteCursorPolicy, RemoteCursorSignature, remote_cursor_policy_sha256,
};
use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_store::{StateRoot, parse_state_root};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const REMOTE_CURSOR_CAS_REQUEST_SCHEMA: &str =
    "bloch.products.remote-monotonic-cursor-cas-request.v1";
pub const REMOTE_CURSOR_CAS_RECEIPT_ENVELOPE_SCHEMA: &str =
    "bloch.products.remote-monotonic-cursor-cas-receipt-envelope.v1";
pub const REMOTE_CURSOR_CAS_RECEIPT_SCHEMA: &str =
    "bloch.products.remote-monotonic-cursor-cas-receipt.v1";
pub const MAX_REMOTE_CURSOR_CAS_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_REMOTE_CURSOR_CAS_RECEIPT_BYTES: usize = 128 * 1024;
const CAS_SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-REMOTE-MONOTONIC-CURSOR-CAS-V1\0";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteCursorCasMode {
    CreateOnceBootstrap,
    CompareAndSwap,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "result",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RemoteCursorCasDecision {
    Accepted,
    Refused { reason_code: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteCursorCasRequest {
    schema: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_id: String,
    request_nonce: String,
    requested_at_unix_seconds: u64,
    mode: RemoteCursorCasMode,
    expected_current_cursor_sha256: Option<String>,
    expected_current_cursor: Option<CheckpointCursor>,
    successor_cursor_sha256: String,
    successor_cursor: CheckpointCursor,
    successor_root: StateRoot,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteCursorCasReceiptEnvelope {
    schema: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_sha256: String,
    request: RemoteCursorCasRequest,
    decided_at_unix_seconds: u64,
    decision: RemoteCursorCasDecision,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteCursorCasReceipt {
    schema: String,
    envelope: RemoteCursorCasReceiptEnvelope,
    signatures: Vec<RemoteCursorSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteCursorCasAcceptance {
    successor: CheckpointCursor,
    request_sha256: String,
    receipt_sha256: String,
    decided_at_unix_seconds: u64,
    authority_ids: Vec<String>,
}

impl VerifiedRemoteCursorCasAcceptance {
    pub fn successor(&self) -> &CheckpointCursor {
        &self.successor
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn decided_at_unix_seconds(&self) -> u64 {
        self.decided_at_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
    pub fn remote_cas_execution_proven(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteCursorCasRefusal {
    reason_code: String,
    request_sha256: String,
    receipt_sha256: String,
    decided_at_unix_seconds: u64,
    authority_ids: Vec<String>,
}

impl VerifiedRemoteCursorCasRefusal {
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn decided_at_unix_seconds(&self) -> u64 {
        self.decided_at_unix_seconds
    }
    pub fn authority_ids(&self) -> &[String] {
        &self.authority_ids
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedRemoteCursorCasReceipt {
    Accepted(VerifiedRemoteCursorCasAcceptance),
    Refused(VerifiedRemoteCursorCasRefusal),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteCursorCasError {
    #[error("remote cursor CAS request is invalid or non-canonical")]
    InvalidRequest,
    #[error("remote cursor CAS request violates successor lineage")]
    InvalidSuccessor,
    #[error("remote cursor CAS receipt is invalid or non-canonical")]
    InvalidReceipt,
    #[error("remote cursor CAS receipt does not bind the independently expected request")]
    RequestMismatch,
    #[error("remote cursor CAS receipt is outside the validity or freshness window")]
    OutsideFreshnessWindow,
    #[error("remote cursor CAS receipt signature threshold is not met")]
    ThresholdNotMet,
    #[error("remote cursor CAS receipt authority is not trusted")]
    UntrustedAuthority,
    #[error("remote cursor CAS receipt signature is invalid")]
    InvalidSignature,
    #[error("remote cursor policy validation failed")]
    Policy(#[source] RemoteCursorError),
}

pub struct RemoteCursorCasRequestParameters<'a> {
    pub expected_current: Option<&'a CheckpointCursor>,
    pub successor_cursor: &'a CheckpointCursor,
    pub successor_root: &'a StateRoot,
    pub request_id: &'a str,
    pub request_nonce: &'a str,
    pub requested_at_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRemoteCursorCasRequest {
    request: RemoteCursorCasRequest,
    request_sha256: String,
}

impl ValidatedRemoteCursorCasRequest {
    pub fn mode(&self) -> RemoteCursorCasMode {
        self.request.mode
    }
    pub fn state_identity(&self) -> &str {
        &self.request.state_identity
    }
    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }
    pub fn request_nonce(&self) -> &str {
        &self.request.request_nonce
    }
    pub fn requested_at_unix_seconds(&self) -> u64 {
        self.request.requested_at_unix_seconds
    }
    pub fn expected_current(&self) -> Option<&CheckpointCursor> {
        self.request.expected_current_cursor.as_ref()
    }
    pub fn successor(&self) -> &CheckpointCursor {
        &self.request.successor_cursor
    }
    pub fn successor_root(&self) -> &StateRoot {
        &self.request.successor_root
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
}

/// Strictly validates a request before a control plane considers any CAS.
/// Parsing authenticates no caller and performs no mutation.
pub fn parse_remote_cursor_cas_request(
    bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<ValidatedRemoteCursorCasRequest, RemoteCursorCasError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let request = parse_request(bytes, policy, expected_policy_sha256)?;
    Ok(ValidatedRemoteCursorCasRequest {
        request,
        request_sha256: hash(bytes),
    })
}

pub fn create_remote_cursor_cas_request(
    parameters: RemoteCursorCasRequestParameters<'_>,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<Vec<u8>, RemoteCursorCasError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    validate_issue_time(policy, parameters.requested_at_unix_seconds)?;
    if !valid_id(parameters.request_id) || !valid_nonce(parameters.request_nonce) {
        return Err(RemoteCursorCasError::InvalidRequest);
    }
    let mode = if parameters.expected_current.is_some() {
        RemoteCursorCasMode::CompareAndSwap
    } else {
        RemoteCursorCasMode::CreateOnceBootstrap
    };
    let request = RemoteCursorCasRequest {
        schema: REMOTE_CURSOR_CAS_REQUEST_SCHEMA.into(),
        remote_cursor_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        request_id: parameters.request_id.into(),
        request_nonce: parameters.request_nonce.into(),
        requested_at_unix_seconds: parameters.requested_at_unix_seconds,
        mode,
        expected_current_cursor_sha256: parameters.expected_current.map(cursor_hash).transpose()?,
        expected_current_cursor: parameters.expected_current.cloned(),
        successor_cursor_sha256: cursor_hash(parameters.successor_cursor)?,
        successor_cursor: parameters.successor_cursor.clone(),
        successor_root: parameters.successor_root.clone(),
    };
    validate_request(&request, policy, expected_policy_sha256)?;
    let bytes = serde_json::to_vec(&request).map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    if bytes.len() > MAX_REMOTE_CURSOR_CAS_REQUEST_BYTES {
        return Err(RemoteCursorCasError::InvalidRequest);
    }
    Ok(bytes)
}

pub fn remote_cursor_cas_receipt_signature_message(
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    decision: &RemoteCursorCasDecision,
    decided_at_unix_seconds: u64,
) -> Result<Vec<u8>, RemoteCursorCasError> {
    let envelope = receipt_envelope(
        request_bytes,
        policy,
        expected_policy_sha256,
        decision,
        decided_at_unix_seconds,
    )?;
    signing_bytes(&envelope)
}

pub fn create_remote_cursor_cas_receipt(
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    decision: &RemoteCursorCasDecision,
    decided_at_unix_seconds: u64,
    signatures: &[RemoteCursorSignature],
) -> Result<Vec<u8>, RemoteCursorCasError> {
    let envelope = receipt_envelope(
        request_bytes,
        policy,
        expected_policy_sha256,
        decision,
        decided_at_unix_seconds,
    )?;
    let message = signing_bytes(&envelope)?;
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    verify_signatures(policy, &message, &signatures)?;
    let receipt = RemoteCursorCasReceipt {
        schema: REMOTE_CURSOR_CAS_RECEIPT_SCHEMA.into(),
        envelope,
        signatures,
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|_| RemoteCursorCasError::InvalidReceipt)?;
    if bytes.len() > MAX_REMOTE_CURSOR_CAS_RECEIPT_BYTES {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    Ok(bytes)
}

pub fn verify_remote_cursor_cas_receipt(
    receipt_bytes: &[u8],
    expected_request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedRemoteCursorCasReceipt, RemoteCursorCasError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    let expected_request = parse_request(expected_request_bytes, policy, expected_policy_sha256)?;
    if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_REMOTE_CURSOR_CAS_RECEIPT_BYTES {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    let receipt: RemoteCursorCasReceipt =
        serde_json::from_slice(receipt_bytes).map_err(|_| RemoteCursorCasError::InvalidReceipt)?;
    if serde_json::to_vec(&receipt).map_err(|_| RemoteCursorCasError::InvalidReceipt)?
        != receipt_bytes
        || receipt.schema != REMOTE_CURSOR_CAS_RECEIPT_SCHEMA
    {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    validate_receipt_envelope(&receipt.envelope, policy, expected_policy_sha256)?;
    if receipt.envelope.request != expected_request
        || receipt.envelope.request_sha256 != hash(expected_request_bytes)
    {
        return Err(RemoteCursorCasError::RequestMismatch);
    }
    validate_receipt_freshness(
        policy,
        expected_request.requested_at_unix_seconds,
        receipt.envelope.decided_at_unix_seconds,
        evaluated_at_unix_seconds,
    )?;
    let message = signing_bytes(&receipt.envelope)?;
    verify_signatures(policy, &message, &receipt.signatures)?;
    let authority_ids = receipt
        .signatures
        .into_iter()
        .map(|signature| signature.authority_id)
        .collect();
    let request_sha256 = receipt.envelope.request_sha256;
    let receipt_sha256 = hash(receipt_bytes);
    let decided_at_unix_seconds = receipt.envelope.decided_at_unix_seconds;
    match receipt.envelope.decision {
        RemoteCursorCasDecision::Accepted => Ok(VerifiedRemoteCursorCasReceipt::Accepted(
            VerifiedRemoteCursorCasAcceptance {
                successor: expected_request.successor_cursor,
                request_sha256,
                receipt_sha256,
                decided_at_unix_seconds,
                authority_ids,
            },
        )),
        RemoteCursorCasDecision::Refused { reason_code } => Ok(
            VerifiedRemoteCursorCasReceipt::Refused(VerifiedRemoteCursorCasRefusal {
                reason_code,
                request_sha256,
                receipt_sha256,
                decided_at_unix_seconds,
                authority_ids,
            }),
        ),
    }
}

fn receipt_envelope(
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    decision: &RemoteCursorCasDecision,
    decided_at_unix_seconds: u64,
) -> Result<RemoteCursorCasReceiptEnvelope, RemoteCursorCasError> {
    let request = parse_request(request_bytes, policy, expected_policy_sha256)?;
    validate_decision(decision)?;
    if decided_at_unix_seconds < request.requested_at_unix_seconds {
        return Err(RemoteCursorCasError::OutsideFreshnessWindow);
    }
    validate_issue_time(policy, decided_at_unix_seconds)?;
    let envelope = RemoteCursorCasReceiptEnvelope {
        schema: REMOTE_CURSOR_CAS_RECEIPT_ENVELOPE_SCHEMA.into(),
        remote_cursor_policy_sha256: expected_policy_sha256.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        request_sha256: hash(request_bytes),
        request,
        decided_at_unix_seconds,
        decision: decision.clone(),
    };
    validate_receipt_envelope(&envelope, policy, expected_policy_sha256)?;
    Ok(envelope)
}

fn parse_request(
    bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<RemoteCursorCasRequest, RemoteCursorCasError> {
    if bytes.is_empty() || bytes.len() > MAX_REMOTE_CURSOR_CAS_REQUEST_BYTES {
        return Err(RemoteCursorCasError::InvalidRequest);
    }
    let request: RemoteCursorCasRequest =
        serde_json::from_slice(bytes).map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    if serde_json::to_vec(&request).map_err(|_| RemoteCursorCasError::InvalidRequest)? != bytes {
        return Err(RemoteCursorCasError::InvalidRequest);
    }
    validate_request(&request, policy, expected_policy_sha256)?;
    Ok(request)
}

fn validate_request(
    request: &RemoteCursorCasRequest,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<(), RemoteCursorCasError> {
    if request.schema != REMOTE_CURSOR_CAS_REQUEST_SCHEMA
        || request.remote_cursor_policy_sha256 != expected_policy_sha256
        || request.signature_domain != policy.signature_domain
        || request.state_identity != policy.state_identity
        || request.successor_cursor.state_identity() != policy.state_identity
        || request.successor_root.state_identity() != policy.state_identity
        || !valid_id(&request.request_id)
        || !valid_nonce(&request.request_nonce)
        || !valid_sha256(&request.successor_cursor_sha256)
    {
        return Err(RemoteCursorCasError::InvalidRequest);
    }
    validate_issue_time(policy, request.requested_at_unix_seconds)?;
    validate_cursor(&request.successor_cursor)?;
    validate_root(&request.successor_root)?;
    if cursor_hash(&request.successor_cursor)? != request.successor_cursor_sha256
        || request.successor_cursor.generation() != request.successor_root.generation()
        || request.successor_cursor.state_sha256() != request.successor_root.state_sha256()
        || request.successor_cursor.state_root_sha256() != root_hash(&request.successor_root)?
    {
        return Err(RemoteCursorCasError::InvalidSuccessor);
    }
    match (
        request.mode,
        request.expected_current_cursor.as_ref(),
        request.expected_current_cursor_sha256.as_ref(),
    ) {
        (RemoteCursorCasMode::CreateOnceBootstrap, None, None) => {
            if request.successor_cursor.generation() != 0
                || request.successor_root.previous_root_sha256().is_some()
            {
                return Err(RemoteCursorCasError::InvalidSuccessor);
            }
        }
        (RemoteCursorCasMode::CompareAndSwap, Some(current), Some(current_sha256)) => {
            validate_cursor(current)?;
            if current.state_identity() != policy.state_identity
                || !valid_sha256(current_sha256)
                || cursor_hash(current)? != *current_sha256
                || request.successor_cursor.generation()
                    != current
                        .generation()
                        .checked_add(1)
                        .ok_or(RemoteCursorCasError::InvalidSuccessor)?
                || request.successor_root.previous_root_sha256()
                    != Some(current.state_root_sha256())
            {
                return Err(RemoteCursorCasError::InvalidSuccessor);
            }
        }
        _ => return Err(RemoteCursorCasError::InvalidRequest),
    }
    Ok(())
}

fn validate_receipt_envelope(
    envelope: &RemoteCursorCasReceiptEnvelope,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
) -> Result<(), RemoteCursorCasError> {
    if envelope.schema != REMOTE_CURSOR_CAS_RECEIPT_ENVELOPE_SCHEMA
        || envelope.remote_cursor_policy_sha256 != expected_policy_sha256
        || envelope.signature_domain != policy.signature_domain
        || envelope.state_identity != policy.state_identity
        || !valid_sha256(&envelope.request_sha256)
    {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    validate_request(&envelope.request, policy, expected_policy_sha256)?;
    validate_decision(&envelope.decision)?;
    let request_bytes =
        serde_json::to_vec(&envelope.request).map_err(|_| RemoteCursorCasError::InvalidReceipt)?;
    if hash(&request_bytes) != envelope.request_sha256 {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    if envelope.decided_at_unix_seconds < envelope.request.requested_at_unix_seconds {
        return Err(RemoteCursorCasError::OutsideFreshnessWindow);
    }
    validate_issue_time(policy, envelope.decided_at_unix_seconds)
}

fn validate_decision(decision: &RemoteCursorCasDecision) -> Result<(), RemoteCursorCasError> {
    if let RemoteCursorCasDecision::Refused { reason_code } = decision
        && !valid_id(reason_code)
    {
        return Err(RemoteCursorCasError::InvalidReceipt);
    }
    Ok(())
}

fn validate_receipt_freshness(
    policy: &RemoteCursorPolicy,
    requested_at: u64,
    decided_at: u64,
    evaluated_at: u64,
) -> Result<(), RemoteCursorCasError> {
    if decided_at < requested_at
        || evaluated_at < decided_at
        || evaluated_at > policy.expires_at_unix_seconds
        || evaluated_at - decided_at > policy.max_observation_age_seconds
        || decided_at - requested_at > policy.max_observation_age_seconds
    {
        return Err(RemoteCursorCasError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn signing_bytes(
    envelope: &RemoteCursorCasReceiptEnvelope,
) -> Result<Vec<u8>, RemoteCursorCasError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| RemoteCursorCasError::InvalidReceipt)?;
    let mut message = Vec::with_capacity(CAS_SIGNING_PREFIX.len() + 8 + bytes.len());
    message.extend_from_slice(CAS_SIGNING_PREFIX);
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&bytes);
    Ok(message)
}

fn verify_signatures(
    policy: &RemoteCursorPolicy,
    message: &[u8],
    signatures: &[RemoteCursorSignature],
) -> Result<(), RemoteCursorCasError> {
    if signatures.len() < usize::from(policy.threshold)
        || signatures.len() > policy.authorities.len()
    {
        return Err(RemoteCursorCasError::ThresholdNotMet);
    }
    let mut previous: Option<&str> = None;
    let mut seen = BTreeSet::new();
    for detached in signatures {
        if !valid_id(&detached.authority_id)
            || previous.is_some_and(|id| id >= detached.authority_id.as_str())
            || !seen.insert(detached.authority_id.as_str())
        {
            return Err(RemoteCursorCasError::InvalidReceipt);
        }
        let authority = policy
            .authorities
            .binary_search_by(|authority| authority.authority_id.cmp(&detached.authority_id))
            .ok()
            .map(|index| &policy.authorities[index])
            .ok_or(RemoteCursorCasError::UntrustedAuthority)?;
        let key = decode_fixed::<32>(&authority.ed25519_public_key).ok_or(
            RemoteCursorCasError::Policy(RemoteCursorError::InvalidPolicy),
        )?;
        let key = VerifyingKey::from_bytes(&key)
            .map_err(|_| RemoteCursorCasError::Policy(RemoteCursorError::InvalidPolicy))?;
        let signature = decode_fixed::<64>(&detached.signature)
            .ok_or(RemoteCursorCasError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| RemoteCursorCasError::InvalidSignature)?;
        previous = Some(&detached.authority_id);
    }
    Ok(())
}

fn validate_policy_pin(
    policy: &RemoteCursorPolicy,
    expected: &str,
) -> Result<(), RemoteCursorCasError> {
    if !valid_sha256(expected)
        || remote_cursor_policy_sha256(policy).map_err(RemoteCursorCasError::Policy)? != expected
    {
        return Err(RemoteCursorCasError::Policy(
            RemoteCursorError::PolicyPinMismatch,
        ));
    }
    Ok(())
}

fn validate_issue_time(
    policy: &RemoteCursorPolicy,
    timestamp: u64,
) -> Result<(), RemoteCursorCasError> {
    if timestamp < policy.effective_at_unix_seconds || timestamp > policy.expires_at_unix_seconds {
        return Err(RemoteCursorCasError::OutsideFreshnessWindow);
    }
    Ok(())
}

fn validate_cursor(cursor: &CheckpointCursor) -> Result<(), RemoteCursorCasError> {
    let bytes = cursor
        .canonical_bytes()
        .map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    parse_cursor(&bytes).map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    Ok(())
}

fn validate_root(root: &StateRoot) -> Result<(), RemoteCursorCasError> {
    let bytes = root
        .canonical_bytes()
        .map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    parse_state_root(&bytes).map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    Ok(())
}

fn cursor_hash(cursor: &CheckpointCursor) -> Result<String, RemoteCursorCasError> {
    let bytes = cursor
        .canonical_bytes()
        .map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    Ok(hash(&bytes))
}

fn root_hash(root: &StateRoot) -> Result<String, RemoteCursorCasError> {
    let bytes = root
        .canonical_bytes()
        .map_err(|_| RemoteCursorCasError::InvalidRequest)?;
    Ok(hash(&bytes))
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
    use crate::{REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority};
    use bloch_local_state_store::write_state;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const NONCE: &str = "cas_nonce_0123456789abcdef0123456789abcdef";
    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Roots {
        path: std::path::PathBuf,
        current_root: StateRoot,
        successor_root: StateRoot,
        current_cursor: CheckpointCursor,
        successor_cursor: CheckpointCursor,
    }

    impl Roots {
        fn new() -> Self {
            Self::with_initial(b"zero")
        }

        fn with_initial(initial_state: &[u8]) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "bloch-remote-cas-{}-{nonce}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let current_root =
                write_state(&path, "data:tenant-a:lifecycle", 0, initial_state, None).unwrap();
            let successor_root = write_state(
                &path,
                "data:tenant-a:lifecycle",
                1,
                b"one",
                Some(&current_root),
            )
            .unwrap();
            let current_cursor = cursor_for(&current_root, 11);
            let successor_cursor = cursor_for(&successor_root, 21);
            Self {
                path,
                current_root,
                successor_root,
                current_cursor,
                successor_cursor,
            }
        }
    }

    impl Drop for Roots {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn cursor_for(root: &StateRoot, marker: u8) -> CheckpointCursor {
        let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
        let root_digest = hash(&root.canonical_bytes().unwrap());
        let bytes = format!(
            "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
            root.state_identity(),
            root.generation(),
            digest(marker),
            digest(marker + 1),
            digest(marker + 2),
            root_digest,
            root.state_sha256()
        );
        parse_cursor(bytes.as_bytes()).unwrap()
    }

    fn policy() -> (RemoteCursorPolicy, Vec<SigningKey>, String) {
        let keys = vec![
            SigningKey::from_bytes(&[71; 32]),
            SigningKey::from_bytes(&[72; 32]),
        ];
        let policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-cas-policy".into(),
            signature_domain: "bloch-control-plane-cas".into(),
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

    fn signed_receipt(
        request: &[u8],
        decision: RemoteCursorCasDecision,
    ) -> (Vec<u8>, RemoteCursorPolicy, String) {
        let (policy, keys, pin) = policy();
        let message =
            remote_cursor_cas_receipt_signature_message(request, &policy, &pin, &decision, 210)
                .unwrap();
        let signatures = keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let receipt =
            create_remote_cursor_cas_receipt(request, &policy, &pin, &decision, 210, &signatures)
                .unwrap();
        (receipt, policy, pin)
    }

    #[test]
    fn accepted_receipt_binds_exact_current_successor_and_lineage() {
        let roots = Roots::new();
        let (policy, _, pin) = policy();
        let request = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&roots.current_cursor),
                successor_cursor: &roots.successor_cursor,
                successor_root: &roots.successor_root,
                request_id: "request-1",
                request_nonce: NONCE,
                requested_at_unix_seconds: 200,
            },
            &policy,
            &pin,
        )
        .unwrap();
        let (receipt, policy, pin) = signed_receipt(&request, RemoteCursorCasDecision::Accepted);
        let verified =
            verify_remote_cursor_cas_receipt(&receipt, &request, &policy, &pin, 250).unwrap();
        let VerifiedRemoteCursorCasReceipt::Accepted(accepted) = verified else {
            panic!("acceptance must not decode as refusal");
        };
        assert_eq!(accepted.successor(), &roots.successor_cursor);
        assert_eq!(accepted.authority_ids(), &["authority-1", "authority-2"]);
        assert!(!accepted.remote_cas_execution_proven());
    }

    #[test]
    fn signed_refusal_cannot_be_interpreted_as_acceptance() {
        let roots = Roots::new();
        let (policy, _, pin) = policy();
        let request = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&roots.current_cursor),
                successor_cursor: &roots.successor_cursor,
                successor_root: &roots.successor_root,
                request_id: "request-2",
                request_nonce: NONCE,
                requested_at_unix_seconds: 200,
            },
            &policy,
            &pin,
        )
        .unwrap();
        let decision = RemoteCursorCasDecision::Refused {
            reason_code: "compare_and_swap_conflict".into(),
        };
        let (receipt, policy, pin) = signed_receipt(&request, decision);
        let verified =
            verify_remote_cursor_cas_receipt(&receipt, &request, &policy, &pin, 250).unwrap();
        let VerifiedRemoteCursorCasReceipt::Refused(refused) = verified else {
            panic!("refusal must remain a distinct type");
        };
        assert_eq!(refused.reason_code(), "compare_and_swap_conflict");
    }

    #[test]
    fn request_substitution_stale_receipt_and_tampering_fail_closed() {
        let roots = Roots::new();
        let (policy, keys, pin) = policy();
        let request = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&roots.current_cursor),
                successor_cursor: &roots.successor_cursor,
                successor_root: &roots.successor_root,
                request_id: "request-3",
                request_nonce: NONCE,
                requested_at_unix_seconds: 200,
            },
            &policy,
            &pin,
        )
        .unwrap();
        let message = remote_cursor_cas_receipt_signature_message(
            &request,
            &policy,
            &pin,
            &RemoteCursorCasDecision::Accepted,
            210,
        )
        .unwrap();
        let one = [RemoteCursorSignature {
            authority_id: "authority-1".into(),
            signature: format!("0x{}", hex::encode(keys[0].sign(&message).to_bytes())),
        }];
        assert!(matches!(
            create_remote_cursor_cas_receipt(
                &request,
                &policy,
                &pin,
                &RemoteCursorCasDecision::Accepted,
                210,
                &one
            ),
            Err(RemoteCursorCasError::ThresholdNotMet)
        ));
        let other_request = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&roots.current_cursor),
                successor_cursor: &roots.successor_cursor,
                successor_root: &roots.successor_root,
                request_id: "request-other",
                request_nonce: NONCE,
                requested_at_unix_seconds: 200,
            },
            &policy,
            &pin,
        )
        .unwrap();
        let (receipt, policy, pin) = signed_receipt(&request, RemoteCursorCasDecision::Accepted);
        assert!(matches!(
            verify_remote_cursor_cas_receipt(&receipt, &other_request, &policy, &pin, 250),
            Err(RemoteCursorCasError::RequestMismatch)
        ));
        assert!(matches!(
            verify_remote_cursor_cas_receipt(&receipt, &request, &policy, &pin, 271),
            Err(RemoteCursorCasError::OutsideFreshnessWindow)
        ));
        let mut noncanonical = receipt;
        noncanonical.push(b'\n');
        assert!(matches!(
            verify_remote_cursor_cas_receipt(&noncanonical, &request, &policy, &pin, 250),
            Err(RemoteCursorCasError::InvalidReceipt)
        ));
    }

    #[test]
    fn bootstrap_is_explicit_and_invalid_lineage_is_rejected() {
        let roots = Roots::new();
        let (policy, _, pin) = policy();
        let bootstrap = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: None,
                successor_cursor: &roots.current_cursor,
                successor_root: &roots.current_root,
                request_id: "bootstrap-1",
                request_nonce: NONCE,
                requested_at_unix_seconds: 200,
            },
            &policy,
            &pin,
        )
        .unwrap();
        let parsed = parse_remote_cursor_cas_request(&bootstrap, &policy, &pin).unwrap();
        assert_eq!(parsed.mode(), RemoteCursorCasMode::CreateOnceBootstrap);
        assert!(parsed.expected_current().is_none());
        assert_eq!(parsed.successor(), &roots.current_cursor);
        assert!(matches!(
            create_remote_cursor_cas_request(
                RemoteCursorCasRequestParameters {
                    expected_current: None,
                    successor_cursor: &roots.successor_cursor,
                    successor_root: &roots.successor_root,
                    request_id: "bootstrap-invalid",
                    request_nonce: NONCE,
                    requested_at_unix_seconds: 200,
                },
                &policy,
                &pin
            ),
            Err(RemoteCursorCasError::InvalidSuccessor)
        ));

        let other = Roots::with_initial(b"different-zero");
        assert!(matches!(
            create_remote_cursor_cas_request(
                RemoteCursorCasRequestParameters {
                    expected_current: Some(&roots.current_cursor),
                    successor_cursor: &other.successor_cursor,
                    successor_root: &other.successor_root,
                    request_id: "wrong-lineage",
                    request_nonce: NONCE,
                    requested_at_unix_seconds: 200,
                },
                &policy,
                &pin
            ),
            Err(RemoteCursorCasError::InvalidSuccessor)
        ));
    }
}
