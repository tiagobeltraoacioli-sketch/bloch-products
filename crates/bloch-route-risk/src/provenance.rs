use crate::{RouteQuote, validate_quotes};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const QUOTE_PROVENANCE_POLICY_SCHEMA: &str = "bloch.products.quote-provenance-policy.v1";
pub const QUOTE_PROVENANCE_ENVELOPE_SCHEMA: &str = "bloch.products.quote-provenance-envelope.v1";
pub const MAX_PROVENANCE_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_PROVENANCE_ENVELOPE_BYTES: usize = 256 * 1024;
const MAX_AUTHORITIES: usize = 128;
const SIGNING_PREFIX: &[u8] = b"BLOCH-PRODUCTS-QUOTE-PROVENANCE-V1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuoteAuthority {
    pub authority_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuoteProvenancePolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub audience: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signature_threshold: u16,
    pub authorities: Vec<QuoteAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuoteAuthoritySignature {
    pub authority_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuoteProvenanceEnvelope {
    pub schema: String,
    pub provenance_policy_sha256: String,
    pub route_risk_policy_sha256: String,
    pub signature_domain: String,
    pub audience: String,
    pub quote_set_sha256: String,
    pub issued_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub signatures: Vec<QuoteAuthoritySignature>,
}

/// Non-cloneable evidence that a pinned authority quorum signed one exact quote
/// set. This is source provenance, not an execution or finality capability.
#[derive(Debug)]
pub struct VerifiedQuoteProvenance {
    provenance_policy_sha256: String,
    route_risk_policy_sha256: String,
    quote_set_sha256: String,
    audience: String,
    signer_ids: Vec<String>,
    verified_at_unix_seconds: u64,
    deadline_unix_seconds: u64,
}

impl VerifiedQuoteProvenance {
    pub fn provenance_policy_sha256(&self) -> &str {
        &self.provenance_policy_sha256
    }
    pub fn route_risk_policy_sha256(&self) -> &str {
        &self.route_risk_policy_sha256
    }
    pub fn quote_set_sha256(&self) -> &str {
        &self.quote_set_sha256
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn signer_ids(&self) -> &[String] {
        &self.signer_ids
    }
    pub fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }
    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }
    pub(crate) fn authorize_comparison(
        &self,
        route_policy: &str,
        quotes: &[RouteQuote],
        at: u64,
    ) -> Result<(), QuoteProvenanceError> {
        if route_policy != self.route_risk_policy_sha256
            || quote_set_sha256(quotes)? != self.quote_set_sha256
        {
            return Err(QuoteProvenanceError::BindingMismatch);
        }
        // `verified_at` is an audit input, not authenticated production time.
        // Do not turn it into a reusable clock capability for another instant.
        if at != self.verified_at_unix_seconds || at >= self.deadline_unix_seconds {
            return Err(QuoteProvenanceError::AuditInstantMismatch);
        }
        Ok(())
    }
    pub fn quote_quality_proven(&self) -> bool {
        false
    }
    pub fn settlement_or_finality_proven(&self) -> bool {
        false
    }
    pub fn execution_authorized(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuoteProvenanceError {
    #[error("quote-provenance policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("quote-provenance policy pin mismatch")]
    PolicyPinMismatch,
    #[error("quote-provenance envelope is invalid")]
    InvalidEnvelope,
    #[error("quote provenance audience does not match")]
    AudienceMismatch,
    #[error("quote provenance is not effective or has expired")]
    NotEffective,
    #[error("quote provenance does not bind the exact policy and quote set")]
    BindingMismatch,
    #[error("quote authority is not trusted")]
    UntrustedAuthority,
    #[error("quote authority signature is duplicated")]
    DuplicateSignature,
    #[error("quote authority signature is invalid")]
    InvalidSignature,
    #[error("quote authority signature threshold was not met")]
    InsufficientSignatures,
    #[error("quote-provenance capability is bound to a different audit instant")]
    AuditInstantMismatch,
    #[error("quote set is invalid")]
    InvalidQuotes,
}

pub fn canonical_quote_provenance_policy_bytes(
    policy: &QuoteProvenancePolicy,
) -> Result<Vec<u8>, QuoteProvenanceError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| QuoteProvenanceError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_PROVENANCE_POLICY_BYTES {
        return Err(QuoteProvenanceError::InvalidPolicy);
    }
    Ok(bytes)
}
pub fn quote_provenance_policy_sha256(
    policy: &QuoteProvenancePolicy,
) -> Result<String, QuoteProvenanceError> {
    Ok(hash(&canonical_quote_provenance_policy_bytes(policy)?))
}
pub fn parse_quote_provenance_policy(
    bytes: &[u8],
    expected: &str,
) -> Result<QuoteProvenancePolicy, QuoteProvenanceError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVENANCE_POLICY_BYTES || !valid_hash(expected) {
        return Err(QuoteProvenanceError::InvalidPolicy);
    }
    let policy: QuoteProvenancePolicy =
        serde_json::from_slice(bytes).map_err(|_| QuoteProvenanceError::InvalidPolicy)?;
    if canonical_quote_provenance_policy_bytes(&policy)? != bytes {
        return Err(QuoteProvenanceError::InvalidPolicy);
    }
    if quote_provenance_policy_sha256(&policy)? != expected {
        return Err(QuoteProvenanceError::PolicyPinMismatch);
    }
    Ok(policy)
}
pub fn canonical_quote_bytes(quotes: &[RouteQuote]) -> Result<Vec<u8>, QuoteProvenanceError> {
    validate_quotes(quotes).map_err(|_| QuoteProvenanceError::InvalidQuotes)?;
    serde_json::to_vec(quotes).map_err(|_| QuoteProvenanceError::InvalidQuotes)
}
pub fn quote_set_sha256(quotes: &[RouteQuote]) -> Result<String, QuoteProvenanceError> {
    Ok(hash(&canonical_quote_bytes(quotes)?))
}

pub fn quote_signing_message(
    envelope: &QuoteProvenanceEnvelope,
) -> Result<Vec<u8>, QuoteProvenanceError> {
    validate_envelope(envelope, false)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fields<'a> {
        schema: &'a str,
        provenance_policy_sha256: &'a str,
        route_risk_policy_sha256: &'a str,
        signature_domain: &'a str,
        audience: &'a str,
        quote_set_sha256: &'a str,
        issued_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
    }
    let fields = Fields {
        schema: &envelope.schema,
        provenance_policy_sha256: &envelope.provenance_policy_sha256,
        route_risk_policy_sha256: &envelope.route_risk_policy_sha256,
        signature_domain: &envelope.signature_domain,
        audience: &envelope.audience,
        quote_set_sha256: &envelope.quote_set_sha256,
        issued_at_unix_seconds: envelope.issued_at_unix_seconds,
        valid_until_unix_seconds: envelope.valid_until_unix_seconds,
    };
    let canonical =
        serde_json::to_vec(&fields).map_err(|_| QuoteProvenanceError::InvalidEnvelope)?;
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + canonical.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(&canonical);
    Ok(message)
}

pub fn verify_quote_provenance(
    policy: &QuoteProvenancePolicy,
    expected_policy: &str,
    expected_route_policy: &str,
    expected_audience: &str,
    quotes: &[RouteQuote],
    envelope: &QuoteProvenanceEnvelope,
    verified_at: u64,
) -> Result<VerifiedQuoteProvenance, QuoteProvenanceError> {
    let actual_policy = quote_provenance_policy_sha256(policy)?;
    if !valid_hash(expected_policy) || actual_policy != expected_policy {
        return Err(QuoteProvenanceError::PolicyPinMismatch);
    }
    validate_envelope(envelope, true)?;
    if envelope.provenance_policy_sha256 != expected_policy
        || envelope.route_risk_policy_sha256 != expected_route_policy
        || envelope.quote_set_sha256 != quote_set_sha256(quotes)?
    {
        return Err(QuoteProvenanceError::BindingMismatch);
    }
    if envelope.audience != policy.audience
        || envelope.audience != expected_audience
        || envelope.signature_domain != policy.signature_domain
    {
        return Err(QuoteProvenanceError::AudienceMismatch);
    }
    let quote_expiry = quotes
        .iter()
        .map(|q| q.expires_at_unix_seconds)
        .min()
        .ok_or(QuoteProvenanceError::InvalidQuotes)?;
    let latest_observation = quotes
        .iter()
        .map(|q| q.observed_at_unix_seconds)
        .max()
        .ok_or(QuoteProvenanceError::InvalidQuotes)?;
    if verified_at < policy.effective_at_unix_seconds
        || verified_at >= policy.expires_at_unix_seconds
        || envelope.issued_at_unix_seconds < policy.effective_at_unix_seconds
        || envelope.issued_at_unix_seconds < latest_observation
        || envelope.issued_at_unix_seconds > verified_at
        || envelope.valid_until_unix_seconds <= verified_at
        || envelope.valid_until_unix_seconds > policy.expires_at_unix_seconds
        || envelope.valid_until_unix_seconds > quote_expiry
    {
        return Err(QuoteProvenanceError::NotEffective);
    }
    let message = quote_signing_message(envelope)?;
    let authorities: BTreeMap<&str, &QuoteAuthority> = policy
        .authorities
        .iter()
        .map(|a| (a.authority_id.as_str(), a))
        .collect();
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut signer_ids = Vec::new();
    for signed in &envelope.signatures {
        if !valid_id(&signed.authority_id)
            || previous.is_some_and(|value| value > signed.authority_id.as_str())
        {
            return Err(QuoteProvenanceError::InvalidEnvelope);
        }
        if !seen.insert(signed.authority_id.as_str()) {
            return Err(QuoteProvenanceError::DuplicateSignature);
        }
        let authority = authorities
            .get(signed.authority_id.as_str())
            .ok_or(QuoteProvenanceError::UntrustedAuthority)?;
        let key_bytes: [u8; 32] = decode_fixed(&authority.ed25519_public_key)
            .ok_or(QuoteProvenanceError::InvalidPolicy)?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| QuoteProvenanceError::InvalidPolicy)?;
        if key.is_weak() {
            return Err(QuoteProvenanceError::InvalidPolicy);
        }
        let signature: [u8; 64] =
            decode_fixed(&signed.signature).ok_or(QuoteProvenanceError::InvalidSignature)?;
        key.verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| QuoteProvenanceError::InvalidSignature)?;
        signer_ids.push(signed.authority_id.clone());
        previous = Some(&signed.authority_id);
    }
    if signer_ids.len() < usize::from(policy.signature_threshold) {
        return Err(QuoteProvenanceError::InsufficientSignatures);
    }
    Ok(VerifiedQuoteProvenance {
        provenance_policy_sha256: actual_policy,
        route_risk_policy_sha256: envelope.route_risk_policy_sha256.clone(),
        quote_set_sha256: envelope.quote_set_sha256.clone(),
        audience: envelope.audience.clone(),
        signer_ids,
        verified_at_unix_seconds: verified_at,
        deadline_unix_seconds: envelope.valid_until_unix_seconds,
    })
}

fn validate_policy(policy: &QuoteProvenancePolicy) -> Result<(), QuoteProvenanceError> {
    if policy.schema != QUOTE_PROVENANCE_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_id(&policy.audience)
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.authorities.is_empty()
        || policy.authorities.len() > MAX_AUTHORITIES
        || policy.signature_threshold == 0
        || usize::from(policy.signature_threshold) > policy.authorities.len()
    {
        return Err(QuoteProvenanceError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for authority in &policy.authorities {
        let bytes: [u8; 32] = decode_fixed(&authority.ed25519_public_key)
            .ok_or(QuoteProvenanceError::InvalidPolicy)?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| QuoteProvenanceError::InvalidPolicy)?;
        if key.is_weak()
            || !valid_id(&authority.authority_id)
            || previous.is_some_and(|v| v >= authority.authority_id.as_str())
            || !keys.insert(bytes)
        {
            return Err(QuoteProvenanceError::InvalidPolicy);
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}
fn validate_envelope(
    envelope: &QuoteProvenanceEnvelope,
    require_signatures: bool,
) -> Result<(), QuoteProvenanceError> {
    let encoded_len = serde_json::to_vec(envelope)
        .map_err(|_| QuoteProvenanceError::InvalidEnvelope)?
        .len();
    if envelope.schema != QUOTE_PROVENANCE_ENVELOPE_SCHEMA
        || !valid_hash(&envelope.provenance_policy_sha256)
        || !valid_hash(&envelope.route_risk_policy_sha256)
        || !valid_hash(&envelope.quote_set_sha256)
        || !valid_id(&envelope.signature_domain)
        || !valid_id(&envelope.audience)
        || envelope.issued_at_unix_seconds == 0
        || envelope.valid_until_unix_seconds <= envelope.issued_at_unix_seconds
        || (require_signatures && envelope.signatures.is_empty())
        || envelope.signatures.len() > MAX_AUTHORITIES
        || encoded_len > MAX_PROVENANCE_ENVELOPE_BYTES
    {
        return Err(QuoteProvenanceError::InvalidEnvelope);
    }
    Ok(())
}
fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != 2 + N * 2 || !value.starts_with("0x") {
        return None;
    }
    hex::decode(&value[2..]).ok()?.try_into().ok()
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
