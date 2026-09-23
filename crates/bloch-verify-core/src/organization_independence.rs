//! Threshold-attested organizational-independence evidence.
//!
//! This verifier proves that a pinned reviewer policy signed one exact set of
//! disjoint control claims for one evidence bundle. It cannot inspect company
//! registries, beneficial ownership, infrastructure or key custody itself.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const ORGANIZATION_INDEPENDENCE_POLICY_SCHEMA: &str =
    "bloch.verify.organization-independence-policy.v1";
pub const ORGANIZATION_INDEPENDENCE_EVIDENCE_SCHEMA: &str =
    "bloch.verify.organization-independence-evidence.v1";
const SIGNING_PREFIX: &[u8] = b"BLOCH-VERIFY-ORGANIZATION-INDEPENDENCE-V1\0";
const MAX_BYTES: usize = 64 * 1024;
const MAX_ORGANIZATIONS: usize = 16;
const MAX_REVIEWERS: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OrganizationControlProfile {
    pub organization_id: String,
    pub legal_identity_evidence_sha256: String,
    pub beneficial_control_evidence_sha256: String,
    pub administrative_control_domain: String,
    pub infrastructure_control_domain: String,
    pub signing_key_control_domain: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IndependenceReviewer {
    pub reviewer_id: String,
    pub organization_id: String,
    pub control_domain: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OrganizationIndependencePolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub expected_network_sha256: String,
    pub minimum_organizations: u16,
    pub reviewer_threshold: u16,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub organizations: Vec<OrganizationControlProfile>,
    pub reviewers: Vec<IndependenceReviewer>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IndependenceSignature {
    pub reviewer_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IndependenceEnvelope {
    schema: String,
    organization_independence_policy_sha256: String,
    assessed_bundle_sha256: String,
    expected_network_sha256: String,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedIndependenceEvidence {
    envelope: IndependenceEnvelope,
    signatures: Vec<IndependenceSignature>,
}

/// Non-cloneable proof of a threshold-attested, structurally disjoint claim.
#[derive(Debug)]
pub struct VerifiedOrganizationIndependence {
    policy_sha256: String,
    evidence_sha256: String,
    assessed_bundle_sha256: String,
    expected_network_sha256: String,
    organization_ids: Vec<String>,
    reviewer_ids: Vec<String>,
    expires_at: Instant,
}

impl VerifiedOrganizationIndependence {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
    pub fn assessed_bundle_sha256(&self) -> &str {
        &self.assessed_bundle_sha256
    }
    pub fn expected_network_sha256(&self) -> &str {
        &self.expected_network_sha256
    }
    pub fn organization_ids(&self) -> &[String] {
        &self.organization_ids
    }
    pub fn reviewer_ids(&self) -> &[String] {
        &self.reviewer_ids
    }
    pub fn ensure_monotonic_freshness(&self) -> Result<(), OrganizationIndependenceError> {
        if Instant::now() >= self.expires_at {
            Err(OrganizationIndependenceError::ExpiredCapability)
        } else {
            Ok(())
        }
    }
    pub fn external_legal_facts_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrganizationIndependenceError {
    #[error("organization-independence policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("organization-independence policy pin mismatch")]
    PolicyPinMismatch,
    #[error("organization-independence evidence is invalid or non-canonical")]
    InvalidEvidence,
    #[error("organization-independence evidence crosses its pinned audience")]
    AudienceMismatch,
    #[error("organization-independence evidence is outside its validity window")]
    InvalidTime,
    #[error("organization-independence capability has expired")]
    ExpiredCapability,
    #[error("organization-independence reviewer is untrusted")]
    UntrustedReviewer,
    #[error("organization-independence signature is duplicated")]
    DuplicateSignature,
    #[error("organization-independence signature is invalid")]
    InvalidSignature,
    #[error("organization-independence reviewer threshold is not met")]
    ThresholdNotMet,
}

pub fn organization_independence_policy_bytes(
    policy: &OrganizationIndependencePolicy,
) -> Result<Vec<u8>, OrganizationIndependenceError> {
    validate_policy(policy)?;
    let bytes =
        serde_json::to_vec(policy).map_err(|_| OrganizationIndependenceError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(OrganizationIndependenceError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn organization_independence_policy_sha256(
    policy: &OrganizationIndependencePolicy,
) -> Result<String, OrganizationIndependenceError> {
    Ok(hash(&organization_independence_policy_bytes(policy)?))
}

pub fn parse_organization_independence_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<OrganizationIndependencePolicy, OrganizationIndependenceError> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES || !valid_sha256(expected_sha256) {
        return Err(OrganizationIndependenceError::InvalidPolicy);
    }
    let policy: OrganizationIndependencePolicy =
        serde_json::from_slice(bytes).map_err(|_| OrganizationIndependenceError::InvalidPolicy)?;
    if organization_independence_policy_bytes(&policy)? != bytes {
        return Err(OrganizationIndependenceError::InvalidPolicy);
    }
    if organization_independence_policy_sha256(&policy)? != expected_sha256 {
        return Err(OrganizationIndependenceError::PolicyPinMismatch);
    }
    Ok(policy)
}

pub fn organization_independence_signature_message(
    policy: &OrganizationIndependencePolicy,
    expected_policy_sha256: &str,
    assessed_bundle_sha256: &str,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
) -> Result<Vec<u8>, OrganizationIndependenceError> {
    let envelope = build_envelope(
        policy,
        expected_policy_sha256,
        assessed_bundle_sha256,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?;
    signing_bytes(&envelope)
}

pub fn create_organization_independence_evidence(
    policy: &OrganizationIndependencePolicy,
    expected_policy_sha256: &str,
    assessed_bundle_sha256: &str,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    signatures: Vec<IndependenceSignature>,
) -> Result<Vec<u8>, OrganizationIndependenceError> {
    let envelope = build_envelope(
        policy,
        expected_policy_sha256,
        assessed_bundle_sha256,
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    )?;
    validate_signature_order(&signatures)?;
    verify_signatures(policy, &signing_bytes(&envelope)?, &signatures)?;
    let bytes = serde_json::to_vec(&SignedIndependenceEvidence {
        envelope,
        signatures,
    })
    .map_err(|_| OrganizationIndependenceError::InvalidEvidence)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(OrganizationIndependenceError::InvalidEvidence);
    }
    Ok(bytes)
}

pub fn verify_organization_independence_evidence(
    evidence_bytes: &[u8],
    policy: &OrganizationIndependencePolicy,
    expected_policy_sha256: &str,
    expected_bundle_sha256: &str,
    expected_network_sha256: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<VerifiedOrganizationIndependence, OrganizationIndependenceError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if evidence_bytes.is_empty()
        || evidence_bytes.len() > MAX_BYTES
        || !valid_sha256(expected_bundle_sha256)
        || !valid_sha256(expected_network_sha256)
    {
        return Err(OrganizationIndependenceError::InvalidEvidence);
    }
    let evidence: SignedIndependenceEvidence = serde_json::from_slice(evidence_bytes)
        .map_err(|_| OrganizationIndependenceError::InvalidEvidence)?;
    if serde_json::to_vec(&evidence).map_err(|_| OrganizationIndependenceError::InvalidEvidence)?
        != evidence_bytes
    {
        return Err(OrganizationIndependenceError::InvalidEvidence);
    }
    let envelope = &evidence.envelope;
    if envelope.schema != ORGANIZATION_INDEPENDENCE_EVIDENCE_SCHEMA
        || envelope.organization_independence_policy_sha256 != expected_policy_sha256
        || envelope.assessed_bundle_sha256 != expected_bundle_sha256
        || envelope.expected_network_sha256 != expected_network_sha256
        || policy.expected_network_sha256 != expected_network_sha256
    {
        return Err(OrganizationIndependenceError::AudienceMismatch);
    }
    validate_times(
        policy,
        envelope.attested_at_unix_seconds,
        envelope.valid_until_unix_seconds,
    )?;
    if evaluated_at_unix_seconds < envelope.attested_at_unix_seconds
        || evaluated_at_unix_seconds >= envelope.valid_until_unix_seconds
        || evaluated_at_unix_seconds < policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= policy.expires_at_unix_seconds
        || evaluated_at_unix_seconds - envelope.attested_at_unix_seconds
            > policy.maximum_evidence_age_seconds
    {
        return Err(OrganizationIndependenceError::InvalidTime);
    }
    validate_signature_order(&evidence.signatures)?;
    verify_signatures(policy, &signing_bytes(envelope)?, &evidence.signatures)?;
    let remaining = envelope.valid_until_unix_seconds - evaluated_at_unix_seconds;
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(OrganizationIndependenceError::InvalidTime)?;
    Ok(VerifiedOrganizationIndependence {
        policy_sha256: expected_policy_sha256.into(),
        evidence_sha256: hash(evidence_bytes),
        assessed_bundle_sha256: expected_bundle_sha256.into(),
        expected_network_sha256: expected_network_sha256.into(),
        organization_ids: policy
            .organizations
            .iter()
            .map(|organization| organization.organization_id.clone())
            .collect(),
        reviewer_ids: evidence
            .signatures
            .iter()
            .map(|signature| signature.reviewer_id.clone())
            .collect(),
        expires_at,
    })
}

fn build_envelope(
    policy: &OrganizationIndependencePolicy,
    expected_policy_sha256: &str,
    assessed_bundle_sha256: &str,
    attested_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
) -> Result<IndependenceEnvelope, OrganizationIndependenceError> {
    validate_policy_pin(policy, expected_policy_sha256)?;
    if !valid_sha256(assessed_bundle_sha256) {
        return Err(OrganizationIndependenceError::InvalidEvidence);
    }
    validate_times(policy, attested_at_unix_seconds, valid_until_unix_seconds)?;
    Ok(IndependenceEnvelope {
        schema: ORGANIZATION_INDEPENDENCE_EVIDENCE_SCHEMA.into(),
        organization_independence_policy_sha256: expected_policy_sha256.into(),
        assessed_bundle_sha256: assessed_bundle_sha256.into(),
        expected_network_sha256: policy.expected_network_sha256.clone(),
        attested_at_unix_seconds,
        valid_until_unix_seconds,
    })
}

fn signing_bytes(
    envelope: &IndependenceEnvelope,
) -> Result<Vec<u8>, OrganizationIndependenceError> {
    let canonical =
        serde_json::to_vec(envelope).map_err(|_| OrganizationIndependenceError::InvalidEvidence)?;
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + canonical.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn validate_policy_pin(
    policy: &OrganizationIndependencePolicy,
    expected: &str,
) -> Result<(), OrganizationIndependenceError> {
    if !valid_sha256(expected) || organization_independence_policy_sha256(policy)? != expected {
        return Err(OrganizationIndependenceError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_times(
    policy: &OrganizationIndependencePolicy,
    attested_at: u64,
    valid_until: u64,
) -> Result<(), OrganizationIndependenceError> {
    let lifetime = valid_until
        .checked_sub(attested_at)
        .ok_or(OrganizationIndependenceError::InvalidTime)?;
    if lifetime == 0
        || lifetime > policy.maximum_evidence_age_seconds
        || attested_at < policy.effective_at_unix_seconds
        || valid_until > policy.expires_at_unix_seconds
    {
        return Err(OrganizationIndependenceError::InvalidTime);
    }
    Ok(())
}

fn validate_policy(
    policy: &OrganizationIndependencePolicy,
) -> Result<(), OrganizationIndependenceError> {
    if policy.schema != ORGANIZATION_INDEPENDENCE_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || !valid_id(&policy.signature_domain)
        || !valid_sha256(&policy.expected_network_sha256)
        || policy.minimum_organizations < 3
        || usize::from(policy.minimum_organizations) > policy.organizations.len()
        || policy.organizations.len() > MAX_ORGANIZATIONS
        || policy.reviewer_threshold < 2
        || usize::from(policy.reviewer_threshold) > policy.reviewers.len()
        || policy.reviewers.len() > MAX_REVIEWERS
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.maximum_evidence_age_seconds == 0
        || policy.maximum_evidence_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
    {
        return Err(OrganizationIndependenceError::InvalidPolicy);
    }
    let mut previous_org: Option<&str> = None;
    let mut legal = BTreeSet::new();
    let mut beneficial = BTreeSet::new();
    let mut organization_ids = BTreeSet::new();
    let mut organization_domains: Vec<BTreeSet<&str>> = Vec::new();
    for organization in &policy.organizations {
        if !valid_id(&organization.organization_id)
            || previous_org
                .is_some_and(|previous| previous >= organization.organization_id.as_str())
            || !valid_sha256(&organization.legal_identity_evidence_sha256)
            || !valid_sha256(&organization.beneficial_control_evidence_sha256)
            || !valid_id(&organization.administrative_control_domain)
            || !valid_id(&organization.infrastructure_control_domain)
            || !valid_id(&organization.signing_key_control_domain)
            || !legal.insert(organization.legal_identity_evidence_sha256.as_str())
            || !beneficial.insert(organization.beneficial_control_evidence_sha256.as_str())
        {
            return Err(OrganizationIndependenceError::InvalidPolicy);
        }
        let domains = BTreeSet::from([
            organization.administrative_control_domain.as_str(),
            organization.infrastructure_control_domain.as_str(),
            organization.signing_key_control_domain.as_str(),
        ]);
        if organization_domains
            .iter()
            .any(|existing| !existing.is_disjoint(&domains))
        {
            return Err(OrganizationIndependenceError::InvalidPolicy);
        }
        organization_domains.push(domains);
        organization_ids.insert(organization.organization_id.as_str());
        previous_org = Some(&organization.organization_id);
    }
    let all_assessed_domains = organization_domains
        .iter()
        .flat_map(|domains| domains.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut previous_reviewer: Option<&str> = None;
    let mut reviewer_organizations = BTreeSet::new();
    let mut reviewer_domains = BTreeSet::new();
    let mut reviewer_keys = BTreeSet::new();
    for reviewer in &policy.reviewers {
        let key = decode_key(&reviewer.ed25519_public_key)
            .map_err(|_| OrganizationIndependenceError::InvalidPolicy)?;
        if !valid_id(&reviewer.reviewer_id)
            || !valid_id(&reviewer.organization_id)
            || !valid_id(&reviewer.control_domain)
            || previous_reviewer.is_some_and(|previous| previous >= reviewer.reviewer_id.as_str())
            || organization_ids.contains(reviewer.organization_id.as_str())
            || all_assessed_domains.contains(reviewer.control_domain.as_str())
            || !reviewer_organizations.insert(reviewer.organization_id.as_str())
            || !reviewer_domains.insert(reviewer.control_domain.as_str())
            || !reviewer_keys.insert(key)
        {
            return Err(OrganizationIndependenceError::InvalidPolicy);
        }
        previous_reviewer = Some(&reviewer.reviewer_id);
    }
    Ok(())
}

fn validate_signature_order(
    signatures: &[IndependenceSignature],
) -> Result<(), OrganizationIndependenceError> {
    let mut previous: Option<&str> = None;
    for signature in signatures {
        if !valid_id(&signature.reviewer_id)
            || previous.is_some_and(|value| value >= signature.reviewer_id.as_str())
        {
            return Err(OrganizationIndependenceError::DuplicateSignature);
        }
        previous = Some(&signature.reviewer_id);
    }
    Ok(())
}

fn verify_signatures(
    policy: &OrganizationIndependencePolicy,
    message: &[u8],
    signatures: &[IndependenceSignature],
) -> Result<(), OrganizationIndependenceError> {
    let mut verified = 0usize;
    for signed in signatures {
        let reviewer = policy
            .reviewers
            .iter()
            .find(|reviewer| reviewer.reviewer_id == signed.reviewer_id)
            .ok_or(OrganizationIndependenceError::UntrustedReviewer)?;
        let key = VerifyingKey::from_bytes(&decode_key(&reviewer.ed25519_public_key)?)
            .map_err(|_| OrganizationIndependenceError::InvalidPolicy)?;
        let signature_bytes = decode_fixed::<64>(&signed.signature)
            .map_err(|_| OrganizationIndependenceError::InvalidSignature)?;
        key.verify(message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| OrganizationIndependenceError::InvalidSignature)?;
        verified += 1;
    }
    if verified < usize::from(policy.reviewer_threshold) {
        return Err(OrganizationIndependenceError::ThresholdNotMet);
    }
    Ok(())
}

fn decode_key(value: &str) -> Result<[u8; 32], OrganizationIndependenceError> {
    decode_fixed(value).map_err(|_| OrganizationIndependenceError::InvalidPolicy)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != 2 + N * 2 || !value.starts_with("0x") {
        return Err(());
    }
    let decoded = hex::decode(&value[2..]).map_err(|_| ())?;
    decoded.try_into().map_err(|_| ())
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
