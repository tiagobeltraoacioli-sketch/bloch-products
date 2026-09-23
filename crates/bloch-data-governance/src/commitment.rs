//! A narrowly scoped salted SHA-256 commitment for already-authorized records.
//!
//! This construction is useful for deterministic offline verification when the
//! verifier possesses the authorized source values and the external nonce. It
//! is not claimed to be a qualified hiding commitment: low-entropy values are
//! susceptible to dictionary attacks if the nonce is weak, reused or leaked.

use crate::{AuthorizedDecision, AuthorizedJsonIngestion, DataOperation, OnChainCommitmentInput};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SALTED_RECORD_COMMITMENT_CONSTRUCTION_ID: &str = "sha256-salted-authorized-record-v1";
pub const MIN_EXTERNAL_NONCE_BYTES: usize = 32;
pub const MAX_EXTERNAL_NONCE_BYTES: usize = 64;
const PREIMAGE_DOMAIN: &[u8] = b"bloch.data.salted-authorized-record-commitment.v1";

/// Inputs which must remain off-chain together with the protected record.
///
/// The caller must source a fresh, unpredictable nonce independently for every
/// commitment. This crate checks its size and rejects obvious degenerate input,
/// but cannot infer or prove its entropy, freshness or secrecy from bytes.
#[derive(Clone, Copy)]
pub struct SaltedRecordCommitmentRequest<'a> {
    pub artifact_rule_id: &'a str,
    pub external_nonce: &'a [u8],
}

/// Opaque result safe to pass to the existing on-chain authorization gate.
///
/// It contains no opening, record value, source-field name, policy digest,
/// tenant, dataset, schema digest or external nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaltedRecordCommitment {
    artifact_rule_id: String,
    domain: String,
    commitment: [u8; 32],
}

impl SaltedRecordCommitment {
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn as_onchain_input(&self) -> OnChainCommitmentInput {
        OnChainCommitmentInput {
            artifact_rule_id: self.artifact_rule_id.clone(),
            construction_id: SALTED_RECORD_COMMITMENT_CONSTRUCTION_ID.into(),
            domain: self.domain.clone(),
            commitment: self.commitment,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OfflineCommitmentError {
    #[error("commitment publication authorization is not valid for this record: {0}")]
    Authorization(&'static str),
    #[error("commitment rule is not valid for this construction: {0}")]
    Rule(&'static str),
    #[error("external nonce length must be between {minimum} and {maximum} bytes: {actual} bytes")]
    NonceLength {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error("external nonce is an obviously degenerate value")]
    DegenerateNonce,
    #[error("authorized record representation is invalid")]
    InvalidAuthorizedRecord,
    #[error("commitment does not match the authorized record opening")]
    CommitmentMismatch,
}

/// Commits to the policy-authorized projection of an authorized JSON record.
///
/// Both opaque capabilities are required: ingestion proves structural and
/// governance admission of the exact record; publication proves that the same
/// pinned policy authorized the exact hidden-source inventory for the named
/// commitment rule. No I/O, nonce generation, key management or publication is
/// performed here.
pub fn commit_authorized_json_record(
    ingestion: &AuthorizedJsonIngestion,
    publication: &AuthorizedDecision,
    request: SaltedRecordCommitmentRequest<'_>,
) -> Result<SaltedRecordCommitment, OfflineCommitmentError> {
    validate_nonce(request.external_nonce)?;
    let (domain, commitment) = calculate(ingestion, publication, request)?;
    Ok(SaltedRecordCommitment {
        artifact_rule_id: request.artifact_rule_id.into(),
        domain,
        commitment,
    })
}

/// Recomputes and compares a commitment without network access.
///
/// Success proves only equality under this SHA-256 construction and the two
/// supplied authorization capabilities. It does not prove provenance, truth,
/// freshness, legal compliance, consensus finality or hiding strength.
pub fn verify_authorized_json_record_commitment(
    ingestion: &AuthorizedJsonIngestion,
    publication: &AuthorizedDecision,
    request: SaltedRecordCommitmentRequest<'_>,
    expected: &SaltedRecordCommitment,
) -> Result<(), OfflineCommitmentError> {
    let actual = commit_authorized_json_record(ingestion, publication, request)?;
    if actual.artifact_rule_id != expected.artifact_rule_id
        || actual.domain != expected.domain
        || !constant_time_equal(&actual.commitment, &expected.commitment)
    {
        return Err(OfflineCommitmentError::CommitmentMismatch);
    }
    Ok(())
}

fn calculate(
    ingestion: &AuthorizedJsonIngestion,
    publication: &AuthorizedDecision,
    request: SaltedRecordCommitmentRequest<'_>,
) -> Result<(String, [u8; 32]), OfflineCommitmentError> {
    if publication.operation != DataOperation::PublishCommitment {
        return Err(OfflineCommitmentError::Authorization("operation"));
    }
    if ingestion.authorization().policy_sha256 != publication.policy_sha256 {
        return Err(OfflineCommitmentError::Authorization("policySha256"));
    }
    let rule = publication
        .commitment_rules
        .get(request.artifact_rule_id)
        .ok_or(OfflineCommitmentError::Rule("artifactRuleId"))?;
    if rule.construction_id != SALTED_RECORD_COMMITMENT_CONSTRUCTION_ID {
        return Err(OfflineCommitmentError::Rule("constructionId"));
    }

    let publication_fields = publication
        .observed_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let rule_fields = rule
        .hidden_source_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if publication_fields != rule_fields {
        return Err(OfflineCommitmentError::Authorization("hiddenSourceFields"));
    }
    if !rule
        .hidden_source_fields
        .iter()
        .all(|field| ingestion.observed_field_ids().binary_search(field).is_ok())
    {
        return Err(OfflineCommitmentError::Authorization("recordFields"));
    }

    let record: Value = serde_json::from_slice(ingestion.canonical_record_bytes())
        .map_err(|_| OfflineCommitmentError::InvalidAuthorizedRecord)?;
    let object = record
        .as_object()
        .ok_or(OfflineCommitmentError::InvalidAuthorizedRecord)?;

    let mut digest = Sha256::new();
    update_framed(&mut digest, PREIMAGE_DOMAIN);
    update_framed(&mut digest, publication.policy_sha256.as_bytes());
    update_framed(&mut digest, request.artifact_rule_id.as_bytes());
    update_framed(
        &mut digest,
        SALTED_RECORD_COMMITMENT_CONSTRUCTION_ID.as_bytes(),
    );
    update_framed(&mut digest, rule.domain.as_bytes());
    update_framed(&mut digest, ingestion.dataset_schema_sha256().as_bytes());
    update_framed(
        &mut digest,
        &(rule.hidden_source_fields.len() as u64).to_be_bytes(),
    );
    for field in &rule.hidden_source_fields {
        let value = object
            .get(field)
            .ok_or(OfflineCommitmentError::InvalidAuthorizedRecord)?;
        let canonical_value = serde_json::to_vec(value)
            .map_err(|_| OfflineCommitmentError::InvalidAuthorizedRecord)?;
        update_framed(&mut digest, field.as_bytes());
        update_framed(&mut digest, &canonical_value);
    }
    update_framed(&mut digest, request.external_nonce);
    Ok((rule.domain.clone(), digest.finalize().into()))
}

fn validate_nonce(nonce: &[u8]) -> Result<(), OfflineCommitmentError> {
    if !(MIN_EXTERNAL_NONCE_BYTES..=MAX_EXTERNAL_NONCE_BYTES).contains(&nonce.len()) {
        return Err(OfflineCommitmentError::NonceLength {
            actual: nonce.len(),
            minimum: MIN_EXTERNAL_NONCE_BYTES,
            maximum: MAX_EXTERNAL_NONCE_BYTES,
        });
    }
    if nonce.iter().all(|byte| *byte == nonce[0]) {
        return Err(OfflineCommitmentError::DegenerateNonce);
    }
    Ok(())
}

fn update_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
