use crate::{
    AuthorizedDecision, DataOperation, DecisionContext, GovernanceError, GovernancePolicy,
    MAX_FIELDS, authorize_governance_gate, reject_duplicate_keys, valid_identifier,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_JSON_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Runtime facts for a JSON ingestion. The field inventory is deliberately
/// absent: `authorize_json_ingestion` derives it from the exact payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonIngestionContext {
    pub now_unix_seconds: u64,
    pub institution_id: String,
    pub tenant_id: String,
    pub dataset_id: String,
    pub dataset_schema_id: String,
    pub purpose_id: String,
    pub processing_region: String,
    pub storage_region: String,
    pub jurisdictions: Vec<String>,
    pub workload_id: String,
    pub key_domain: String,
}

/// Opaque capability produced only after the exact JSON field inventory passes
/// the pinned governance policy.
#[derive(Clone, Debug)]
pub struct AuthorizedJsonIngestion {
    authorization: AuthorizedDecision,
    canonical_record_bytes: Vec<u8>,
    record_sha256: String,
    observed_field_ids: Vec<String>,
}

impl AuthorizedJsonIngestion {
    pub fn authorization(&self) -> &AuthorizedDecision {
        &self.authorization
    }

    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    pub fn canonical_record_bytes(&self) -> &[u8] {
        &self.canonical_record_bytes
    }

    pub fn observed_field_ids(&self) -> &[String] {
        &self.observed_field_ids
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JsonIngestionError {
    #[error("JSON record is empty")]
    Empty,
    #[error("JSON record exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid JSON record: {0}")]
    InvalidJson(String),
    #[error("JSON record must be a top-level object")]
    NotObject,
    #[error("JSON record has an invalid or excessive field inventory")]
    InvalidFieldInventory,
    #[error("cannot encode canonical JSON record: {0}")]
    Encoding(String),
    #[error("governance denied JSON ingestion: {0}")]
    Governance(#[from] GovernanceError),
}

/// Derives the top-level field inventory from exact JSON bytes and authorizes
/// ingestion against the independently pinned policy.
///
/// This function does not persist or decrypt data. The caller remains
/// responsible for authenticating runtime facts and writing only to the
/// admitted tenant/key domain after this capability is returned.
pub fn authorize_json_ingestion(
    policy: &GovernancePolicy,
    context: &JsonIngestionContext,
    record_bytes: &[u8],
) -> Result<AuthorizedJsonIngestion, JsonIngestionError> {
    if record_bytes.is_empty() {
        return Err(JsonIngestionError::Empty);
    }
    if record_bytes.len() > MAX_JSON_RECORD_BYTES {
        return Err(JsonIngestionError::TooLarge {
            actual: record_bytes.len(),
            maximum: MAX_JSON_RECORD_BYTES,
        });
    }
    reject_duplicate_keys(record_bytes)?;
    let value: Value = serde_json::from_slice(record_bytes)
        .map_err(|error| JsonIngestionError::InvalidJson(error.to_string()))?;
    let object = value.as_object().ok_or(JsonIngestionError::NotObject)?;
    if object.is_empty()
        || object.len() > MAX_FIELDS
        || object.keys().any(|field| !valid_identifier(field))
    {
        return Err(JsonIngestionError::InvalidFieldInventory);
    }
    let mut observed_field_ids = object.keys().cloned().collect::<Vec<_>>();
    observed_field_ids.sort();

    let decision = DecisionContext {
        now_unix_seconds: context.now_unix_seconds,
        institution_id: context.institution_id.clone(),
        tenant_id: context.tenant_id.clone(),
        dataset_id: context.dataset_id.clone(),
        dataset_schema_id: context.dataset_schema_id.clone(),
        purpose_id: context.purpose_id.clone(),
        operation: DataOperation::Ingest,
        processing_region: context.processing_region.clone(),
        storage_region: context.storage_region.clone(),
        jurisdictions: context.jurisdictions.clone(),
        workload_id: context.workload_id.clone(),
        key_domain: context.key_domain.clone(),
        recipient_id: None,
        observed_field_ids: observed_field_ids.clone(),
    };
    let authorization = authorize_governance_gate(policy, &decision)?;
    let canonical_record_bytes = serde_json::to_vec(&value)
        .map_err(|error| JsonIngestionError::Encoding(error.to_string()))?;
    let record_sha256 = format!("0x{}", hex::encode(Sha256::digest(&canonical_record_bytes)));
    Ok(AuthorizedJsonIngestion {
        authorization,
        canonical_record_bytes,
        record_sha256,
        observed_field_ids,
    })
}
