//! Offline, fail-closed policy enforcement for regulated-data operations.
//!
//! The crate enforces an approved, independently pinned decision. It does not
//! decide legal applicability, authenticate runtime facts, execute retention,
//! or prove that an external commitment construction is privacy preserving.

use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

mod dataset_schema;
mod record;
pub use dataset_schema::{
    DATASET_SCHEMA_SCHEMA, DatasetFieldSchema, DatasetSchema, DatasetSchemaError,
    DatasetValueSchema, MAX_ARRAY_ITEMS, MAX_DATASET_SCHEMA_BYTES, MAX_STRING_BYTES, ScalarType,
    canonical_dataset_schema_bytes, dataset_schema_sha256, parse_dataset_schema,
};
pub use record::{
    AuthorizedJsonIngestion, JsonIngestionContext, JsonIngestionError, MAX_JSON_RECORD_BYTES,
    authorize_json_ingestion,
};

pub const GOVERNANCE_POLICY_SCHEMA: &str = "bloch.data.governance-policy.v1";
pub const DECISION_REPORT_SCHEMA: &str = "bloch.data.governance-decision.v1";
pub const ONCHAIN_COMMITMENT_SCHEMA: &str = "bloch.data.minimized-commitment.v1";
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_FIELDS: usize = 1_024;
pub const MAX_ARTIFACT_RULES: usize = 128;
pub const MAX_LIST_ITEMS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DataOperation {
    Ingest,
    Read,
    Derive,
    Export,
    PublishCommitment,
    Delete,
    IrreversiblyAnonymize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Personal,
    SensitivePersonal,
    FinancialConfidential,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCategory {
    PublicNonIdentifying,
    Operational,
    Pii,
    AccountIdentifier,
    CorrelatableIdentifier,
    Order,
    Trade,
    Balance,
    Position,
    Custody,
    Credential,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldPlacement {
    /// The value stays off-chain and cannot feed an on-chain artifact.
    OffChainOnly,
    /// The value stays off-chain but may be a hidden input to an approved
    /// randomized commitment. It is never included in the envelope.
    OffChainCommitmentSource,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDisposition {
    Delete,
    IrreversiblyAnonymize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetentionRule {
    pub dispose_after_unix_seconds: u64,
    pub legal_hold_id: Option<String>,
    pub disposition: RetentionDisposition,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FieldRule {
    pub field_id: String,
    pub classification: DataClassification,
    pub semantic_category: SemanticCategory,
    pub placement: FieldPlacement,
    pub required_for: Vec<DataOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OnChainCommitmentRule {
    pub artifact_rule_id: String,
    pub construction_id: String,
    pub domain: String,
    pub hidden_source_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GovernancePolicy {
    pub schema: String,
    pub policy_id: String,
    pub version: u64,
    pub institution_id: String,
    pub tenant_id: String,
    pub dataset_id: String,
    pub dataset_schema_id: String,
    pub purpose_id: String,
    pub effective_at_unix_seconds: u64,
    pub approval_expires_at_unix_seconds: u64,
    pub allowed_operations: Vec<DataOperation>,
    pub applicable_jurisdictions: Vec<String>,
    pub processing_regions: Vec<String>,
    pub storage_regions: Vec<String>,
    pub controller_id: String,
    pub operator_id: String,
    pub privacy_contact_id: String,
    pub authorization_evidence_sha256: String,
    pub key_domain: String,
    pub allowed_workload_ids: Vec<String>,
    pub permitted_recipient_ids: Vec<String>,
    pub forbidden_field_ids: Vec<String>,
    pub retention: RetentionRule,
    pub fields: Vec<FieldRule>,
    pub onchain_commitments: Vec<OnChainCommitmentRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionContext {
    pub now_unix_seconds: u64,
    pub institution_id: String,
    pub tenant_id: String,
    pub dataset_id: String,
    pub dataset_schema_id: String,
    pub purpose_id: String,
    pub operation: DataOperation,
    pub processing_region: String,
    pub storage_region: String,
    pub jurisdictions: Vec<String>,
    pub workload_id: String,
    pub key_domain: String,
    pub recipient_id: Option<String>,
    /// Must be populated by the trusted schema decoder, not from an
    /// unauthenticated caller's declaration.
    pub observed_field_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecisionCheck {
    check_id: String,
    outcome: CheckOutcome,
    code: String,
}

impl DecisionCheck {
    pub fn check_id(&self) -> &str {
        &self.check_id
    }
    pub fn outcome(&self) -> CheckOutcome {
        self.outcome
    }
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecisionReport {
    schema: String,
    policy_sha256: String,
    admitted: bool,
    checks: Vec<DecisionCheck>,
}

impl DecisionReport {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn admitted(&self) -> bool {
        self.admitted
    }
    pub fn checks(&self) -> &[DecisionCheck] {
        &self.checks
    }
}

/// Only `authorize_governance_gate` can construct this capability.
#[derive(Clone, Debug)]
pub struct AuthorizedDecision {
    policy_sha256: String,
    operation: DataOperation,
    observed_fields: BTreeSet<String>,
    commitment_rules: BTreeMap<String, OnChainCommitmentRule>,
}

impl AuthorizedDecision {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn operation(&self) -> DataOperation {
        self.operation
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnChainCommitmentInput {
    pub artifact_rule_id: String,
    pub construction_id: String,
    pub domain: String,
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OnChainCommitmentEnvelope {
    schema: String,
    artifact_rule_id: String,
    construction_id: String,
    domain: String,
    commitment: String,
    authorization_context_sha256: String,
}

impl OnChainCommitmentEnvelope {
    pub fn artifact_rule_id(&self) -> &str {
        &self.artifact_rule_id
    }
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
    pub fn authorization_context_sha256(&self) -> &str {
        &self.authorization_context_sha256
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GovernanceError {
    #[error("governance policy input is empty")]
    Empty,
    #[error("governance policy exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid governance policy JSON: {0}")]
    InvalidJson(String),
    #[error("invalid governance policy field: {0}")]
    InvalidPolicy(&'static str),
    #[error("governance policy is not canonical JSON")]
    NonCanonicalPolicy,
    #[error("governance policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("governance decision denied")]
    Denied,
    #[error("on-chain commitment authorization is invalid: {0}")]
    InvalidCommitment(&'static str),
    #[error("cannot encode governance output: {0}")]
    Encoding(String),
}

pub fn canonical_governance_policy_bytes(
    policy: &GovernancePolicy,
) -> Result<Vec<u8>, GovernanceError> {
    validate_policy(policy)?;
    serde_json::to_vec(policy).map_err(|error| GovernanceError::Encoding(error.to_string()))
}

pub fn governance_policy_sha256(policy: &GovernancePolicy) -> Result<String, GovernanceError> {
    Ok(sha256(&canonical_governance_policy_bytes(policy)?))
}

pub fn parse_governance_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<GovernancePolicy, GovernanceError> {
    check_size(bytes)?;
    require_nonzero_sha256(expected_sha256, "expectedSha256")?;
    reject_duplicate_keys(bytes)?;
    let policy: GovernancePolicy = serde_json::from_slice(bytes)
        .map_err(|error| GovernanceError::InvalidJson(error.to_string()))?;
    validate_policy(&policy)?;
    if canonical_governance_policy_bytes(&policy)? != bytes {
        return Err(GovernanceError::NonCanonicalPolicy);
    }
    if sha256(bytes) != expected_sha256 {
        return Err(GovernanceError::PolicyDigestMismatch);
    }
    Ok(policy)
}

pub fn evaluate_governance_gate(
    policy: &GovernancePolicy,
    context: &DecisionContext,
) -> Result<DecisionReport, GovernanceError> {
    validate_policy(policy)?;
    let policy_sha256 = governance_policy_sha256(policy)?;
    let mut checks = Vec::with_capacity(12);
    check(
        &mut checks,
        "context.identity",
        context.institution_id == policy.institution_id
            && context.tenant_id == policy.tenant_id
            && context.dataset_id == policy.dataset_id
            && context.dataset_schema_id == policy.dataset_schema_id,
        "identity_verified",
        "identity_mismatch",
    );
    check(
        &mut checks,
        "context.purpose",
        context.purpose_id == policy.purpose_id,
        "purpose_verified",
        "purpose_mismatch",
    );
    check(
        &mut checks,
        "context.operation",
        policy
            .allowed_operations
            .binary_search(&context.operation)
            .is_ok(),
        "operation_allowed",
        "operation_denied",
    );
    check(
        &mut checks,
        "context.workload",
        policy
            .allowed_workload_ids
            .binary_search(&context.workload_id)
            .is_ok(),
        "workload_allowed",
        "workload_denied",
    );
    check(
        &mut checks,
        "context.key_domain",
        context.key_domain == policy.key_domain,
        "key_domain_verified",
        "key_domain_denied",
    );
    check(
        &mut checks,
        "context.processing_region",
        policy
            .processing_regions
            .binary_search(&context.processing_region)
            .is_ok(),
        "processing_region_allowed",
        "processing_region_denied",
    );
    check(
        &mut checks,
        "context.storage_region",
        policy
            .storage_regions
            .binary_search(&context.storage_region)
            .is_ok(),
        "storage_region_allowed",
        "storage_region_denied",
    );
    let jurisdictions_valid = is_sorted_unique(&context.jurisdictions)
        && !context.jurisdictions.is_empty()
        && context
            .jurisdictions
            .iter()
            .all(|item| policy.applicable_jurisdictions.binary_search(item).is_ok());
    check(
        &mut checks,
        "context.jurisdictions",
        jurisdictions_valid,
        "jurisdictions_allowed",
        "jurisdictions_denied",
    );
    let recipient_valid = match context.operation {
        DataOperation::Export => context.recipient_id.as_ref().is_some_and(|recipient| {
            policy
                .permitted_recipient_ids
                .binary_search(recipient)
                .is_ok()
        }),
        _ => context.recipient_id.is_none(),
    };
    check(
        &mut checks,
        "context.recipient",
        recipient_valid,
        "recipient_allowed",
        "recipient_denied",
    );
    let lifecycle = matches!(
        context.operation,
        DataOperation::Delete | DataOperation::IrreversiblyAnonymize
    );
    let time_valid = if lifecycle {
        context.now_unix_seconds >= policy.retention.dispose_after_unix_seconds
            && policy.retention.legal_hold_id.is_none()
            && matches!(
                (context.operation, policy.retention.disposition),
                (DataOperation::Delete, RetentionDisposition::Delete)
                    | (
                        DataOperation::IrreversiblyAnonymize,
                        RetentionDisposition::IrreversiblyAnonymize
                    )
            )
    } else {
        context.now_unix_seconds >= policy.effective_at_unix_seconds
            && context.now_unix_seconds < policy.approval_expires_at_unix_seconds
            && context.now_unix_seconds < policy.retention.dispose_after_unix_seconds
    };
    check(
        &mut checks,
        "context.time_retention",
        time_valid,
        "time_and_retention_allowed",
        "time_or_retention_denied",
    );
    let fields_valid = validate_observed_fields(policy, context);
    check(
        &mut checks,
        "context.fields",
        fields_valid,
        "fields_minimized",
        "fields_denied",
    );
    let commitment_context = context.operation != DataOperation::PublishCommitment
        || !policy.onchain_commitments.is_empty();
    check(
        &mut checks,
        "context.onchain",
        commitment_context,
        "onchain_rule_available",
        "onchain_rule_missing",
    );
    let admitted = checks
        .iter()
        .all(|item| item.outcome == CheckOutcome::Passed);
    Ok(DecisionReport {
        schema: DECISION_REPORT_SCHEMA.into(),
        policy_sha256,
        admitted,
        checks,
    })
}

pub fn authorize_governance_gate(
    policy: &GovernancePolicy,
    context: &DecisionContext,
) -> Result<AuthorizedDecision, GovernanceError> {
    let report = evaluate_governance_gate(policy, context)?;
    if !report.admitted {
        return Err(GovernanceError::Denied);
    }
    Ok(AuthorizedDecision {
        policy_sha256: report.policy_sha256,
        operation: context.operation,
        observed_fields: context.observed_field_ids.iter().cloned().collect(),
        commitment_rules: policy
            .onchain_commitments
            .iter()
            .cloned()
            .map(|rule| (rule.artifact_rule_id.clone(), rule))
            .collect(),
    })
}

pub fn authorize_onchain_commitment(
    authorization: &AuthorizedDecision,
    input: &OnChainCommitmentInput,
) -> Result<OnChainCommitmentEnvelope, GovernanceError> {
    if authorization.operation != DataOperation::PublishCommitment {
        return Err(GovernanceError::InvalidCommitment("operation"));
    }
    let rule = authorization
        .commitment_rules
        .get(&input.artifact_rule_id)
        .ok_or(GovernanceError::InvalidCommitment("artifactRuleId"))?;
    if input.construction_id != rule.construction_id {
        return Err(GovernanceError::InvalidCommitment("constructionId"));
    }
    if input.domain != rule.domain {
        return Err(GovernanceError::InvalidCommitment("domain"));
    }
    if input.commitment.iter().all(|byte| *byte == 0) {
        return Err(GovernanceError::InvalidCommitment("commitment"));
    }
    if !rule
        .hidden_source_fields
        .iter()
        .all(|field| authorization.observed_fields.contains(field))
    {
        return Err(GovernanceError::InvalidCommitment("hiddenSourceFields"));
    }
    let authorization_context_sha256 = commitment_authorization_context_sha256(
        &authorization.policy_sha256,
        rule,
        &input.commitment,
    );
    Ok(OnChainCommitmentEnvelope {
        schema: ONCHAIN_COMMITMENT_SCHEMA.into(),
        artifact_rule_id: rule.artifact_rule_id.clone(),
        construction_id: rule.construction_id.clone(),
        domain: rule.domain.clone(),
        commitment: format!("0x{}", hex::encode(input.commitment)),
        authorization_context_sha256,
    })
}

pub fn decision_report_bytes(report: &DecisionReport) -> Result<Vec<u8>, GovernanceError> {
    serde_json::to_vec(report).map_err(|error| GovernanceError::Encoding(error.to_string()))
}

pub fn onchain_commitment_envelope_bytes(
    envelope: &OnChainCommitmentEnvelope,
) -> Result<Vec<u8>, GovernanceError> {
    serde_json::to_vec(envelope).map_err(|error| GovernanceError::Encoding(error.to_string()))
}

fn validate_policy(policy: &GovernancePolicy) -> Result<(), GovernanceError> {
    if policy.schema != GOVERNANCE_POLICY_SCHEMA {
        return invalid("schema");
    }
    for value in [
        &policy.policy_id,
        &policy.institution_id,
        &policy.tenant_id,
        &policy.dataset_id,
        &policy.dataset_schema_id,
        &policy.purpose_id,
        &policy.controller_id,
        &policy.operator_id,
        &policy.privacy_contact_id,
        &policy.key_domain,
    ] {
        if !valid_identifier(value) {
            return invalid("identifier");
        }
    }
    if policy.version == 0
        || policy.effective_at_unix_seconds >= policy.approval_expires_at_unix_seconds
        || policy.retention.dispose_after_unix_seconds < policy.effective_at_unix_seconds
    {
        return invalid("timeline");
    }
    require_nonzero_sha256(
        &policy.authorization_evidence_sha256,
        "authorizationEvidenceSha256",
    )?;
    validate_sorted_list(
        &policy.allowed_operations,
        MAX_LIST_ITEMS,
        "allowedOperations",
    )?;
    validate_identifier_list(&policy.processing_regions, false, "processingRegions")?;
    validate_identifier_list(&policy.storage_regions, false, "storageRegions")?;
    validate_identifier_list(&policy.allowed_workload_ids, false, "allowedWorkloadIds")?;
    validate_identifier_list(
        &policy.permitted_recipient_ids,
        true,
        "permittedRecipientIds",
    )?;
    validate_identifier_list(&policy.forbidden_field_ids, true, "forbiddenFieldIds")?;
    if policy.applicable_jurisdictions.is_empty()
        || policy.applicable_jurisdictions.len() > MAX_LIST_ITEMS
        || !is_sorted_unique(&policy.applicable_jurisdictions)
        || !policy
            .applicable_jurisdictions
            .iter()
            .all(|value| valid_jurisdiction(value))
    {
        return invalid("applicableJurisdictions");
    }
    if let Some(hold) = &policy.retention.legal_hold_id
        && !valid_identifier(hold)
    {
        return invalid("legalHoldId");
    }
    if policy.fields.is_empty() || policy.fields.len() > MAX_FIELDS {
        return invalid("fields");
    }
    let forbidden: BTreeSet<_> = policy
        .forbidden_field_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut previous = None;
    let mut fields = BTreeMap::new();
    for field in &policy.fields {
        if !valid_identifier(&field.field_id)
            || previous.is_some_and(|value: &str| value >= field.field_id.as_str())
            || forbidden.contains(field.field_id.as_str())
            || !is_sorted_unique(&field.required_for)
        {
            return invalid("fieldRule");
        }
        previous = Some(field.field_id.as_str());
        fields.insert(field.field_id.as_str(), field);
    }
    if policy.onchain_commitments.len() > MAX_ARTIFACT_RULES {
        return invalid("onchainCommitments");
    }
    let mut rule_ids = BTreeSet::new();
    for rule in &policy.onchain_commitments {
        if !valid_identifier(&rule.artifact_rule_id)
            || !valid_identifier(&rule.construction_id)
            || !valid_identifier(&rule.domain)
            || !rule_ids.insert(rule.artifact_rule_id.as_str())
            || rule.hidden_source_fields.is_empty()
            || rule.hidden_source_fields.len() > MAX_FIELDS
            || !is_sorted_unique(&rule.hidden_source_fields)
        {
            return invalid("onchainCommitmentRule");
        }
        for source in &rule.hidden_source_fields {
            let field = fields
                .get(source.as_str())
                .ok_or(GovernanceError::InvalidPolicy("commitmentSource"))?;
            if field.placement != FieldPlacement::OffChainCommitmentSource {
                return invalid("commitmentSourcePlacement");
            }
        }
    }
    Ok(())
}

fn validate_observed_fields(policy: &GovernancePolicy, context: &DecisionContext) -> bool {
    if context.observed_field_ids.len() > MAX_FIELDS
        || !is_sorted_unique(&context.observed_field_ids)
    {
        return false;
    }
    let fields: BTreeMap<_, _> = policy
        .fields
        .iter()
        .map(|field| (field.field_id.as_str(), field))
        .collect();
    if context.observed_field_ids.iter().any(|field| {
        policy.forbidden_field_ids.binary_search(field).is_ok()
            || !fields.contains_key(field.as_str())
    }) {
        return false;
    }
    policy
        .fields
        .iter()
        .filter(|field| field.required_for.binary_search(&context.operation).is_ok())
        .all(|field| {
            context
                .observed_field_ids
                .binary_search(&field.field_id)
                .is_ok()
        })
}

fn check(
    checks: &mut Vec<DecisionCheck>,
    id: &str,
    passed: bool,
    pass_code: &str,
    fail_code: &str,
) {
    checks.push(DecisionCheck {
        check_id: id.into(),
        outcome: if passed {
            CheckOutcome::Passed
        } else {
            CheckOutcome::Failed
        },
        code: if passed {
            pass_code.into()
        } else {
            fail_code.into()
        },
    });
}

fn validate_identifier_list(
    values: &[String],
    allow_empty: bool,
    field: &'static str,
) -> Result<(), GovernanceError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_LIST_ITEMS
        || !is_sorted_unique(values)
        || !values.iter().all(|value| valid_identifier(value))
    {
        return invalid(field);
    }
    Ok(())
}

fn validate_sorted_list<T: Ord>(
    values: &[T],
    maximum: usize,
    field: &'static str,
) -> Result<(), GovernanceError> {
    if values.is_empty() || values.len() > maximum || !is_sorted_unique(values) {
        return invalid(field);
    }
    Ok(())
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn valid_jurisdiction(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn require_nonzero_sha256(value: &str, field: &'static str) -> Result<(), GovernanceError> {
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value[2..].bytes().all(|byte| byte == b'0')
    {
        return invalid(field);
    }
    Ok(())
}

fn invalid<T>(field: &'static str) -> Result<T, GovernanceError> {
    Err(GovernanceError::InvalidPolicy(field))
}

fn check_size(bytes: &[u8]) -> Result<(), GovernanceError> {
    if bytes.is_empty() {
        return Err(GovernanceError::Empty);
    }
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(GovernanceError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_POLICY_BYTES,
        });
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn commitment_authorization_context_sha256(
    policy_sha256: &str,
    rule: &OnChainCommitmentRule,
    commitment: &[u8; 32],
) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"bloch.data.minimized-commitment.authorization-context.v1".as_slice(),
        policy_sha256.as_bytes(),
        rule.artifact_rule_id.as_bytes(),
        rule.construction_id.as_bytes(),
        rule.domain.as_bytes(),
        commitment,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("0x{}", hex::encode(digest.finalize()))
}

pub(crate) fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), GovernanceError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedValue::deserialize(&mut decoder)
        .map_err(|error| GovernanceError::InvalidJson(error.to_string()))?;
    decoder
        .end()
        .map_err(|error| GovernanceError::InvalidJson(error.to_string()))
}

struct DuplicateCheckedValue;
impl<'de> Deserialize<'de> for DuplicateCheckedValue {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(DuplicateVisitor)
    }
}
struct DuplicateVisitor;
impl<'de> de::Visitor<'de> for DuplicateVisitor {
    type Value = DuplicateCheckedValue;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate keys")
    }
    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            map.next_value::<DuplicateCheckedValue>()?;
        }
        Ok(DuplicateCheckedValue)
    }
    fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while sequence.next_element::<DuplicateCheckedValue>()?.is_some() {}
        Ok(DuplicateCheckedValue)
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        DuplicateCheckedValue::deserialize(decoder)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue)
    }
}
