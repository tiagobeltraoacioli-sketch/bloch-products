//! Offline, fail-closed admission for an indexer delivery service.
//!
//! Admission is derived from canonical, independently pinned configuration and
//! exact evidence bytes. No caller-provided success boolean is accepted. This
//! crate performs no network, secret-key, deployment, or filesystem access.

use bloch_data_governance::parse_governance_policy;
use bloch_indexer_audit::parse_audit_trust_policy;
use bloch_indexer_audit_retention::parse_retention_checkpoint_policy;
use bloch_indexer_core::{BlockAnchor, CanonicalIndexer, ChainIdentity};
use bloch_indexer_delivery_protocol::parse_trust_policy;
use bloch_indexer_input::authenticated::parse_authentication_policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const OPERATIONAL_MANIFEST_SCHEMA: &str = "bloch.data.indexer-delivery-service-admission.v1";
pub const ADMISSION_REPORT_SCHEMA: &str = "bloch.data.indexer-delivery-service-admission-report.v1";
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

type CapabilitySelector = fn(&ExternalCapabilities) -> &Capability;

const CAPABILITIES: [(&str, CapabilitySelector); 5] = [
    ("network_tls", |value| &value.network_tls),
    ("external_signer", |value| &value.external_signer),
    ("replica_worm", |value| &value.replica_worm),
    ("high_availability", |value| &value.high_availability),
    ("data_governance_enforcement", |value| {
        &value.data_governance_enforcement
    }),
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationalManifest {
    pub schema: String,
    pub service_id: String,
    pub network: ChainIdentity,
    pub anchor: BlockAnchor,
    pub domains: ServiceDomains,
    pub policy_sha256: PolicyDigests,
    pub storage: StorageBindings,
    pub capabilities: ExternalCapabilities,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceDomains {
    pub producer: String,
    pub delivery: String,
    pub audit: String,
    pub checkpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyDigests {
    pub producer: String,
    pub delivery: String,
    pub audit: String,
    pub checkpoint: String,
    pub data_governance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StorageBindings {
    pub snapshot_path: String,
    pub snapshot_id: String,
    pub spool_path: String,
    pub spool_id: String,
    pub receiver_state_path: String,
    pub audit_ledger_path: String,
    pub receiver_id: String,
    pub ledger_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalCapabilities {
    pub network_tls: Capability,
    pub external_signer: Capability,
    pub replica_worm: Capability,
    pub high_availability: Capability,
    pub data_governance_enforcement: Capability,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capability {
    Evidence {
        #[serde(rename = "evidenceId")]
        evidence_id: String,
        sha256: String,
    },
    Unavailable {
        #[serde(rename = "reasonCode")]
        reason_code: String,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyMaterials<'a> {
    pub producer: Option<&'a [u8]>,
    pub delivery: Option<&'a [u8]>,
    pub audit: Option<&'a [u8]>,
    pub checkpoint: Option<&'a [u8]>,
    pub data_governance: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct EvidenceMaterial<'a> {
    pub evidence_id: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct AdmissionMaterials<'a> {
    pub policies: PolicyMaterials<'a>,
    pub evidence: &'a [EvidenceMaterial<'a>],
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReport {
    schema: String,
    manifest_sha256: String,
    service_id: String,
    admitted: bool,
    checks: Vec<AdmissionCheck>,
}

impl AdmissionReport {
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn admitted(&self) -> bool {
        self.admitted
    }

    pub fn checks(&self) -> &[AdmissionCheck] {
        &self.checks
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionCheck {
    check_id: String,
    outcome: CheckOutcome,
    code: String,
}

impl AdmissionCheck {
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

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("operational manifest is empty")]
    Empty,
    #[error("operational manifest exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid operational manifest JSON: {0}")]
    InvalidJson(String),
    #[error("invalid operational manifest field: {0}")]
    InvalidManifest(&'static str),
    #[error("operational manifest is not canonical JSON")]
    NonCanonicalManifest,
    #[error("operational manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("cannot encode admission report: {0}")]
    ReportEncoding(String),
}

/// Canonical JSON used to provision the manifest digest independently.
pub fn canonical_manifest_bytes(manifest: &OperationalManifest) -> Result<Vec<u8>, AdmissionError> {
    validate_manifest(manifest)?;
    serde_json::to_vec(manifest).map_err(|error| AdmissionError::InvalidJson(error.to_string()))
}

pub fn operational_manifest_sha256(
    manifest: &OperationalManifest,
) -> Result<String, AdmissionError> {
    Ok(sha256(&canonical_manifest_bytes(manifest)?))
}

/// Parses canonical JSON and verifies a digest provisioned outside the file.
pub fn parse_operational_manifest(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<OperationalManifest, AdmissionError> {
    check_manifest_size(bytes)?;
    require_digest(expected_sha256, "expectedSha256")?;
    let manifest: OperationalManifest = serde_json::from_slice(bytes)
        .map_err(|error| AdmissionError::InvalidJson(error.to_string()))?;
    validate_manifest(&manifest)?;
    if canonical_manifest_bytes(&manifest)? != bytes {
        return Err(AdmissionError::NonCanonicalManifest);
    }
    if sha256(bytes) != expected_sha256 {
        return Err(AdmissionError::ManifestDigestMismatch);
    }
    Ok(manifest)
}

/// Evaluates every trust and capability gate and always fails closed.
///
/// The `admitted` field is computed exclusively from the resulting checks.
/// No boolean assertion is accepted in either the manifest or materials.
pub fn evaluate_operational_admission(
    manifest_bytes: &[u8],
    expected_manifest_sha256: &str,
    materials: AdmissionMaterials<'_>,
) -> Result<AdmissionReport, AdmissionError> {
    let manifest = parse_operational_manifest(manifest_bytes, expected_manifest_sha256)?;
    let mut checks = Vec::with_capacity(10);

    check_producer_policy(&manifest, materials.policies.producer, &mut checks);
    check_delivery_policy(&manifest, materials.policies.delivery, &mut checks);
    check_audit_policy(&manifest, materials.policies.audit, &mut checks);
    check_checkpoint_policy(&manifest, materials.policies.checkpoint, &mut checks);
    check_data_governance_policy(&manifest, materials.policies.data_governance, &mut checks);

    let evidence = collect_evidence(materials.evidence);
    for (name, select) in CAPABILITIES {
        check_capability(name, select(&manifest.capabilities), &evidence, &mut checks);
    }
    let admitted = checks
        .iter()
        .all(|check| check.outcome == CheckOutcome::Passed);
    Ok(AdmissionReport {
        schema: ADMISSION_REPORT_SCHEMA.into(),
        manifest_sha256: expected_manifest_sha256.into(),
        service_id: manifest.service_id,
        admitted,
        checks,
    })
}

pub fn admission_report_bytes(report: &AdmissionReport) -> Result<Vec<u8>, AdmissionError> {
    serde_json::to_vec(report).map_err(|error| AdmissionError::ReportEncoding(error.to_string()))
}

fn check_producer_policy(
    manifest: &OperationalManifest,
    bytes: Option<&[u8]>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let result = bounded_policy(bytes).and_then(|bytes| {
        parse_authentication_policy(bytes, &manifest.policy_sha256.producer)
            .map_err(|_| "policy_invalid")
    });
    match result {
        Ok(policy)
            if policy.network == manifest.network
                && policy.anchor == manifest.anchor
                && policy.deployment_domain == manifest.domains.producer =>
        {
            pass(checks, "policy.producer", "policy_verified")
        }
        Ok(_) => fail(checks, "policy.producer", "context_mismatch"),
        Err(code) => fail(checks, "policy.producer", code),
    }
}

fn check_delivery_policy(
    manifest: &OperationalManifest,
    bytes: Option<&[u8]>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let result = bounded_policy(bytes).and_then(|bytes| {
        parse_trust_policy(bytes, &manifest.policy_sha256.delivery).map_err(|_| "policy_invalid")
    });
    match result {
        Ok(policy)
            if policy.network == manifest.network
                && policy.destination_domain == manifest.domains.delivery
                && policy
                    .receivers
                    .iter()
                    .any(|receiver| receiver.signer_id == manifest.storage.receiver_id) =>
        {
            pass(checks, "policy.delivery", "policy_verified")
        }
        Ok(_) => fail(checks, "policy.delivery", "context_mismatch"),
        Err(code) => fail(checks, "policy.delivery", code),
    }
}

fn check_audit_policy(
    manifest: &OperationalManifest,
    bytes: Option<&[u8]>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let result = bounded_policy(bytes).and_then(|bytes| {
        parse_audit_trust_policy(bytes, &manifest.policy_sha256.audit).map_err(|_| "policy_invalid")
    });
    match result {
        Ok(policy)
            if policy.network == manifest.network
                && policy.anchor_tip_hash == manifest.anchor.block_hash
                && policy.audit_domain == manifest.domains.audit =>
        {
            pass(checks, "policy.audit", "policy_verified")
        }
        Ok(_) => fail(checks, "policy.audit", "context_mismatch"),
        Err(code) => fail(checks, "policy.audit", code),
    }
}

fn check_checkpoint_policy(
    manifest: &OperationalManifest,
    bytes: Option<&[u8]>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let result = bounded_policy(bytes).and_then(|bytes| {
        parse_retention_checkpoint_policy(bytes, &manifest.policy_sha256.checkpoint)
            .map_err(|_| "policy_invalid")
    });
    match result {
        Ok(policy)
            if policy.checkpoint_domain == manifest.domains.checkpoint
                && policy.ledger_id == manifest.storage.ledger_id =>
        {
            pass(checks, "policy.checkpoint", "policy_verified")
        }
        Ok(_) => fail(checks, "policy.checkpoint", "context_mismatch"),
        Err(code) => fail(checks, "policy.checkpoint", code),
    }
}

fn check_data_governance_policy(
    manifest: &OperationalManifest,
    bytes: Option<&[u8]>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let result = bounded_policy(bytes).and_then(|bytes| {
        parse_governance_policy(bytes, &manifest.policy_sha256.data_governance)
            .map_err(|_| "policy_invalid")
    });
    match result {
        Ok(policy)
            if policy
                .allowed_workload_ids
                .binary_search(&manifest.service_id)
                .is_ok() =>
        {
            pass(checks, "policy.data_governance", "policy_verified")
        }
        Ok(_) => fail(checks, "policy.data_governance", "context_mismatch"),
        Err(code) => fail(checks, "policy.data_governance", code),
    }
}

fn bounded_policy(bytes: Option<&[u8]>) -> Result<&[u8], &'static str> {
    match bytes {
        None => Err("policy_missing"),
        Some(bytes) if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES => {
            Err("policy_size_invalid")
        }
        Some(bytes) => Ok(bytes),
    }
}

fn collect_evidence<'a>(
    material: &'a [EvidenceMaterial<'a>],
) -> BTreeMap<&'a str, Result<&'a [u8], &'static str>> {
    let mut result = BTreeMap::new();
    for item in material {
        if !valid_identifier(item.evidence_id) {
            continue;
        }
        if result.contains_key(item.evidence_id) {
            result.insert(item.evidence_id, Err("evidence_duplicate"));
        } else if item.bytes.is_empty() || item.bytes.len() > MAX_EVIDENCE_BYTES {
            result.insert(item.evidence_id, Err("evidence_size_invalid"));
        } else {
            result.insert(item.evidence_id, Ok(item.bytes));
        }
    }
    result
}

fn check_capability(
    name: &str,
    capability: &Capability,
    evidence: &BTreeMap<&str, Result<&[u8], &'static str>>,
    checks: &mut Vec<AdmissionCheck>,
) {
    let check_id = format!("capability.{name}");
    match capability {
        Capability::Unavailable { .. } => fail(checks, &check_id, "capability_unavailable"),
        Capability::Evidence {
            evidence_id,
            sha256: expected,
        } => match evidence.get(evidence_id.as_str()) {
            None => fail(checks, &check_id, "evidence_missing"),
            Some(Err(code)) => fail(checks, &check_id, code),
            Some(Ok(bytes)) if sha256(bytes) == *expected => {
                pass(checks, &check_id, "evidence_digest_verified")
            }
            Some(Ok(_)) => fail(checks, &check_id, "evidence_digest_mismatch"),
        },
    }
}

fn pass(checks: &mut Vec<AdmissionCheck>, id: &str, code: &str) {
    checks.push(AdmissionCheck {
        check_id: id.into(),
        outcome: CheckOutcome::Passed,
        code: code.into(),
    });
}

fn fail(checks: &mut Vec<AdmissionCheck>, id: &str, code: &str) {
    checks.push(AdmissionCheck {
        check_id: id.into(),
        outcome: CheckOutcome::Failed,
        code: code.into(),
    });
}

fn validate_manifest(manifest: &OperationalManifest) -> Result<(), AdmissionError> {
    if manifest.schema != OPERATIONAL_MANIFEST_SCHEMA {
        return Err(AdmissionError::InvalidManifest("schema"));
    }
    if !valid_identifier(&manifest.service_id) {
        return Err(AdmissionError::InvalidManifest("serviceId"));
    }
    CanonicalIndexer::new(manifest.network.clone(), manifest.anchor.clone(), 1)
        .map_err(|_| AdmissionError::InvalidManifest("chainContext"))?;
    let domains = [
        &manifest.domains.producer,
        &manifest.domains.delivery,
        &manifest.domains.audit,
        &manifest.domains.checkpoint,
    ];
    if domains.iter().any(|value| !valid_identifier(value))
        || domains.iter().collect::<BTreeSet<_>>().len() != domains.len()
    {
        return Err(AdmissionError::InvalidManifest("domains"));
    }
    for digest in [
        &manifest.policy_sha256.producer,
        &manifest.policy_sha256.delivery,
        &manifest.policy_sha256.audit,
        &manifest.policy_sha256.checkpoint,
        &manifest.policy_sha256.data_governance,
    ] {
        require_digest(digest, "policySha256")?;
    }
    let storage_ids = [
        &manifest.storage.snapshot_id,
        &manifest.storage.spool_id,
        &manifest.storage.receiver_id,
        &manifest.storage.ledger_id,
    ];
    if storage_ids.iter().any(|value| !valid_identifier(value))
        || storage_ids.iter().collect::<BTreeSet<_>>().len() != storage_ids.len()
    {
        return Err(AdmissionError::InvalidManifest("storageIds"));
    }
    let paths = [
        &manifest.storage.snapshot_path,
        &manifest.storage.spool_path,
        &manifest.storage.receiver_state_path,
        &manifest.storage.audit_ledger_path,
    ];
    if paths.iter().any(|path| !valid_absolute_path(path))
        || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
    {
        return Err(AdmissionError::InvalidManifest("storagePaths"));
    }
    let mut evidence_ids = BTreeSet::new();
    let mut evidence_digests = BTreeSet::new();
    for (_, select) in CAPABILITIES {
        match select(&manifest.capabilities) {
            Capability::Evidence {
                evidence_id,
                sha256,
            } => {
                if !valid_identifier(evidence_id)
                    || require_digest(sha256, "capability.sha256").is_err()
                    || !evidence_ids.insert(evidence_id)
                    || !evidence_digests.insert(sha256)
                {
                    return Err(AdmissionError::InvalidManifest("capabilityEvidence"));
                }
            }
            Capability::Unavailable { reason_code } if !valid_identifier(reason_code) => {
                return Err(AdmissionError::InvalidManifest("capabilityReason"));
            }
            Capability::Unavailable { .. } => {}
        }
    }
    Ok(())
}

fn check_manifest_size(bytes: &[u8]) -> Result<(), AdmissionError> {
    if bytes.is_empty() {
        Err(AdmissionError::Empty)
    } else if bytes.len() > MAX_MANIFEST_BYTES {
        Err(AdmissionError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_MANIFEST_BYTES,
        })
    } else {
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_absolute_path(path: &str) -> bool {
    (2..=1024).contains(&path.len())
        && path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && path.is_ascii()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn require_digest(value: &str, field: &'static str) -> Result<(), AdmissionError> {
    if !valid_digest(value) {
        return Err(AdmissionError::InvalidManifest(field));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    let Some(raw) = value.strip_prefix("0x") else {
        return false;
    };
    raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && raw.bytes().any(|byte| byte != b'0')
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
