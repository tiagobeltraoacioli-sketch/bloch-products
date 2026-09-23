use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_OBSERVATIONS: usize = 64;
const SCHEMA: &str = "bloch.verify.checkpoint-bundle.v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("evidence bundle is empty or exceeds 1 MiB")]
    UnsafeSize,
    #[error("invalid evidence JSON: {0}")]
    InvalidJson(String),
    #[error("invalid evidence field: {0}")]
    InvalidField(&'static str),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceBundle {
    pub schema: String,
    pub network: NetworkIdentity,
    pub checkpoint: Checkpoint,
    pub policy: ComparisonPolicy,
    pub observations: Vec<NodeObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkIdentity {
    pub network: String,
    pub chain_id: u64,
    pub genesis_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComparisonPolicy {
    pub minimum_observers: u16,
    pub minimum_organizations: u16,
    pub maximum_observation_age_seconds: u64,
    pub maximum_future_skew_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeObservation {
    pub observer_id: String,
    pub organization_id: String,
    pub endpoint_sha256: String,
    pub observed_at_unix_seconds: u64,
    pub network: String,
    pub chain_id: u64,
    pub genesis_hash: String,
    pub checkpoint_height: u64,
    pub checkpoint_block_hash: String,
    pub checkpoint_state_root: String,
    pub claimed_finalized_height: u64,
    pub node_version: String,
    pub release_revision: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentReport {
    pub schema: &'static str,
    pub bundle_sha256: String,
    pub evaluated_at_unix_seconds: u64,
    pub observation_count: usize,
    pub distinct_organization_count: usize,
    pub checks: Checks,
    pub comparison_passed: bool,
    pub authentication: AuthenticationBoundary,
    pub production_qualified: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Checks {
    pub unique_observers: bool,
    pub threshold_satisfied: bool,
    pub observations_fresh: bool,
    pub network_consistent: bool,
    pub checkpoint_consistent: bool,
    pub claimed_finality_covers_checkpoint: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationBoundary {
    pub observations_signed: bool,
    pub organizations_authenticated: bool,
    pub checkpoint_ancestry_verified: bool,
    pub finality_authenticated: bool,
}

pub fn parse_bundle(bytes: &[u8]) -> Result<EvidenceBundle, VerifyError> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::UnsafeSize);
    }
    let bundle: EvidenceBundle = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    validate_shape(&bundle)?;
    Ok(bundle)
}

pub fn assess(
    bundle: &EvidenceBundle,
    evaluated_at_unix_seconds: u64,
) -> Result<AssessmentReport, VerifyError> {
    validate_shape(bundle)?;
    let mut canonical = bundle.clone();
    canonical
        .observations
        .sort_by(|left, right| left.observer_id.cmp(&right.observer_id));
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    let bundle_sha256 = format!("0x{}", hex::encode(Sha256::digest(canonical_bytes)));

    let mut observer_ids = BTreeSet::new();
    let organizations: BTreeSet<_> = bundle
        .observations
        .iter()
        .map(|observation| observation.organization_id.as_str())
        .collect();
    let unique_observers = bundle
        .observations
        .iter()
        .all(|observation| observer_ids.insert(observation.observer_id.as_str()));
    let threshold_satisfied = bundle.observations.len()
        >= usize::from(bundle.policy.minimum_observers)
        && organizations.len() >= usize::from(bundle.policy.minimum_organizations);
    let observations_fresh = bundle.observations.iter().all(|observation| {
        observation.observed_at_unix_seconds
            <= evaluated_at_unix_seconds.saturating_add(bundle.policy.maximum_future_skew_seconds)
            && evaluated_at_unix_seconds.saturating_sub(observation.observed_at_unix_seconds)
                <= bundle.policy.maximum_observation_age_seconds
    });
    let network_consistent = bundle.observations.iter().all(|observation| {
        observation.network == bundle.network.network
            && observation.chain_id == bundle.network.chain_id
            && observation.genesis_hash == bundle.network.genesis_hash
    });
    let checkpoint_consistent = bundle.observations.iter().all(|observation| {
        observation.checkpoint_height == bundle.checkpoint.height
            && observation.checkpoint_block_hash == bundle.checkpoint.block_hash
            && observation.checkpoint_state_root == bundle.checkpoint.state_root
    });
    let claimed_finality_covers_checkpoint = bundle
        .observations
        .iter()
        .all(|observation| observation.claimed_finalized_height >= bundle.checkpoint.height);

    let checks = Checks {
        unique_observers,
        threshold_satisfied,
        observations_fresh,
        network_consistent,
        checkpoint_consistent,
        claimed_finality_covers_checkpoint,
    };
    let mut reasons = Vec::new();
    if !checks.unique_observers {
        reasons.push("duplicate observer identity".into());
    }
    if !checks.threshold_satisfied {
        reasons.push("observer or independent-organization threshold not met".into());
    }
    if !checks.observations_fresh {
        reasons.push("stale or future-dated observation".into());
    }
    if !checks.network_consistent {
        reasons.push("network, chain ID or genesis mismatch".into());
    }
    if !checks.checkpoint_consistent {
        reasons.push("checkpoint block or state mismatch".into());
    }
    if !checks.claimed_finality_covers_checkpoint {
        reasons.push("claimed finality does not cover checkpoint".into());
    }
    reasons.push("MVP observations are unsigned and finality/ancestry is not authenticated".into());
    let comparison_passed = checks.unique_observers
        && checks.threshold_satisfied
        && checks.observations_fresh
        && checks.network_consistent
        && checks.checkpoint_consistent
        && checks.claimed_finality_covers_checkpoint;

    Ok(AssessmentReport {
        schema: "bloch.verify.assessment.v1",
        bundle_sha256,
        evaluated_at_unix_seconds,
        observation_count: bundle.observations.len(),
        distinct_organization_count: organizations.len(),
        checks,
        comparison_passed,
        authentication: AuthenticationBoundary {
            observations_signed: false,
            organizations_authenticated: false,
            checkpoint_ancestry_verified: false,
            finality_authenticated: false,
        },
        production_qualified: false,
        reasons,
    })
}

fn validate_shape(bundle: &EvidenceBundle) -> Result<(), VerifyError> {
    if bundle.schema != SCHEMA {
        return Err(VerifyError::InvalidField("schema"));
    }
    if !valid_identifier(&bundle.network.network) {
        return Err(VerifyError::InvalidField("network.network"));
    }
    if bundle.network.chain_id == 0 {
        return Err(VerifyError::InvalidField("network.chainId"));
    }
    hash32(&bundle.network.genesis_hash, "network.genesisHash")?;
    if bundle.checkpoint.height == 0 {
        return Err(VerifyError::InvalidField("checkpoint.height"));
    }
    hash32(&bundle.checkpoint.block_hash, "checkpoint.blockHash")?;
    hash32(&bundle.checkpoint.state_root, "checkpoint.stateRoot")?;
    if bundle.observations.is_empty() || bundle.observations.len() > MAX_OBSERVATIONS {
        return Err(VerifyError::InvalidField("observations"));
    }
    if bundle.policy.minimum_observers == 0
        || usize::from(bundle.policy.minimum_observers) > bundle.observations.len()
        || bundle.policy.minimum_organizations == 0
        || bundle.policy.minimum_organizations > bundle.policy.minimum_observers
        || bundle.policy.maximum_observation_age_seconds == 0
        || bundle.policy.maximum_observation_age_seconds > 86_400
        || bundle.policy.maximum_future_skew_seconds > 300
    {
        return Err(VerifyError::InvalidField("policy"));
    }
    for observation in &bundle.observations {
        if !valid_identifier(&observation.observer_id)
            || !valid_identifier(&observation.organization_id)
            || !valid_identifier(&observation.network)
            || observation.observed_at_unix_seconds == 0
            || observation.chain_id == 0
            || observation.checkpoint_height == 0
            || observation.claimed_finalized_height == 0
            || !valid_version(&observation.node_version)
            || !is_lower_hex(&observation.release_revision, 20, false)
        {
            return Err(VerifyError::InvalidField("observation"));
        }
        hash32(&observation.endpoint_sha256, "observation.endpointSha256")?;
        hash32(&observation.genesis_hash, "observation.genesisHash")?;
        hash32(
            &observation.checkpoint_block_hash,
            "observation.checkpointBlockHash",
        )?;
        hash32(
            &observation.checkpoint_state_root,
            "observation.checkpointStateRoot",
        )?;
    }
    Ok(())
}

fn hash32(value: &str, field: &'static str) -> Result<(), VerifyError> {
    if !is_lower_hex(value, 32, true) {
        return Err(VerifyError::InvalidField(field));
    }
    Ok(())
}

fn is_lower_hex(value: &str, bytes: usize, reject_zero: bool) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == bytes * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (!reject_zero || hex.bytes().any(|byte| byte != b'0'))
}

fn valid_identifier(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

    #[test]
    fn matching_observations_pass_comparison_but_not_production_qualification() {
        let bundle = parse_bundle(FIXTURE).unwrap();
        let report = assess(&bundle, 1_790_121_600).unwrap();
        assert!(report.comparison_passed);
        assert!(!report.production_qualified);
        assert!(!report.authentication.finality_authenticated);
        assert_eq!(report.distinct_organization_count, 2);
    }

    #[test]
    fn checkpoint_disagreement_fails_closed() {
        let mut bundle = parse_bundle(FIXTURE).unwrap();
        bundle.observations[1].checkpoint_block_hash = format!("0x{}", "9".repeat(64));
        let report = assess(&bundle, 1_790_121_600).unwrap();
        assert!(!report.comparison_passed);
        assert!(!report.checks.checkpoint_consistent);
    }

    #[test]
    fn stale_observation_fails_closed() {
        let bundle = parse_bundle(FIXTURE).unwrap();
        let report = assess(&bundle, 1_790_125_000).unwrap();
        assert!(!report.comparison_passed);
        assert!(!report.checks.observations_fresh);
    }

    #[test]
    fn input_order_does_not_change_canonical_digest() {
        let first = parse_bundle(FIXTURE).unwrap();
        let mut second = first.clone();
        second.observations.reverse();
        assert_eq!(
            assess(&first, 1_790_121_600).unwrap().bundle_sha256,
            assess(&second, 1_790_121_600).unwrap().bundle_sha256
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        value["authorize"] = serde_json::Value::Bool(true);
        assert!(matches!(
            parse_bundle(&serde_json::to_vec(&value).unwrap()),
            Err(VerifyError::InvalidJson(_))
        ));
    }
}
