use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_OBSERVATIONS: usize = 64;
const SCHEMA: &str = "bloch.verify.checkpoint-bundle.v1";
const SIGNED_SCHEMA: &str = "bloch.verify.signed-checkpoint-bundle.v1";
const TRUST_POLICY_SCHEMA: &str = "bloch.verify.operator-trust-policy.v1";
const OBSERVATION_SIGNATURE_DOMAIN: &str = "bloch.verify.node-observation.v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("evidence bundle is empty or exceeds 1 MiB")]
    UnsafeSize,
    #[error("invalid evidence JSON: {0}")]
    InvalidJson(String),
    #[error("invalid evidence field: {0}")]
    InvalidField(&'static str),
    #[error("trust policy digest mismatch")]
    TrustPolicyDigestMismatch,
    #[error("untrusted or duplicated observer: {0}")]
    UntrustedObserver(String),
    #[error("invalid observation signature: {0}")]
    InvalidSignature(String),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperatorTrustPolicy {
    pub schema: String,
    pub policy_id: String,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub comparison: ComparisonPolicy,
    pub operators: Vec<TrustedOperator>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedOperator {
    pub observer_id: String,
    pub organization_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedEvidenceBundle {
    pub schema: String,
    pub network: NetworkIdentity,
    pub checkpoint: Checkpoint,
    pub trust_policy_sha256: String,
    pub signed_observations: Vec<SignedNodeObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedNodeObservation {
    pub observation: NodeObservation,
    pub signature: String,
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
    pub authenticated_comparison_passed: bool,
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
    pub trust_policy_digest_matched: bool,
    pub operator_keys_pinned: bool,
    pub organizations_externally_verified: bool,
    pub checkpoint_ancestry_verified: bool,
    pub finality_authenticated: bool,
}

pub fn parse_bundle(bytes: &[u8]) -> Result<EvidenceBundle, VerifyError> {
    safe_size(bytes)?;
    let bundle: EvidenceBundle = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    validate_shape(&bundle)?;
    Ok(bundle)
}

pub fn parse_signed_bundle(bytes: &[u8]) -> Result<SignedEvidenceBundle, VerifyError> {
    safe_size(bytes)?;
    let bundle: SignedEvidenceBundle = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    validate_signed_shape(&bundle)?;
    Ok(bundle)
}

pub fn parse_trust_policy(bytes: &[u8]) -> Result<OperatorTrustPolicy, VerifyError> {
    safe_size(bytes)?;
    let policy: OperatorTrustPolicy = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    validate_trust_policy(&policy)?;
    Ok(policy)
}

pub fn trust_policy_sha256(policy: &OperatorTrustPolicy) -> Result<String, VerifyError> {
    validate_trust_policy(policy)?;
    let mut canonical = policy.clone();
    canonical
        .operators
        .sort_by(|left, right| left.observer_id.cmp(&right.observer_id));
    canonical_digest(&canonical)
}

pub fn signed_observation_message(
    trust_policy_sha256: &str,
    observation: &NodeObservation,
) -> Result<Vec<u8>, VerifyError> {
    hash32(trust_policy_sha256, "trustPolicySha256")?;
    validate_observation(observation)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        domain: &'static str,
        trust_policy_sha256: &'a str,
        observation: &'a NodeObservation,
    }
    serde_json::to_vec(&Payload {
        domain: OBSERVATION_SIGNATURE_DOMAIN,
        trust_policy_sha256,
        observation,
    })
    .map_err(|error| VerifyError::InvalidJson(error.to_string()))
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
        authenticated_comparison_passed: false,
        authentication: AuthenticationBoundary {
            observations_signed: false,
            trust_policy_digest_matched: false,
            operator_keys_pinned: false,
            organizations_externally_verified: false,
            checkpoint_ancestry_verified: false,
            finality_authenticated: false,
        },
        production_qualified: false,
        reasons,
    })
}

pub fn assess_signed(
    bundle: &SignedEvidenceBundle,
    policy: &OperatorTrustPolicy,
    expected_trust_policy_sha256: &str,
    evaluated_at_unix_seconds: u64,
) -> Result<AssessmentReport, VerifyError> {
    validate_signed_shape(bundle)?;
    validate_trust_policy(policy)?;
    hash32(expected_trust_policy_sha256, "expectedTrustPolicySha256")?;
    let policy_sha256 = trust_policy_sha256(policy)?;
    if policy_sha256 != expected_trust_policy_sha256
        || bundle.trust_policy_sha256 != expected_trust_policy_sha256
    {
        return Err(VerifyError::TrustPolicyDigestMismatch);
    }
    if evaluated_at_unix_seconds < policy.valid_from_unix_seconds
        || evaluated_at_unix_seconds > policy.valid_until_unix_seconds
    {
        return Err(VerifyError::InvalidField("trustPolicy.validity"));
    }

    let mut trusted = std::collections::BTreeMap::new();
    for operator in &policy.operators {
        trusted.insert(operator.observer_id.as_str(), operator);
    }
    let mut supplied = BTreeSet::new();
    for signed in &bundle.signed_observations {
        let observation = &signed.observation;
        if !supplied.insert(observation.observer_id.as_str()) {
            return Err(VerifyError::UntrustedObserver(
                observation.observer_id.clone(),
            ));
        }
        let operator = trusted
            .get(observation.observer_id.as_str())
            .ok_or_else(|| VerifyError::UntrustedObserver(observation.observer_id.clone()))?;
        if operator.organization_id != observation.organization_id {
            return Err(VerifyError::UntrustedObserver(
                observation.observer_id.clone(),
            ));
        }
        let key_bytes = decode_hex_array::<32>(
            &operator.ed25519_public_key,
            "trustPolicy.operator.ed25519PublicKey",
        )?;
        let signature_bytes =
            decode_hex_array::<64>(&signed.signature, "signedObservation.signature")?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| VerifyError::InvalidField("trustPolicy.operator.ed25519PublicKey"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let message = signed_observation_message(&policy_sha256, observation)?;
        key.verify(&message, &signature)
            .map_err(|_| VerifyError::InvalidSignature(observation.observer_id.clone()))?;
    }

    let unsigned = EvidenceBundle {
        schema: SCHEMA.into(),
        network: bundle.network.clone(),
        checkpoint: bundle.checkpoint.clone(),
        policy: policy.comparison.clone(),
        observations: bundle
            .signed_observations
            .iter()
            .map(|signed| signed.observation.clone())
            .collect(),
    };
    let mut report = assess(&unsigned, evaluated_at_unix_seconds)?;
    let mut canonical = bundle.clone();
    canonical.signed_observations.sort_by(|left, right| {
        left.observation
            .observer_id
            .cmp(&right.observation.observer_id)
    });
    report.bundle_sha256 = canonical_digest(&canonical)?;
    report.schema = "bloch.verify.signed-assessment.v1";
    report.authenticated_comparison_passed = report.comparison_passed;
    report.authentication = AuthenticationBoundary {
        observations_signed: true,
        trust_policy_digest_matched: true,
        operator_keys_pinned: true,
        organizations_externally_verified: false,
        checkpoint_ancestry_verified: false,
        finality_authenticated: false,
    };
    report.reasons.retain(|reason| {
        reason != "MVP observations are unsigned and finality/ancestry is not authenticated"
    });
    report.reasons.push(
        "operator organization claims still require independent external verification".into(),
    );
    report.reasons.push(
        "checkpoint ancestry and consensus finality are not authenticated by signed observations"
            .into(),
    );
    Ok(report)
}

fn safe_size(bytes: &[u8]) -> Result<(), VerifyError> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::UnsafeSize);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, VerifyError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    Ok(format!("0x{}", hex::encode(Sha256::digest(bytes))))
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
    validate_comparison_policy(&bundle.policy, bundle.observations.len())?;
    for observation in &bundle.observations {
        validate_observation(observation)?;
    }
    Ok(())
}

fn validate_signed_shape(bundle: &SignedEvidenceBundle) -> Result<(), VerifyError> {
    if bundle.schema != SIGNED_SCHEMA {
        return Err(VerifyError::InvalidField("schema"));
    }
    if !valid_identifier(&bundle.network.network) || bundle.network.chain_id == 0 {
        return Err(VerifyError::InvalidField("network"));
    }
    hash32(&bundle.network.genesis_hash, "network.genesisHash")?;
    if bundle.checkpoint.height == 0 {
        return Err(VerifyError::InvalidField("checkpoint.height"));
    }
    hash32(&bundle.checkpoint.block_hash, "checkpoint.blockHash")?;
    hash32(&bundle.checkpoint.state_root, "checkpoint.stateRoot")?;
    hash32(&bundle.trust_policy_sha256, "trustPolicySha256")?;
    if bundle.signed_observations.is_empty() || bundle.signed_observations.len() > MAX_OBSERVATIONS
    {
        return Err(VerifyError::InvalidField("signedObservations"));
    }
    for signed in &bundle.signed_observations {
        validate_observation(&signed.observation)?;
        if !is_lower_hex(&signed.signature, 64, true) {
            return Err(VerifyError::InvalidField("signedObservation.signature"));
        }
    }
    Ok(())
}

fn validate_trust_policy(policy: &OperatorTrustPolicy) -> Result<(), VerifyError> {
    if policy.schema != TRUST_POLICY_SCHEMA
        || !valid_identifier(&policy.policy_id)
        || policy.valid_from_unix_seconds == 0
        || policy.valid_until_unix_seconds <= policy.valid_from_unix_seconds
        || policy.operators.is_empty()
        || policy.operators.len() > MAX_OBSERVATIONS
    {
        return Err(VerifyError::InvalidField("trustPolicy"));
    }
    validate_comparison_policy(&policy.comparison, policy.operators.len())?;
    let mut observers = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for operator in &policy.operators {
        if !valid_identifier(&operator.observer_id)
            || !valid_identifier(&operator.organization_id)
            || !is_lower_hex(&operator.ed25519_public_key, 32, true)
            || !observers.insert(operator.observer_id.as_str())
            || !keys.insert(operator.ed25519_public_key.as_str())
        {
            return Err(VerifyError::InvalidField("trustPolicy.operator"));
        }
        let bytes = decode_hex_array::<32>(
            &operator.ed25519_public_key,
            "trustPolicy.operator.ed25519PublicKey",
        )?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| VerifyError::InvalidField("trustPolicy.operator.ed25519PublicKey"))?;
    }
    Ok(())
}

fn validate_comparison_policy(
    policy: &ComparisonPolicy,
    available_observers: usize,
) -> Result<(), VerifyError> {
    if policy.minimum_observers == 0
        || usize::from(policy.minimum_observers) > available_observers
        || policy.minimum_organizations == 0
        || policy.minimum_organizations > policy.minimum_observers
        || policy.maximum_observation_age_seconds == 0
        || policy.maximum_observation_age_seconds > 86_400
        || policy.maximum_future_skew_seconds > 300
    {
        return Err(VerifyError::InvalidField("policy"));
    }
    Ok(())
}

fn validate_observation(observation: &NodeObservation) -> Result<(), VerifyError> {
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
    Ok(())
}

fn decode_hex_array<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], VerifyError> {
    if !is_lower_hex(value, N, true) {
        return Err(VerifyError::InvalidField(field));
    }
    let decoded = hex::decode(&value[2..]).map_err(|_| VerifyError::InvalidField(field))?;
    decoded
        .try_into()
        .map_err(|_| VerifyError::InvalidField(field))
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
    use ed25519_dalek::{Signer, SigningKey};

    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

    fn signed_fixture() -> (OperatorTrustPolicy, SignedEvidenceBundle, String) {
        let unsigned = parse_bundle(FIXTURE).unwrap();
        let keys = [
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
        ];
        let policy = OperatorTrustPolicy {
            schema: TRUST_POLICY_SCHEMA.into(),
            policy_id: "genesis-4-operators-2026-09".into(),
            valid_from_unix_seconds: 1_790_000_000,
            valid_until_unix_seconds: 1_790_200_000,
            comparison: unsigned.policy.clone(),
            operators: unsigned
                .observations
                .iter()
                .zip(&keys)
                .map(|(observation, key)| TrustedOperator {
                    observer_id: observation.observer_id.clone(),
                    organization_id: observation.organization_id.clone(),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().to_bytes())
                    ),
                })
                .collect(),
        };
        let digest = trust_policy_sha256(&policy).unwrap();
        let signed_observations = unsigned
            .observations
            .iter()
            .zip(&keys)
            .map(|(observation, key)| {
                let message = signed_observation_message(&digest, observation).unwrap();
                SignedNodeObservation {
                    observation: observation.clone(),
                    signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
                }
            })
            .collect();
        let bundle = SignedEvidenceBundle {
            schema: SIGNED_SCHEMA.into(),
            network: unsigned.network,
            checkpoint: unsigned.checkpoint,
            trust_policy_sha256: digest.clone(),
            signed_observations,
        };
        (policy, bundle, digest)
    }

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

    #[test]
    fn signed_observations_authenticate_comparison_but_not_finality() {
        let (policy, bundle, digest) = signed_fixture();
        let report = assess_signed(&bundle, &policy, &digest, 1_790_121_600).unwrap();
        assert!(report.comparison_passed);
        assert!(report.authenticated_comparison_passed);
        assert!(report.authentication.observations_signed);
        assert!(report.authentication.trust_policy_digest_matched);
        assert!(report.authentication.operator_keys_pinned);
        assert!(!report.authentication.organizations_externally_verified);
        assert!(!report.authentication.finality_authenticated);
        assert!(!report.production_qualified);
    }

    #[test]
    fn signed_observation_tampering_is_refused() {
        let (policy, mut bundle, digest) = signed_fixture();
        bundle.signed_observations[0]
            .observation
            .claimed_finalized_height += 1;
        assert!(matches!(
            assess_signed(&bundle, &policy, &digest, 1_790_121_600),
            Err(VerifyError::InvalidSignature(_))
        ));
    }

    #[test]
    fn caller_cannot_substitute_trust_policy_digest() {
        let (policy, bundle, _) = signed_fixture();
        let foreign = format!("0x{}", "f".repeat(64));
        assert_eq!(
            assess_signed(&bundle, &policy, &foreign, 1_790_121_600).unwrap_err(),
            VerifyError::TrustPolicyDigestMismatch
        );
    }

    #[test]
    fn trust_policy_digest_is_independent_of_operator_order() {
        let (mut policy, _, digest) = signed_fixture();
        policy.operators.reverse();
        assert_eq!(trust_policy_sha256(&policy).unwrap(), digest);
    }
}
