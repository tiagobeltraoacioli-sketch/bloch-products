use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub mod qualification;

const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_OBSERVATIONS: usize = 64;
const SCHEMA: &str = "bloch.verify.checkpoint-bundle.v1";
const SIGNED_SCHEMA: &str = "bloch.verify.signed-checkpoint-bundle.v1";
const TRUST_POLICY_SCHEMA: &str = "bloch.verify.operator-trust-policy.v1";
const OBSERVATION_SIGNATURE_DOMAIN: &str = "bloch.verify.node-observation.v1";
const SIGNING_REQUEST_SCHEMA: &str = "bloch.verify.observation-signing-request.v1";
const SIGNED_RESPONSE_SCHEMA: &str = "bloch.verify.signed-observation-response.v1";
const EVM_RPC_CAPTURE_SCHEMA: &str = "bloch.verify.evm-rpc-capture.v1";
const EVM_ANCESTRY_EVIDENCE_SCHEMA: &str = "bloch.verify.evm-ancestry-evidence.v1";
const MAX_ANCESTRY_HEADERS: usize = 4_096;

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationSigningRequest {
    pub schema: String,
    pub domain: String,
    pub trust_policy_sha256: String,
    pub observer_id: String,
    pub organization_id: String,
    pub ed25519_public_key: String,
    pub observation_sha256: String,
    pub message_sha256: String,
    pub observation: NodeObservation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedObservationResponse {
    pub schema: String,
    pub request_sha256: String,
    pub request: ObservationSigningRequest,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvmRpcCapture {
    pub schema: String,
    pub observer_id: String,
    pub organization_id: String,
    pub endpoint_sha256: String,
    pub observed_at_unix_seconds: u64,
    pub network: String,
    pub release_revision: String,
    pub client_version: JsonRpcExchange,
    pub chain_id: JsonRpcExchange,
    pub genesis_block: JsonRpcExchange,
    pub finalized_block: JsonRpcExchange,
}

/// An offline, ordered snapshot of EVM headers linking a checkpoint to a block
/// an upstream source labels finalized. This proves only internal parent-hash
/// linkage; it does not prove that consensus finalized the terminal block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvmAncestryEvidence {
    pub schema: String,
    pub network: NetworkIdentity,
    pub checkpoint: Checkpoint,
    pub finalized: EvmBlockReference,
    pub headers: Vec<EvmAncestryHeader>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvmBlockReference {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvmAncestryHeader {
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvmAncestryReport {
    pub schema: &'static str,
    pub evidence_sha256: String,
    pub checkpoint_height: u64,
    pub finalized_height: u64,
    pub header_count: usize,
    pub contiguous_heights: bool,
    pub parent_hash_linkage_verified: bool,
    pub endpoints_matched: bool,
    pub consensus_finality_authenticated: bool,
    pub production_qualified: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JsonRpcExchange {
    pub request: JsonRpcRequest,
    pub response: JsonRpcResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvmBlockHeader {
    number: String,
    hash: String,
    parent_hash: String,
    state_root: String,
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
    let bundle: EvidenceBundle = parse_strict_json(bytes)?;
    validate_shape(&bundle)?;
    Ok(bundle)
}

pub fn parse_signed_bundle(bytes: &[u8]) -> Result<SignedEvidenceBundle, VerifyError> {
    safe_size(bytes)?;
    let bundle: SignedEvidenceBundle = parse_strict_json(bytes)?;
    validate_signed_shape(&bundle)?;
    Ok(bundle)
}

pub fn parse_trust_policy(bytes: &[u8]) -> Result<OperatorTrustPolicy, VerifyError> {
    safe_size(bytes)?;
    let policy: OperatorTrustPolicy = parse_strict_json(bytes)?;
    validate_trust_policy(&policy)?;
    Ok(policy)
}

pub fn parse_observation(bytes: &[u8]) -> Result<NodeObservation, VerifyError> {
    safe_size(bytes)?;
    let observation: NodeObservation = parse_strict_json(bytes)?;
    validate_observation(&observation)?;
    Ok(observation)
}

pub fn parse_signing_request(bytes: &[u8]) -> Result<ObservationSigningRequest, VerifyError> {
    safe_size(bytes)?;
    let request: ObservationSigningRequest = parse_strict_json(bytes)?;
    validate_signing_request(&request)?;
    Ok(request)
}

pub fn parse_signed_response(bytes: &[u8]) -> Result<SignedObservationResponse, VerifyError> {
    safe_size(bytes)?;
    let response: SignedObservationResponse = parse_strict_json(bytes)?;
    validate_signed_response(&response)?;
    Ok(response)
}

pub fn parse_evm_rpc_capture(bytes: &[u8]) -> Result<EvmRpcCapture, VerifyError> {
    safe_size(bytes)?;
    let capture: EvmRpcCapture = parse_strict_json(bytes)?;
    validate_evm_rpc_capture(&capture)?;
    observation_from_evm_rpc_capture(&capture)?;
    Ok(capture)
}

pub fn parse_json_rpc_responses(bytes: &[u8]) -> Result<Vec<JsonRpcResponse>, VerifyError> {
    safe_size(bytes)?;
    parse_strict_json(bytes)
}

pub fn parse_evm_ancestry_evidence(bytes: &[u8]) -> Result<EvmAncestryEvidence, VerifyError> {
    safe_size(bytes)?;
    let evidence: EvmAncestryEvidence = parse_strict_json(bytes)?;
    validate_evm_ancestry_evidence(&evidence)?;
    Ok(evidence)
}

/// Verifies the exact, ascending parent-hash chain in an offline evidence
/// object. A successful report must not be interpreted as consensus finality:
/// the terminal `finalized` label still originates outside this verifier.
pub fn verify_evm_ancestry_evidence(
    evidence: &EvmAncestryEvidence,
) -> Result<EvmAncestryReport, VerifyError> {
    validate_evm_ancestry_evidence(evidence)?;
    Ok(EvmAncestryReport {
        schema: "bloch.verify.evm-ancestry-report.v1",
        evidence_sha256: canonical_digest(evidence)?,
        checkpoint_height: evidence.checkpoint.height,
        finalized_height: evidence.finalized.height,
        header_count: evidence.headers.len(),
        contiguous_heights: true,
        parent_hash_linkage_verified: true,
        endpoints_matched: true,
        consensus_finality_authenticated: false,
        production_qualified: false,
        reasons: vec![
            "header ancestry is internally linked but the finalized label is not a consensus proof"
                .into(),
        ],
    })
}

pub fn observation_from_evm_rpc_capture(
    capture: &EvmRpcCapture,
) -> Result<NodeObservation, VerifyError> {
    validate_evm_rpc_capture(capture)?;
    let chain_id = parse_quantity(
        capture
            .chain_id
            .response
            .result
            .as_str()
            .ok_or(VerifyError::InvalidField("evmRpcCapture.chainId.result"))?,
        "evmRpcCapture.chainId.result",
    )?;
    if chain_id == 0 {
        return Err(VerifyError::InvalidField("evmRpcCapture.chainId.result"));
    }
    let genesis = parse_block_header(&capture.genesis_block.response.result, "genesisBlock")?;
    let finalized = parse_block_header(&capture.finalized_block.response.result, "finalizedBlock")?;
    let genesis_height = parse_quantity(&genesis.number, "evmRpcCapture.genesisBlock.number")?;
    let finalized_height =
        parse_quantity(&finalized.number, "evmRpcCapture.finalizedBlock.number")?;
    if genesis_height != 0 || finalized_height == 0 {
        return Err(VerifyError::InvalidField("evmRpcCapture.blockHeight"));
    }
    hash32(&genesis.hash, "evmRpcCapture.genesisBlock.hash")?;
    zero_hash32(
        &genesis.parent_hash,
        "evmRpcCapture.genesisBlock.parentHash",
    )?;
    hash32(&genesis.state_root, "evmRpcCapture.genesisBlock.stateRoot")?;
    hash32(&finalized.hash, "evmRpcCapture.finalizedBlock.hash")?;
    hash32(
        &finalized.parent_hash,
        "evmRpcCapture.finalizedBlock.parentHash",
    )?;
    hash32(
        &finalized.state_root,
        "evmRpcCapture.finalizedBlock.stateRoot",
    )?;
    if finalized.hash == genesis.hash || finalized.hash == finalized.parent_hash {
        return Err(VerifyError::InvalidField("evmRpcCapture.finalizedBlock"));
    }
    let node_version = capture
        .client_version
        .response
        .result
        .as_str()
        .ok_or(VerifyError::InvalidField(
            "evmRpcCapture.clientVersion.result",
        ))?
        .to_owned();
    let observation = NodeObservation {
        observer_id: capture.observer_id.clone(),
        organization_id: capture.organization_id.clone(),
        endpoint_sha256: capture.endpoint_sha256.clone(),
        observed_at_unix_seconds: capture.observed_at_unix_seconds,
        network: capture.network.clone(),
        chain_id,
        genesis_hash: genesis.hash,
        checkpoint_height: finalized_height,
        checkpoint_block_hash: finalized.hash,
        checkpoint_state_root: finalized.state_root,
        claimed_finalized_height: finalized_height,
        node_version,
        release_revision: capture.release_revision.clone(),
    };
    validate_observation(&observation)?;
    Ok(observation)
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

pub fn prepare_signing_request(
    policy: &OperatorTrustPolicy,
    expected_trust_policy_sha256: &str,
    observation: &NodeObservation,
) -> Result<(ObservationSigningRequest, Vec<u8>), VerifyError> {
    validate_trust_policy(policy)?;
    validate_observation(observation)?;
    let digest = trust_policy_sha256(policy)?;
    if digest != expected_trust_policy_sha256 {
        return Err(VerifyError::TrustPolicyDigestMismatch);
    }
    let operator = policy
        .operators
        .iter()
        .find(|operator| operator.observer_id == observation.observer_id)
        .ok_or_else(|| VerifyError::UntrustedObserver(observation.observer_id.clone()))?;
    if operator.organization_id != observation.organization_id {
        return Err(VerifyError::UntrustedObserver(
            observation.observer_id.clone(),
        ));
    }
    let message = signed_observation_message(&digest, observation)?;
    let request = ObservationSigningRequest {
        schema: SIGNING_REQUEST_SCHEMA.into(),
        domain: OBSERVATION_SIGNATURE_DOMAIN.into(),
        trust_policy_sha256: digest,
        observer_id: observation.observer_id.clone(),
        organization_id: observation.organization_id.clone(),
        ed25519_public_key: operator.ed25519_public_key.clone(),
        observation_sha256: canonical_digest(observation)?,
        message_sha256: sha256(&message),
        observation: observation.clone(),
    };
    validate_signing_request(&request)?;
    Ok((request, message))
}

pub fn import_observation_signature(
    request: &ObservationSigningRequest,
    signature_bytes: &[u8],
) -> Result<SignedObservationResponse, VerifyError> {
    validate_signing_request(request)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidField("signature"))?;
    let signature = Signature::from_bytes(&signature_array);
    let key_bytes = decode_hex_array::<32>(
        &request.ed25519_public_key,
        "signingRequest.ed25519PublicKey",
    )?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| VerifyError::InvalidField("signingRequest.ed25519PublicKey"))?;
    let message = signed_observation_message(&request.trust_policy_sha256, &request.observation)?;
    key.verify(&message, &signature)
        .map_err(|_| VerifyError::InvalidSignature(request.observer_id.clone()))?;
    let response = SignedObservationResponse {
        schema: SIGNED_RESPONSE_SCHEMA.into(),
        request_sha256: canonical_digest(request)?,
        request: request.clone(),
        signature: format!("0x{}", hex::encode(signature_array)),
    };
    validate_signed_response(&response)?;
    Ok(response)
}

pub fn assemble_signed_bundle(
    policy: &OperatorTrustPolicy,
    expected_trust_policy_sha256: &str,
    responses: &[SignedObservationResponse],
) -> Result<SignedEvidenceBundle, VerifyError> {
    validate_trust_policy(policy)?;
    let policy_sha256 = trust_policy_sha256(policy)?;
    if policy_sha256 != expected_trust_policy_sha256 {
        return Err(VerifyError::TrustPolicyDigestMismatch);
    }
    if responses.is_empty() || responses.len() > MAX_OBSERVATIONS {
        return Err(VerifyError::InvalidField("responses"));
    }
    let mut signed_observations = Vec::with_capacity(responses.len());
    let mut observer_ids = BTreeSet::new();
    let mut expected_checkpoint: Option<&NodeObservation> = None;
    for response in responses {
        validate_signed_response(response)?;
        if response.request.trust_policy_sha256 != policy_sha256 {
            return Err(VerifyError::TrustPolicyDigestMismatch);
        }
        let operator = policy
            .operators
            .iter()
            .find(|operator| operator.observer_id == response.request.observer_id)
            .ok_or_else(|| VerifyError::UntrustedObserver(response.request.observer_id.clone()))?;
        if operator.organization_id != response.request.organization_id
            || operator.ed25519_public_key != response.request.ed25519_public_key
        {
            return Err(VerifyError::UntrustedObserver(
                response.request.observer_id.clone(),
            ));
        }
        if !observer_ids.insert(response.request.observer_id.as_str()) {
            return Err(VerifyError::UntrustedObserver(
                response.request.observer_id.clone(),
            ));
        }
        let observation = &response.request.observation;
        if let Some(expected) = expected_checkpoint {
            if observation.network != expected.network
                || observation.chain_id != expected.chain_id
                || observation.genesis_hash != expected.genesis_hash
                || observation.checkpoint_height != expected.checkpoint_height
                || observation.checkpoint_block_hash != expected.checkpoint_block_hash
                || observation.checkpoint_state_root != expected.checkpoint_state_root
            {
                return Err(VerifyError::InvalidField("responses.checkpoint"));
            }
        } else {
            expected_checkpoint = Some(observation);
        }
        let signature =
            decode_hex_array::<64>(&response.signature, "signedObservationResponse.signature")?;
        import_observation_signature(&response.request, &signature)?;
        signed_observations.push(SignedNodeObservation {
            observation: response.request.observation.clone(),
            signature: response.signature.clone(),
        });
    }
    signed_observations.sort_by(|left, right| {
        left.observation
            .observer_id
            .cmp(&right.observation.observer_id)
    });
    let first = &signed_observations[0].observation;
    let bundle = SignedEvidenceBundle {
        schema: SIGNED_SCHEMA.into(),
        network: NetworkIdentity {
            network: first.network.clone(),
            chain_id: first.chain_id,
            genesis_hash: first.genesis_hash.clone(),
        },
        checkpoint: Checkpoint {
            height: first.checkpoint_height,
            block_hash: first.checkpoint_block_hash.clone(),
            state_root: first.checkpoint_state_root.clone(),
        },
        trust_policy_sha256: policy_sha256,
        signed_observations,
    };
    validate_signed_shape(&bundle)?;
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

fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, VerifyError> {
    let mut duplicate_check = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked
        .deserialize(&mut duplicate_check)
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    duplicate_check
        .end()
        .map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    serde_json::from_slice(bytes).map_err(|error| VerifyError::InvalidJson(error.to_string()))
}

struct DuplicateChecked;

impl<'de> DeserializeSeed<'de> for DuplicateChecked {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedVisitor)
    }
}

struct DuplicateCheckedVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateChecked)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            map.next_value_seed(DuplicateChecked)?;
        }
        Ok(())
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, VerifyError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| VerifyError::InvalidJson(error.to_string()))?;
    Ok(format!("0x{}", hex::encode(Sha256::digest(bytes))))
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_signing_request(request: &ObservationSigningRequest) -> Result<(), VerifyError> {
    if request.schema != SIGNING_REQUEST_SCHEMA
        || request.domain != OBSERVATION_SIGNATURE_DOMAIN
        || request.observer_id != request.observation.observer_id
        || request.organization_id != request.observation.organization_id
    {
        return Err(VerifyError::InvalidField("signingRequest"));
    }
    hash32(
        &request.trust_policy_sha256,
        "signingRequest.trustPolicySha256",
    )?;
    decode_hex_array::<32>(
        &request.ed25519_public_key,
        "signingRequest.ed25519PublicKey",
    )?;
    validate_observation(&request.observation)?;
    if request.observation_sha256 != canonical_digest(&request.observation)? {
        return Err(VerifyError::InvalidField(
            "signingRequest.observationSha256",
        ));
    }
    let message = signed_observation_message(&request.trust_policy_sha256, &request.observation)?;
    if request.message_sha256 != sha256(&message) {
        return Err(VerifyError::InvalidField("signingRequest.messageSha256"));
    }
    Ok(())
}

fn validate_signed_response(response: &SignedObservationResponse) -> Result<(), VerifyError> {
    if response.schema != SIGNED_RESPONSE_SCHEMA {
        return Err(VerifyError::InvalidField(
            "signedObservationResponse.schema",
        ));
    }
    validate_signing_request(&response.request)?;
    if response.request_sha256 != canonical_digest(&response.request)? {
        return Err(VerifyError::InvalidField(
            "signedObservationResponse.requestSha256",
        ));
    }
    let signature_bytes =
        decode_hex_array::<64>(&response.signature, "signedObservationResponse.signature")?;
    let key_bytes = decode_hex_array::<32>(
        &response.request.ed25519_public_key,
        "signingRequest.ed25519PublicKey",
    )?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| VerifyError::InvalidField("signingRequest.ed25519PublicKey"))?;
    let message = signed_observation_message(
        &response.request.trust_policy_sha256,
        &response.request.observation,
    )?;
    key.verify(&message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| VerifyError::InvalidSignature(response.request.observer_id.clone()))?;
    Ok(())
}

fn validate_evm_ancestry_evidence(evidence: &EvmAncestryEvidence) -> Result<(), VerifyError> {
    if evidence.schema != EVM_ANCESTRY_EVIDENCE_SCHEMA
        || !valid_identifier(&evidence.network.network)
        || evidence.network.chain_id == 0
    {
        return Err(VerifyError::InvalidField("evmAncestryEvidence"));
    }
    hash32(
        &evidence.network.genesis_hash,
        "evmAncestryEvidence.network.genesisHash",
    )?;
    if evidence.checkpoint.height == 0 {
        return Err(VerifyError::InvalidField(
            "evmAncestryEvidence.checkpoint.height",
        ));
    }
    hash32(
        &evidence.checkpoint.block_hash,
        "evmAncestryEvidence.checkpoint.blockHash",
    )?;
    hash32(
        &evidence.checkpoint.state_root,
        "evmAncestryEvidence.checkpoint.stateRoot",
    )?;
    if evidence.finalized.height <= evidence.checkpoint.height {
        return Err(VerifyError::InvalidField(
            "evmAncestryEvidence.finalized.height",
        ));
    }
    hash32(
        &evidence.finalized.block_hash,
        "evmAncestryEvidence.finalized.blockHash",
    )?;
    hash32(
        &evidence.finalized.state_root,
        "evmAncestryEvidence.finalized.stateRoot",
    )?;

    let height_span = evidence
        .finalized
        .height
        .checked_sub(evidence.checkpoint.height)
        .and_then(|span| span.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(VerifyError::InvalidField("evmAncestryEvidence.heightSpan"))?;
    if evidence.headers.len() != height_span
        || evidence.headers.len() < 2
        || evidence.headers.len() > MAX_ANCESTRY_HEADERS
    {
        return Err(VerifyError::InvalidField("evmAncestryEvidence.headers"));
    }

    let mut hashes = BTreeSet::new();
    for (index, header) in evidence.headers.iter().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| VerifyError::InvalidField("evmAncestryEvidence.header.height"))?;
        let expected_height =
            evidence
                .checkpoint
                .height
                .checked_add(offset)
                .ok_or(VerifyError::InvalidField(
                    "evmAncestryEvidence.header.height",
                ))?;
        if header.height != expected_height {
            return Err(VerifyError::InvalidField(
                "evmAncestryEvidence.header.height",
            ));
        }
        hash32(&header.block_hash, "evmAncestryEvidence.header.blockHash")?;
        hash32(&header.parent_hash, "evmAncestryEvidence.header.parentHash")?;
        hash32(&header.state_root, "evmAncestryEvidence.header.stateRoot")?;
        if header.block_hash == header.parent_hash || !hashes.insert(header.block_hash.as_str()) {
            return Err(VerifyError::InvalidField(
                "evmAncestryEvidence.header.blockHash",
            ));
        }
        if index > 0 && header.parent_hash != evidence.headers[index - 1].block_hash {
            return Err(VerifyError::InvalidField(
                "evmAncestryEvidence.header.parentHash",
            ));
        }
    }

    let first = &evidence.headers[0];
    if first.height != evidence.checkpoint.height
        || first.block_hash != evidence.checkpoint.block_hash
        || first.state_root != evidence.checkpoint.state_root
    {
        return Err(VerifyError::InvalidField("evmAncestryEvidence.checkpoint"));
    }
    let last = evidence
        .headers
        .last()
        .ok_or(VerifyError::InvalidField("evmAncestryEvidence.headers"))?;
    if last.height != evidence.finalized.height
        || last.block_hash != evidence.finalized.block_hash
        || last.state_root != evidence.finalized.state_root
    {
        return Err(VerifyError::InvalidField("evmAncestryEvidence.finalized"));
    }
    Ok(())
}

fn validate_evm_rpc_capture(capture: &EvmRpcCapture) -> Result<(), VerifyError> {
    if capture.schema != EVM_RPC_CAPTURE_SCHEMA
        || !valid_identifier(&capture.observer_id)
        || !valid_identifier(&capture.organization_id)
        || !valid_identifier(&capture.network)
        || capture.observed_at_unix_seconds == 0
        || !is_lower_hex(&capture.release_revision, 20, false)
    {
        return Err(VerifyError::InvalidField("evmRpcCapture"));
    }
    hash32(&capture.endpoint_sha256, "evmRpcCapture.endpointSha256")?;
    validate_exchange(
        &capture.client_version,
        "web3_clientVersion",
        &serde_json::json!([]),
    )?;
    validate_exchange(&capture.chain_id, "eth_chainId", &serde_json::json!([]))?;
    validate_exchange(
        &capture.genesis_block,
        "eth_getBlockByNumber",
        &serde_json::json!(["0x0", false]),
    )?;
    validate_exchange(
        &capture.finalized_block,
        "eth_getBlockByNumber",
        &serde_json::json!(["finalized", false]),
    )?;
    let ids = [
        capture.client_version.request.id,
        capture.chain_id.request.id,
        capture.genesis_block.request.id,
        capture.finalized_block.request.id,
    ];
    if ids.into_iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(VerifyError::InvalidField("evmRpcCapture.requestIds"));
    }
    Ok(())
}

fn validate_exchange(
    exchange: &JsonRpcExchange,
    method: &'static str,
    params: &serde_json::Value,
) -> Result<(), VerifyError> {
    if exchange.request.jsonrpc != "2.0"
        || exchange.response.jsonrpc != "2.0"
        || exchange.request.id != exchange.response.id
        || exchange.request.method != method
        || exchange.request.params != *params
        || exchange.response.result.is_null()
    {
        return Err(VerifyError::InvalidField("evmRpcCapture.exchange"));
    }
    Ok(())
}

fn parse_block_header(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<EvmBlockHeader, VerifyError> {
    serde_json::from_value(value.clone()).map_err(|_| VerifyError::InvalidField(field))
}

fn parse_quantity(value: &str, field: &'static str) -> Result<u64, VerifyError> {
    let Some(digits) = value.strip_prefix("0x") else {
        return Err(VerifyError::InvalidField(field));
    };
    if digits.is_empty()
        || digits.len() > 16
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifyError::InvalidField(field));
    }
    u64::from_str_radix(digits, 16).map_err(|_| VerifyError::InvalidField(field))
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

fn zero_hash32(value: &str, field: &'static str) -> Result<(), VerifyError> {
    if !is_lower_hex(value, 32, false) || value.as_bytes()[2..].iter().any(|byte| *byte != b'0') {
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

    #[test]
    fn detached_signature_workflow_builds_the_same_authenticated_bundle() {
        let unsigned = parse_bundle(FIXTURE).unwrap();
        let (policy, _, digest) = signed_fixture();
        let keys = [
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
        ];
        let responses: Vec<_> = unsigned
            .observations
            .iter()
            .zip(&keys)
            .map(|(observation, key)| {
                let (request, message) =
                    prepare_signing_request(&policy, &digest, observation).unwrap();
                assert_eq!(request.message_sha256, sha256(&message));
                import_observation_signature(&request, &key.sign(&message).to_bytes()).unwrap()
            })
            .collect();
        let bundle = assemble_signed_bundle(&policy, &digest, &responses).unwrap();
        let report = assess_signed(&bundle, &policy, &digest, 1_790_121_600).unwrap();
        assert!(report.authenticated_comparison_passed);
        assert!(!report.production_qualified);
    }

    #[test]
    fn request_and_response_bind_every_observation_byte() {
        let unsigned = parse_bundle(FIXTURE).unwrap();
        let (policy, _, digest) = signed_fixture();
        let key = SigningKey::from_bytes(&[7; 32]);
        let (request, message) =
            prepare_signing_request(&policy, &digest, &unsigned.observations[0]).unwrap();
        let mut response =
            import_observation_signature(&request, &key.sign(&message).to_bytes()).unwrap();
        response.request.observation.claimed_finalized_height += 1;
        assert!(parse_signed_response(&serde_json::to_vec(&response).unwrap()).is_err());
        assert!(matches!(
            import_observation_signature(&request, &[0; 63]),
            Err(VerifyError::InvalidField("signature"))
        ));
    }

    #[test]
    fn assembly_refuses_duplicate_observers_and_divergent_checkpoints() {
        let unsigned = parse_bundle(FIXTURE).unwrap();
        let (policy, _, digest) = signed_fixture();
        let keys = [
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
        ];
        let responses: Vec<_> = unsigned
            .observations
            .iter()
            .zip(&keys)
            .map(|(observation, key)| {
                let (request, message) =
                    prepare_signing_request(&policy, &digest, observation).unwrap();
                import_observation_signature(&request, &key.sign(&message).to_bytes()).unwrap()
            })
            .collect();
        assert!(matches!(
            assemble_signed_bundle(
                &policy,
                &digest,
                &[responses[0].clone(), responses[0].clone()]
            ),
            Err(VerifyError::UntrustedObserver(_))
        ));

        let mut divergent = unsigned.observations[1].clone();
        divergent.checkpoint_block_hash = format!("0x{}", "9".repeat(64));
        let (request, message) = prepare_signing_request(&policy, &digest, &divergent).unwrap();
        let divergent_response =
            import_observation_signature(&request, &keys[1].sign(&message).to_bytes()).unwrap();
        assert_eq!(
            assemble_signed_bundle(
                &policy,
                &digest,
                &[responses[0].clone(), divergent_response]
            )
            .unwrap_err(),
            VerifyError::InvalidField("responses.checkpoint")
        );
    }

    #[test]
    fn evm_capture_converts_finalized_header_without_upgrading_its_trust() {
        let bytes = serde_json::to_vec(&evm_capture()).unwrap();
        let capture = parse_evm_rpc_capture(&bytes).unwrap();
        let observation = observation_from_evm_rpc_capture(&capture).unwrap();
        assert_eq!(observation.chain_id, 700_771);
        assert_eq!(observation.checkpoint_height, 42);
        assert_eq!(observation.claimed_finalized_height, 42);
        assert_eq!(observation.node_version, "bloch-l2/v0.1.0");
    }

    #[test]
    fn evm_capture_refuses_null_finalized_and_noncanonical_quantity() {
        let mut capture = evm_capture();
        capture["finalizedBlock"]["response"]["result"] = serde_json::Value::Null;
        assert!(parse_evm_rpc_capture(&serde_json::to_vec(&capture).unwrap()).is_err());

        let mut capture = evm_capture();
        capture["chainId"]["response"]["result"] = serde_json::json!("0x0ab163");
        assert!(parse_evm_rpc_capture(&serde_json::to_vec(&capture).unwrap()).is_err());
    }

    #[test]
    fn evm_capture_refuses_impossible_genesis_and_finalized_headers() {
        let mut capture = evm_capture();
        capture["genesisBlock"]["response"]["result"]["parentHash"] =
            serde_json::json!(format!("0x{}", "8".repeat(64)));
        assert_eq!(
            parse_evm_rpc_capture(&serde_json::to_vec(&capture).unwrap()).unwrap_err(),
            VerifyError::InvalidField("evmRpcCapture.genesisBlock.parentHash")
        );

        let mut capture = evm_capture();
        capture["finalizedBlock"]["response"]["result"]["hash"] =
            capture["genesisBlock"]["response"]["result"]["hash"].clone();
        assert_eq!(
            parse_evm_rpc_capture(&serde_json::to_vec(&capture).unwrap()).unwrap_err(),
            VerifyError::InvalidField("evmRpcCapture.finalizedBlock")
        );
    }

    #[test]
    fn evm_ancestry_verifies_contiguous_parent_links_without_claiming_finality() {
        let evidence = evm_ancestry_evidence();
        let bytes = serde_json::to_vec(&evidence).unwrap();
        let parsed = parse_evm_ancestry_evidence(&bytes).unwrap();
        let report = verify_evm_ancestry_evidence(&parsed).unwrap();
        assert_eq!(report.header_count, 3);
        assert!(report.contiguous_heights);
        assert!(report.parent_hash_linkage_verified);
        assert!(report.endpoints_matched);
        assert!(!report.consensus_finality_authenticated);
        assert!(!report.production_qualified);
    }

    #[test]
    fn evm_ancestry_refuses_gap_broken_link_and_endpoint_substitution() {
        let mut gap = evm_ancestry_evidence();
        gap.headers[1].height += 1;
        assert_eq!(
            verify_evm_ancestry_evidence(&gap).unwrap_err(),
            VerifyError::InvalidField("evmAncestryEvidence.header.height")
        );

        let mut broken = evm_ancestry_evidence();
        broken.headers[2].parent_hash = format!("0x{}", "9".repeat(64));
        assert_eq!(
            verify_evm_ancestry_evidence(&broken).unwrap_err(),
            VerifyError::InvalidField("evmAncestryEvidence.header.parentHash")
        );

        let mut substituted = evm_ancestry_evidence();
        substituted.finalized.block_hash = format!("0x{}", "8".repeat(64));
        assert_eq!(
            verify_evm_ancestry_evidence(&substituted).unwrap_err(),
            VerifyError::InvalidField("evmAncestryEvidence.finalized")
        );
    }

    #[test]
    fn evm_ancestry_refuses_trivial_or_oversized_claims_and_unknown_fields() {
        let mut trivial = evm_ancestry_evidence();
        trivial.finalized.height = trivial.checkpoint.height;
        assert_eq!(
            verify_evm_ancestry_evidence(&trivial).unwrap_err(),
            VerifyError::InvalidField("evmAncestryEvidence.finalized.height")
        );

        let mut value = serde_json::to_value(evm_ancestry_evidence()).unwrap();
        value["consensusFinalized"] = serde_json::Value::Bool(true);
        assert!(matches!(
            parse_evm_ancestry_evidence(&serde_json::to_vec(&value).unwrap()),
            Err(VerifyError::InvalidJson(_))
        ));

        let mut oversized = evm_ancestry_evidence();
        oversized.finalized.height = oversized.checkpoint.height + MAX_ANCESTRY_HEADERS as u64;
        oversized.headers = vec![oversized.headers[0].clone(); MAX_ANCESTRY_HEADERS + 1];
        assert_eq!(
            verify_evm_ancestry_evidence(&oversized).unwrap_err(),
            VerifyError::InvalidField("evmAncestryEvidence.headers")
        );
    }

    fn evm_ancestry_evidence() -> EvmAncestryEvidence {
        let checkpoint_hash = format!("0x{}", "5".repeat(64));
        let middle_hash = format!("0x{}", "6".repeat(64));
        let finalized_hash = format!("0x{}", "7".repeat(64));
        let checkpoint_root = format!("0x{}", "a".repeat(64));
        let finalized_root = format!("0x{}", "c".repeat(64));
        EvmAncestryEvidence {
            schema: EVM_ANCESTRY_EVIDENCE_SCHEMA.into(),
            network: NetworkIdentity {
                network: "bloch-l2".into(),
                chain_id: 700_771,
                genesis_hash: format!("0x{}", "3".repeat(64)),
            },
            checkpoint: Checkpoint {
                height: 40,
                block_hash: checkpoint_hash.clone(),
                state_root: checkpoint_root.clone(),
            },
            finalized: EvmBlockReference {
                height: 42,
                block_hash: finalized_hash.clone(),
                state_root: finalized_root.clone(),
            },
            headers: vec![
                EvmAncestryHeader {
                    height: 40,
                    block_hash: checkpoint_hash,
                    parent_hash: format!("0x{}", "4".repeat(64)),
                    state_root: checkpoint_root,
                },
                EvmAncestryHeader {
                    height: 41,
                    block_hash: middle_hash.clone(),
                    parent_hash: format!("0x{}", "5".repeat(64)),
                    state_root: format!("0x{}", "b".repeat(64)),
                },
                EvmAncestryHeader {
                    height: 42,
                    block_hash: finalized_hash,
                    parent_hash: middle_hash,
                    state_root: finalized_root,
                },
            ],
        }
    }

    fn evm_capture() -> serde_json::Value {
        fn exchange(
            id: u64,
            method: &str,
            params: serde_json::Value,
            result: serde_json::Value,
        ) -> serde_json::Value {
            serde_json::json!({
                "request": {"jsonrpc": "2.0", "id": id, "method": method, "params": params},
                "response": {"jsonrpc": "2.0", "id": id, "result": result}
            })
        }
        serde_json::json!({
            "schema": "bloch.verify.evm-rpc-capture.v1",
            "observerId": "observer-a",
            "organizationId": "organization-a",
            "endpointSha256": format!("0x{}", "1".repeat(64)),
            "observedAtUnixSeconds": 1_790_121_600u64,
            "network": "bloch-l2",
            "releaseRevision": format!("0x{}", "2".repeat(40)),
            "clientVersion": exchange(1, "web3_clientVersion", serde_json::json!([]), serde_json::json!("bloch-l2/v0.1.0")),
            "chainId": exchange(2, "eth_chainId", serde_json::json!([]), serde_json::json!("0xab163")),
            "genesisBlock": exchange(3, "eth_getBlockByNumber", serde_json::json!(["0x0", false]), serde_json::json!({
                "number": "0x0",
                "hash": format!("0x{}", "3".repeat(64)),
                "parentHash": format!("0x{}", "0".repeat(64)),
                "stateRoot": format!("0x{}", "4".repeat(64))
            })),
            "finalizedBlock": exchange(4, "eth_getBlockByNumber", serde_json::json!(["finalized", false]), serde_json::json!({
                "number": "0x2a",
                "hash": format!("0x{}", "5".repeat(64)),
                "parentHash": format!("0x{}", "6".repeat(64)),
                "stateRoot": format!("0x{}", "7".repeat(64))
            }))
        })
    }

    #[test]
    fn duplicate_json_keys_are_refused_at_every_depth() {
        let duplicate_top_level = br#"{"schema":"bloch.verify.evm-rpc-capture.v1","schema":"bloch.verify.evm-rpc-capture.v1"}"#;
        assert!(matches!(
            parse_evm_rpc_capture(duplicate_top_level),
            Err(VerifyError::InvalidJson(message)) if message.contains("duplicate JSON object key")
        ));

        let duplicate_nested =
            br#"[{"jsonrpc":"2.0","id":1,"result":{"hash":"first","hash":"second"}}]"#;
        assert!(matches!(
            parse_json_rpc_responses(duplicate_nested),
            Err(VerifyError::InvalidJson(message)) if message.contains("duplicate JSON object key")
        ));
    }
}
