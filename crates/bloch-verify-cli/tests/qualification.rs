use bloch_verify_core::{
    EvidenceBundle, NetworkIdentity, OperatorTrustPolicy, SignedEvidenceBundle,
    SignedNodeObservation, TrustedOperator, network_identity_sha256, parse_bundle,
    signed_observation_message, trust_policy_sha256,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

#[test]
fn qualification_cli_binds_network_digest_and_keeps_unavailable_gates_closed() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let (policy, bundle, network, policy_digest) = signed_fixture();
    let network_digest = network_identity_sha256(&network).unwrap();
    let bundle_path = root.join("bundle.json");
    let policy_path = root.join("policy.json");
    let network_path = root.join("network.json");
    let report_path = root.join("report.json");
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::write(&network_path, serde_json::to_vec(&network).unwrap()).unwrap();

    let digest_output = Command::new(env!("CARGO_BIN_EXE_bloch-verify-qualify"))
        .arg("digest-network")
        .arg("--network")
        .arg(&network_path)
        .output()
        .unwrap();
    assert!(digest_output.status.success());
    assert_eq!(
        String::from_utf8(digest_output.stdout).unwrap().trim(),
        network_digest
    );

    let output = command(
        &bundle_path,
        &policy_path,
        &policy_digest,
        &network_path,
        &network_digest,
        &report_path,
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["expectedNetworkSha256"], network_digest);
    assert_eq!(report["gates"][0]["passed"], true);
    assert_eq!(report["gates"][1]["passed"], true);
    assert_eq!(report["gates"][2]["disposition"], "verifierUnavailable");
    assert_eq!(report["productionQualified"], false);

    let refused_path = root.join("refused.json");
    let refused = command(
        &bundle_path,
        &policy_path,
        &policy_digest,
        &network_path,
        &format!("0x{}", "f".repeat(64)),
        &refused_path,
    )
    .output()
    .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(!refused_path.exists());
    fs::remove_dir_all(root).unwrap();
}

fn command(
    bundle: &std::path::Path,
    policy: &std::path::Path,
    policy_digest: &str,
    network: &std::path::Path,
    network_digest: &str,
    report: &std::path::Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-verify-qualify"));
    command
        .arg("assess-signed")
        .arg("--bundle")
        .arg(bundle)
        .arg("--trust-policy")
        .arg(policy)
        .arg("--expected-trust-policy-sha256")
        .arg(policy_digest)
        .arg("--expected-network")
        .arg(network)
        .arg("--expected-network-sha256")
        .arg(network_digest)
        .arg("--at")
        .arg("1790121600")
        .arg("--report-out")
        .arg(report);
    command
}

fn signed_fixture() -> (
    OperatorTrustPolicy,
    SignedEvidenceBundle,
    NetworkIdentity,
    String,
) {
    let mut unsigned: EvidenceBundle = parse_bundle(FIXTURE).unwrap();
    let network = NetworkIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: format!("0x{}", "9".repeat(64)),
    };
    unsigned.network = network.clone();
    for observation in &mut unsigned.observations {
        observation.network = network.network.clone();
        observation.chain_id = network.chain_id;
        observation.genesis_hash = network.genesis_hash.clone();
    }
    let keys = [
        SigningKey::from_bytes(&[31; 32]),
        SigningKey::from_bytes(&[37; 32]),
    ];
    let policy = OperatorTrustPolicy {
        schema: "bloch.verify.operator-trust-policy.v1".into(),
        policy_id: "qualification-cli-test".into(),
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
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
            })
            .collect(),
    };
    let policy_digest = trust_policy_sha256(&policy).unwrap();
    let signed_observations = unsigned
        .observations
        .iter()
        .zip(&keys)
        .map(|(observation, key)| SignedNodeObservation {
            observation: observation.clone(),
            signature: format!(
                "0x{}",
                hex::encode(
                    key.sign(&signed_observation_message(&policy_digest, observation).unwrap())
                        .to_bytes()
                )
            ),
        })
        .collect();
    (
        policy,
        SignedEvidenceBundle {
            schema: "bloch.verify.signed-checkpoint-bundle.v1".into(),
            network,
            checkpoint: unsigned.checkpoint,
            trust_policy_sha256: policy_digest.clone(),
            signed_observations,
        },
        unsigned.network,
        policy_digest,
    )
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-qualification-{}-{nonce}",
        std::process::id()
    ))
}
