use bloch_verify_core::{
    EvidenceBundle, OperatorTrustPolicy, SignedEvidenceBundle, SignedNodeObservation,
    TrustedOperator, parse_bundle, signed_observation_message, trust_policy_sha256,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

#[test]
fn signed_cli_passes_authenticated_comparison_and_keeps_production_closed() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let (policy, signed, digest) = signed_fixture();
    let policy_path = root.join("policy.json");
    let bundle_path = root.join("signed.json");
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    fs::write(&bundle_path, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();

    let success = command(&bundle_path, &policy_path, &digest)
        .arg("--require-authenticated-comparison")
        .output()
        .unwrap();
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(report["authenticatedComparisonPassed"], true);
    assert_eq!(report["authentication"]["observationsSigned"], true);
    assert_eq!(report["productionQualified"], false);

    let closed = command(&bundle_path, &policy_path, &digest)
        .arg("--require-production-qualified")
        .output()
        .unwrap();
    assert_eq!(closed.status.code(), Some(1));

    let substituted = command(&bundle_path, &policy_path, &format!("0x{}", "f".repeat(64)))
        .output()
        .unwrap();
    assert_eq!(substituted.status.code(), Some(2));

    fs::remove_dir_all(root).unwrap();
}

fn command(bundle: &Path, policy: &Path, digest: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-verify"));
    command.args([
        "assess-signed",
        "--bundle",
        bundle.to_str().unwrap(),
        "--trust-policy",
        policy.to_str().unwrap(),
        "--expected-trust-policy-sha256",
        digest,
        "--at",
        "1790121600",
    ]);
    command
}

fn signed_fixture() -> (OperatorTrustPolicy, SignedEvidenceBundle, String) {
    let unsigned: EvidenceBundle = parse_bundle(FIXTURE).unwrap();
    let keys = [
        SigningKey::from_bytes(&[17; 32]),
        SigningKey::from_bytes(&[19; 32]),
    ];
    let policy = OperatorTrustPolicy {
        schema: "bloch.verify.operator-trust-policy.v1".into(),
        policy_id: "cli-integration-policy".into(),
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
    let digest = trust_policy_sha256(&policy).unwrap();
    let signed_observations = unsigned
        .observations
        .iter()
        .zip(&keys)
        .map(|(observation, key)| SignedNodeObservation {
            observation: observation.clone(),
            signature: format!(
                "0x{}",
                hex::encode(
                    key.sign(&signed_observation_message(&digest, observation).unwrap())
                        .to_bytes()
                )
            ),
        })
        .collect();
    (
        policy,
        SignedEvidenceBundle {
            schema: "bloch.verify.signed-checkpoint-bundle.v1".into(),
            network: unsigned.network,
            checkpoint: unsigned.checkpoint,
            trust_policy_sha256: digest.clone(),
            signed_observations,
        },
        digest,
    )
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("bloch-verify-cli-{}-{nonce}", std::process::id()))
}
