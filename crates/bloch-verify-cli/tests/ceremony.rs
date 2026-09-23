use bloch_verify_core::{
    EvidenceBundle, OperatorTrustPolicy, TrustedOperator, parse_bundle, trust_policy_sha256,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

#[test]
fn detached_ceremony_cli_is_create_once_and_builds_authenticated_evidence() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let unsigned: EvidenceBundle = parse_bundle(FIXTURE).unwrap();
    let keys = [
        SigningKey::from_bytes(&[23; 32]),
        SigningKey::from_bytes(&[29; 32]),
    ];
    let policy = policy(&unsigned, &keys);
    let digest = trust_policy_sha256(&policy).unwrap();
    let policy_path = root.join("policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let mut response_paths = Vec::new();
    for (index, (observation, key)) in unsigned.observations.iter().zip(&keys).enumerate() {
        let observation_path = root.join(format!("observation-{index}.json"));
        let request_dir = root.join(format!("request-{index}"));
        let signature_path = root.join(format!("signature-{index}.bin"));
        let response_path = root.join(format!("response-{index}.json"));
        fs::write(&observation_path, serde_json::to_vec(observation).unwrap()).unwrap();

        succeeds(
            ceremony()
                .arg("prepare")
                .arg("--observation")
                .arg(&observation_path)
                .arg("--trust-policy")
                .arg(&policy_path)
                .arg("--expected-trust-policy-sha256")
                .arg(&digest)
                .arg("--out-dir")
                .arg(&request_dir),
        );
        let message = fs::read(request_dir.join("message.bin")).unwrap();
        fs::write(&signature_path, key.sign(&message).to_bytes()).unwrap();
        succeeds(
            ceremony()
                .arg("import")
                .arg("--request")
                .arg(request_dir.join("request.json"))
                .arg("--signature")
                .arg(&signature_path)
                .arg("--response-out")
                .arg(&response_path),
        );

        let overwrite = ceremony()
            .arg("import")
            .arg("--request")
            .arg(request_dir.join("request.json"))
            .arg("--signature")
            .arg(&signature_path)
            .arg("--response-out")
            .arg(&response_path)
            .output()
            .unwrap();
        assert_eq!(overwrite.status.code(), Some(2));
        response_paths.push(response_path);
    }

    let bundle_path = root.join("signed-bundle.json");
    let mut assemble = ceremony();
    assemble
        .arg("assemble")
        .arg("--trust-policy")
        .arg(&policy_path)
        .arg("--expected-trust-policy-sha256")
        .arg(&digest);
    for response in &response_paths {
        assemble.arg("--response").arg(response);
    }
    succeeds(assemble.arg("--bundle-out").arg(&bundle_path));

    let assessment = Command::new(env!("CARGO_BIN_EXE_bloch-verify"))
        .arg("assess-signed")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trust-policy")
        .arg(&policy_path)
        .arg("--expected-trust-policy-sha256")
        .arg(&digest)
        .arg("--at")
        .arg("1790121600")
        .arg("--require-authenticated-comparison")
        .output()
        .unwrap();
    assert!(assessment.status.success());
    let report: serde_json::Value = serde_json::from_slice(&assessment.stdout).unwrap();
    assert_eq!(report["authenticatedComparisonPassed"], true);
    assert_eq!(report["productionQualified"], false);

    let mut corrupted = fs::read(root.join("signature-0.bin")).unwrap();
    corrupted[0] ^= 1;
    let corrupted_path = root.join("corrupted.bin");
    fs::write(&corrupted_path, corrupted).unwrap();
    let refused = ceremony()
        .arg("import")
        .arg("--request")
        .arg(root.join("request-0/request.json"))
        .arg("--signature")
        .arg(corrupted_path)
        .arg("--response-out")
        .arg(root.join("corrupted-response.json"))
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));

    fs::remove_dir_all(root).unwrap();
}

fn policy(unsigned: &EvidenceBundle, keys: &[SigningKey; 2]) -> OperatorTrustPolicy {
    OperatorTrustPolicy {
        schema: "bloch.verify.operator-trust-policy.v1".into(),
        policy_id: "detached-cli-integration-policy".into(),
        valid_from_unix_seconds: 1_790_000_000,
        valid_until_unix_seconds: 1_790_200_000,
        comparison: unsigned.policy.clone(),
        operators: unsigned
            .observations
            .iter()
            .zip(keys)
            .map(|(observation, key)| TrustedOperator {
                observer_id: observation.observer_id.clone(),
                organization_id: observation.organization_id.clone(),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
            })
            .collect(),
    }
}

fn ceremony() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bloch-verify-ceremony"))
}

fn succeeds(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-ceremony-cli-{}-{nonce}",
        std::process::id()
    ))
}
