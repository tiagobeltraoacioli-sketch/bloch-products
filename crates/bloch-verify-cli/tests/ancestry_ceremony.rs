use bloch_verify_core::checkpoint_ancestry::{
    AncestryAuthority, AncestrySignature, CHECKPOINT_ANCESTRY_POLICY_SCHEMA,
    CheckpointAncestryAudience, CheckpointAncestryPolicy, checkpoint_ancestry_policy_sha256,
    checkpoint_ancestry_signature_message, create_checkpoint_ancestry_evidence,
};
use bloch_verify_core::{
    EvmAncestryEvidence, network_identity_sha256, parse_evm_ancestry_evidence,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    ancestry: EvmAncestryEvidence,
    policy: CheckpointAncestryPolicy,
    policy_sha256: String,
    network_sha256: String,
    bundle_sha256: String,
    keys: Vec<SigningKey>,
    policy_path: PathBuf,
    ancestry_path: PathBuf,
    network_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = unique_directory();
        fs::create_dir(&root).unwrap();
        let ancestry = parse_evm_ancestry_evidence(include_bytes!(
            "../../../fixtures/valid-evm-ancestry.json"
        ))
        .unwrap();
        let network_sha256 = network_identity_sha256(&ancestry.network).unwrap();
        let keys = vec![
            SigningKey::from_bytes(&[71; 32]),
            SigningKey::from_bytes(&[73; 32]),
        ];
        let policy = CheckpointAncestryPolicy {
            schema: CHECKPOINT_ANCESTRY_POLICY_SCHEMA.into(),
            policy_id: "offline-ancestry-ceremony-test".into(),
            signature_domain: "offline-ancestry-ceremony".into(),
            expected_network_sha256: network_sha256.clone(),
            trusted_anchor_height: ancestry.finalized.height,
            trusted_anchor_block_hash: ancestry.finalized.block_hash.clone(),
            trusted_anchor_state_root: ancestry.finalized.state_root.clone(),
            trusted_time_policy_sha256: format!("0x{}", "9".repeat(64)),
            trusted_time_state_identity: "verify:ancestry:700771".into(),
            authority_threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            maximum_evidence_age_seconds: 100,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| AncestryAuthority {
                    authority_id: format!("ancestry-{index}"),
                    organization_id: format!("organization-{index}"),
                    control_domain: format!("control-{index}"),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let policy_sha256 = checkpoint_ancestry_policy_sha256(&policy).unwrap();
        let policy_path = root.join("policy.json");
        let ancestry_path = root.join("ancestry.json");
        let network_path = root.join("network.json");
        fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::write(&ancestry_path, serde_json::to_vec(&ancestry).unwrap()).unwrap();
        fs::write(
            &network_path,
            serde_json::to_vec(&ancestry.network).unwrap(),
        )
        .unwrap();
        Self {
            root,
            ancestry,
            policy,
            policy_sha256,
            network_sha256,
            bundle_sha256: format!("0x{}", "8".repeat(64)),
            keys,
            policy_path,
            ancestry_path,
            network_path,
        }
    }

    fn audience(&self) -> CheckpointAncestryAudience<'_> {
        CheckpointAncestryAudience {
            assessed_bundle_sha256: &self.bundle_sha256,
            expected_network_sha256: &self.network_sha256,
            expected_checkpoint: &self.ancestry.checkpoint,
        }
    }

    fn command(&self, action: &str, output_option: &str, output: &Path) -> Command {
        self.command_for_bundle(action, output_option, output, &self.bundle_sha256)
    }

    fn command_for_bundle(
        &self,
        action: &str,
        output_option: &str,
        output: &Path,
        bundle_sha256: &str,
    ) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-verify-ancestry-ceremony"));
        command
            .arg(action)
            .arg("--policy")
            .arg(&self.policy_path)
            .args(["--expected-policy-sha256", &self.policy_sha256])
            .arg("--ancestry")
            .arg(&self.ancestry_path)
            .args(["--expected-bundle-sha256", bundle_sha256])
            .arg("--expected-network")
            .arg(&self.network_path)
            .args(["--expected-network-sha256", &self.network_sha256])
            .args(["--attested-at", "2000"])
            .args(["--valid-until", "2100"])
            .arg(output_option)
            .arg(output);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn publishes_exact_message_and_assembles_only_valid_threshold_signatures() {
    let fixture = Fixture::new();
    let digest = Command::new(env!("CARGO_BIN_EXE_bloch-verify-ancestry-ceremony"))
        .args(["digest-policy", "--policy"])
        .arg(&fixture.policy_path)
        .output()
        .unwrap();
    assert!(digest.status.success());
    assert_eq!(
        String::from_utf8(digest.stdout).unwrap().trim(),
        fixture.policy_sha256
    );

    let expected_message = checkpoint_ancestry_signature_message(
        &fixture.policy,
        &fixture.policy_sha256,
        &fixture.ancestry,
        &fixture.audience(),
        2_000,
        2_100,
    )
    .unwrap();
    let message_path = fixture.root.join("message.bin");
    let prepared = fixture
        .command("prepare-message", "--message-out", &message_path)
        .output()
        .unwrap();
    assert!(prepared.status.success());
    assert_eq!(fs::read(&message_path).unwrap(), expected_message);

    let signatures = fixture
        .keys
        .iter()
        .enumerate()
        .map(|(index, key)| AncestrySignature {
            authority_id: format!("ancestry-{index}"),
            signature: format!("0x{}", hex::encode(key.sign(&expected_message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let signatures_path = fixture.root.join("signatures.json");
    fs::write(&signatures_path, serde_json::to_vec(&signatures).unwrap()).unwrap();
    let evidence_path = fixture.root.join("evidence.json");
    let assembled = fixture
        .command("assemble-evidence", "--evidence-out", &evidence_path)
        .arg("--signatures")
        .arg(&signatures_path)
        .output()
        .unwrap();
    assert!(assembled.status.success());
    assert_eq!(
        fs::read(&evidence_path).unwrap(),
        create_checkpoint_ancestry_evidence(
            &fixture.policy,
            &fixture.policy_sha256,
            &fixture.ancestry,
            &fixture.audience(),
            2_000,
            2_100,
            signatures,
        )
        .unwrap()
    );
}

#[test]
fn refuses_unsafe_artifacts_and_binds_audience_changes_into_message() {
    let fixture = Fixture::new();
    let message_path = fixture.root.join("message.bin");
    fs::write(&message_path, b"retain-me").unwrap();
    let overwrite = fixture
        .command("prepare-message", "--message-out", &message_path)
        .output()
        .unwrap();
    assert_eq!(overwrite.status.code(), Some(2));
    assert_eq!(fs::read(&message_path).unwrap(), b"retain-me");

    let message = checkpoint_ancestry_signature_message(
        &fixture.policy,
        &fixture.policy_sha256,
        &fixture.ancestry,
        &fixture.audience(),
        2_000,
        2_100,
    )
    .unwrap();
    let mut signatures = fixture
        .keys
        .iter()
        .enumerate()
        .map(|(index, key)| AncestrySignature {
            authority_id: format!("ancestry-{index}"),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    signatures[1].signature = format!("0x{}", "00".repeat(64));
    let invalid_path = fixture.root.join("invalid-signatures.json");
    fs::write(&invalid_path, serde_json::to_vec(&signatures).unwrap()).unwrap();
    let invalid_output = fixture.root.join("invalid-evidence.json");
    let invalid = fixture
        .command("assemble-evidence", "--evidence-out", &invalid_output)
        .arg("--signatures")
        .arg(&invalid_path)
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!invalid_output.exists());

    let noncanonical_path = fixture.root.join("noncanonical-signatures.json");
    fs::write(
        &noncanonical_path,
        serde_json::to_vec_pretty(&signatures).unwrap(),
    )
    .unwrap();
    let noncanonical_output = fixture.root.join("noncanonical-evidence.json");
    let noncanonical = fixture
        .command("assemble-evidence", "--evidence-out", &noncanonical_output)
        .arg("--signatures")
        .arg(&noncanonical_path)
        .output()
        .unwrap();
    assert_eq!(noncanonical.status.code(), Some(2));
    assert!(!noncanonical_output.exists());

    let changed_bundle_output = fixture.root.join("changed-bundle.bin");
    let changed_bundle_sha256 = format!("0x{}", "7".repeat(64));
    let changed_bundle = fixture
        .command_for_bundle(
            "prepare-message",
            "--message-out",
            &changed_bundle_output,
            &changed_bundle_sha256,
        )
        .output()
        .unwrap();
    assert!(changed_bundle.status.success());
    assert_ne!(fs::read(&changed_bundle_output).unwrap(), message);
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_inputs() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let linked_policy = fixture.root.join("linked-policy.json");
    symlink(&fixture.policy_path, &linked_policy).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bloch-verify-ancestry-ceremony"))
        .args(["digest-policy", "--policy"])
        .arg(&linked_policy)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-ancestry-ceremony-{}-{nonce}-{}",
        std::process::id(),
        DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}
