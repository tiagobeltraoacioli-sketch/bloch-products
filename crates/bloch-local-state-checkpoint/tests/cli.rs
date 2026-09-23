#![cfg(unix)]

use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    checkpoint_policy_bytes, checkpoint_policy_sha256,
};
use bloch_local_state_store::write_state;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    other_root: PathBuf,
    policy: PathBuf,
    policy_pin: String,
    semantic_pin: String,
    keys: Vec<SigningKey>,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "bloch-checkpoint-cli-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let root_value = write_state(
            &directory.join("store"),
            "data:tenant-a:lifecycle",
            0,
            b"state-a",
            None,
        )
        .unwrap();
        let other_root_value = write_state(
            &directory.join("other-store"),
            "data:tenant-a:lifecycle",
            0,
            b"state-b",
            None,
        )
        .unwrap();
        let root = directory.join("root.json");
        let other_root = directory.join("other-root.json");
        write_private(&root, &root_value.canonical_bytes().unwrap());
        write_private(&other_root, &other_root_value.canonical_bytes().unwrap());

        let keys = vec![
            SigningKey::from_bytes(&[11; 32]),
            SigningKey::from_bytes(&[22; 32]),
        ];
        let policy_value = CheckpointPolicy {
            schema: POLICY_SCHEMA.into(),
            policy_id: "cli-policy".into(),
            checkpoint_domain: "bloch-products-test".into(),
            state_identity: "data:tenant-a:lifecycle".into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_checkpoint_age_seconds: 200,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CheckpointAuthority {
                    authority_id: format!("authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let policy_pin = checkpoint_policy_sha256(&policy_value).unwrap();
        let policy = directory.join("policy.json");
        write_private(&policy, &checkpoint_policy_bytes(&policy_value).unwrap());
        Self {
            directory,
            root,
            other_root,
            policy,
            policy_pin,
            semantic_pin: format!("0x{}", "42".repeat(32)),
            keys,
        }
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-local-state-checkpoint"));
        command.arg(operation);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn offline_request_assemble_and_exact_verify_emit_no_stdout() {
    let fixture = Fixture::new();
    let request = fixture.directory.join("request.json");
    let message = fixture.directory.join("message.bin");
    let output = fixture
        .command("request")
        .args([
            "--root",
            fixture.root.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--created-at",
            "200",
            "--request-out",
            request.to_str().unwrap(),
            "--message-out",
            message.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success_without_stdout(&output);
    assert_eq!(
        fs::metadata(&request).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&message).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let signing_message = fs::read(&message).unwrap();
    let signatures = json!({
        "schema": "bloch.products.local-state-checkpoint-signatures.v1",
        "signatures": fixture.keys.iter().enumerate().map(|(index, key)| {
            DetachedCheckpointSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&signing_message).to_bytes())),
            }
        }).collect::<Vec<_>>()
    });
    let signatures_path = fixture.directory.join("signatures.json");
    write_private(&signatures_path, &serde_json::to_vec(&signatures).unwrap());
    let artifact = fixture.directory.join("artifact.json");
    let output = fixture
        .command("assemble")
        .args([
            "--root",
            fixture.root.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--created-at",
            "200",
            "--signatures",
            signatures_path.to_str().unwrap(),
            "--artifact-out",
            artifact.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success_without_stdout(&output);

    let receipt = fixture.directory.join("receipt.json");
    let output = fixture
        .command("verify")
        .args([
            "--artifact",
            artifact.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--expected-semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--expected-root",
            fixture.root.to_str().unwrap(),
            "--evaluated-at",
            "250",
            "--receipt-out",
            receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success_without_stdout(&output);
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
    assert_eq!(receipt["antiRollbackExpectationMatched"], true);
    assert_eq!(receipt["authorityIndependenceProven"], false);
    assert_eq!(receipt["semanticManifestSha256"], fixture.semantic_pin);

    let wrong_semantic_receipt = fixture.directory.join("wrong-semantic.json");
    let wrong_semantic_pin = format!("0x{}", "24".repeat(32));
    let output = fixture
        .command("verify")
        .args([
            "--artifact",
            artifact.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--expected-semantic-manifest-sha256",
            &wrong_semantic_pin,
            "--expected-root",
            fixture.root.to_str().unwrap(),
            "--evaluated-at",
            "250",
            "--receipt-out",
            wrong_semantic_receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!wrong_semantic_receipt.exists());

    let rejected_receipt = fixture.directory.join("rejected.json");
    let output = fixture
        .command("verify")
        .args([
            "--artifact",
            artifact.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--expected-semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--expected-root",
            fixture.other_root.to_str().unwrap(),
            "--evaluated-at",
            "250",
            "--receipt-out",
            rejected_receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!rejected_receipt.exists());
}

#[test]
fn outputs_are_create_only_and_inputs_must_be_owner_only() {
    let fixture = Fixture::new();
    let request = fixture.directory.join("request.json");
    let message = fixture.directory.join("message.bin");
    write_private(&message, b"occupied");
    let output = fixture
        .command("request")
        .args([
            "--root",
            fixture.root.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--created-at",
            "200",
            "--request-out",
            request.to_str().unwrap(),
            "--message-out",
            message.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!request.exists());
    assert_eq!(fs::read(message).unwrap(), b"occupied");

    fs::set_permissions(&fixture.policy, fs::Permissions::from_mode(0o644)).unwrap();
    let new_message = fixture.directory.join("new-message");
    let output = fixture
        .command("request")
        .args([
            "--root",
            fixture.root.to_str().unwrap(),
            "--policy",
            fixture.policy.to_str().unwrap(),
            "--policy-sha256",
            &fixture.policy_pin,
            "--semantic-manifest-sha256",
            &fixture.semantic_pin,
            "--created-at",
            "200",
            "--request-out",
            request.to_str().unwrap(),
            "--message-out",
            new_message.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!request.exists());
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn success_without_stdout(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}
