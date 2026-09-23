#![cfg(unix)]

use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    authenticate_root_checkpoint, checkpoint_policy_bytes, checkpoint_policy_sha256,
    checkpoint_signature_message, create_root_checkpoint,
};
use bloch_local_state_coordination::{
    provision_local_state_coordination_directory, with_coordinated_state_transition,
};
use bloch_local_state_cursor::admit_checkpoint;
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    create_remote_cursor_observation, remote_cursor_policy_bytes, remote_cursor_policy_sha256,
    remote_cursor_signature_message,
};
use bloch_local_state_store::write_state;
use bloch_pay_adjustments::{ADJUSTMENT_STATE_SCHEMA, AdjustmentStatus};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bloch-admission-cli-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_bloch-local-state-admission")
}

#[test]
fn rejects_unknown_missing_duplicate_and_unsafe_inputs_without_stdout() {
    for arguments in [
        vec!["unknown"],
        vec!["pay"],
        vec!["pay", "--artifact", "a", "--artifact", "b"],
        vec!["pay", "--unknown", "x"],
        vec!["manual-pay", "--expected-cursor", "raw-cursor.json"],
    ] {
        let output = Command::new(binary()).args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }

    let temp = Temp::new();
    let target = temp.0.join("artifact.json");
    let link = temp.0.join("artifact-link.json");
    fs::write(&target, b"{}").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &link).unwrap();
    let output = Command::new(binary())
        .args([
            "manual-pay",
            "--artifact",
            link.to_str().unwrap(),
            "--checkpoint-policy",
            target.to_str().unwrap(),
            "--coordination-directory",
            temp.0.to_str().unwrap(),
            "--cursor-store",
            temp.0.to_str().unwrap(),
            "--remote-observation",
            target.to_str().unwrap(),
            "--remote-policy",
            target.to_str().unwrap(),
            "--remote-policy-pin",
            target.to_str().unwrap(),
            "--request-nonce",
            target.to_str().unwrap(),
            "--semantic-manifest",
            target.to_str().unwrap(),
            "--state-store",
            temp.0.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn mixed_remote_inputs_and_cross_product_identity_fail_closed() {
    let mixed = Temp::new();
    let mixed_coordination = mixed.0.join("coordination");
    let mixed_arguments = retained_pay_arguments(&mixed, &mixed_coordination);
    let pin_path = argument_path(&mixed_arguments, "--remote-policy-pin");
    write_private(&pin_path, digest(b"wrong-remote-policy").as_bytes());
    let output = Command::new(binary())
        .args(&mixed_arguments)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let cross = Temp::new();
    let cross_coordination = cross.0.join("coordination");
    let mut cross_arguments = retained_pay_arguments(&cross, &cross_coordination);
    cross_arguments[0] = "manual-data".into();
    let lifecycle = cross.0.join("lifecycle-policy.json");
    write_private(&lifecycle, b"{}");
    cross_arguments.push("--lifecycle-policy".into());
    cross_arguments.push(lifecycle.to_string_lossy().into_owned());
    let output = Command::new(binary())
        .args(&cross_arguments)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("wrong product identity")
    );
}

#[test]
fn cli_uses_shared_lock_fails_bounded_and_never_leaks_state() {
    let temp = Temp::new();
    let coordination = temp.0.join("coordination");
    let arguments = retained_pay_arguments(&temp, &coordination);
    provision_local_state_coordination_directory(&coordination).unwrap();

    with_coordinated_state_transition(&coordination, |_scope| {
        let started = Instant::now();
        let output = Command::new(binary()).args(&arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("local state coordination failed"));
        assert!(!stderr.contains("highly-sensitive-adjustment"));
        Ok::<_, std::io::Error>(())
    })
    .unwrap();

    let output = Command::new(binary()).args(&arguments).output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitialAdjustmentState<'a> {
    schema: &'static str,
    adjustment_policy_sha256: &'a str,
    reconciliation_policy_sha256: &'a str,
    adjustment_id: &'a str,
    payment_observation_id: &'a str,
    payment_observation_sha256: &'a str,
    payment_amount_minor: u64,
    generation: u64,
    status: AdjustmentStatus,
    applied_events: Vec<serde_json::Value>,
    settlement_qualified: bool,
    credit_authorized: bool,
    funds_moved: bool,
}

fn retained_pay_arguments(temp: &Temp, coordination: &std::path::Path) -> Vec<String> {
    let identity = "pay:merchant-a:adjustment-1";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state_store = temp.0.join("state-store");
    let cursor_store = temp.0.join("cursor-store");
    let adjustment_policy = digest(b"adjustment-policy");
    let reconciliation_policy = digest(b"reconciliation-policy");
    let observation = digest(b"payment-observation");
    let state = serde_json::to_vec(&InitialAdjustmentState {
        schema: ADJUSTMENT_STATE_SCHEMA,
        adjustment_policy_sha256: &adjustment_policy,
        reconciliation_policy_sha256: &reconciliation_policy,
        adjustment_id: "highly-sensitive-adjustment",
        payment_observation_id: "observation-1",
        payment_observation_sha256: &observation,
        payment_amount_minor: 125,
        generation: 0,
        status: AdjustmentStatus::Active,
        applied_events: vec![],
        settlement_qualified: false,
        credit_authorized: false,
        funds_moved: false,
    })
    .unwrap();
    let root = write_state(&state_store, identity, 0, &state, None).unwrap();
    let semantic_manifest = PayAdjustmentSemanticManifest {
        schema: PAY_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: identity.into(),
        adjustment_policy_sha256: adjustment_policy,
        reconciliation_policy_sha256: reconciliation_policy,
        adjustment_id: "highly-sensitive-adjustment".into(),
        payment_observation_id: "observation-1".into(),
        payment_observation_sha256: observation,
        payment_amount_minor: 125,
        generation: 0,
    };
    let semantic = pay_semantic_manifest_bytes(&semantic_manifest).unwrap();
    let semantic_pin = pay_semantic_manifest_sha256(&semantic_manifest).unwrap();
    let keys = [
        SigningKey::from_bytes(&[71; 32]),
        SigningKey::from_bytes(&[72; 32]),
    ];
    let policy = CheckpointPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "cli-admission-policy".into(),
        checkpoint_domain: "bloch-products-cli-test".into(),
        state_identity: identity.into(),
        threshold: 2,
        effective_at_unix_seconds: now - 100,
        expires_at_unix_seconds: now + 1_000,
        max_checkpoint_age_seconds: 200,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| CheckpointAuthority {
                authority_id: format!("authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let policy_pin = checkpoint_policy_sha256(&policy).unwrap();
    let created_at = now - 50;
    let message =
        checkpoint_signature_message(&root, &policy, &policy_pin, &semantic_pin, created_at)
            .unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| DetachedCheckpointSignature {
            authority_id: format!("authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let artifact = create_root_checkpoint(
        &root,
        &policy,
        &policy_pin,
        &semantic_pin,
        created_at,
        &signatures,
    )
    .unwrap();
    let verified = authenticate_root_checkpoint(&artifact, &policy, &policy_pin, now).unwrap();
    let cursor = admit_checkpoint(&cursor_store, &verified, None).unwrap();

    let remote_keys = [
        SigningKey::from_bytes(&[73; 32]),
        SigningKey::from_bytes(&[74; 32]),
    ];
    let remote_policy = RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "cli-remote-policy".into(),
        signature_domain: "bloch-products-cli-remote".into(),
        state_identity: identity.into(),
        threshold: 2,
        effective_at_unix_seconds: now - 100,
        expires_at_unix_seconds: now + 1_000,
        max_observation_age_seconds: 100,
        authorities: remote_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorAuthority {
                authority_id: format!("remote-authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
    let nonce = "cli-request-nonce-0123456789abcdef0123456789abcdef";
    let remote_message =
        remote_cursor_signature_message(&cursor, &remote_policy, &remote_pin, nonce, now).unwrap();
    let remote_signatures = remote_keys
        .iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorSignature {
            authority_id: format!("remote-authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&remote_message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let remote_observation = create_remote_cursor_observation(
        &cursor,
        &remote_policy,
        &remote_pin,
        nonce,
        now,
        &remote_signatures,
    )
    .unwrap();

    let artifact_path = temp.0.join("checkpoint.json");
    let policy_path = temp.0.join("policy.json");
    let semantic_path = temp.0.join("semantic.json");
    let remote_observation_path = temp.0.join("remote-observation.json");
    let remote_policy_path = temp.0.join("remote-policy.json");
    let remote_pin_path = temp.0.join("remote-policy-pin");
    let nonce_path = temp.0.join("request-nonce");
    let identity_path = temp.0.join("expected-state-identity");
    write_private(&artifact_path, &artifact);
    write_private(&policy_path, &checkpoint_policy_bytes(&policy).unwrap());
    write_private(&semantic_path, &semantic);
    write_private(&remote_observation_path, &remote_observation);
    write_private(
        &remote_policy_path,
        &remote_cursor_policy_bytes(&remote_policy).unwrap(),
    );
    write_private(&remote_pin_path, remote_pin.as_bytes());
    write_private(&nonce_path, nonce.as_bytes());
    write_private(&identity_path, identity.as_bytes());

    [
        "manual-pay".to_owned(),
        "--artifact".to_owned(),
        artifact_path.to_string_lossy().into_owned(),
        "--checkpoint-policy".to_owned(),
        policy_path.to_string_lossy().into_owned(),
        "--coordination-directory".to_owned(),
        coordination.to_string_lossy().into_owned(),
        "--cursor-store".to_owned(),
        cursor_store.to_string_lossy().into_owned(),
        "--expected-state-identity".to_owned(),
        identity_path.to_string_lossy().into_owned(),
        "--remote-observation".to_owned(),
        remote_observation_path.to_string_lossy().into_owned(),
        "--remote-policy".to_owned(),
        remote_policy_path.to_string_lossy().into_owned(),
        "--remote-policy-pin".to_owned(),
        remote_pin_path.to_string_lossy().into_owned(),
        "--request-nonce".to_owned(),
        nonce_path.to_string_lossy().into_owned(),
        "--semantic-manifest".to_owned(),
        semantic_path.to_string_lossy().into_owned(),
        "--state-store".to_owned(),
        state_store.to_string_lossy().into_owned(),
    ]
    .into()
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn argument_path(arguments: &[String], flag: &str) -> PathBuf {
    let index = arguments.iter().position(|value| value == flag).unwrap();
    PathBuf::from(&arguments[index + 1])
}

fn digest(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
use bloch_local_state_admission::{
    PAY_SEMANTIC_MANIFEST_SCHEMA, PayAdjustmentSemanticManifest, pay_semantic_manifest_bytes,
    pay_semantic_manifest_sha256,
};
