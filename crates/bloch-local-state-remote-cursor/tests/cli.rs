#![cfg(unix)]

use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    create_remote_cursor_observation, remote_cursor_policy_bytes, remote_cursor_policy_sha256,
    remote_cursor_signature_message,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bloch-remote-cursor-cli-{}-{nonce}-{}",
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
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn generates_nonce_and_verifies_response_without_stdout() {
    let directory = Temp::new();
    let nonce_path = directory.0.join("nonce.txt");
    let output = command()
        .args(["nonce", "--out", nonce_path.to_str().unwrap()])
        .output()
        .unwrap();
    success_without_stdout(&output);
    let nonce = fs::read_to_string(&nonce_path).unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(mode(&nonce_path), 0o600);

    let cursor = cursor();
    let (policy, keys, pin) = policy();
    let observed_at = now();
    let policy_path = directory.0.join("policy.json");
    write_private(&policy_path, &remote_cursor_policy_bytes(&policy).unwrap());
    let message =
        remote_cursor_signature_message(&cursor, &policy, &pin, &nonce, observed_at).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorSignature {
            authority_id: format!("authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let observation =
        create_remote_cursor_observation(&cursor, &policy, &pin, &nonce, observed_at, &signatures)
            .unwrap();
    let observation_path = directory.0.join("observation.json");
    write_private(&observation_path, &observation);
    let cursor_path = directory.0.join("cursor.json");
    let output = command()
        .args([
            "verify",
            "--observation",
            observation_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--policy-sha256",
            &pin,
            "--nonce",
            nonce_path.to_str().unwrap(),
            "--cursor-out",
            cursor_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success_without_stdout(&output);
    assert_eq!(
        parse_cursor(&fs::read(&cursor_path).unwrap()).unwrap(),
        cursor
    );
    assert_eq!(mode(&cursor_path), 0o600);

    let stale_at = now().saturating_sub(101);
    let message =
        remote_cursor_signature_message(&cursor, &policy, &pin, &nonce, stale_at).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorSignature {
            authority_id: format!("authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let stale =
        create_remote_cursor_observation(&cursor, &policy, &pin, &nonce, stale_at, &signatures)
            .unwrap();
    let stale_path = directory.0.join("stale.json");
    write_private(&stale_path, &stale);
    let stale_output = directory.0.join("stale-cursor.json");
    let output = command()
        .args([
            "verify",
            "--observation",
            stale_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--policy-sha256",
            &pin,
            "--nonce",
            nonce_path.to_str().unwrap(),
            "--cursor-out",
            stale_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!stale_output.exists());
}

#[test]
fn refuses_overwrite_symlink_and_permissive_input() {
    let directory = Temp::new();
    let existing = directory.0.join("existing.txt");
    write_private(&existing, b"do-not-overwrite");
    let output = command()
        .args(["nonce", "--out", existing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&existing).unwrap(), b"do-not-overwrite");

    let link = directory.0.join("nonce-link.txt");
    symlink(&existing, &link).unwrap();
    let cursor_output = directory.0.join("cursor.json");
    let output = command()
        .args([
            "verify",
            "--observation",
            existing.to_str().unwrap(),
            "--policy",
            link.to_str().unwrap(),
            "--policy-sha256",
            &format!("0x{}", "00".repeat(32)),
            "--nonce",
            existing.to_str().unwrap(),
            "--cursor-out",
            cursor_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    fs::set_permissions(&existing, fs::Permissions::from_mode(0o644)).unwrap();
    let cursor_output = directory.0.join("cursor-2.json");
    let output = command()
        .args([
            "verify",
            "--observation",
            existing.to_str().unwrap(),
            "--policy",
            existing.to_str().unwrap(),
            "--policy-sha256",
            &format!("0x{}", "00".repeat(32)),
            "--nonce",
            existing.to_str().unwrap(),
            "--cursor-out",
            cursor_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

fn cursor() -> CheckpointCursor {
    let h = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"data:tenant-a:lifecycle\",\"generation\":7,\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        h(1),
        h(2),
        h(3),
        h(4),
        h(5)
    );
    parse_cursor(bytes.as_bytes()).unwrap()
}

fn policy() -> (RemoteCursorPolicy, Vec<SigningKey>, String) {
    let now = now();
    let keys = vec![
        SigningKey::from_bytes(&[61; 32]),
        SigningKey::from_bytes(&[62; 32]),
    ];
    let policy = RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "cli-policy".into(),
        signature_domain: "bloch-control-plane-test".into(),
        state_identity: "data:tenant-a:lifecycle".into(),
        threshold: 2,
        effective_at_unix_seconds: now.saturating_sub(300),
        expires_at_unix_seconds: now + 300,
        max_observation_age_seconds: 100,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorAuthority {
                authority_id: format!("authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let pin = remote_cursor_policy_sha256(&policy).unwrap();
    (policy, keys, pin)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bloch-local-state-remote-cursor"))
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

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn success_without_stdout(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}
