#![cfg(unix)]

use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasDecision,
    RemoteCursorCasRequestParameters, RemoteCursorPolicy, ValidatedRemoteCursorCasRequest,
    create_remote_cursor_cas_request, parse_remote_cursor_cas_request, remote_cursor_policy_sha256,
};
use bloch_local_state_remote_cursor_control_plane::{
    ControlPlaneError, apply_request, load_current_cursor, provision_control_plane_store,
};
use bloch_local_state_store::{StateRoot, write_state};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const NONCE: &str = "control_plane_nonce_0123456789abcdef0123456789abcdef";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-control-plane-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Chain {
    _store: Temp,
    root0: StateRoot,
    root1: StateRoot,
    cursor0: CheckpointCursor,
    cursor1: CheckpointCursor,
}

impl Chain {
    fn new(next: &[u8], marker: u8) -> Self {
        let store = Temp::new("source-state");
        let root0 = write_state(&store.0, IDENTITY, 0, b"zero", None).unwrap();
        let root1 = write_state(&store.0, IDENTITY, 1, next, Some(&root0)).unwrap();
        let cursor0 = cursor(&root0, 10);
        let cursor1 = cursor(&root1, marker);
        Self {
            _store: store,
            root0,
            root1,
            cursor0,
            cursor1,
        }
    }
}

#[test]
fn create_once_cas_and_replay_are_durable_and_idempotent() {
    let control = Temp::new("idempotent");
    let chain = Chain::new(b"one", 20);
    let (policy, pin) = policy();
    let unprovisioned = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "unprovisioned",
        &policy,
        &pin,
    );
    assert!(matches!(
        apply_request(&control.0, IDENTITY, &unprovisioned),
        Err(ControlPlaneError::StateMissing)
    ));
    provision(&control.0, &policy, &pin);
    assert!(matches!(
        provision_control_plane_store(&control.0, IDENTITY, &pin, &policy.signature_domain),
        Err(ControlPlaneError::AlreadyProvisioned)
    ));
    let mut wrong_policy = policy.clone();
    wrong_policy.signature_domain = "different-control-plane-domain".into();
    let wrong_pin = remote_cursor_policy_sha256(&wrong_policy).unwrap();
    let wrong_policy_request = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "wrong-policy",
        &wrong_policy,
        &wrong_pin,
    );
    assert!(matches!(
        apply_request(&control.0, IDENTITY, &wrong_policy_request),
        Err(ControlPlaneError::InvalidInput)
    ));
    let bootstrap = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "bootstrap-1",
        &policy,
        &pin,
    );
    let accepted = apply_request(&control.0, IDENTITY, &bootstrap).unwrap();
    assert_eq!(accepted.decision(), &RemoteCursorCasDecision::Accepted);
    assert_eq!(accepted.resulting_cursor(), Some(&chain.cursor0));
    assert!(!accepted.signed_receipt_created());
    let before = fs::read(control.0.join("state.json")).unwrap();
    assert_eq!(
        apply_request(&control.0, IDENTITY, &bootstrap).unwrap(),
        accepted
    );
    assert_eq!(fs::read(control.0.join("state.json")).unwrap(), before);

    let advance = request(
        Some(&chain.cursor0),
        &chain.cursor1,
        &chain.root1,
        "advance-1",
        &policy,
        &pin,
    );
    let accepted = apply_request(&control.0, IDENTITY, &advance).unwrap();
    assert_eq!(accepted.decision(), &RemoteCursorCasDecision::Accepted);
    assert_eq!(
        load_current_cursor(&control.0, IDENTITY, &pin, &policy.signature_domain).unwrap(),
        Some(chain.cursor1)
    );
    fs::remove_file(control.0.join("state.json")).unwrap();
    assert!(matches!(
        apply_request(&control.0, IDENTITY, &advance),
        Err(ControlPlaneError::StateMissing)
    ));
    assert!(!control.0.join("state.json").exists());
}

#[test]
fn conflict_is_persisted_and_request_id_substitution_fails() {
    let control = Temp::new("conflict");
    let chain = Chain::new(b"one", 20);
    let fork = Chain::new(b"fork", 30);
    let (policy, pin) = policy();
    provision(&control.0, &policy, &pin);
    let bootstrap = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "bootstrap",
        &policy,
        &pin,
    );
    apply_request(&control.0, IDENTITY, &bootstrap).unwrap();
    let advance = request(
        Some(&chain.cursor0),
        &chain.cursor1,
        &chain.root1,
        "advance",
        &policy,
        &pin,
    );
    apply_request(&control.0, IDENTITY, &advance).unwrap();
    let stale = request(
        Some(&chain.cursor0),
        &fork.cursor1,
        &fork.root1,
        "stale-request",
        &policy,
        &pin,
    );
    let refused = apply_request(&control.0, IDENTITY, &stale).unwrap();
    assert_eq!(
        refused.decision(),
        &RemoteCursorCasDecision::Refused {
            reason_code: "compare_and_swap_conflict".into()
        }
    );
    assert!(refused.resulting_cursor().is_none());
    assert_eq!(
        apply_request(&control.0, IDENTITY, &stale).unwrap(),
        refused
    );

    let substituted = request(
        Some(&chain.cursor0),
        &chain.cursor1,
        &chain.root1,
        "stale-request",
        &policy,
        &pin,
    );
    assert!(matches!(
        apply_request(&control.0, IDENTITY, &substituted),
        Err(ControlPlaneError::RequestIdConflict)
    ));
}

#[test]
fn concurrent_competing_cas_has_one_acceptance_and_one_refusal() {
    let control = Temp::new("concurrent");
    let chain = Chain::new(b"one", 20);
    let fork = Chain::new(b"fork", 30);
    let (policy, pin) = policy();
    provision(&control.0, &policy, &pin);
    let bootstrap = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "bootstrap",
        &policy,
        &pin,
    );
    apply_request(&control.0, IDENTITY, &bootstrap).unwrap();
    let left = request(
        Some(&chain.cursor0),
        &chain.cursor1,
        &chain.root1,
        "left",
        &policy,
        &pin,
    );
    let right = request(
        Some(&fork.cursor0),
        &fork.cursor1,
        &fork.root1,
        "right",
        &policy,
        &pin,
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for request in [left, right] {
        let barrier = barrier.clone();
        let store = control.0.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            apply_request(&store, IDENTITY, &request).unwrap()
        }));
    }
    barrier.wait();
    let decisions = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| decision.decision() == &RemoteCursorCasDecision::Accepted)
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(
                decision.decision(),
                RemoteCursorCasDecision::Refused { .. }
            ))
            .count(),
        1
    );
}

#[test]
fn stale_crash_temp_is_cleaned_and_unsafe_state_fails_closed() {
    let control = Temp::new("crash");
    let chain = Chain::new(b"one", 20);
    let (policy, pin) = policy();
    provision(&control.0, &policy, &pin);
    let bootstrap = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "bootstrap",
        &policy,
        &pin,
    );
    apply_request(&control.0, IDENTITY, &bootstrap).unwrap();
    let stale = control
        .0
        .join(".state.json.tmp-0123456789abcdef0123456789abcdef");
    fs::write(&stale, b"interrupted-write").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        apply_request(&control.0, IDENTITY, &bootstrap)
            .unwrap()
            .decision(),
        &RemoteCursorCasDecision::Accepted
    );
    assert!(!stale.exists());

    let alias = control.0.join("state-alias.json");
    fs::hard_link(control.0.join("state.json"), &alias).unwrap();
    assert!(matches!(
        load_current_cursor(&control.0, IDENTITY, &pin, &policy.signature_domain),
        Err(ControlPlaneError::UnsafeStore(_))
    ));
}

#[test]
fn live_writer_lock_is_bounded_and_fails_closed() {
    let control = Temp::new("busy");
    let chain = Chain::new(b"one", 20);
    let (policy, pin) = policy();
    provision(&control.0, &policy, &pin);
    let bootstrap = request(
        None,
        &chain.cursor0,
        &chain.root0,
        "bootstrap",
        &policy,
        &pin,
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(control.0.join("store.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(matches!(
        apply_request(&control.0, IDENTITY, &bootstrap),
        Err(ControlPlaneError::StoreBusy)
    ));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}

fn request(
    current: Option<&CheckpointCursor>,
    successor: &CheckpointCursor,
    successor_root: &StateRoot,
    request_id: &str,
    policy: &RemoteCursorPolicy,
    pin: &str,
) -> ValidatedRemoteCursorCasRequest {
    let bytes = create_remote_cursor_cas_request(
        RemoteCursorCasRequestParameters {
            expected_current: current,
            successor_cursor: successor,
            successor_root,
            request_id,
            request_nonce: NONCE,
            requested_at_unix_seconds: 200,
        },
        policy,
        pin,
    )
    .unwrap();
    parse_remote_cursor_cas_request(&bytes, policy, pin).unwrap()
}

fn cursor(root: &StateRoot, marker: u8) -> CheckpointCursor {
    let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
    let root_sha = format!(
        "0x{}",
        hex::encode(Sha256::digest(root.canonical_bytes().unwrap()))
    );
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        root.state_identity(),
        root.generation(),
        digest(marker),
        digest(marker + 1),
        digest(marker + 2),
        root_sha,
        root.state_sha256()
    );
    parse_cursor(bytes.as_bytes()).unwrap()
}

fn policy() -> (RemoteCursorPolicy, String) {
    let keys = [
        SigningKey::from_bytes(&[81; 32]),
        SigningKey::from_bytes(&[82; 32]),
    ];
    let policy = RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "control-plane-policy".into(),
        signature_domain: "bloch-control-plane-core".into(),
        state_identity: IDENTITY.into(),
        threshold: 2,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
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
    (policy, pin)
}

fn provision(path: &std::path::Path, policy: &RemoteCursorPolicy, pin: &str) {
    provision_control_plane_store(path, IDENTITY, pin, &policy.signature_domain).unwrap();
}
