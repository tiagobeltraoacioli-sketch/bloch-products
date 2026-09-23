#![cfg(unix)]

use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    VerifiedRemoteCursor, create_remote_cursor_observation, remote_cursor_policy_sha256,
    remote_cursor_signature_message, verify_remote_cursor_observation,
};
use bloch_local_state_remote_cursor_quorum_report_store::{
    QUORUM_REPORT_STORE_POLICY_SCHEMA, QuorumReportStoreError, QuorumReportStorePolicy,
    StoreOutcome, persist_verified_quorum_report, provision_quorum_report_store,
    read_quorum_report_summary, store_policy_sha256,
};
use bloch_local_state_remote_cursor_replica_quorum::{
    REPLICA_QUORUM_POLICY_SCHEMA, ReplicaDescriptor, ReplicaEvidence, ReplicaQuorumPolicy,
    VerifiedReplicaQuorum, replica_quorum_policy_sha256, verify_replica_quorum,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    create_trusted_time_token, trusted_time_policy_sha256, trusted_time_signature_message,
    verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Barrier};

struct Fixture {
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
    quorum_policy: ReplicaQuorumPolicy,
    quorum_pin: String,
    store_policy: QuorumReportStorePolicy,
    store_pin: String,
}

fn digest(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(32))
}

fn cursor(generation: u64, marker: u8) -> CheckpointCursor {
    parse_cursor(format!("{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"data:tenant-a:lifecycle\",\"generation\":{generation},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}", digest(marker), digest(20), digest(21), digest(marker + 1), digest(marker + 2)).as_bytes()).unwrap()
}

fn fixture() -> Fixture {
    let remote_keys = vec![
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    ];
    let remote_policy = RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "remote-prod".into(),
        signature_domain: "remote-prod-domain".into(),
        state_identity: "data:tenant-a:lifecycle".into(),
        threshold: 1,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        max_observation_age_seconds: 100,
        authorities: remote_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorAuthority {
                authority_id: format!("replica-{}-signer", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
    let time_keys = vec![
        SigningKey::from_bytes(&[71; 32]),
        SigningKey::from_bytes(&[72; 32]),
    ];
    let time_policy = TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: "quorum-time".into(),
        signature_domain: "quorum-time-domain".into(),
        state_identity: remote_policy.state_identity.clone(),
        remote_cursor_policy_sha256: remote_pin.clone(),
        threshold: 2,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        max_token_lifetime_seconds: 60,
        authorities: time_keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeAuthority {
                authority_id: format!("time-authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
    let quorum_policy = ReplicaQuorumPolicy {
        schema: REPLICA_QUORUM_POLICY_SCHEMA.into(),
        policy_id: "quorum-prod".into(),
        state_identity: remote_policy.state_identity.clone(),
        remote_cursor_policy_sha256: remote_pin.clone(),
        trusted_time_policy_sha256: time_pin.clone(),
        quorum: 2,
        max_observation_age_seconds: 60,
        max_observation_skew_seconds: 20,
        replicas: (1..=2)
            .map(|index| ReplicaDescriptor {
                replica_id: format!("replica-{index}"),
                provenance_id: format!("domain-{index}"),
                signer_authority_ids: vec![format!("replica-{index}-signer")],
            })
            .collect(),
    };
    let quorum_pin = replica_quorum_policy_sha256(&quorum_policy).unwrap();
    let store_policy = QuorumReportStorePolicy {
        schema: QUORUM_REPORT_STORE_POLICY_SCHEMA.into(),
        policy_id: "report-store-prod".into(),
        state_identity: remote_policy.state_identity.clone(),
        replica_quorum_policy_sha256: quorum_pin.clone(),
        remote_cursor_policy_sha256: remote_pin.clone(),
        trusted_time_policy_sha256: time_pin.clone(),
    };
    let store_pin = store_policy_sha256(&store_policy).unwrap();
    Fixture {
        remote_policy,
        remote_pin,
        remote_keys,
        time_policy,
        time_pin,
        time_keys,
        quorum_policy,
        quorum_pin,
        store_policy,
        store_pin,
    }
}

fn observation(
    f: &Fixture,
    replica: usize,
    cursor: &CheckpointCursor,
    at: u64,
) -> VerifiedRemoteCursor {
    let nonce = format!("replica_{replica}_nonce_0123456789abcdef0123456789abcdef");
    let message =
        remote_cursor_signature_message(cursor, &f.remote_policy, &f.remote_pin, &nonce, at)
            .unwrap();
    let signature = RemoteCursorSignature {
        authority_id: format!("replica-{}-signer", replica + 1),
        signature: format!(
            "0x{}",
            hex::encode(f.remote_keys[replica].sign(&message).to_bytes())
        ),
    };
    let bytes = create_remote_cursor_observation(
        cursor,
        &f.remote_policy,
        &f.remote_pin,
        &nonce,
        at,
        &[signature],
    )
    .unwrap();
    verify_remote_cursor_observation(&bytes, &f.remote_policy, &f.remote_pin, &nonce, at + 1)
        .unwrap()
}

fn report(
    f: &Fixture,
    cursor: &CheckpointCursor,
    observed: u64,
    now: u64,
) -> VerifiedReplicaQuorum {
    let observations = [
        observation(f, 0, cursor, observed),
        observation(f, 1, cursor, observed),
    ];
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &observations[0],
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &observations[1],
        },
    ];
    let nonce = "quorum_time_nonce_0123456789abcdef0123456789abcdef";
    let message =
        trusted_time_signature_message(&f.time_policy, &f.time_pin, nonce, now, now + 30).unwrap();
    let signatures = f
        .time_keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let token = create_trusted_time_token(
        &f.time_policy,
        &f.time_pin,
        nonce,
        now,
        now + 30,
        &signatures,
    )
    .unwrap();
    let trusted_time =
        verify_trusted_time_token(&token, &f.time_policy, &f.time_pin, nonce, None).unwrap();
    verify_replica_quorum(
        &evidence,
        &f.quorum_policy,
        &f.quorum_pin,
        None,
        &trusted_time,
    )
    .unwrap()
}

fn temporary(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bloch-quorum-report-store-{name}-{}-{}",
        std::process::id(),
        rand_suffix()
    ))
}
fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[test]
fn create_replay_advance_and_reject_rollback_or_equivocation() {
    let f = fixture();
    let root = temporary("monotonic");
    provision_quorum_report_store(&root, &f.store_policy, &f.store_pin).unwrap();
    let seven = report(&f, &cursor(7, 9), 200, 210);
    assert_eq!(
        persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &seven).unwrap(),
        StoreOutcome::Created
    );
    assert_eq!(
        persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &seven).unwrap(),
        StoreOutcome::ExactReplay
    );
    let conflicting = report(&f, &cursor(7, 10), 201, 211);
    assert!(matches!(
        persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &conflicting),
        Err(QuorumReportStoreError::Equivocation)
    ));
    let eight = report(&f, &cursor(8, 11), 202, 212);
    assert_eq!(
        persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &eight).unwrap(),
        StoreOutcome::Advanced
    );
    assert!(matches!(
        persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &seven),
        Err(QuorumReportStoreError::Rollback)
    ));
    let summary = read_quorum_report_summary(&root, &f.store_policy, &f.store_pin)
        .unwrap()
        .unwrap();
    assert_eq!(summary.generation, 8);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_cross_audience_and_policy_pin() {
    let f = fixture();
    let root = temporary("audience");
    provision_quorum_report_store(&root, &f.store_policy, &f.store_pin).unwrap();
    let report = report(&f, &cursor(7, 9), 200, 210);
    let mut wrong = f.store_policy.clone();
    wrong.remote_cursor_policy_sha256 = digest(99);
    let wrong_pin = store_policy_sha256(&wrong).unwrap();
    assert!(matches!(
        persist_verified_quorum_report(&root, &wrong, &wrong_pin, &report),
        Err(QuorumReportStoreError::AudienceMismatch)
    ));
    assert!(matches!(
        persist_verified_quorum_report(&root, &f.store_policy, &digest(1), &report),
        Err(QuorumReportStoreError::PolicyPinMismatch)
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn removes_crash_temporary_and_serializes_concurrent_exact_replays() {
    let f = fixture();
    let root = temporary("concurrent");
    provision_quorum_report_store(&root, &f.store_policy, &f.store_pin).unwrap();
    let report = report(&f, &cursor(7, 9), 200, 210);
    persist_verified_quorum_report(&root, &f.store_policy, &f.store_pin, &report).unwrap();
    let stale = root.join(".state.json.tmp-0123456789abcdef0123456789abcdef");
    std::fs::write(&stale, b"incomplete").unwrap();
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600)).unwrap();
    let barrier = Arc::new(Barrier::new(5));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let root = root.clone();
        let policy = f.store_policy.clone();
        let pin = f.store_pin.clone();
        let report = report.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            persist_verified_quorum_report(&root, &policy, &pin, &report)
        }));
    }
    barrier.wait();
    for thread in threads {
        assert_eq!(thread.join().unwrap().unwrap(), StoreOutcome::ExactReplay);
    }
    assert!(!stale.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_symlink_hardlink_and_unsafe_modes() {
    let f = fixture();
    let real = temporary("unsafe-real");
    let link = temporary("unsafe-link");
    provision_quorum_report_store(&real, &f.store_policy, &f.store_pin).unwrap();
    symlink(&real, &link).unwrap();
    assert!(matches!(
        read_quorum_report_summary(&link, &f.store_policy, &f.store_pin),
        Err(QuorumReportStoreError::UnsafeStore(_))
    ));
    std::fs::remove_file(&link).unwrap();
    let state = real.join("state.json");
    let hardlink = real.join("state.backup");
    std::fs::hard_link(&state, &hardlink).unwrap();
    assert!(matches!(
        read_quorum_report_summary(&real, &f.store_policy, &f.store_pin),
        Err(QuorumReportStoreError::UnsafeStore(_))
    ));
    std::fs::remove_file(hardlink).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        read_quorum_report_summary(&real, &f.store_policy, &f.store_pin),
        Err(QuorumReportStoreError::UnsafeStore(_))
    ));
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(real).unwrap();
}

#[test]
fn fails_closed_when_the_bounded_lock_is_contended() {
    let f = fixture();
    let root = temporary("busy");
    provision_quorum_report_store(&root, &f.store_policy, &f.store_pin).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("store.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let started = std::time::Instant::now();
    assert!(matches!(
        read_quorum_report_summary(&root, &f.store_policy, &f.store_pin),
        Err(QuorumReportStoreError::StoreBusy)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    std::fs::remove_dir_all(root).unwrap();
}
