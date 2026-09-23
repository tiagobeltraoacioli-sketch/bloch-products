#![cfg(unix)]

use bloch_trusted_time::{TrustedTimeBoundary, parse_trusted_time_boundary};
use bloch_trusted_time_boundary_store::{
    BoundaryStoreError, TrustedTimeBoundaryAudience, advance_trusted_time_boundary,
    load_trusted_time_boundary, provision_trusted_time_boundary_store,
};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const REMOTE_POLICY: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const IDENTITY: &str = "data:tenant-a:lifecycle";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-time-boundary-{label}-{}-{nonce}-{}",
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

fn audience() -> TrustedTimeBoundaryAudience<'static> {
    TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: POLICY,
        state_identity: IDENTITY,
        remote_cursor_policy_sha256: REMOTE_POLICY,
    }
}

fn boundary(seconds: u64) -> TrustedTimeBoundary {
    let bytes = format!(
        "{{\"schema\":\"bloch.products.trusted-time-boundary.v1\",\"trustedTimePolicySha256\":\"{POLICY}\",\"notBeforeUnixSeconds\":{seconds}}}"
    );
    parse_trusted_time_boundary(bytes.as_bytes(), POLICY).unwrap()
}

#[test]
fn explicit_provision_update_replay_and_rollback_are_fail_closed() {
    let store = Temp::new("lifecycle");
    assert!(matches!(
        load_trusted_time_boundary(&store.0, audience()),
        Err(BoundaryStoreError::StateMissing)
    ));
    provision_trusted_time_boundary_store(&store.0, audience(), &boundary(10)).unwrap();
    assert!(matches!(
        provision_trusted_time_boundary_store(&store.0, audience(), &boundary(10)),
        Err(BoundaryStoreError::AlreadyProvisioned)
    ));
    assert_eq!(
        load_trusted_time_boundary(&store.0, audience())
            .unwrap()
            .not_before_unix_seconds(),
        10
    );

    let advanced = advance_trusted_time_boundary(&store.0, audience(), &boundary(20)).unwrap();
    assert_eq!(advanced.not_before_unix_seconds(), 20);
    let before_replay = fs::read(store.0.join("state.json")).unwrap();
    let replayed = advance_trusted_time_boundary(&store.0, audience(), &boundary(20)).unwrap();
    assert_eq!(replayed.not_before_unix_seconds(), 20);
    assert_eq!(fs::read(store.0.join("state.json")).unwrap(), before_replay);
    assert!(matches!(
        advance_trusted_time_boundary(&store.0, audience(), &boundary(19)),
        Err(BoundaryStoreError::RollbackRefused)
    ));
    assert_eq!(
        load_trusted_time_boundary(&store.0, audience())
            .unwrap()
            .not_before_unix_seconds(),
        20
    );
}

#[test]
fn audience_and_policy_substitution_are_rejected() {
    let store = Temp::new("audience");
    provision_trusted_time_boundary_store(&store.0, audience(), &boundary(10)).unwrap();
    for substituted in [
        TrustedTimeBoundaryAudience {
            state_identity: "pay:tenant-a:lifecycle",
            ..audience()
        },
        TrustedTimeBoundaryAudience {
            remote_cursor_policy_sha256: "0x3333333333333333333333333333333333333333333333333333333333333333",
            ..audience()
        },
        TrustedTimeBoundaryAudience {
            trusted_time_policy_sha256: "0x4444444444444444444444444444444444444444444444444444444444444444",
            ..audience()
        },
    ] {
        assert!(matches!(
            load_trusted_time_boundary(&store.0, substituted),
            Err(BoundaryStoreError::InvalidInput)
        ));
    }
}

#[test]
fn concurrent_updates_leave_the_maximum_boundary() {
    let store = Temp::new("concurrent");
    provision_trusted_time_boundary_store(&store.0, audience(), &boundary(10)).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for seconds in [20, 30] {
        let path = store.0.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            advance_trusted_time_boundary(&path, audience(), &boundary(seconds))
        }));
    }
    barrier.wait();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert!(outcomes.iter().any(|outcome| {
        outcome
            .as_ref()
            .is_ok_and(|value| value.not_before_unix_seconds() == 30)
    }));
    assert!(outcomes.iter().all(|outcome| {
        outcome.is_ok() || matches!(outcome, Err(BoundaryStoreError::RollbackRefused))
    }));
    assert_eq!(
        load_trusted_time_boundary(&store.0, audience())
            .unwrap()
            .not_before_unix_seconds(),
        30
    );
}

#[test]
fn state_and_lock_links_are_rejected() {
    let state_store = Temp::new("state-hardlink");
    provision_trusted_time_boundary_store(&state_store.0, audience(), &boundary(10)).unwrap();
    fs::hard_link(
        state_store.0.join("state.json"),
        state_store.0.join("state-copy.json"),
    )
    .unwrap();
    assert!(matches!(
        load_trusted_time_boundary(&state_store.0, audience()),
        Err(BoundaryStoreError::UnsafeStore(_))
    ));

    let lock_store = Temp::new("lock-hardlink");
    provision_trusted_time_boundary_store(&lock_store.0, audience(), &boundary(10)).unwrap();
    fs::hard_link(
        lock_store.0.join("store.lock"),
        lock_store.0.join("lock-copy"),
    )
    .unwrap();
    assert!(matches!(
        load_trusted_time_boundary(&lock_store.0, audience()),
        Err(BoundaryStoreError::UnsafeStore(_))
    ));

    let target = Temp::new("symlink-target");
    provision_trusted_time_boundary_store(&target.0, audience(), &boundary(10)).unwrap();
    let alias = Temp::new("symlink-alias");
    std::os::unix::fs::symlink(&target.0, &alias.0).unwrap();
    assert!(matches!(
        load_trusted_time_boundary(&alias.0, audience()),
        Err(BoundaryStoreError::UnsafeStore(_))
    ));
}

#[test]
fn deleted_state_or_lock_is_not_recreated() {
    let state_store = Temp::new("missing-state");
    provision_trusted_time_boundary_store(&state_store.0, audience(), &boundary(10)).unwrap();
    fs::remove_file(state_store.0.join("state.json")).unwrap();
    assert!(matches!(
        advance_trusted_time_boundary(&state_store.0, audience(), &boundary(20)),
        Err(BoundaryStoreError::StateMissing)
    ));
    assert!(!state_store.0.join("state.json").exists());

    let lock_store = Temp::new("missing-lock");
    provision_trusted_time_boundary_store(&lock_store.0, audience(), &boundary(10)).unwrap();
    fs::remove_file(lock_store.0.join("store.lock")).unwrap();
    assert!(matches!(
        load_trusted_time_boundary(&lock_store.0, audience()),
        Err(BoundaryStoreError::StateMissing)
    ));
    assert!(!lock_store.0.join("store.lock").exists());
}

#[test]
fn live_lock_wait_is_bounded() {
    let store = Temp::new("busy");
    provision_trusted_time_boundary_store(&store.0, audience(), &boundary(10)).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(store.0.join("store.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(matches!(
        advance_trusted_time_boundary(&store.0, audience(), &boundary(20)),
        Err(BoundaryStoreError::StoreBusy)
    ));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}
