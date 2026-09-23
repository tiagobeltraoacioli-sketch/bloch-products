#![cfg(unix)]

use bloch_local_state_remote_cursor_challenge_store::{
    ChallengeAudience, ChallengeStoreError, consume_challenge, invalidate_outstanding_challenges,
    issue_challenge, provision_challenge_store,
};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CALLER: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const REMOTE: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
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
            "bloch-cas-challenge-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
    }
}

fn audience() -> ChallengeAudience<'static> {
    ChallengeAudience {
        caller_policy_sha256: CALLER,
        remote_cursor_policy_sha256: REMOTE,
        state_identity: IDENTITY,
    }
}

#[test]
fn exact_nonce_is_consumed_once_and_returns_bound_capability() {
    let store = Temp::new("lifecycle");
    provision_challenge_store(&store.0).unwrap();
    assert!(matches!(
        provision_challenge_store(&store.0),
        Err(ChallengeStoreError::AlreadyProvisioned)
    ));
    let issued = issue_challenge(&store.0, audience(), Duration::from_secs(30)).unwrap();
    let nonce = issued.nonce().to_owned();
    let consumed = consume_challenge(&store.0, audience(), issued, &nonce).unwrap();
    assert_eq!(consumed.nonce(), nonce);
    assert_eq!(consumed.caller_policy_sha256(), CALLER);
    assert_eq!(consumed.remote_cursor_policy_sha256(), REMOTE);
    assert_eq!(consumed.state_identity(), IDENTITY);
    assert!(consumed.consumption_sha256().starts_with("0x"));
    consumed.ensure_monotonic_freshness().unwrap();
    let replacement = issue_challenge(&store.0, audience(), Duration::from_secs(30)).unwrap();
    assert!(matches!(
        consume_challenge(&store.0, audience(), replacement, &nonce),
        Err(ChallengeStoreError::ChallengeMismatch)
    ));
    assert_eq!(invalidate_outstanding_challenges(&store.0).unwrap(), 1);
}

#[test]
fn wrong_nonce_or_audience_cannot_mutate_state() {
    let store = Temp::new("audience");
    provision_challenge_store(&store.0).unwrap();
    let wrong_nonce_lease = issue_challenge(&store.0, audience(), Duration::from_secs(30)).unwrap();
    let wrong_audience_lease =
        issue_challenge(&store.0, audience(), Duration::from_secs(30)).unwrap();
    let before = fs::read(store.0.join("state.json")).unwrap();
    assert!(matches!(
        consume_challenge(
            &store.0,
            audience(),
            wrong_nonce_lease,
            &format!("0x{}", "3".repeat(64))
        ),
        Err(ChallengeStoreError::ChallengeMismatch)
    ));
    let wrong = ChallengeAudience {
        state_identity: "pay:tenant-a:lifecycle",
        ..audience()
    };
    let nonce = wrong_audience_lease.nonce().to_owned();
    assert!(matches!(
        consume_challenge(&store.0, wrong, wrong_audience_lease, &nonce),
        Err(ChallengeStoreError::ChallengeMismatch)
    ));
    assert_eq!(fs::read(store.0.join("state.json")).unwrap(), before);
    assert_eq!(invalidate_outstanding_challenges(&store.0).unwrap(), 2);
}

#[test]
fn expiry_uses_monotonic_deadline_and_does_not_consume() {
    let store = Temp::new("expiry");
    provision_challenge_store(&store.0).unwrap();
    let issued = issue_challenge(&store.0, audience(), Duration::from_secs(1)).unwrap();
    thread::sleep(Duration::from_millis(1_100));
    let before = fs::read(store.0.join("state.json")).unwrap();
    let nonce = issued.nonce().to_owned();
    assert!(matches!(
        consume_challenge(&store.0, audience(), issued, &nonce),
        Err(ChallengeStoreError::Expired)
    ));
    assert_eq!(fs::read(store.0.join("state.json")).unwrap(), before);
    assert_eq!(invalidate_outstanding_challenges(&store.0).unwrap(), 1);
}

#[test]
fn concurrent_distinct_consumers_are_serialized_without_loss() {
    let store = Temp::new("concurrent");
    provision_challenge_store(&store.0).unwrap();
    let leases = (0..2)
        .map(|_| issue_challenge(&store.0, audience(), Duration::from_secs(30)).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for issued in leases {
        let path = store.0.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            let nonce = issued.nonce().to_owned();
            barrier.wait();
            consume_challenge(&path, audience(), issued, &nonce)
        }));
    }
    barrier.wait();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
}

#[test]
fn symlink_and_hardlinked_store_objects_are_rejected() {
    let target = Temp::new("target");
    provision_challenge_store(&target.0).unwrap();
    let alias = Temp::new("alias");
    std::os::unix::fs::symlink(&target.0, &alias.0).unwrap();
    assert!(matches!(
        issue_challenge(&alias.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::UnsafeStore(_))
    ));

    let state_store = Temp::new("state-hardlink");
    provision_challenge_store(&state_store.0).unwrap();
    fs::hard_link(
        state_store.0.join("state.json"),
        state_store.0.join("state-copy.json"),
    )
    .unwrap();
    assert!(matches!(
        issue_challenge(&state_store.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::UnsafeStore(_))
    ));

    let lock_store = Temp::new("lock-hardlink");
    provision_challenge_store(&lock_store.0).unwrap();
    fs::hard_link(
        lock_store.0.join("store.lock"),
        lock_store.0.join("lock-copy"),
    )
    .unwrap();
    assert!(matches!(
        issue_challenge(&lock_store.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::UnsafeStore(_))
    ));
}

#[test]
fn missing_store_state_or_lock_is_never_created_implicitly() {
    let missing = Temp::new("missing");
    assert!(matches!(
        issue_challenge(&missing.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::StateMissing)
    ));

    let state_store = Temp::new("missing-state");
    provision_challenge_store(&state_store.0).unwrap();
    fs::remove_file(state_store.0.join("state.json")).unwrap();
    assert!(matches!(
        issue_challenge(&state_store.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::StateMissing)
    ));
    assert!(!state_store.0.join("state.json").exists());

    let lock_store = Temp::new("missing-lock");
    provision_challenge_store(&lock_store.0).unwrap();
    fs::remove_file(lock_store.0.join("store.lock")).unwrap();
    assert!(matches!(
        issue_challenge(&lock_store.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::StateMissing)
    ));
    assert!(!lock_store.0.join("store.lock").exists());
}

#[test]
fn live_lock_wait_is_bounded() {
    let store = Temp::new("busy");
    provision_challenge_store(&store.0).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(store.0.join("store.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(matches!(
        issue_challenge(&store.0, audience(), Duration::from_secs(30)),
        Err(ChallengeStoreError::StoreBusy)
    ));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}
