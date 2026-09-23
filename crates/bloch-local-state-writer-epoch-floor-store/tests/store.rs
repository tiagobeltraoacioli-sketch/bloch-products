#![cfg(unix)]

use bloch_local_state_writer_epoch_floor_store::{
    WriterEpochFloorAudience, WriterEpochFloorStoreError, advance_writer_epoch_floor,
    load_writer_epoch_floor, provision_writer_epoch_floor_store,
};
use bloch_local_state_writer_fencing::{
    FencingAuthority, FencingSignature, WRITER_FENCING_POLICY_SCHEMA, WriterFencingPolicy,
    WriterLeaseParameters, create_writer_fencing_certificate, verify_successor_writer_lease,
    writer_fencing_policy_sha256, writer_fencing_signature_message,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    create_trusted_time_token, trusted_time_policy_sha256, trusted_time_signature_message,
    verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const REMOTE: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const CAS: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-writer-floor-{label}-{}-{nonce}-{}",
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

struct Fixture {
    keys: Vec<SigningKey>,
    policy: WriterFencingPolicy,
    policy_pin: String,
    time: bloch_trusted_time::VerifiedTrustedTime,
}

impl Fixture {
    fn new() -> Self {
        let keys: Vec<_> = [1_u8, 2, 3]
            .map(|s| SigningKey::from_bytes(&[s; 32]))
            .into();
        let time_keys: Vec<_> = [11_u8, 12, 13]
            .map(|s| SigningKey::from_bytes(&[s; 32]))
            .into();
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "time-policy".into(),
            signature_domain: "bloch:time".into(),
            state_identity: "bloch-data:prod".into(),
            remote_cursor_policy_sha256: REMOTE.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_token_lifetime_seconds: 60,
            authorities: time_keys
                .iter()
                .enumerate()
                .map(|(i, k)| TrustedTimeAuthority {
                    authority_id: format!("time-{}", i + 1),
                    ed25519_public_key: format!("0x{}", hex::encode(k.verifying_key().to_bytes())),
                })
                .collect(),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let message =
            trusted_time_signature_message(&time_policy, &time_pin, NONCE, 200, 230).unwrap();
        let signatures: Vec<_> = time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, k)| TrustedTimeSignature {
                authority_id: format!("time-{}", i + 1),
                signature: format!("0x{}", hex::encode(k.sign(&message).to_bytes())),
            })
            .collect();
        let token =
            create_trusted_time_token(&time_policy, &time_pin, NONCE, 200, 230, &signatures)
                .unwrap();
        let time = verify_trusted_time_token(&token, &time_policy, &time_pin, NONCE, None).unwrap();
        let policy = WriterFencingPolicy {
            schema: WRITER_FENCING_POLICY_SCHEMA.into(),
            policy_id: "fence-policy".into(),
            signature_domain: "bloch:fence".into(),
            state_identity: "bloch-data:prod".into(),
            remote_cursor_policy_sha256: REMOTE.into(),
            cas_service_id: "cas-primary".into(),
            cas_policy_sha256: CAS.into(),
            trusted_time_policy_sha256: time_pin,
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_lease_lifetime_seconds: 60,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(i, k)| FencingAuthority {
                    authority_id: format!("fence-{}", i + 1),
                    ed25519_public_key: format!("0x{}", hex::encode(k.verifying_key().to_bytes())),
                })
                .collect(),
        };
        let policy_pin = writer_fencing_policy_sha256(&policy).unwrap();
        Self {
            keys,
            policy,
            policy_pin,
            time,
        }
    }

    fn lease(
        &self,
        writer: &str,
        epoch: u64,
    ) -> bloch_local_state_writer_fencing::VerifiedWriterLease {
        let parameters = WriterLeaseParameters {
            writer_id: writer,
            epoch,
            effective_at_unix_seconds: 190,
            expires_at_unix_seconds: 220,
        };
        let message =
            writer_fencing_signature_message(&self.policy, &self.policy_pin, parameters).unwrap();
        let signatures = self
            .keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, k)| FencingSignature {
                authority_id: format!("fence-{}", i + 1),
                signature: format!("0x{}", hex::encode(k.sign(&message).to_bytes())),
            })
            .collect();
        let certificate = create_writer_fencing_certificate(
            &self.policy,
            &self.policy_pin,
            parameters,
            signatures,
        )
        .unwrap();
        verify_successor_writer_lease(
            &certificate,
            &self.policy,
            &self.policy_pin,
            epoch - 1,
            &self.time,
        )
        .unwrap()
    }

    fn audience(&self) -> WriterEpochFloorAudience<'_> {
        WriterEpochFloorAudience {
            writer_fencing_policy_sha256: &self.policy_pin,
            state_identity: "bloch-data:prod",
            remote_cursor_policy_sha256: REMOTE,
            cas_service_id: "cas-primary",
            cas_policy_sha256: CAS,
        }
    }
}

#[test]
fn explicit_provision_and_strict_advance_are_fail_closed() {
    let f = Fixture::new();
    let store = Temp::new("lifecycle");
    let first = f.lease("writer-a", 7);
    assert!(matches!(
        load_writer_epoch_floor(&store.0, f.audience()),
        Err(WriterEpochFloorStoreError::StateMissing)
    ));
    let floor = provision_writer_epoch_floor_store(&store.0, f.audience(), &first).unwrap();
    assert_eq!(floor.epoch(), 7);
    assert_eq!(floor.writer_id(), "writer-a");
    assert_eq!(floor.writer_fencing_policy_sha256(), f.policy_pin);
    assert_eq!(floor.state_identity(), "bloch-data:prod");
    assert_eq!(floor.remote_cursor_policy_sha256(), REMOTE);
    assert_eq!(floor.cas_service_id(), "cas-primary");
    assert_eq!(floor.cas_policy_sha256(), CAS);
    assert_eq!(floor.store_id().len(), 66);
    assert_eq!(floor.state_sha256().len(), 66);
    assert_eq!(floor.evidence_sha256().len(), 66);
    let durable_bytes = fs::read(store.0.join("state.json")).unwrap();
    assert_eq!(
        floor.state_sha256(),
        format!("0x{}", hex::encode(Sha256::digest(&durable_bytes)))
    );
    assert!(!floor.worm_proven());
    assert!(!floor.snapshot_rollback_proven());
    assert!(!floor.multi_host_linearizability_proven());
    assert!(!floor.post_load_currentness_proven());
    let loaded = load_writer_epoch_floor(&store.0, f.audience()).unwrap();
    assert_eq!(loaded.store_id(), floor.store_id());
    assert_eq!(loaded.state_sha256(), floor.state_sha256());
    assert_eq!(loaded.evidence_sha256(), floor.evidence_sha256());
    let independent_store = Temp::new("independent");
    let independent =
        provision_writer_epoch_floor_store(&independent_store.0, f.audience(), &first).unwrap();
    assert_ne!(independent.store_id(), floor.store_id());
    assert_ne!(independent.state_sha256(), floor.state_sha256());
    assert_ne!(independent.evidence_sha256(), floor.evidence_sha256());
    assert!(matches!(
        provision_writer_epoch_floor_store(&store.0, f.audience(), &first),
        Err(WriterEpochFloorStoreError::AlreadyProvisioned)
    ));
    assert!(matches!(
        advance_writer_epoch_floor(&store.0, f.audience(), &first),
        Err(WriterEpochFloorStoreError::EpochDidNotAdvance)
    ));
    let next = f.lease("writer-b", 9);
    let advanced = advance_writer_epoch_floor(&store.0, f.audience(), &next).unwrap();
    assert_eq!(advanced.epoch(), 9);
    assert_eq!(advanced.store_id(), floor.store_id());
    assert_ne!(advanced.state_sha256(), floor.state_sha256());
    assert_ne!(advanced.evidence_sha256(), floor.evidence_sha256());
    let lower = f.lease("writer-c", 8);
    assert!(matches!(
        advance_writer_epoch_floor(&store.0, f.audience(), &lower),
        Err(WriterEpochFloorStoreError::EpochDidNotAdvance)
    ));
    assert_eq!(
        load_writer_epoch_floor(&store.0, f.audience())
            .unwrap()
            .epoch(),
        9
    );
}

#[test]
fn audience_substitution_is_rejected() {
    let f = Fixture::new();
    let store = Temp::new("audience");
    let lease = f.lease("writer-a", 7);
    provision_writer_epoch_floor_store(&store.0, f.audience(), &lease).unwrap();
    let wrong = WriterEpochFloorAudience {
        state_identity: "bloch-pay:prod",
        ..f.audience()
    };
    assert!(matches!(
        load_writer_epoch_floor(&store.0, wrong),
        Err(WriterEpochFloorStoreError::InvalidInput)
    ));
    let wrong = WriterEpochFloorAudience {
        cas_policy_sha256: REMOTE,
        ..f.audience()
    };
    assert!(matches!(
        advance_writer_epoch_floor(&store.0, wrong, &f.lease("writer-b", 8)),
        Err(WriterEpochFloorStoreError::InvalidInput)
    ));
}

#[test]
fn symlinks_hardlinks_and_unsafe_permissions_are_rejected() {
    let f = Fixture::new();
    let store = Temp::new("links");
    let lease = f.lease("writer-a", 7);
    provision_writer_epoch_floor_store(&store.0, f.audience(), &lease).unwrap();
    fs::hard_link(store.0.join("state.json"), store.0.join("copy")).unwrap();
    assert!(matches!(
        load_writer_epoch_floor(&store.0, f.audience()),
        Err(WriterEpochFloorStoreError::UnsafeStore(_))
    ));

    let target = Temp::new("target");
    provision_writer_epoch_floor_store(&target.0, f.audience(), &lease).unwrap();
    let alias = Temp::new("alias");
    std::os::unix::fs::symlink(&target.0, &alias.0).unwrap();
    assert!(matches!(
        load_writer_epoch_floor(&alias.0, f.audience()),
        Err(WriterEpochFloorStoreError::UnsafeStore(_))
    ));

    let mode = Temp::new("mode");
    provision_writer_epoch_floor_store(&mode.0, f.audience(), &lease).unwrap();
    fs::set_permissions(mode.0.join("state.json"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_writer_epoch_floor(&mode.0, f.audience()),
        Err(WriterEpochFloorStoreError::UnsafeStore(_))
    ));
}

#[test]
fn deletion_is_not_repaired_and_live_lock_wait_is_bounded() {
    let f = Fixture::new();
    let store = Temp::new("missing");
    let lease = f.lease("writer-a", 7);
    provision_writer_epoch_floor_store(&store.0, f.audience(), &lease).unwrap();
    fs::remove_file(store.0.join("state.json")).unwrap();
    assert!(matches!(
        advance_writer_epoch_floor(&store.0, f.audience(), &f.lease("writer-b", 8)),
        Err(WriterEpochFloorStoreError::StateMissing)
    ));
    assert!(!store.0.join("state.json").exists());

    let busy = Temp::new("busy");
    provision_writer_epoch_floor_store(&busy.0, f.audience(), &lease).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(busy.0.join("store.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(matches!(
        load_writer_epoch_floor(&busy.0, f.audience()),
        Err(WriterEpochFloorStoreError::StoreBusy)
    ));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}

#[test]
fn malformed_and_oversized_state_are_rejected() {
    let f = Fixture::new();
    let store = Temp::new("malformed");
    let lease = f.lease("writer-a", 7);
    provision_writer_epoch_floor_store(&store.0, f.audience(), &lease).unwrap();
    fs::write(store.0.join("state.json"), b"{}").unwrap();
    assert!(matches!(
        load_writer_epoch_floor(&store.0, f.audience()),
        Err(WriterEpochFloorStoreError::InvalidState)
    ));
    fs::write(store.0.join("state.json"), vec![b'x'; 4097]).unwrap();
    assert!(matches!(
        load_writer_epoch_floor(&store.0, f.audience()),
        Err(WriterEpochFloorStoreError::InvalidState)
    ));
}
