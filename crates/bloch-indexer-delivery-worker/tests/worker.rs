use bloch_indexer_core::{
    BlockAnchor, CanonicalBlock, CanonicalEvent, CanonicalIndexer, ChainIdentity,
    delivery::ResolutionOutcome,
    outbox::build_outbox,
    storage::{DurableState, apply_and_persist, load_snapshot, write_snapshot},
};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, TrustedSigner, build_delivery_signature_message, build_receipt_signature_message,
    canonical_record_bytes, encode_accepted_receipt, encode_delivery, verify_delivery,
};
use bloch_indexer_delivery_transport::{decode_request, decode_response, encode_response};
use bloch_indexer_delivery_worker::{
    PrepareOutcome, WorkerError, accept_response, acknowledge, prepare_next, schedule_retry,
    stage_signed_delivery,
};
use bloch_indexer_receipt_ack::acknowledge_authenticated_receipt_and_persist;
use bloch_indexer_receiver_core::{
    AcceptanceStatus, import_acceptance_signature, prepare_acceptance,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    spool: PathBuf,
    snapshot: PathBuf,
    state: DurableState,
    policy: TrustPolicy,
    sender: SigningKey,
    receiver: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let root = private_directory();
        let spool = root.join("spool");
        let snapshot = root.join("snapshot.json");
        let network = network();
        let indexer = CanonicalIndexer::new(
            network.clone(),
            BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('a'),
            },
            16,
        )
        .unwrap();
        let mut state = DurableState::new(indexer);
        write_snapshot(&state, &snapshot).unwrap();
        apply_and_persist(&mut state, block(network.clone()), &snapshot).unwrap();
        let sender = SigningKey::from_bytes(&[7; 32]);
        let receiver = SigningKey::from_bytes(&[8; 32]);
        let policy = TrustPolicy {
            destination_domain: "bloch-indexer-receiver".into(),
            network,
            senders: vec![TrustedSigner {
                signer_id: "sender-1".into(),
                ed25519_public_key: key(&sender),
            }],
            receivers: vec![TrustedSigner {
                signer_id: "receiver-1".into(),
                ed25519_public_key: key(&receiver),
            }],
        };
        Self {
            root,
            spool,
            snapshot,
            state,
            policy,
            sender,
            receiver,
        }
    }

    fn prepare(&mut self, token: &str) -> bloch_indexer_delivery_worker::SpoolJob {
        match prepare_next(
            &mut self.state,
            &self.snapshot,
            &self.spool,
            1_800_000_001,
            60,
            token,
            &self.policy,
        )
        .unwrap()
        {
            PrepareOutcome::Ready(job) => job,
            other => panic!("expected ready, got {other:?}"),
        }
    }

    fn delivery(&self, job: &bloch_indexer_delivery_worker::SpoolJob) -> Vec<u8> {
        let record = build_outbox(
            &self.policy.network,
            &hash('1'),
            &block(self.policy.network.clone()),
            &[],
        )
        .unwrap()
        .records
        .remove(0);
        assert_eq!(record.id, job.claim.record_id);
        let record_bytes = canonical_record_bytes(&record).unwrap();
        let message = build_delivery_signature_message(
            &self.policy.destination_domain,
            &self.policy.network,
            "sender-1",
            job.claim.attempt,
            job.claim.generation,
            &record_bytes,
        )
        .unwrap();
        encode_delivery(
            &self.policy.destination_domain,
            &self.policy.network,
            "sender-1",
            job.claim.attempt,
            job.claim.generation,
            &record_bytes,
            &self.sender.sign(&message).to_bytes(),
        )
        .unwrap()
    }

    fn response(&self, job: &bloch_indexer_delivery_worker::SpoolJob, delivery: &[u8]) -> Vec<u8> {
        let verified = verify_delivery(delivery, &self.policy).unwrap();
        let message = build_receipt_signature_message(
            &self.policy.destination_domain,
            &self.policy.network,
            "receiver-1",
            verified.sha256(),
            &job.claim.record_id,
            job.claim.attempt,
            job.claim.generation,
        )
        .unwrap();
        let receipt = encode_accepted_receipt(
            &self.policy.destination_domain,
            &self.policy.network,
            "receiver-1",
            &verified,
            &self.receiver.sign(&message).to_bytes(),
        )
        .unwrap();
        encode_response(&job.request_id, &receipt, delivery, &self.policy).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn complete_cycle_survives_idempotent_replay() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('9'));
    let delivery = fixture.delivery(&job);
    let request =
        stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    assert_eq!(
        decode_request(&request, &fixture.policy)
            .unwrap()
            .request_id(),
        job.request_id
    );
    let response = fixture.response(&job, &delivery);
    accept_response(&fixture.spool, &job.job_id, &response, &fixture.policy).unwrap();
    assert_eq!(
        acknowledge(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_002,
            &fixture.policy
        )
        .unwrap()
        .outcome,
        ResolutionOutcome::Applied
    );
    assert_eq!(
        acknowledge(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_003,
            &fixture.policy
        )
        .unwrap()
        .outcome,
        ResolutionOutcome::Idempotent
    );
    assert_eq!(
        load_snapshot(&fixture.snapshot)
            .unwrap()
            .delivery
            .pending_position(),
        (1, 0)
    );
}

#[cfg(unix)]
#[test]
fn complete_cycle_crosses_the_durable_receiver_boundary() {
    use std::os::unix::fs::PermissionsExt;

    let mut fixture = Fixture::new();
    let receiver_store = fixture.root.join("receiver-store");
    fs::create_dir(&receiver_store).unwrap();
    fs::set_permissions(&receiver_store, fs::Permissions::from_mode(0o700)).unwrap();

    let job = fixture.prepare(&hash('e'));
    let delivery = fixture.delivery(&job);
    let request =
        stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    let policy_pin = bloch_indexer_delivery_protocol::trust_policy_sha256(&fixture.policy).unwrap();
    let prepared = match prepare_acceptance(
        &receiver_store,
        &request,
        &fixture.policy,
        &policy_pin,
        "receiver-1",
    )
    .unwrap()
    {
        AcceptanceStatus::AwaitingSignature(prepared) => prepared,
        AcceptanceStatus::Completed(_) => panic!("new delivery was already completed"),
    };
    let signature = fixture
        .receiver
        .sign(prepared.receipt_signature_message())
        .to_bytes();
    let receiver_response = import_acceptance_signature(
        &receiver_store,
        &request,
        &signature,
        &fixture.policy,
        &policy_pin,
        "receiver-1",
    )
    .unwrap();
    accept_response(
        &fixture.spool,
        &job.job_id,
        receiver_response.response_bytes(),
        &fixture.policy,
    )
    .unwrap();
    let acknowledged = acknowledge(
        &mut fixture.state,
        &fixture.snapshot,
        &fixture.spool,
        &job.job_id,
        1_800_000_002,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(acknowledged.outcome, ResolutionOutcome::Applied);
    assert_eq!(
        load_snapshot(&fixture.snapshot)
            .unwrap()
            .delivery
            .last_acknowledgement_evidence()
            .unwrap()
            .trust_policy_sha256,
        policy_pin
    );
}

#[test]
fn crash_after_durable_ack_before_completion_recovers_idempotently() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('c'));
    let delivery = fixture.delivery(&job);
    stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    let response = fixture.response(&job, &delivery);
    accept_response(&fixture.spool, &job.job_id, &response, &fixture.policy).unwrap();
    let receipt = decode_response(&response, &job.request_id, &delivery, &fixture.policy)
        .unwrap()
        .receipt_bytes()
        .to_vec();
    assert_eq!(
        acknowledge_authenticated_receipt_and_persist(
            &mut fixture.state,
            &fixture.snapshot,
            &job.claim,
            1_800_000_002,
            &delivery,
            &receipt,
            &fixture.policy,
        )
        .unwrap()
        .outcome,
        ResolutionOutcome::Applied
    );
    assert_eq!(
        acknowledge(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_003,
            &fixture.policy,
        )
        .unwrap()
        .outcome,
        ResolutionOutcome::Idempotent
    );
}

#[test]
fn active_job_is_discoverable_and_requires_same_token() {
    let mut fixture = Fixture::new();
    let original = fixture.prepare(&hash('8'));
    let recovered = fixture.prepare(&hash('8'));
    assert_eq!(recovered, original);
    assert_eq!(recovered.claim.attempt, 1);
    assert_eq!(recovered.claim.generation, 1);
    assert!(matches!(
        prepare_next(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            1_800_000_002,
            60,
            &hash('9'),
            &fixture.policy
        ),
        Err(WorkerError::JobMismatch)
    ));
}

#[test]
fn replay_or_mix_for_another_claim_fails_closed() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('7'));
    let delivery = fixture.delivery(&job);
    stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    let mut changed = delivery.clone();
    let last = changed.len() - 2;
    changed[last] ^= 1;
    assert!(matches!(
        stage_signed_delivery(&fixture.spool, &job.job_id, &changed, &fixture.policy),
        Err(WorkerError::Protocol(_))
    ));
    let mut wrong_policy = fixture.policy.clone();
    wrong_policy.destination_domain = "other-domain".into();
    assert!(matches!(
        stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &wrong_policy),
        Err(WorkerError::JobMismatch)
    ));
}

#[test]
fn explicit_retry_is_terminal_and_received_response_cannot_be_discarded() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('6'));
    let delivery = fixture.delivery(&job);
    stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    let response = fixture.response(&job, &delivery);
    accept_response(&fixture.spool, &job.job_id, &response, &fixture.policy).unwrap();
    assert!(matches!(
        schedule_retry(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_002,
            10,
            &fixture.policy
        ),
        Err(WorkerError::Terminal)
    ));

    acknowledge(
        &mut fixture.state,
        &fixture.snapshot,
        &fixture.spool,
        &job.job_id,
        1_800_000_002,
        &fixture.policy,
    )
    .unwrap();
}

#[test]
fn incomplete_job_can_only_retry_explicitly() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('5'));
    assert!(matches!(
        acknowledge(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_002,
            &fixture.policy
        ),
        Err(WorkerError::Incomplete(_))
    ));
    assert_eq!(
        schedule_retry(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            &job.job_id,
            1_800_000_002,
            10,
            &fixture.policy
        )
        .unwrap(),
        ResolutionOutcome::Applied
    );
}

#[test]
fn malformed_terminal_marker_never_releases_active_job() {
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('d'));
    let completion = fixture
        .spool
        .join(format!("{}.completion.json", job.job_id));
    fs::write(&completion, b"{}").unwrap();
    assert!(matches!(
        prepare_next(
            &mut fixture.state,
            &fixture.snapshot,
            &fixture.spool,
            1_800_000_002,
            60,
            &hash('d'),
            &fixture.policy
        ),
        Err(WorkerError::InvalidArtifact | WorkerError::UnsafeSpool(_))
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_artifact_is_never_followed() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('4'));
    let delivery = fixture.delivery(&job);
    stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy).unwrap();
    let path = fixture.spool.join(format!("{}.delivery.json", job.job_id));
    fs::remove_file(&path).unwrap();
    symlink(&fixture.snapshot, &path).unwrap();
    let response = fixture.response(&job, &delivery);
    assert!(accept_response(&fixture.spool, &job.job_id, &response, &fixture.policy).is_err());
}

#[test]
fn external_job_identifier_cannot_escape_spool() {
    let fixture = Fixture::new();
    assert!(matches!(
        stage_signed_delivery(
            &fixture.spool,
            "../../outside",
            b"delivery",
            &fixture.policy
        ),
        Err(WorkerError::JobMismatch)
    ));
    assert!(!fixture.root.join("outside.lock").exists());
}

#[cfg(unix)]
#[test]
fn live_job_lock_returns_busy_after_bounded_wait() {
    use std::{
        fs::OpenOptions,
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('b'));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.spool.join(format!("{}.lock", job.job_id)))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let delivery = fixture.delivery(&job);
    let started = Instant::now();
    assert!(matches!(
        stage_signed_delivery(&fixture.spool, &job.job_id, &delivery, &fixture.policy),
        Err(WorkerError::Busy)
    ));
    assert!(started.elapsed() >= Duration::from_millis(450));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}

#[cfg(unix)]
#[test]
fn directory_replacement_during_locked_mutation_fails_closed() {
    use std::{
        fs::OpenOptions, os::fd::AsRawFd, os::unix::fs::PermissionsExt, thread, time::Duration,
    };
    let mut fixture = Fixture::new();
    let job = fixture.prepare(&hash('e'));
    let delivery = fixture.delivery(&job);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.spool.join(format!("{}.lock", job.job_id)))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let spool = fixture.spool.clone();
    let job_id = job.job_id.clone();
    let policy = fixture.policy.clone();
    let worker = thread::spawn(move || stage_signed_delivery(&spool, &job_id, &delivery, &policy));
    thread::sleep(Duration::from_millis(100));
    let moved = fixture.root.join("original-spool");
    fs::rename(&fixture.spool, &moved).unwrap();
    fs::create_dir(&fixture.spool).unwrap();
    fs::set_permissions(&fixture.spool, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(matches!(
        worker.join().unwrap(),
        Err(WorkerError::UnsafeSpool("directoryReplaced"))
    ));
}

fn network() -> ChainIdentity {
    ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('a'),
    }
}
fn block(network: ChainIdentity) -> CanonicalBlock {
    CanonicalBlock {
        schema: "bloch.data.canonical-block.v1".into(),
        network,
        height: 101,
        block_hash: hash('2'),
        parent_hash: hash('1'),
        state_root: hash('b'),
        timestamp_unix_seconds: 1_800_000_000,
        events: vec![CanonicalEvent {
            transaction_hash: hash('3'),
            transaction_index: 0,
            log_index: 0,
            address: format!("0x{}", "4".repeat(40)),
            topics: vec![hash('5')],
            data: "0x".into(),
        }],
    }
}
fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
fn key(signing: &SigningKey) -> String {
    format!("0x{}", hex::encode(signing.verifying_key().to_bytes()))
}
fn private_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bloch-delivery-worker-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}
