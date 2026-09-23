#![cfg(unix)]

use bloch_indexer_core::{CanonicalBlock, ChainIdentity, outbox::build_outbox};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, TrustedSigner, build_delivery_signature_message, canonical_record_bytes,
    encode_delivery, trust_policy_sha256, verify_delivery,
};
use bloch_indexer_delivery_transport::{decode_response, encode_request};
use bloch_indexer_receiver_core::{
    AcceptanceStatus, ReceiverError, import_acceptance_signature, prepare_acceptance,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn persists_before_exposing_stable_external_signing_bytes() {
    let fixture = Fixture::new();
    let first = fixture.prepare(&fixture.request).unwrap();
    let first = match first {
        AcceptanceStatus::AwaitingSignature(value) => value,
        _ => panic!("unexpected completion"),
    };
    assert!(!first.receipt_signature_message().is_empty());
    assert_eq!(first.attempt(), 1);
    assert_eq!(first.generation(), 7);
    assert!(
        entries(&fixture.store)
            .iter()
            .any(|name| name.ends_with(".acceptance.json"))
    );

    let second = fixture.prepare(&fixture.request).unwrap();
    let second = match second {
        AcceptanceStatus::AwaitingSignature(value) => value,
        _ => panic!("unexpected completion"),
    };
    assert_eq!(
        first.receipt_signature_message(),
        second.receipt_signature_message()
    );
    assert_eq!(first.delivery_sha256(), second.delivery_sha256());
}

#[test]
fn completion_is_durable_and_recoverable_for_another_request_id() {
    let fixture = Fixture::new();
    let prepared = match fixture.prepare(&fixture.request).unwrap() {
        AcceptanceStatus::AwaitingSignature(value) => value,
        _ => panic!("unexpected completion"),
    };
    let signature = fixture
        .receiver
        .sign(prepared.receipt_signature_message())
        .to_bytes();
    let completed = fixture.complete(&fixture.request, &signature).unwrap();
    let decoded = decode_response(
        completed.response_bytes(),
        "request-1",
        &fixture.delivery,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(decoded.receipt().receiver_id(), "receiver-1");

    let retry = encode_request("request-2", &fixture.delivery, &fixture.policy).unwrap();
    let recovered = match fixture.prepare(&retry).unwrap() {
        AcceptanceStatus::Completed(value) => value,
        _ => panic!("completion was not recovered"),
    };
    assert_eq!(recovered.receipt_bytes(), completed.receipt_bytes());
    assert_eq!(recovered.request_id(), "request-2");
    decode_response(
        recovered.response_bytes(),
        "request-2",
        &fixture.delivery,
        &fixture.policy,
    )
    .unwrap();
}

#[test]
fn invalid_signature_never_creates_completion() {
    let fixture = Fixture::new();
    fixture.prepare(&fixture.request).unwrap();
    assert!(matches!(
        fixture.complete(&fixture.request, &[0; 64]),
        Err(ReceiverError::InvalidSignature)
    ));
    assert!(
        !entries(&fixture.store)
            .iter()
            .any(|name| name.ends_with(".completion.json"))
    );
    assert!(matches!(
        fixture.prepare(&fixture.request).unwrap(),
        AcceptanceStatus::AwaitingSignature(_)
    ));
}

#[test]
fn response_loss_allows_new_attempt_without_repeating_record_outcome() {
    let fixture = Fixture::new();
    let first = match fixture.prepare(&fixture.request).unwrap() {
        AcceptanceStatus::AwaitingSignature(value) => value,
        _ => panic!("unexpected completion"),
    };
    fixture
        .complete(
            &fixture.request,
            &fixture
                .receiver
                .sign(first.receipt_signature_message())
                .to_bytes(),
        )
        .unwrap();

    let retry_delivery = fixture.delivery(2, 8);
    let retry = encode_request("request-retry", &retry_delivery, &fixture.policy).unwrap();
    let retry_prepared = match fixture.prepare(&retry).unwrap() {
        AcceptanceStatus::AwaitingSignature(value) => value,
        _ => panic!("new delivery identity reused an old receipt"),
    };
    assert_eq!(retry_prepared.attempt(), 2);
    assert_eq!(retry_prepared.generation(), 8);
    assert_eq!(
        entries(&fixture.store)
            .iter()
            .filter(|name| name.ends_with(".outcome.json"))
            .count(),
        1
    );
    assert_eq!(
        entries(&fixture.store)
            .iter()
            .filter(|name| name.ends_with(".acceptance.json"))
            .count(),
        2
    );
}

#[test]
fn trust_pin_and_receiver_role_are_fail_closed() {
    let fixture = Fixture::new();
    assert!(matches!(
        prepare_acceptance(
            &fixture.store,
            &fixture.request,
            &fixture.policy,
            &hash('f'),
            "receiver-1"
        ),
        Err(ReceiverError::PolicyPinMismatch)
    ));
    assert!(matches!(
        prepare_acceptance(
            &fixture.store,
            &fixture.request,
            &fixture.policy,
            &fixture.pin,
            "receiver-unknown"
        ),
        Err(ReceiverError::UntrustedReceiver)
    ));
    assert!(entries(&fixture.store).is_empty());
}

#[test]
fn unsafe_directory_and_symlink_store_are_rejected() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        fixture.prepare(&fixture.request),
        Err(ReceiverError::UnsafeStore(_))
    ));
    fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o700)).unwrap();
    let link = fixture.root.join("store-link");
    symlink(&fixture.store, &link).unwrap();
    assert!(matches!(
        prepare_acceptance(
            &link,
            &fixture.request,
            &fixture.policy,
            &fixture.pin,
            "receiver-1"
        ),
        Err(ReceiverError::UnsafeStore(_))
    ));
}

#[test]
fn hardlinked_or_corrupted_state_fails_closed() {
    let fixture = Fixture::new();
    fixture.prepare(&fixture.request).unwrap();
    let acceptance = fs::read_dir(&fixture.store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_string_lossy().ends_with(".acceptance.json"))
        .unwrap();
    let alias = fixture.store.join("attacker-hardlink");
    fs::hard_link(&acceptance, &alias).unwrap();
    assert!(matches!(
        fixture.prepare(&fixture.request),
        Err(ReceiverError::UnsafeStore(_))
    ));
    fs::remove_file(alias).unwrap();

    fs::write(&acceptance, b"{}").unwrap();
    assert!(matches!(
        fixture.prepare(&fixture.request),
        Err(ReceiverError::AcceptanceConflict | ReceiverError::InvalidState)
    ));
}

#[test]
fn live_lock_holder_causes_bounded_busy_failure() {
    let fixture = Fixture::new();
    fixture.prepare(&fixture.request).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.store.join(".receiver.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let started = std::time::Instant::now();
    assert!(matches!(
        fixture.prepare(&fixture.request),
        Err(ReceiverError::StoreBusy)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

struct Fixture {
    root: PathBuf,
    store: PathBuf,
    policy: TrustPolicy,
    pin: String,
    sender: SigningKey,
    receiver: SigningKey,
    delivery: Vec<u8>,
    request: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "bloch-receiver-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = root.join("store");
        fs::create_dir_all(&store).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let sender = SigningKey::from_bytes(&[7; 32]);
        let receiver = SigningKey::from_bytes(&[9; 32]);
        let network = network();
        let policy = TrustPolicy {
            destination_domain: "bloch-receiver-prod".into(),
            network: network.clone(),
            senders: vec![TrustedSigner {
                signer_id: "sender-1".into(),
                ed25519_public_key: key(&sender),
            }],
            receivers: vec![TrustedSigner {
                signer_id: "receiver-1".into(),
                ed25519_public_key: key(&receiver),
            }],
        };
        let pin = trust_policy_sha256(&policy).unwrap();
        let record = build_outbox(&network, &hash('1'), &block(&network), &[])
            .unwrap()
            .records
            .remove(0);
        let record_bytes = canonical_record_bytes(&record).unwrap();
        let message = build_delivery_signature_message(
            &policy.destination_domain,
            &network,
            "sender-1",
            1,
            7,
            &record_bytes,
        )
        .unwrap();
        let delivery = encode_delivery(
            &policy.destination_domain,
            &network,
            "sender-1",
            1,
            7,
            &record_bytes,
            &sender.sign(&message).to_bytes(),
        )
        .unwrap();
        let request = encode_request("request-1", &delivery, &policy).unwrap();
        Self {
            root,
            store,
            policy,
            pin,
            sender,
            receiver,
            delivery,
            request,
        }
    }

    fn prepare(&self, request: &[u8]) -> Result<AcceptanceStatus, ReceiverError> {
        prepare_acceptance(&self.store, request, &self.policy, &self.pin, "receiver-1")
    }
    fn complete(
        &self,
        request: &[u8],
        signature: &[u8],
    ) -> Result<bloch_indexer_receiver_core::ReceiverResponse, ReceiverError> {
        import_acceptance_signature(
            &self.store,
            request,
            signature,
            &self.policy,
            &self.pin,
            "receiver-1",
        )
    }
    fn delivery(&self, attempt: u32, generation: u64) -> Vec<u8> {
        let verified = verify_delivery(&self.delivery, &self.policy).unwrap();
        let record = canonical_record_bytes(verified.record()).unwrap();
        let message = build_delivery_signature_message(
            &self.policy.destination_domain,
            &self.policy.network,
            "sender-1",
            attempt,
            generation,
            &record,
        )
        .unwrap();
        encode_delivery(
            &self.policy.destination_domain,
            &self.policy.network,
            "sender-1",
            attempt,
            generation,
            &record,
            &self.sender.sign(&message).to_bytes(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn entries(path: &std::path::Path) -> Vec<String> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != ".receiver.lock")
        .collect()
}
fn key(signing: &SigningKey) -> String {
    format!("0x{}", hex::encode(signing.verifying_key().as_bytes()))
}
fn network() -> ChainIdentity {
    ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('a'),
    }
}
fn block(network: &ChainIdentity) -> CanonicalBlock {
    serde_json::from_value(json!({
        "schema":"bloch.data.canonical-block.v1", "network":network, "height":101,
        "blockHash":hash('2'), "parentHash":hash('1'), "stateRoot":hash('e'),
        "timestampUnixSeconds":1_700_000_101_u64, "events":[]
    }))
    .unwrap()
}
fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
