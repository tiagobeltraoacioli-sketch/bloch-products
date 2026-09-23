#![cfg(unix)]

use bloch_indexer_core::{CanonicalBlock, ChainIdentity, outbox::build_outbox};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, TrustedSigner, canonical_trust_policy_bytes, trust_policy_sha256,
    verify_accepted_receipt, verify_delivery,
};
use bloch_indexer_delivery_transport::{decode_response, encode_request};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn external_delivery_and_receipt_signing_is_recoverable_and_verified() {
    let fixture = Fixture::new();
    let delivery_request = fixture.root.join("delivery-request.json");
    let delivery_message = fixture.root.join("delivery-message.bin");
    let delivery_signature = fixture.root.join("delivery-signature.bin");
    let delivery = fixture.root.join("delivery.json");

    fixture.assert_success(&[
        "prepare-delivery",
        "--record",
        path(&fixture.record),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--sender-id",
        "sender-1",
        "--attempt",
        "1",
        "--generation",
        "7",
        "--request-out",
        path(&delivery_request),
        "--message-out",
        path(&delivery_message),
    ]);
    // A retry after a partial/crashed orchestration is an exact no-op.
    fixture.assert_success(&[
        "prepare-delivery",
        "--record",
        path(&fixture.record),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--sender-id",
        "sender-1",
        "--attempt",
        "1",
        "--generation",
        "7",
        "--request-out",
        path(&delivery_request),
        "--message-out",
        path(&delivery_message),
    ]);
    write_private(
        &delivery_signature,
        &fixture
            .sender
            .sign(&fs::read(&delivery_message).unwrap())
            .to_bytes(),
    );
    fixture.assert_success(&[
        "import-delivery",
        "--request",
        path(&delivery_request),
        "--signature",
        path(&delivery_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--delivery-out",
        path(&delivery),
    ]);
    let delivery_bytes = fs::read(&delivery).unwrap();
    verify_delivery(&delivery_bytes, &fixture.policy).unwrap();

    // Operational receiving goes through the durable receiver state machine,
    // not the protocol-only receipt helper below.
    let transport_request = fixture.root.join("transport-request.json");
    write_private(
        &transport_request,
        &encode_request("request-1", &delivery_bytes, &fixture.policy).unwrap(),
    );
    let receiver_store = fixture.root.join("receiver-store");
    fs::create_dir(&receiver_store).unwrap();
    fs::set_permissions(&receiver_store, fs::Permissions::from_mode(0o700)).unwrap();
    let operational_message = fixture.root.join("operational-message.bin");
    let operational_signature = fixture.root.join("operational-signature.bin");
    let transport_response = fixture.root.join("transport-response.json");
    fixture.assert_success(&[
        "receiver-prepare",
        "--transport-request",
        path(&transport_request),
        "--store",
        path(&receiver_store),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--receiver-id",
        "receiver-1",
        "--message-out",
        path(&operational_message),
        "--response-out",
        path(&transport_response),
    ]);
    write_private(
        &operational_signature,
        &fixture
            .receiver
            .sign(&fs::read(&operational_message).unwrap())
            .to_bytes(),
    );
    fixture.assert_success(&[
        "receiver-import",
        "--transport-request",
        path(&transport_request),
        "--store",
        path(&receiver_store),
        "--signature",
        path(&operational_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--receiver-id",
        "receiver-1",
        "--response-out",
        path(&transport_response),
    ]);
    decode_response(
        &fs::read(&transport_response).unwrap(),
        "request-1",
        &delivery_bytes,
        &fixture.policy,
    )
    .unwrap();
    // Completed durable state recovers the exact response without signing.
    fixture.assert_success(&[
        "receiver-prepare",
        "--transport-request",
        path(&transport_request),
        "--store",
        path(&receiver_store),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--receiver-id",
        "receiver-1",
        "--message-out",
        path(&operational_message),
        "--response-out",
        path(&transport_response),
    ]);

    let receipt_request = fixture.root.join("receipt-request.json");
    let receipt_message = fixture.root.join("receipt-message.bin");
    let receipt_signature = fixture.root.join("receipt-signature.bin");
    let receipt = fixture.root.join("receipt.json");
    fixture.assert_success(&[
        "prepare-receipt",
        "--delivery",
        path(&delivery),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--receiver-id",
        "receiver-1",
        "--request-out",
        path(&receipt_request),
        "--message-out",
        path(&receipt_message),
    ]);
    write_private(
        &receipt_signature,
        &fixture
            .receiver
            .sign(&fs::read(&receipt_message).unwrap())
            .to_bytes(),
    );
    fixture.assert_success(&[
        "import-receipt",
        "--request",
        path(&receipt_request),
        "--signature",
        path(&receipt_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--receipt-out",
        path(&receipt),
    ]);
    verify_accepted_receipt(
        &fs::read(receipt).unwrap(),
        &delivery_bytes,
        &fixture.policy,
    )
    .unwrap();
}

#[test]
fn import_refuses_tampering_wrong_signatures_symlinks_and_overwrite() {
    let fixture = Fixture::new();
    let noncanonical_request = fixture.root.join("noncanonical-request.json");
    let noncanonical_message = fixture.root.join("noncanonical-message.bin");
    let refused = fixture.run(&[
        "prepare-delivery",
        "--record",
        path(&fixture.record),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--sender-id",
        "sender-1",
        "--attempt",
        "01",
        "--generation",
        "7",
        "--request-out",
        path(&noncanonical_request),
        "--message-out",
        path(&noncanonical_message),
    ]);
    assert!(!refused.status.success());
    assert!(!noncanonical_request.exists());

    let request = fixture.root.join("request.json");
    let message = fixture.root.join("message.bin");
    fixture.prepare_delivery(&request, &message);

    let wrong_signature = fixture.root.join("wrong.bin");
    write_private(
        &wrong_signature,
        &fixture
            .receiver
            .sign(&fs::read(&message).unwrap())
            .to_bytes(),
    );
    let output = fixture.root.join("delivery.json");
    let refused = fixture.run(&[
        "import-delivery",
        "--request",
        path(&request),
        "--signature",
        path(&wrong_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--delivery-out",
        path(&output),
    ]);
    assert!(!refused.status.success());
    assert!(!output.exists());

    let alias = fixture.root.join("signature-link.bin");
    symlink(&wrong_signature, &alias).unwrap();
    let refused = fixture.run(&[
        "import-delivery",
        "--request",
        path(&request),
        "--signature",
        path(&alias),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--delivery-out",
        path(&output),
    ]);
    assert!(!refused.status.success());

    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
    document["messageSha256"] = json!(hash('f'));
    let tampered = fixture.root.join("tampered.json");
    write_private(&tampered, &serde_json::to_vec(&document).unwrap());
    let valid_signature = fixture.root.join("valid.bin");
    write_private(
        &valid_signature,
        &fixture.sender.sign(&fs::read(&message).unwrap()).to_bytes(),
    );
    let refused = fixture.run(&[
        "import-delivery",
        "--request",
        path(&tampered),
        "--signature",
        path(&valid_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--delivery-out",
        path(&output),
    ]);
    assert!(!refused.status.success());

    write_private(&output, b"do-not-replace");
    let refused = fixture.run(&[
        "import-delivery",
        "--request",
        path(&request),
        "--signature",
        path(&valid_signature),
        "--trust-policy",
        path(&fixture.policy_path),
        "--expected-trust-policy-sha256",
        &fixture.pin,
        "--delivery-out",
        path(&output),
    ]);
    assert!(!refused.status.success());
    assert_eq!(fs::read(output).unwrap(), b"do-not-replace");
}

struct Fixture {
    root: PathBuf,
    policy: TrustPolicy,
    policy_path: PathBuf,
    record: PathBuf,
    pin: String,
    sender: SigningKey,
    receiver: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let root = private_temp();
        let sender = SigningKey::from_bytes(&[7; 32]);
        let receiver = SigningKey::from_bytes(&[9; 32]);
        let network = ChainIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: hash('a'),
        };
        let policy = TrustPolicy {
            destination_domain: "dex-webhooks-prod".into(),
            network: network.clone(),
            senders: vec![TrustedSigner {
                signer_id: "sender-1".into(),
                ed25519_public_key: format!("0x{}", hex::encode(sender.verifying_key().as_bytes())),
            }],
            receivers: vec![TrustedSigner {
                signer_id: "receiver-1".into(),
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(receiver.verifying_key().as_bytes())
                ),
            }],
        };
        let pin = trust_policy_sha256(&policy).unwrap();
        let policy_path = root.join("policy.json");
        write_private(
            &policy_path,
            &canonical_trust_policy_bytes(&policy).unwrap(),
        );
        let block: CanonicalBlock = serde_json::from_value(json!({
            "schema": "bloch.data.canonical-block.v1",
            "network": network,
            "height": 101,
            "blockHash": hash('2'),
            "parentHash": hash('1'),
            "stateRoot": hash('e'),
            "timestampUnixSeconds": 1_700_000_101_u64,
            "events": []
        }))
        .unwrap();
        let record_value = build_outbox(&network, &hash('1'), &block, &[])
            .unwrap()
            .records
            .remove(0);
        let record = root.join("record.json");
        write_private(&record, &serde_json::to_vec(&record_value).unwrap());
        Self {
            root,
            policy,
            policy_path,
            record,
            pin,
            sender,
            receiver,
        }
    }

    fn prepare_delivery(&self, request: &Path, message: &Path) {
        self.assert_success(&[
            "prepare-delivery",
            "--record",
            path(&self.record),
            "--trust-policy",
            path(&self.policy_path),
            "--expected-trust-policy-sha256",
            &self.pin,
            "--sender-id",
            "sender-1",
            "--attempt",
            "1",
            "--generation",
            "7",
            "--request-out",
            path(request),
            "--message-out",
            path(message),
        ]);
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bloch-indexer-signing-ceremony"))
            .args(arguments)
            .output()
            .unwrap()
    }

    fn assert_success(&self, arguments: &[&str]) {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn private_temp() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bloch-indexer-signing-ceremony-{}-{nonce}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
