use bloch_indexer_core::{CanonicalBlock, ChainIdentity, outbox::build_outbox};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, TrustedSigner, VerifiedDelivery, build_delivery_signature_message,
    build_receipt_signature_message, canonical_record_bytes, encode_accepted_receipt,
    encode_delivery, verify_delivery,
};
use bloch_indexer_delivery_transport::{
    DELIVERY_CONTENT_TYPE, MAX_REQUEST_BYTES, PROTOCOL_VERSION, RECEIPT_CONTENT_TYPE,
    TransportError, decode_request, decode_response, encode_request, encode_response,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

#[test]
fn round_trip_authenticates_delivery_and_acceptance() {
    let fixture = Fixture::new();
    let request = encode_request("delivery:0001", &fixture.delivery, &fixture.policy).unwrap();
    let decoded = decode_request(&request, &fixture.policy).unwrap();
    assert_eq!(decoded.request_id(), "delivery:0001");
    assert_eq!(decoded.delivery_bytes(), fixture.delivery);
    assert_eq!(
        decoded.delivery().record(),
        fixture.delivery_record.record()
    );

    let response = encode_response(
        decoded.request_id(),
        &fixture.receipt,
        decoded.delivery_bytes(),
        &fixture.policy,
    )
    .unwrap();
    let accepted = decode_response(
        &response,
        "delivery:0001",
        &fixture.delivery,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(accepted.request_id(), "delivery:0001");
    assert_eq!(accepted.receipt_bytes(), fixture.receipt);
    assert_eq!(accepted.receipt().receiver_id(), "receiver-1");
}

#[test]
fn freezes_content_types_version_domain_and_canonical_encoding() {
    let fixture = Fixture::new();
    let request = encode_request("r-1", &fixture.delivery, &fixture.policy).unwrap();
    let value: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(value["contentType"], DELIVERY_CONTENT_TYPE);
    assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);

    let text = String::from_utf8(request.clone()).unwrap();
    for (needle, replacement, expected) in [
        (
            DELIVERY_CONTENT_TYPE.to_string(),
            RECEIPT_CONTENT_TYPE.to_string(),
            TransportError::UnsupportedContentType,
        ),
        (
            format!("\"protocolVersion\":{PROTOCOL_VERSION}"),
            "\"protocolVersion\":2".into(),
            TransportError::UnsupportedVersion,
        ),
        (
            fixture.policy.destination_domain.clone(),
            "another-domain".into(),
            TransportError::DomainMismatch,
        ),
    ] {
        let changed = text.replacen(&needle, &replacement, 1);
        assert_eq!(
            decode_request(changed.as_bytes(), &fixture.policy).unwrap_err(),
            expected
        );
    }

    let prefixed = [b" ".as_slice(), request.as_slice()].concat();
    assert_eq!(
        decode_request(&prefixed, &fixture.policy).unwrap_err(),
        TransportError::InvalidMessage
    );
}

#[test]
fn rejects_duplicate_unknown_trailing_and_malformed_payloads() {
    let fixture = Fixture::new();
    let request = encode_request("r-1", &fixture.delivery, &fixture.policy).unwrap();
    let text = String::from_utf8(request.clone()).unwrap();

    let duplicate = text.replacen(
        "\"schema\":",
        "\"schema\":\"bloch.data.delivery-transport-request.v1\",\"schema\":",
        1,
    );
    assert_eq!(
        decode_request(duplicate.as_bytes(), &fixture.policy).unwrap_err(),
        TransportError::InvalidMessage
    );

    let mut unknown: Value = serde_json::from_slice(&request).unwrap();
    unknown["acknowledge"] = Value::Bool(true);
    assert_eq!(
        decode_request(&serde_json::to_vec(&unknown).unwrap(), &fixture.policy).unwrap_err(),
        TransportError::InvalidMessage
    );
    assert_eq!(
        decode_request(format!("{text}{{}}").as_bytes(), &fixture.policy).unwrap_err(),
        TransportError::InvalidMessage
    );

    let mut malformed: Value = serde_json::from_slice(&request).unwrap();
    malformed["deliveryHex"] = Value::String("0xABC".into());
    assert_eq!(
        decode_request(&serde_json::to_vec(&malformed).unwrap(), &fixture.policy).unwrap_err(),
        TransportError::InvalidMessage
    );
}

#[test]
fn applies_outer_and_embedded_payload_limits_before_decoding() {
    let fixture = Fixture::new();
    assert_eq!(
        decode_request(&[], &fixture.policy).unwrap_err(),
        TransportError::Empty
    );
    assert_eq!(
        decode_request(&vec![b' '; MAX_REQUEST_BYTES + 1], &fixture.policy).unwrap_err(),
        TransportError::MessageTooLarge
    );

    let request = encode_request("r-1", &fixture.delivery, &fixture.policy).unwrap();
    let text = String::from_utf8(request).unwrap();
    let needle = format!("0x{}", hex::encode(&fixture.delivery));
    let replacement = format!(
        "0x{}",
        "00".repeat(bloch_indexer_delivery_protocol::MAX_DELIVERY_BYTES + 1)
    );
    let oversized = text.replacen(&needle, &replacement, 1);
    assert_eq!(
        decode_request(oversized.as_bytes(), &fixture.policy).unwrap_err(),
        TransportError::PayloadTooLarge
    );
}

#[test]
fn rejects_request_replay_and_receipt_for_another_delivery() {
    let fixture = Fixture::new();
    let response =
        encode_response("r-1", &fixture.receipt, &fixture.delivery, &fixture.policy).unwrap();
    assert_eq!(
        decode_response(&response, "r-2", &fixture.delivery, &fixture.policy).unwrap_err(),
        TransportError::RequestMismatch
    );

    let other = fixture.delivery(2, 8);
    assert_eq!(
        decode_response(&response, "r-1", &other, &fixture.policy).unwrap_err(),
        TransportError::InvalidReceipt
    );
}

#[test]
fn rejects_tampered_signed_payload_and_invalid_identifiers() {
    let fixture = Fixture::new();
    let request = encode_request("r-1", &fixture.delivery, &fixture.policy).unwrap();
    let text = String::from_utf8(request).unwrap();
    let original = format!("0x{}", hex::encode(&fixture.delivery));
    let mut delivery = fixture.delivery.clone();
    let last = delivery.len() - 2;
    delivery[last] ^= 1;
    let changed = text.replacen(&original, &format!("0x{}", hex::encode(delivery)), 1);
    assert_eq!(
        decode_request(changed.as_bytes(), &fixture.policy).unwrap_err(),
        TransportError::InvalidDelivery
    );

    for invalid in ["", "has space", "line\nbreak"] {
        assert_eq!(
            encode_request(invalid, &fixture.delivery, &fixture.policy).unwrap_err(),
            TransportError::InvalidRequestId
        );
    }

    assert_eq!(TransportError::InvalidDelivery.code(), "invalid_delivery");
    assert_eq!(TransportError::RequestMismatch.code(), "request_mismatch");
}

struct Fixture {
    policy: TrustPolicy,
    sender: SigningKey,
    delivery: Vec<u8>,
    delivery_record: VerifiedDelivery,
    receipt: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let sender = SigningKey::from_bytes(&[7; 32]);
        let receiver = SigningKey::from_bytes(&[9; 32]);
        let network = network();
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
        let delivery_record = verify_delivery(&delivery, &policy).unwrap();
        let message = build_receipt_signature_message(
            &policy.destination_domain,
            &network,
            "receiver-1",
            delivery_record.sha256(),
            &delivery_record.record().id,
            delivery_record.attempt(),
            delivery_record.generation(),
        )
        .unwrap();
        let receipt = encode_accepted_receipt(
            &policy.destination_domain,
            &network,
            "receiver-1",
            &delivery_record,
            &receiver.sign(&message).to_bytes(),
        )
        .unwrap();
        Self {
            policy,
            sender,
            delivery,
            delivery_record,
            receipt,
        }
    }

    fn delivery(&self, attempt: u32, generation: u64) -> Vec<u8> {
        let record = canonical_record_bytes(self.delivery_record.record()).unwrap();
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

fn network() -> ChainIdentity {
    ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('a'),
    }
}

fn block(network: &ChainIdentity) -> CanonicalBlock {
    serde_json::from_value(json!({
        "schema": "bloch.data.canonical-block.v1",
        "network": network,
        "height": 101,
        "blockHash": hash('2'),
        "parentHash": hash('1'),
        "stateRoot": hash('e'),
        "timestampUnixSeconds": 1_700_000_101_u64,
        "events": []
    }))
    .unwrap()
}

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
