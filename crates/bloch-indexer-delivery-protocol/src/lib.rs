//! Offline authentication for outbox deliveries and acceptance receipts.
//!
//! The caller supplies independently pinned trust policy bytes and public keys.
//! This crate has no private-key, file, socket, HTTP, or durable-state access.
//! A valid receipt is receiver-authenticated acceptance of one exact delivery;
//! it is not chain finality and never acknowledges indexer state automatically.

use bloch_indexer_core::{
    ChainIdentity,
    delivery::DeliveryClaim,
    outbox::{OutboxError, OutboxRecord, validate_outbox_record},
    validate_chain_identity,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const TRUST_POLICY_SCHEMA: &str = "bloch.data.delivery-trust-policy.v1";
pub const DELIVERY_SCHEMA: &str = "bloch.data.authenticated-delivery.v1";
pub const RECEIPT_SCHEMA: &str = "bloch.data.authenticated-receipt.v1";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_DELIVERY_BYTES: usize = 256 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;

const DELIVERY_SIGNATURE_DOMAIN: &[u8] = b"bloch.data.authenticated-delivery.signature.v1";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"bloch.data.authenticated-receipt.signature.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    pub destination_domain: String,
    pub network: ChainIdentity,
    pub senders: Vec<TrustedSigner>,
    pub receivers: Vec<TrustedSigner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSigner {
    pub signer_id: String,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDelivery {
    record: OutboxRecord,
    attempt: u32,
    generation: u64,
    sender_id: String,
    canonical_bytes: Vec<u8>,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReceipt {
    delivery: VerifiedDelivery,
    receiver_id: String,
}

impl VerifiedDelivery {
    pub fn record(&self) -> &OutboxRecord {
        &self.record
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl VerifiedReceipt {
    pub fn delivery(&self) -> &VerifiedDelivery {
        &self.delivery
    }
    pub fn receiver_id(&self) -> &str {
        &self.receiver_id
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("{kind} JSON is empty")]
    Empty { kind: &'static str },
    #[error("{kind} JSON is too large: {actual} bytes exceeds the {maximum} byte limit")]
    TooLarge {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid {kind} JSON: {message}")]
    InvalidJson { kind: &'static str, message: String },
    #[error("invalid protocol field: {0}")]
    InvalidField(&'static str),
    #[error("trust policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("message is not in canonical JSON encoding")]
    NonCanonicalJson,
    #[error("message does not match the pinned trust context")]
    TrustContextMismatch,
    #[error("untrusted signer")]
    UntrustedSigner,
    #[error("payload digest mismatch")]
    DigestMismatch,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("receipt does not match the expected delivery claim")]
    ClaimMismatch,
    #[error("invalid outbox record: {0}")]
    InvalidRecord(#[from] OutboxError),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyDocument {
    schema: String,
    destination_domain: String,
    network: ChainIdentity,
    senders: Vec<SignerDocument>,
    receivers: Vec<SignerDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignerDocument {
    signer_id: String,
    ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryEnvelope {
    schema: String,
    destination_domain: String,
    network: ChainIdentity,
    sender_id: String,
    attempt: u32,
    generation: u64,
    canonical_record_hex: String,
    canonical_record_sha256: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReceiptEnvelope {
    schema: String,
    destination_domain: String,
    network: ChainIdentity,
    receiver_id: String,
    delivery_sha256: String,
    record_id: String,
    attempt: u32,
    generation: u64,
    result: ReceiptResult,
    signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReceiptResult {
    Accepted,
}

pub fn parse_trust_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<TrustPolicy, ProtocolError> {
    check_size(bytes, MAX_POLICY_BYTES, "policy")?;
    reject_duplicate_keys(bytes, "policy")?;
    let document: PolicyDocument = parse_json(bytes, "policy")?;
    if document.schema != TRUST_POLICY_SCHEMA {
        return Err(ProtocolError::InvalidField("policy.schema"));
    }
    let mut policy = TrustPolicy {
        destination_domain: document.destination_domain,
        network: document.network,
        senders: document
            .senders
            .into_iter()
            .map(signer_from_document)
            .collect(),
        receivers: document
            .receivers
            .into_iter()
            .map(signer_from_document)
            .collect(),
    };
    sort_signers(&mut policy.senders);
    sort_signers(&mut policy.receivers);
    validate_policy(&policy)?;
    let expected = decode_hex_exact(expected_sha256, 32, "expectedSha256")?;
    if Sha256::digest(canonical_trust_policy_bytes(&policy)?).as_slice() != expected.as_slice() {
        return Err(ProtocolError::PolicyDigestMismatch);
    }
    Ok(policy)
}

pub fn canonical_trust_policy_bytes(policy: &TrustPolicy) -> Result<Vec<u8>, ProtocolError> {
    validate_policy(policy)?;
    let mut senders = policy
        .senders
        .iter()
        .map(signer_document)
        .collect::<Vec<_>>();
    let mut receivers = policy
        .receivers
        .iter()
        .map(signer_document)
        .collect::<Vec<_>>();
    sort_signer_documents(&mut senders);
    sort_signer_documents(&mut receivers);
    serde_json::to_vec(&PolicyDocument {
        schema: TRUST_POLICY_SCHEMA.into(),
        destination_domain: policy.destination_domain.clone(),
        network: policy.network.clone(),
        senders,
        receivers,
    })
    .map_err(|error| invalid_json("policy", error))
}

pub fn trust_policy_sha256(policy: &TrustPolicy) -> Result<String, ProtocolError> {
    Ok(hash_bytes(&canonical_trust_policy_bytes(policy)?))
}

pub fn canonical_record_bytes(record: &OutboxRecord) -> Result<Vec<u8>, ProtocolError> {
    validate_outbox_record(record)?;
    serde_json::to_vec(record).map_err(|error| invalid_json("record", error))
}

/// Deterministic, domain-separated bytes for an external sender to sign.
pub fn build_delivery_signature_message(
    destination_domain: &str,
    network: &ChainIdentity,
    sender_id: &str,
    attempt: u32,
    generation: u64,
    canonical_record: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    validate_context(destination_domain, network)?;
    validate_identifier(sender_id, 128, "senderId")?;
    if attempt == 0 {
        return Err(ProtocolError::InvalidField("attempt"));
    }
    if generation == 0 {
        return Err(ProtocolError::InvalidField("generation"));
    }
    let record = parse_canonical_record(canonical_record)?;
    if record.network != *network {
        return Err(ProtocolError::TrustContextMismatch);
    }
    let mut output = Vec::with_capacity(canonical_record.len() + 512);
    append(&mut output, DELIVERY_SIGNATURE_DOMAIN)?;
    append_context(&mut output, destination_domain, network)?;
    append(&mut output, sender_id.as_bytes())?;
    output.extend_from_slice(&u64::from(attempt).to_be_bytes());
    output.extend_from_slice(&generation.to_be_bytes());
    append(&mut output, canonical_record)?;
    Ok(output)
}

/// Produces canonical JSON after the signature was created externally.
pub fn encode_delivery(
    destination_domain: &str,
    network: &ChainIdentity,
    sender_id: &str,
    attempt: u32,
    generation: u64,
    canonical_record: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let _ = build_delivery_signature_message(
        destination_domain,
        network,
        sender_id,
        attempt,
        generation,
        canonical_record,
    )?;
    if signature.len() != 64 {
        return Err(ProtocolError::InvalidField("signature"));
    }
    serde_json::to_vec(&DeliveryEnvelope {
        schema: DELIVERY_SCHEMA.into(),
        destination_domain: destination_domain.into(),
        network: network.clone(),
        sender_id: sender_id.into(),
        attempt,
        generation,
        canonical_record_hex: format!("0x{}", hex::encode(canonical_record)),
        canonical_record_sha256: hash_bytes(canonical_record),
        signature: format!("0x{}", hex::encode(signature)),
    })
    .map_err(|error| invalid_json("delivery", error))
}

pub fn verify_delivery(
    bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<VerifiedDelivery, ProtocolError> {
    validate_policy(policy)?;
    check_size(bytes, MAX_DELIVERY_BYTES, "delivery")?;
    reject_duplicate_keys(bytes, "delivery")?;
    let envelope: DeliveryEnvelope = parse_json(bytes, "delivery")?;
    if envelope.schema != DELIVERY_SCHEMA {
        return Err(ProtocolError::InvalidField("delivery.schema"));
    }
    if serde_json::to_vec(&envelope).map_err(|error| invalid_json("delivery", error))? != bytes {
        return Err(ProtocolError::NonCanonicalJson);
    }
    if envelope.destination_domain != policy.destination_domain
        || envelope.network != policy.network
    {
        return Err(ProtocolError::TrustContextMismatch);
    }
    let signer = trusted(&policy.senders, &envelope.sender_id)?;
    let record_bytes = decode_hex_bounded(
        &envelope.canonical_record_hex,
        MAX_RECORD_BYTES,
        "canonicalRecordHex",
    )?;
    if envelope.canonical_record_sha256 != hash_bytes(&record_bytes) {
        return Err(ProtocolError::DigestMismatch);
    }
    let message = build_delivery_signature_message(
        &envelope.destination_domain,
        &envelope.network,
        &envelope.sender_id,
        envelope.attempt,
        envelope.generation,
        &record_bytes,
    )?;
    verify_signature(&signer.ed25519_public_key, &envelope.signature, &message)?;
    let record = parse_canonical_record(&record_bytes)?;
    Ok(VerifiedDelivery {
        record,
        attempt: envelope.attempt,
        generation: envelope.generation,
        sender_id: envelope.sender_id,
        canonical_bytes: bytes.to_vec(),
        sha256: hash_bytes(bytes),
    })
}

/// Deterministic bytes for the destination receiver to sign after acceptance.
pub fn build_receipt_signature_message(
    destination_domain: &str,
    network: &ChainIdentity,
    receiver_id: &str,
    delivery_sha256: &str,
    record_id: &str,
    attempt: u32,
    generation: u64,
) -> Result<Vec<u8>, ProtocolError> {
    validate_context(destination_domain, network)?;
    validate_identifier(receiver_id, 128, "receiverId")?;
    let delivery_digest = decode_hex_exact(delivery_sha256, 32, "deliverySha256")?;
    let _ = decode_hex_exact(record_id, 32, "recordId")?;
    if attempt == 0 {
        return Err(ProtocolError::InvalidField("attempt"));
    }
    if generation == 0 {
        return Err(ProtocolError::InvalidField("generation"));
    }
    let mut output = Vec::with_capacity(512);
    append(&mut output, RECEIPT_SIGNATURE_DOMAIN)?;
    append_context(&mut output, destination_domain, network)?;
    append(&mut output, receiver_id.as_bytes())?;
    append(&mut output, &delivery_digest)?;
    append(&mut output, record_id.as_bytes())?;
    output.extend_from_slice(&u64::from(attempt).to_be_bytes());
    output.extend_from_slice(&generation.to_be_bytes());
    append(&mut output, b"accepted")?;
    Ok(output)
}

pub fn encode_accepted_receipt(
    destination_domain: &str,
    network: &ChainIdentity,
    receiver_id: &str,
    delivery: &VerifiedDelivery,
    signature: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if delivery.record.network != *network
        || delivery.sha256 != hash_bytes(&delivery.canonical_bytes)
    {
        return Err(ProtocolError::TrustContextMismatch);
    }
    let _ = build_receipt_signature_message(
        destination_domain,
        network,
        receiver_id,
        &delivery.sha256,
        &delivery.record.id,
        delivery.attempt,
        delivery.generation,
    )?;
    if signature.len() != 64 {
        return Err(ProtocolError::InvalidField("signature"));
    }
    serde_json::to_vec(&ReceiptEnvelope {
        schema: RECEIPT_SCHEMA.into(),
        destination_domain: destination_domain.into(),
        network: network.clone(),
        receiver_id: receiver_id.into(),
        delivery_sha256: delivery.sha256.clone(),
        record_id: delivery.record.id.clone(),
        attempt: delivery.attempt,
        generation: delivery.generation,
        result: ReceiptResult::Accepted,
        signature: format!("0x{}", hex::encode(signature)),
    })
    .map_err(|error| invalid_json("receipt", error))
}

/// Verifies both the exact canonical delivery and its receiver acceptance.
pub fn verify_accepted_receipt(
    receipt_bytes: &[u8],
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<VerifiedReceipt, ProtocolError> {
    let delivery = verify_delivery(delivery_bytes, policy)?;
    check_size(receipt_bytes, MAX_RECEIPT_BYTES, "receipt")?;
    reject_duplicate_keys(receipt_bytes, "receipt")?;
    let receipt: ReceiptEnvelope = parse_json(receipt_bytes, "receipt")?;
    if receipt.schema != RECEIPT_SCHEMA {
        return Err(ProtocolError::InvalidField("receipt.schema"));
    }
    if serde_json::to_vec(&receipt).map_err(|error| invalid_json("receipt", error))?
        != receipt_bytes
    {
        return Err(ProtocolError::NonCanonicalJson);
    }
    if receipt.destination_domain != policy.destination_domain || receipt.network != policy.network
    {
        return Err(ProtocolError::TrustContextMismatch);
    }
    if receipt.delivery_sha256 != delivery.sha256
        || receipt.record_id != delivery.record.id
        || receipt.attempt != delivery.attempt
        || receipt.generation != delivery.generation
    {
        return Err(ProtocolError::DigestMismatch);
    }
    let signer = trusted(&policy.receivers, &receipt.receiver_id)?;
    let message = build_receipt_signature_message(
        &receipt.destination_domain,
        &receipt.network,
        &receipt.receiver_id,
        &receipt.delivery_sha256,
        &receipt.record_id,
        receipt.attempt,
        receipt.generation,
    )?;
    verify_signature(&signer.ed25519_public_key, &receipt.signature, &message)?;
    Ok(VerifiedReceipt {
        delivery,
        receiver_id: receipt.receiver_id,
    })
}

/// Verifies a receipt and binds it to the caller's expected claim without
/// mutating or acknowledging `OutboxDelivery`/`DurableState`.
pub fn verify_accepted_receipt_for_claim(
    receipt_bytes: &[u8],
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
    expected_claim: &DeliveryClaim,
) -> Result<VerifiedReceipt, ProtocolError> {
    let receipt = verify_accepted_receipt(receipt_bytes, delivery_bytes, policy)?;
    if receipt.delivery.record.id != expected_claim.record_id
        || receipt.delivery.attempt != expected_claim.attempt
        || receipt.delivery.generation != expected_claim.generation
    {
        return Err(ProtocolError::ClaimMismatch);
    }
    Ok(receipt)
}

fn parse_canonical_record(bytes: &[u8]) -> Result<OutboxRecord, ProtocolError> {
    check_size(bytes, MAX_RECORD_BYTES, "record")?;
    reject_duplicate_keys(bytes, "record")?;
    let record: OutboxRecord = parse_json(bytes, "record")?;
    validate_outbox_record(&record)?;
    if serde_json::to_vec(&record).map_err(|error| invalid_json("record", error))? != bytes {
        return Err(ProtocolError::NonCanonicalJson);
    }
    Ok(record)
}

fn validate_policy(policy: &TrustPolicy) -> Result<(), ProtocolError> {
    validate_context(&policy.destination_domain, &policy.network)?;
    validate_signers(&policy.senders, "senders")?;
    validate_signers(&policy.receivers, "receivers")?;
    if policy.senders.iter().any(|sender| {
        policy.receivers.iter().any(|receiver| {
            sender.signer_id == receiver.signer_id
                || sender.ed25519_public_key == receiver.ed25519_public_key
        })
    }) {
        return Err(ProtocolError::InvalidField("signerRoleOverlap"));
    }
    Ok(())
}

fn validate_context(domain: &str, network: &ChainIdentity) -> Result<(), ProtocolError> {
    validate_identifier(domain, 256, "destinationDomain")?;
    validate_chain_identity(network).map_err(|_| ProtocolError::InvalidField("network"))?;
    Ok(())
}

fn validate_signers(signers: &[TrustedSigner], field: &'static str) -> Result<(), ProtocolError> {
    if signers.is_empty() || signers.len() > 64 {
        return Err(ProtocolError::InvalidField(field));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in signers {
        validate_identifier(&signer.signer_id, 128, "signerId")?;
        parse_key(&signer.ed25519_public_key)?;
        if !ids.insert(&signer.signer_id) || !keys.insert(&signer.ed25519_public_key) {
            return Err(ProtocolError::InvalidField("duplicateSigner"));
        }
    }
    Ok(())
}

fn trusted<'a>(signers: &'a [TrustedSigner], id: &str) -> Result<&'a TrustedSigner, ProtocolError> {
    validate_identifier(id, 128, "signerId")?;
    signers
        .iter()
        .find(|signer| signer.signer_id == id)
        .ok_or(ProtocolError::UntrustedSigner)
}

fn verify_signature(key: &str, encoded: &str, message: &[u8]) -> Result<(), ProtocolError> {
    let key = parse_key(key)?;
    let bytes = decode_hex_exact(encoded, 64, "signature")?;
    let signature =
        Signature::from_slice(&bytes).map_err(|_| ProtocolError::InvalidField("signature"))?;
    key.verify_strict(message, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

fn parse_key(value: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes: [u8; 32] = decode_hex_exact(value, 32, "ed25519PublicKey")?
        .try_into()
        .map_err(|_| ProtocolError::InvalidField("ed25519PublicKey"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::InvalidField("ed25519PublicKey"))
}

fn append_context(
    out: &mut Vec<u8>,
    domain: &str,
    network: &ChainIdentity,
) -> Result<(), ProtocolError> {
    append(out, domain.as_bytes())?;
    append(out, network.network.as_bytes())?;
    out.extend_from_slice(&network.chain_id.to_be_bytes());
    append(out, network.genesis_hash.as_bytes())
}

fn append(out: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let length = u64::try_from(value.len()).map_err(|_| ProtocolError::InvalidField("length"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn check_size(bytes: &[u8], maximum: usize, kind: &'static str) -> Result<(), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::Empty { kind });
    }
    if bytes.len() > maximum {
        return Err(ProtocolError::TooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn decode_hex_bounded(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    if !value.starts_with("0x")
        || !value.len().is_multiple_of(2)
        || value.len().saturating_sub(2) / 2 > maximum
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ProtocolError::InvalidField(field));
    }
    hex::decode(&value[2..]).map_err(|_| ProtocolError::InvalidField(field))
}

fn decode_hex_exact(
    value: &str,
    expected: usize,
    field: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    if value.len() != expected.saturating_mul(2).saturating_add(2) {
        return Err(ProtocolError::InvalidField(field));
    }
    decode_hex_bounded(value, expected, field)
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_identifier(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn signer_from_document(value: SignerDocument) -> TrustedSigner {
    TrustedSigner {
        signer_id: value.signer_id,
        ed25519_public_key: value.ed25519_public_key,
    }
}
fn signer_document(value: &TrustedSigner) -> SignerDocument {
    SignerDocument {
        signer_id: value.signer_id.clone(),
        ed25519_public_key: value.ed25519_public_key.clone(),
    }
}
fn sort_signers(values: &mut [TrustedSigner]) {
    values.sort_by(|a, b| {
        a.signer_id
            .cmp(&b.signer_id)
            .then_with(|| a.ed25519_public_key.cmp(&b.ed25519_public_key))
    });
}
fn sort_signer_documents(values: &mut [SignerDocument]) {
    values.sort_by(|a, b| {
        a.signer_id
            .cmp(&b.signer_id)
            .then_with(|| a.ed25519_public_key.cmp(&b.ed25519_public_key))
    });
}
fn parse_json<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
    kind: &'static str,
) -> Result<T, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|error| invalid_json(kind, error))
}
fn invalid_json(kind: &'static str, error: serde_json::Error) -> ProtocolError {
    ProtocolError::InvalidJson {
        kind,
        message: error.to_string(),
    }
}

fn reject_duplicate_keys(bytes: &[u8], kind: &'static str) -> Result<(), ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked
        .deserialize(&mut deserializer)
        .map_err(|error| invalid_json(kind, error))?;
    deserializer
        .end()
        .map_err(|error| invalid_json(kind, error))
}
struct DuplicateChecked;
impl<'de> DeserializeSeed<'de> for DuplicateChecked {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}
struct DuplicateVisitor;
impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON without duplicate object keys")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: de::Error>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        DuplicateChecked.deserialize(d)
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        DuplicateChecked.deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element_seed(DuplicateChecked)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            map.next_value_seed(DuplicateChecked)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_indexer_core::{CanonicalBlock, outbox::build_outbox};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    #[test]
    fn authenticates_delivery_and_exact_acceptance_receipt() {
        let fixture = Fixture::new();
        let delivery = fixture.delivery(1, 7, &fixture.record);
        let verified = verify_delivery(&delivery, &fixture.policy).unwrap();
        assert_eq!(verified.record, fixture.record);
        assert_eq!(verified.attempt, 1);
        assert_eq!(verified.generation, 7);

        let receipt = fixture.receipt(&verified);
        let accepted = verify_accepted_receipt(&receipt, &delivery, &fixture.policy).unwrap();
        assert_eq!(accepted.receiver_id, "receiver-1");
        assert_eq!(accepted.delivery.sha256, hash_bytes(&delivery));
    }

    #[test]
    fn rejects_domain_network_and_signer_replay() {
        let fixture = Fixture::new();
        let delivery = fixture.delivery(1, 7, &fixture.record);

        let mut other_domain = fixture.policy.clone();
        other_domain.destination_domain = "another-destination".into();
        assert_eq!(
            verify_delivery(&delivery, &other_domain).unwrap_err(),
            ProtocolError::TrustContextMismatch
        );

        let mut other_network = fixture.policy.clone();
        other_network.network.chain_id += 1;
        assert_eq!(
            verify_delivery(&delivery, &other_network).unwrap_err(),
            ProtocolError::TrustContextMismatch
        );

        let mut no_sender = fixture.policy.clone();
        no_sender.senders[0].signer_id = "sender-2".into();
        assert_eq!(
            verify_delivery(&delivery, &no_sender).unwrap_err(),
            ProtocolError::UntrustedSigner
        );
    }

    #[test]
    fn attempt_generation_and_record_substitution_break_signature() {
        let fixture = Fixture::new();
        let delivery = fixture.delivery(1, 7, &fixture.record);
        for mutation in ["attempt", "generation", "record"] {
            let mut envelope: DeliveryEnvelope = serde_json::from_slice(&delivery).unwrap();
            match mutation {
                "attempt" => envelope.attempt += 1,
                "generation" => envelope.generation += 1,
                "record" => {
                    let other = fixture.record_at(102, '3', '2');
                    let bytes = canonical_record_bytes(&other).unwrap();
                    envelope.canonical_record_hex = format!("0x{}", hex::encode(&bytes));
                    envelope.canonical_record_sha256 = hash_bytes(&bytes);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                verify_delivery(&serde_json::to_vec(&envelope).unwrap(), &fixture.policy)
                    .unwrap_err(),
                ProtocolError::InvalidSignature,
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn receipt_cannot_be_replayed_for_another_delivery() {
        let fixture = Fixture::new();
        let first_bytes = fixture.delivery(1, 7, &fixture.record);
        let first = verify_delivery(&first_bytes, &fixture.policy).unwrap();
        let receipt = fixture.receipt(&first);

        let second_bytes = fixture.delivery(2, 8, &fixture.record);
        assert_eq!(
            verify_accepted_receipt(&receipt, &second_bytes, &fixture.policy).unwrap_err(),
            ProtocolError::DigestMismatch
        );

        let mut changed: ReceiptEnvelope = serde_json::from_slice(&receipt).unwrap();
        changed.attempt += 1;
        assert_eq!(
            verify_accepted_receipt(
                &serde_json::to_vec(&changed).unwrap(),
                &first_bytes,
                &fixture.policy
            )
            .unwrap_err(),
            ProtocolError::DigestMismatch
        );

        let expected_claim = DeliveryClaim {
            token: hash('b'),
            generation: first.generation,
            record_id: first.record.id.clone(),
            attempt: first.attempt,
            claimed_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
        };
        assert!(
            verify_accepted_receipt_for_claim(
                &receipt,
                &first_bytes,
                &fixture.policy,
                &expected_claim,
            )
            .is_ok()
        );
        let stale_claim = DeliveryClaim {
            generation: expected_claim.generation + 1,
            ..expected_claim
        };
        assert_eq!(
            verify_accepted_receipt_for_claim(
                &receipt,
                &first_bytes,
                &fixture.policy,
                &stale_claim,
            )
            .unwrap_err(),
            ProtocolError::ClaimMismatch
        );
    }

    #[test]
    fn sender_cannot_sign_a_receiver_receipt() {
        let fixture = Fixture::new();
        let delivery_bytes = fixture.delivery(1, 7, &fixture.record);
        let delivery = verify_delivery(&delivery_bytes, &fixture.policy).unwrap();
        let message = build_receipt_signature_message(
            &fixture.policy.destination_domain,
            &fixture.policy.network,
            "receiver-1",
            &delivery.sha256,
            &delivery.record.id,
            delivery.attempt,
            delivery.generation,
        )
        .unwrap();
        let forged = encode_accepted_receipt(
            &fixture.policy.destination_domain,
            &fixture.policy.network,
            "receiver-1",
            &delivery,
            &fixture.sender.sign(&message).to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_accepted_receipt(&forged, &delivery_bytes, &fixture.policy).unwrap_err(),
            ProtocolError::InvalidSignature
        );
    }

    #[test]
    fn rejects_duplicate_unknown_trailing_and_noncanonical_json() {
        let fixture = Fixture::new();
        let delivery = fixture.delivery(1, 7, &fixture.record);
        let text = String::from_utf8(delivery.clone()).unwrap();
        let duplicate = text.replacen(
            "\"schema\":",
            "\"schema\":\"bloch.data.authenticated-delivery.v1\",\"schema\":",
            1,
        );
        assert!(matches!(
            verify_delivery(duplicate.as_bytes(), &fixture.policy),
            Err(ProtocolError::InvalidJson { message, .. }) if message.contains("duplicate")
        ));

        let mut unknown: Value = serde_json::from_slice(&delivery).unwrap();
        unknown["acknowledge"] = Value::Bool(true);
        assert!(matches!(
            verify_delivery(&serde_json::to_vec(&unknown).unwrap(), &fixture.policy),
            Err(ProtocolError::InvalidJson { message, .. }) if message.contains("unknown field")
        ));
        assert!(matches!(
            verify_delivery(format!("{text}{{}}").as_bytes(), &fixture.policy),
            Err(ProtocolError::InvalidJson { .. })
        ));
        assert_eq!(
            verify_delivery(format!(" {text}").as_bytes(), &fixture.policy).unwrap_err(),
            ProtocolError::NonCanonicalJson
        );

        let verified = verify_delivery(&delivery, &fixture.policy).unwrap();
        let receipt = fixture.receipt(&verified);
        let receipt_text = String::from_utf8(receipt.clone()).unwrap();
        let duplicate_receipt =
            receipt_text.replacen("\"result\":", "\"result\":\"accepted\",\"result\":", 1);
        assert!(matches!(
            verify_accepted_receipt(duplicate_receipt.as_bytes(), &delivery, &fixture.policy),
            Err(ProtocolError::InvalidJson { message, .. }) if message.contains("duplicate")
        ));
        assert!(matches!(
            verify_accepted_receipt(
                format!("{receipt_text}{{}}").as_bytes(),
                &delivery,
                &fixture.policy,
            ),
            Err(ProtocolError::InvalidJson { .. })
        ));
    }

    #[test]
    fn rejects_noncanonical_inner_record_and_digest_substitution() {
        let fixture = Fixture::new();
        let delivery = fixture.delivery(1, 7, &fixture.record);
        let mut envelope: DeliveryEnvelope = serde_json::from_slice(&delivery).unwrap();
        let mut record_bytes = canonical_record_bytes(&fixture.record).unwrap();
        record_bytes.push(b' ');
        envelope.canonical_record_hex = format!("0x{}", hex::encode(&record_bytes));
        envelope.canonical_record_sha256 = hash_bytes(&record_bytes);
        let message = raw_delivery_message(&fixture.policy, "sender-1", 1, 7, &record_bytes);
        envelope.signature = format!(
            "0x{}",
            hex::encode(fixture.sender.sign(&message).to_bytes())
        );
        assert_eq!(
            verify_delivery(&serde_json::to_vec(&envelope).unwrap(), &fixture.policy).unwrap_err(),
            ProtocolError::NonCanonicalJson
        );

        let mut digest: DeliveryEnvelope = serde_json::from_slice(&delivery).unwrap();
        digest.canonical_record_sha256 = hash('f');
        assert_eq!(
            verify_delivery(&serde_json::to_vec(&digest).unwrap(), &fixture.policy).unwrap_err(),
            ProtocolError::DigestMismatch
        );
    }

    #[test]
    fn policy_is_canonical_pinned_and_cannot_be_supplied_by_envelope() {
        let fixture = Fixture::new();
        let canonical = canonical_trust_policy_bytes(&fixture.policy).unwrap();
        let digest = trust_policy_sha256(&fixture.policy).unwrap();
        assert_eq!(
            parse_trust_policy(&canonical, &digest).unwrap(),
            fixture.policy
        );
        assert_eq!(
            parse_trust_policy(&canonical, &hash('0')).unwrap_err(),
            ProtocolError::PolicyDigestMismatch
        );

        let delivery = fixture.delivery(1, 7, &fixture.record);
        let mut value: Value = serde_json::from_slice(&delivery).unwrap();
        value["trustPolicy"] = serde_json::from_slice(&canonical).unwrap();
        assert!(matches!(
            verify_delivery(&serde_json::to_vec(&value).unwrap(), &fixture.policy),
            Err(ProtocolError::InvalidJson { message, .. }) if message.contains("unknown field")
        ));

        let mut overlapping_roles = fixture.policy.clone();
        overlapping_roles.receivers[0].ed25519_public_key =
            overlapping_roles.senders[0].ed25519_public_key.clone();
        assert_eq!(
            canonical_trust_policy_bytes(&overlapping_roles).unwrap_err(),
            ProtocolError::InvalidField("signerRoleOverlap")
        );
    }

    #[test]
    fn applies_hard_input_limits_and_frozen_domains() {
        let fixture = Fixture::new();
        assert_eq!(
            verify_delivery(&[], &fixture.policy).unwrap_err(),
            ProtocolError::Empty { kind: "delivery" }
        );
        let oversized = vec![b' '; MAX_DELIVERY_BYTES + 1];
        assert_eq!(
            verify_delivery(&oversized, &fixture.policy).unwrap_err(),
            ProtocolError::TooLarge {
                kind: "delivery",
                actual: MAX_DELIVERY_BYTES + 1,
                maximum: MAX_DELIVERY_BYTES,
            }
        );

        let record = canonical_record_bytes(&fixture.record).unwrap();
        let delivery_message = build_delivery_signature_message(
            "dex-webhooks-prod",
            &fixture.policy.network,
            "sender-1",
            1,
            7,
            &record,
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(delivery_message)),
            "27312616c645e5bbc9c1df86c8eb35f9deaea2af1a9877953dba51209e79cac8"
        );
        let receipt_message = build_receipt_signature_message(
            "dex-webhooks-prod",
            &fixture.policy.network,
            "receiver-1",
            &hash('b'),
            &fixture.record.id,
            1,
            7,
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(receipt_message)),
            "d36e1639c51e3ff4d710aac2f6f733c68b1b616de194179550fdcca4786ae4bd"
        );
    }

    struct Fixture {
        policy: TrustPolicy,
        sender: SigningKey,
        receiver: SigningKey,
        record: OutboxRecord,
    }

    impl Fixture {
        fn new() -> Self {
            let sender = SigningKey::from_bytes(&[7; 32]);
            let receiver = SigningKey::from_bytes(&[9; 32]);
            let network = network();
            let record = build_outbox(&network, &hash('1'), &block(&network, 101, '2', '1'), &[])
                .unwrap()
                .records
                .remove(0);
            Self {
                policy: TrustPolicy {
                    destination_domain: "dex-webhooks-prod".into(),
                    network,
                    senders: vec![TrustedSigner {
                        signer_id: "sender-1".into(),
                        ed25519_public_key: format!(
                            "0x{}",
                            hex::encode(sender.verifying_key().as_bytes())
                        ),
                    }],
                    receivers: vec![TrustedSigner {
                        signer_id: "receiver-1".into(),
                        ed25519_public_key: format!(
                            "0x{}",
                            hex::encode(receiver.verifying_key().as_bytes())
                        ),
                    }],
                },
                sender,
                receiver,
                record,
            }
        }

        fn record_at(&self, height: u64, block_hash: char, parent_hash: char) -> OutboxRecord {
            build_outbox(
                &self.policy.network,
                &hash(parent_hash),
                &block(&self.policy.network, height, block_hash, parent_hash),
                &[],
            )
            .unwrap()
            .records
            .remove(0)
        }

        fn delivery(&self, attempt: u32, generation: u64, record: &OutboxRecord) -> Vec<u8> {
            let record = canonical_record_bytes(record).unwrap();
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

        fn receipt(&self, delivery: &VerifiedDelivery) -> Vec<u8> {
            let message = build_receipt_signature_message(
                &self.policy.destination_domain,
                &self.policy.network,
                "receiver-1",
                &delivery.sha256,
                &delivery.record.id,
                delivery.attempt,
                delivery.generation,
            )
            .unwrap();
            encode_accepted_receipt(
                &self.policy.destination_domain,
                &self.policy.network,
                "receiver-1",
                delivery,
                &self.receiver.sign(&message).to_bytes(),
            )
            .unwrap()
        }
    }

    fn raw_delivery_message(
        policy: &TrustPolicy,
        sender_id: &str,
        attempt: u32,
        generation: u64,
        record: &[u8],
    ) -> Vec<u8> {
        let mut output = Vec::new();
        append(&mut output, DELIVERY_SIGNATURE_DOMAIN).unwrap();
        append_context(&mut output, &policy.destination_domain, &policy.network).unwrap();
        append(&mut output, sender_id.as_bytes()).unwrap();
        output.extend_from_slice(&u64::from(attempt).to_be_bytes());
        output.extend_from_slice(&generation.to_be_bytes());
        append(&mut output, record).unwrap();
        output
    }

    fn network() -> ChainIdentity {
        ChainIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: hash('a'),
        }
    }

    fn block(
        network: &ChainIdentity,
        height: u64,
        block_hash: char,
        parent_hash: char,
    ) -> CanonicalBlock {
        serde_json::from_value(json!({
            "schema": "bloch.data.canonical-block.v1",
            "network": network,
            "height": height,
            "blockHash": hash(block_hash),
            "parentHash": hash(parent_hash),
            "stateRoot": hash('e'),
            "timestampUnixSeconds": 1_700_000_000_u64 + height,
            "events": []
        }))
        .unwrap()
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }
}
