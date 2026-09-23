//! Offline authentication boundary for canonical-block ingestion.
//!
//! Verification authenticates a producer against a caller-pinned key and binds
//! the exact block bytes to a deployment domain, network, and immutable anchor.
//! It does not establish chain finality or authorize network access.

use crate::{InputError, MAX_CANONICAL_BLOCK_JSON_BYTES, parse_block, reject_duplicate_keys};
use bloch_indexer_core::{BlockAnchor, CanonicalBlock, CanonicalIndexer, ChainIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ENVELOPE_SCHEMA: &str = "bloch.indexer.authenticated-block.v1";
/// The only authentication-policy schema accepted by this crate.
pub const AUTHENTICATION_POLICY_SCHEMA: &str = "bloch.indexer.authentication-policy.v1";
/// Policies are operator configuration, not an unbounded data channel.
pub const MAX_AUTHENTICATION_POLICY_JSON_BYTES: usize = 64 * 1024;
const SIGNATURE_PROTOCOL_DOMAIN: &[u8] = b"bloch.indexer.authenticated-block.signature.v1";
const MAX_ENVELOPE_OVERHEAD_BYTES: usize = 64 * 1024;
/// A hex-encoded maximum-size block plus bounded envelope metadata.
pub const MAX_AUTHENTICATED_ENVELOPE_BYTES: usize =
    MAX_CANONICAL_BLOCK_JSON_BYTES * 2 + MAX_ENVELOPE_OVERHEAD_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedProducer {
    pub producer_id: String,
    /// Lowercase `0x`-prefixed, 32-byte Ed25519 public key.
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationPolicy {
    /// Operator-selected deployment boundary, for example `bloch-l2-prod-indexer-1`.
    pub deployment_domain: String,
    pub network: ChainIdentity,
    pub anchor: BlockAnchor,
    pub producers: Vec<TrustedProducer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedBlock {
    pub block: CanonicalBlock,
    pub canonical_block_bytes: Vec<u8>,
    pub canonical_block_sha256: String,
    pub producer_id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("authenticated envelope is empty")]
    Empty,
    #[error("authenticated envelope is too large: {actual} bytes exceeds the {maximum} byte limit")]
    TooLarge { actual: usize, maximum: usize },
    #[error("authentication policy JSON is empty")]
    PolicyEmpty,
    #[error(
        "authentication policy JSON is too large: {actual} bytes exceeds the {maximum} byte limit"
    )]
    PolicyTooLarge { actual: usize, maximum: usize },
    #[error("invalid authentication policy JSON: {0}")]
    InvalidPolicyJson(String),
    #[error("authentication policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("invalid authenticated envelope JSON: {0}")]
    InvalidJson(String),
    #[error("invalid authentication policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid authenticated envelope field: {0}")]
    InvalidField(&'static str),
    #[error("authenticated envelope does not match the pinned trust context")]
    TrustContextMismatch,
    #[error("untrusted producer")]
    UntrustedProducer,
    #[error("canonical block digest mismatch")]
    DigestMismatch,
    #[error("invalid producer signature")]
    InvalidSignature,
    #[error("invalid canonical block: {0}")]
    InvalidBlock(#[from] InputError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthenticatedEnvelope {
    schema: String,
    deployment_domain: String,
    network: ChainIdentity,
    anchor: BlockAnchor,
    producer_id: String,
    canonical_block_hex: String,
    canonical_block_sha256: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthenticationPolicyDocument {
    schema: String,
    deployment_domain: String,
    network: ChainIdentity,
    anchor: BlockAnchor,
    producers: Vec<TrustedProducerDocument>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedProducerDocument {
    producer_id: String,
    ed25519_public_key: String,
}

/// Parses a strictly encoded, versioned policy and verifies its canonical
/// SHA-256 digest against a value provisioned by the caller.
///
/// `expected_sha256` is part of the local trust configuration. It must never
/// be copied from an authenticated-block envelope or from the same untrusted
/// transport as `bytes`.
pub fn parse_authentication_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<AuthenticationPolicy, AuthenticationError> {
    if bytes.is_empty() {
        return Err(AuthenticationError::PolicyEmpty);
    }
    if bytes.len() > MAX_AUTHENTICATION_POLICY_JSON_BYTES {
        return Err(AuthenticationError::PolicyTooLarge {
            actual: bytes.len(),
            maximum: MAX_AUTHENTICATION_POLICY_JSON_BYTES,
        });
    }
    reject_duplicate_keys(bytes)
        .map_err(|error| AuthenticationError::InvalidPolicyJson(input_error_message(error)))?;
    let document: AuthenticationPolicyDocument = serde_json::from_slice(bytes)
        .map_err(|error| AuthenticationError::InvalidPolicyJson(error.to_string()))?;
    if document.schema != AUTHENTICATION_POLICY_SCHEMA {
        return Err(AuthenticationError::InvalidPolicy("schema"));
    }
    let mut policy = AuthenticationPolicy {
        deployment_domain: document.deployment_domain,
        network: document.network,
        anchor: document.anchor,
        producers: document
            .producers
            .into_iter()
            .map(|producer| TrustedProducer {
                producer_id: producer.producer_id,
                ed25519_public_key: producer.ed25519_public_key,
            })
            .collect(),
    };
    policy.producers.sort_by(|left, right| {
        left.producer_id
            .cmp(&right.producer_id)
            .then_with(|| left.ed25519_public_key.cmp(&right.ed25519_public_key))
    });
    validate_policy(&policy)?;

    let expected = decode_hex_exact(expected_sha256, 32)
        .map_err(|_| AuthenticationError::InvalidPolicy("expectedSha256"))?;
    let canonical = canonical_authentication_policy_bytes(&policy)?;
    if Sha256::digest(canonical).as_slice() != expected.as_slice() {
        return Err(AuthenticationError::PolicyDigestMismatch);
    }
    Ok(policy)
}

/// Returns the canonical JSON representation used to pin a policy digest.
///
/// Object fields have a frozen order and producers are sorted by producer ID,
/// then public key. Equivalent policies therefore have the same bytes even if
/// their source JSON field or producer order differs.
pub fn canonical_authentication_policy_bytes(
    policy: &AuthenticationPolicy,
) -> Result<Vec<u8>, AuthenticationError> {
    validate_policy(policy)?;
    let mut producers: Vec<_> = policy
        .producers
        .iter()
        .map(|producer| TrustedProducerDocument {
            producer_id: producer.producer_id.clone(),
            ed25519_public_key: producer.ed25519_public_key.clone(),
        })
        .collect();
    producers.sort_by(|left, right| {
        left.producer_id
            .cmp(&right.producer_id)
            .then_with(|| left.ed25519_public_key.cmp(&right.ed25519_public_key))
    });
    serde_json::to_vec(&AuthenticationPolicyDocument {
        schema: AUTHENTICATION_POLICY_SCHEMA.into(),
        deployment_domain: policy.deployment_domain.clone(),
        network: policy.network.clone(),
        anchor: policy.anchor.clone(),
        producers,
    })
    .map_err(|error| AuthenticationError::InvalidPolicyJson(error.to_string()))
}

/// Computes the lowercase `0x`-prefixed digest operators pin independently.
pub fn authentication_policy_sha256(
    policy: &AuthenticationPolicy,
) -> Result<String, AuthenticationError> {
    Ok(format!(
        "0x{}",
        hex::encode(Sha256::digest(canonical_authentication_policy_bytes(
            policy
        )?))
    ))
}

/// Verifies and decodes a single authenticated canonical-block envelope.
///
/// The trust policy must be provisioned independently of the envelope. An
/// envelope cannot introduce or replace a producer key.
pub fn verify_authenticated_block(
    bytes: &[u8],
    policy: &AuthenticationPolicy,
) -> Result<AuthenticatedBlock, AuthenticationError> {
    validate_policy(policy)?;
    if bytes.is_empty() {
        return Err(AuthenticationError::Empty);
    }
    if bytes.len() > MAX_AUTHENTICATED_ENVELOPE_BYTES {
        return Err(AuthenticationError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_AUTHENTICATED_ENVELOPE_BYTES,
        });
    }
    reject_duplicate_keys(bytes)
        .map_err(|error| AuthenticationError::InvalidJson(input_error_message(error)))?;
    let envelope: AuthenticatedEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| AuthenticationError::InvalidJson(error.to_string()))?;
    validate_envelope_fields(&envelope)?;

    if envelope.deployment_domain != policy.deployment_domain
        || envelope.network != policy.network
        || envelope.anchor != policy.anchor
    {
        return Err(AuthenticationError::TrustContextMismatch);
    }
    let trusted = policy
        .producers
        .iter()
        .find(|producer| producer.producer_id == envelope.producer_id)
        .ok_or(AuthenticationError::UntrustedProducer)?;

    let block_bytes = decode_prefixed_hex(
        &envelope.canonical_block_hex,
        MAX_CANONICAL_BLOCK_JSON_BYTES,
        "canonicalBlockHex",
    )?;
    let block_digest = Sha256::digest(&block_bytes);
    if envelope.canonical_block_sha256 != format!("0x{}", hex::encode(block_digest)) {
        return Err(AuthenticationError::DigestMismatch);
    }

    let verifying_key = parse_verifying_key(&trusted.ed25519_public_key)
        .map_err(|_| AuthenticationError::InvalidPolicy("producerPublicKey"))?;
    let signature_bytes = decode_prefixed_hex(&envelope.signature, 64, "signature")?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AuthenticationError::InvalidField("signature"))?;
    let message = build_signature_message(
        &envelope.deployment_domain,
        &envelope.network,
        &envelope.anchor,
        &envelope.producer_id,
        &block_bytes,
    )?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| AuthenticationError::InvalidSignature)?;

    let block = parse_block(&block_bytes)?;
    if block.network != envelope.network {
        return Err(AuthenticationError::TrustContextMismatch);
    }
    Ok(AuthenticatedBlock {
        block,
        canonical_block_bytes: block_bytes,
        canonical_block_sha256: envelope.canonical_block_sha256,
        producer_id: envelope.producer_id,
    })
}

fn validate_policy(policy: &AuthenticationPolicy) -> Result<(), AuthenticationError> {
    if !valid_text_identifier(&policy.deployment_domain, 256) {
        return Err(AuthenticationError::InvalidPolicy("deploymentDomain"));
    }
    if policy.producers.is_empty() || policy.producers.len() > 64 {
        return Err(AuthenticationError::InvalidPolicy("producers"));
    }
    for (position, producer) in policy.producers.iter().enumerate() {
        if !valid_text_identifier(&producer.producer_id, 128) {
            return Err(AuthenticationError::InvalidPolicy("producerId"));
        }
        parse_verifying_key(&producer.ed25519_public_key)
            .map_err(|_| AuthenticationError::InvalidPolicy("producerPublicKey"))?;
        if policy.producers[..position].iter().any(|other| {
            other.producer_id == producer.producer_id
                || other.ed25519_public_key == producer.ed25519_public_key
        }) {
            return Err(AuthenticationError::InvalidPolicy("duplicateProducer"));
        }
    }
    validate_context_fields(&policy.network, &policy.anchor)
        .map_err(|_| AuthenticationError::InvalidPolicy("chainContext"))
}

fn validate_envelope_fields(envelope: &AuthenticatedEnvelope) -> Result<(), AuthenticationError> {
    if envelope.schema != ENVELOPE_SCHEMA {
        return Err(AuthenticationError::InvalidField("schema"));
    }
    if !valid_text_identifier(&envelope.deployment_domain, 256) {
        return Err(AuthenticationError::InvalidField("deploymentDomain"));
    }
    if !valid_text_identifier(&envelope.producer_id, 128) {
        return Err(AuthenticationError::InvalidField("producerId"));
    }
    validate_context_fields(&envelope.network, &envelope.anchor)?;
    if !valid_hash(&envelope.canonical_block_sha256) {
        return Err(AuthenticationError::InvalidField("canonicalBlockSha256"));
    }
    Ok(())
}

fn validate_context_fields(
    network: &ChainIdentity,
    anchor: &BlockAnchor,
) -> Result<(), AuthenticationError> {
    CanonicalIndexer::new(network.clone(), anchor.clone(), 1)
        .map(|_| ())
        .map_err(|_| AuthenticationError::InvalidField("chainContext"))
}

/// Builds the deterministic bytes an offline producer signs.
///
/// Every variable-length field is prefixed by an unsigned 64-bit big-endian
/// byte length. Fixed-width integers are unsigned 64-bit big-endian values.
/// The payload is included byte-for-byte, rather than reserialized JSON.
pub fn build_signature_message(
    deployment_domain: &str,
    network: &ChainIdentity,
    anchor: &BlockAnchor,
    producer_id: &str,
    block_bytes: &[u8],
) -> Result<Vec<u8>, AuthenticationError> {
    if !valid_text_identifier(deployment_domain, 256) {
        return Err(AuthenticationError::InvalidField("deploymentDomain"));
    }
    if !valid_text_identifier(producer_id, 128) {
        return Err(AuthenticationError::InvalidField("producerId"));
    }
    validate_context_fields(network, anchor)?;
    if block_bytes.is_empty() || block_bytes.len() > MAX_CANONICAL_BLOCK_JSON_BYTES {
        return Err(AuthenticationError::InvalidField("canonicalBlockBytes"));
    }
    let mut message = Vec::with_capacity(block_bytes.len().saturating_add(512));
    append_bytes(&mut message, SIGNATURE_PROTOCOL_DOMAIN)?;
    append_bytes(&mut message, deployment_domain.as_bytes())?;
    append_bytes(&mut message, network.network.as_bytes())?;
    message.extend_from_slice(&network.chain_id.to_be_bytes());
    append_bytes(&mut message, network.genesis_hash.as_bytes())?;
    message.extend_from_slice(&anchor.height.to_be_bytes());
    append_bytes(&mut message, anchor.block_hash.as_bytes())?;
    append_bytes(&mut message, anchor.state_root.as_bytes())?;
    append_bytes(&mut message, producer_id.as_bytes())?;
    append_bytes(&mut message, block_bytes)?;
    Ok(message)
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthenticationError> {
    let length =
        u64::try_from(value.len()).map_err(|_| AuthenticationError::InvalidField("length"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn parse_verifying_key(value: &str) -> Result<VerifyingKey, ()> {
    let decoded = decode_hex_exact(value, 32).map_err(|_| ())?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| ())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ())
}

fn decode_prefixed_hex(
    value: &str,
    maximum_decoded_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, AuthenticationError> {
    if !value.starts_with("0x")
        || !value.len().is_multiple_of(2)
        || value.len().saturating_sub(2) / 2 > maximum_decoded_bytes
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuthenticationError::InvalidField(field));
    }
    hex::decode(&value[2..]).map_err(|_| AuthenticationError::InvalidField(field))
}

fn decode_hex_exact(value: &str, expected_bytes: usize) -> Result<Vec<u8>, ()> {
    if value.len() != 2 + expected_bytes * 2 {
        return Err(());
    }
    decode_prefixed_hex(value, expected_bytes, "hex").map_err(|_| ())
}

fn valid_hash(value: &str) -> bool {
    decode_hex_exact(value, 32).is_ok()
}

fn valid_text_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn input_error_message(error: InputError) -> String {
    match error {
        InputError::InvalidJson(message) => message,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    #[test]
    fn authenticates_exact_bytes_against_a_pinned_producer() {
        let fixture = Fixture::new();
        let encoded = fixture.envelope(&fixture.block_bytes, None);
        let verified = verify_authenticated_block(&encoded, &fixture.policy).unwrap();
        assert_eq!(verified.canonical_block_bytes, fixture.block_bytes);
        assert_eq!(verified.producer_id, "producer-1");
        assert_eq!(verified.block.height, 101);
    }

    #[test]
    fn rejects_payload_mutation_even_when_json_semantics_are_unchanged() {
        let fixture = Fixture::new();
        let mut changed = fixture.block_bytes.clone();
        changed.push(b' ');
        let encoded = fixture.envelope_with_signature(&changed, fixture.sign(&fixture.block_bytes));
        assert_eq!(
            verify_authenticated_block(&encoded, &fixture.policy).unwrap_err(),
            AuthenticationError::InvalidSignature
        );
    }

    #[test]
    fn rejects_digest_mutation_before_signature_acceptance() {
        let fixture = Fixture::new();
        let mut envelope: Value =
            serde_json::from_slice(&fixture.envelope(&fixture.block_bytes, None)).unwrap();
        envelope["canonicalBlockSha256"] = Value::String(hash('0'));
        assert_eq!(
            verify_authenticated_block(&serde_json::to_vec(&envelope).unwrap(), &fixture.policy)
                .unwrap_err(),
            AuthenticationError::DigestMismatch
        );
    }

    #[test]
    fn rejects_context_replay_and_untrusted_producers() {
        let fixture = Fixture::new();
        let encoded = fixture.envelope(&fixture.block_bytes, None);
        let mut wrong_domain = fixture.policy.clone();
        wrong_domain.deployment_domain = "another-deployment".into();
        assert_eq!(
            verify_authenticated_block(&encoded, &wrong_domain).unwrap_err(),
            AuthenticationError::TrustContextMismatch
        );

        let mut no_producer = fixture.policy.clone();
        no_producer.producers[0].producer_id = "producer-2".into();
        assert_eq!(
            verify_authenticated_block(&encoded, &no_producer).unwrap_err(),
            AuthenticationError::UntrustedProducer
        );
    }

    #[test]
    fn rejects_duplicate_keys_unknown_fields_and_trailing_json() {
        let fixture = Fixture::new();
        let text = String::from_utf8(fixture.envelope(&fixture.block_bytes, None)).unwrap();
        let duplicate = text.replacen(
            "\"schema\":",
            "\"schema\":\"bloch.indexer.authenticated-block.v1\",\"schema\":",
            1,
        );
        assert!(matches!(
            verify_authenticated_block(duplicate.as_bytes(), &fixture.policy),
            Err(AuthenticationError::InvalidJson(message)) if message.contains("duplicate")
        ));

        let mut unknown: Value = serde_json::from_str(&text).unwrap();
        unknown["activate"] = Value::Bool(true);
        assert!(matches!(
            verify_authenticated_block(&serde_json::to_vec(&unknown).unwrap(), &fixture.policy),
            Err(AuthenticationError::InvalidJson(message)) if message.contains("unknown field")
        ));
        assert!(matches!(
            verify_authenticated_block(format!("{text} {{}}").as_bytes(), &fixture.policy),
            Err(AuthenticationError::InvalidJson(_))
        ));
    }

    #[test]
    fn envelope_cannot_present_a_policy_or_producer_key() {
        let fixture = Fixture::new();
        let encoded = fixture.envelope(&fixture.block_bytes, None);

        for (field, value) in [
            (
                "ed25519PublicKey",
                Value::String(fixture.policy.producers[0].ed25519_public_key.clone()),
            ),
            (
                "authenticationPolicy",
                serde_json::from_slice(&policy_json(&fixture.policy, false)).unwrap(),
            ),
        ] {
            let mut envelope: Value = serde_json::from_slice(&encoded).unwrap();
            envelope[field] = value;
            assert!(matches!(
                verify_authenticated_block(
                    &serde_json::to_vec(&envelope).unwrap(),
                    &fixture.policy
                ),
                Err(AuthenticationError::InvalidJson(message)) if message.contains("unknown field")
            ));
        }
    }

    #[test]
    fn rejects_a_signed_block_with_duplicate_inner_keys() {
        let fixture = Fixture::new();
        let malicious = String::from_utf8(fixture.block_bytes.clone())
            .unwrap()
            .replacen("\"height\":101", "\"height\":101,\"height\":101", 1)
            .into_bytes();
        let encoded = fixture.envelope(&malicious, None);
        assert!(matches!(
            verify_authenticated_block(&encoded, &fixture.policy),
            Err(AuthenticationError::InvalidBlock(InputError::InvalidJson(message)))
                if message.contains("duplicate JSON object key: height")
        ));
    }

    #[test]
    fn signature_message_encoding_is_frozen() {
        let fixture = Fixture::new();
        let message = build_signature_message(
            &fixture.policy.deployment_domain,
            &fixture.policy.network,
            &fixture.policy.anchor,
            "producer-1",
            &fixture.block_bytes,
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(message)),
            "7782ddc11ad1968a713656f53854e02ad708832632b37935e46e716c66551dea"
        );
    }

    #[test]
    fn rejects_noncanonical_hex_and_wrong_block_network() {
        let fixture = Fixture::new();
        let mut uppercase: Value =
            serde_json::from_slice(&fixture.envelope(&fixture.block_bytes, None)).unwrap();
        uppercase["signature"] = Value::String(format!("0x{}", "AA".repeat(64)));
        assert_eq!(
            verify_authenticated_block(&serde_json::to_vec(&uppercase).unwrap(), &fixture.policy)
                .unwrap_err(),
            AuthenticationError::InvalidField("signature")
        );

        let mut other_block: Value = serde_json::from_slice(&fixture.block_bytes).unwrap();
        other_block["network"]["chainId"] = Value::from(700772_u64);
        let other_bytes = serde_json::to_vec(&other_block).unwrap();
        let encoded = fixture.envelope(&other_bytes, None);
        assert_eq!(
            verify_authenticated_block(&encoded, &fixture.policy).unwrap_err(),
            AuthenticationError::TrustContextMismatch
        );
    }

    #[test]
    fn rejects_unsafe_sizes_and_ambiguous_policies() {
        let fixture = Fixture::new();
        assert_eq!(
            verify_authenticated_block(&[], &fixture.policy).unwrap_err(),
            AuthenticationError::Empty
        );
        let oversized = vec![b' '; MAX_AUTHENTICATED_ENVELOPE_BYTES + 1];
        assert_eq!(
            verify_authenticated_block(&oversized, &fixture.policy).unwrap_err(),
            AuthenticationError::TooLarge {
                actual: MAX_AUTHENTICATED_ENVELOPE_BYTES + 1,
                maximum: MAX_AUTHENTICATED_ENVELOPE_BYTES,
            }
        );
        let mut duplicate = fixture.policy.clone();
        duplicate.producers.push(duplicate.producers[0].clone());
        assert_eq!(
            verify_authenticated_block(&fixture.envelope(&fixture.block_bytes, None), &duplicate)
                .unwrap_err(),
            AuthenticationError::InvalidPolicy("duplicateProducer")
        );
    }

    #[test]
    fn policy_digest_is_canonical_across_field_and_producer_reordering() {
        let fixture = Fixture::new();
        let second_key = SigningKey::from_bytes(&[8; 32]);
        let mut policy = fixture.policy.clone();
        policy.producers.push(TrustedProducer {
            producer_id: "producer-2".into(),
            ed25519_public_key: format!("0x{}", hex::encode(second_key.verifying_key().as_bytes())),
        });
        let digest = authentication_policy_sha256(&policy).unwrap();
        let first = policy_json(&policy, false);
        let second = format!(
            concat!(
                "{{\"producers\":{},\"anchor\":{},\"network\":{},",
                "\"deploymentDomain\":{},\"schema\":{}}}"
            ),
            serde_json::to_string(&serde_json::json!([
                {
                    "ed25519PublicKey": policy.producers[1].ed25519_public_key,
                    "producerId": policy.producers[1].producer_id,
                },
                {
                    "ed25519PublicKey": policy.producers[0].ed25519_public_key,
                    "producerId": policy.producers[0].producer_id,
                }
            ]))
            .unwrap(),
            serde_json::to_string(&policy.anchor).unwrap(),
            serde_json::to_string(&policy.network).unwrap(),
            serde_json::to_string(&policy.deployment_domain).unwrap(),
            serde_json::to_string(AUTHENTICATION_POLICY_SCHEMA).unwrap(),
        );

        assert_eq!(
            parse_authentication_policy(&first, &digest).unwrap(),
            policy
        );
        assert_eq!(
            parse_authentication_policy(second.as_bytes(), &digest).unwrap(),
            policy
        );
    }

    #[test]
    fn canonical_policy_digest_encoding_is_frozen() {
        let fixture = Fixture::new();
        assert_eq!(
            authentication_policy_sha256(&fixture.policy).unwrap(),
            "0xc8cc06c48335a4bff3d67245b106550f364e4364587d6ebd4627e2e05812fa1f"
        );
    }

    #[test]
    fn policy_parser_rejects_wrong_digest_duplicates_unknowns_and_trailing_json() {
        let fixture = Fixture::new();
        let bytes = policy_json(&fixture.policy, false);
        assert_eq!(
            parse_authentication_policy(&bytes, &hash('0')).unwrap_err(),
            AuthenticationError::PolicyDigestMismatch
        );
        assert_eq!(
            parse_authentication_policy(&bytes, "0xNOT-A-DIGEST").unwrap_err(),
            AuthenticationError::InvalidPolicy("expectedSha256")
        );

        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen(
            "\"schema\":",
            "\"schema\":\"bloch.indexer.authentication-policy.v1\",\"schema\":",
            1,
        );
        assert!(matches!(
            parse_authentication_policy(duplicate.as_bytes(), &hash('0')),
            Err(AuthenticationError::InvalidPolicyJson(message)) if message.contains("duplicate")
        ));
        let unknown = text.replacen('{', "{\"activate\":true,", 1);
        assert!(matches!(
            parse_authentication_policy(unknown.as_bytes(), &hash('0')),
            Err(AuthenticationError::InvalidPolicyJson(message)) if message.contains("unknown field")
        ));
        assert!(matches!(
            parse_authentication_policy(format!("{text} {{}}").as_bytes(), &hash('0')),
            Err(AuthenticationError::InvalidPolicyJson(_))
        ));
    }

    #[test]
    fn policy_parser_rejects_ambiguous_producers() {
        let fixture = Fixture::new();
        let mut duplicate_id = fixture.policy.clone();
        duplicate_id
            .producers
            .push(duplicate_id.producers[0].clone());
        let bytes = policy_json(&duplicate_id, false);
        assert_eq!(
            parse_authentication_policy(&bytes, &hash('0')).unwrap_err(),
            AuthenticationError::InvalidPolicy("duplicateProducer")
        );

        let second_key = SigningKey::from_bytes(&[8; 32]);
        let mut duplicate_id = fixture.policy.clone();
        duplicate_id.producers.push(TrustedProducer {
            producer_id: "producer-1".into(),
            ed25519_public_key: format!("0x{}", hex::encode(second_key.verifying_key().as_bytes())),
        });
        assert_eq!(
            parse_authentication_policy(&policy_json(&duplicate_id, false), &hash('0'))
                .unwrap_err(),
            AuthenticationError::InvalidPolicy("duplicateProducer")
        );

        let mut duplicate_key = fixture.policy.clone();
        duplicate_key.producers.push(TrustedProducer {
            producer_id: "producer-2".into(),
            ed25519_public_key: duplicate_key.producers[0].ed25519_public_key.clone(),
        });
        assert_eq!(
            parse_authentication_policy(&policy_json(&duplicate_key, false), &hash('0'))
                .unwrap_err(),
            AuthenticationError::InvalidPolicy("duplicateProducer")
        );

        // A distinct producer remains valid; keep the key alive to make the
        // intended distinction explicit in this adversarial fixture.
        duplicate_key.producers[1].ed25519_public_key =
            format!("0x{}", hex::encode(second_key.verifying_key().as_bytes()));
        assert!(authentication_policy_sha256(&duplicate_key).is_ok());
    }

    #[test]
    fn pinned_policy_digest_rejects_network_and_anchor_substitution() {
        let fixture = Fixture::new();
        let digest = authentication_policy_sha256(&fixture.policy).unwrap();

        let mut other_network = fixture.policy.clone();
        other_network.network.chain_id = 700_772;
        assert_eq!(
            parse_authentication_policy(&policy_json(&other_network, false), &digest).unwrap_err(),
            AuthenticationError::PolicyDigestMismatch
        );

        let mut other_anchor = fixture.policy.clone();
        other_anchor.anchor.block_hash = hash('2');
        assert_eq!(
            parse_authentication_policy(&policy_json(&other_anchor, false), &digest).unwrap_err(),
            AuthenticationError::PolicyDigestMismatch
        );
    }

    #[test]
    fn policy_parser_applies_its_own_size_and_schema_boundaries() {
        assert_eq!(
            parse_authentication_policy(&[], &hash('0')).unwrap_err(),
            AuthenticationError::PolicyEmpty
        );
        let oversized = vec![b' '; MAX_AUTHENTICATION_POLICY_JSON_BYTES + 1];
        assert_eq!(
            parse_authentication_policy(&oversized, &hash('0')).unwrap_err(),
            AuthenticationError::PolicyTooLarge {
                actual: MAX_AUTHENTICATION_POLICY_JSON_BYTES + 1,
                maximum: MAX_AUTHENTICATION_POLICY_JSON_BYTES,
            }
        );

        let fixture = Fixture::new();
        let mut wrong_schema: Value =
            serde_json::from_slice(&policy_json(&fixture.policy, false)).unwrap();
        wrong_schema["schema"] = Value::String("bloch.indexer.authentication-policy.v2".into());
        assert_eq!(
            parse_authentication_policy(&serde_json::to_vec(&wrong_schema).unwrap(), &hash('0'))
                .unwrap_err(),
            AuthenticationError::InvalidPolicy("schema")
        );
    }

    struct Fixture {
        signing_key: SigningKey,
        policy: AuthenticationPolicy,
        block_bytes: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            let network = ChainIdentity {
                network: "bloch-l2".into(),
                chain_id: 700771,
                genesis_hash: hash('9'),
            };
            let anchor = BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('8'),
            };
            let block_bytes = serde_json::to_vec(&json!({
                "schema": "bloch.data.canonical-block.v1",
                "network": network,
                "height": 101,
                "blockHash": hash('2'),
                "parentHash": hash('1'),
                "stateRoot": hash('a'),
                "timestampUnixSeconds": 1790000101_u64,
                "events": [],
            }))
            .unwrap();
            let policy = AuthenticationPolicy {
                deployment_domain: "bloch-l2-prod-indexer-1".into(),
                network,
                anchor,
                producers: vec![TrustedProducer {
                    producer_id: "producer-1".into(),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(signing_key.verifying_key().as_bytes())
                    ),
                }],
            };
            Self {
                signing_key,
                policy,
                block_bytes,
            }
        }

        fn sign(&self, block_bytes: &[u8]) -> Signature {
            let message = build_signature_message(
                &self.policy.deployment_domain,
                &self.policy.network,
                &self.policy.anchor,
                "producer-1",
                block_bytes,
            )
            .unwrap();
            self.signing_key.sign(&message)
        }

        fn envelope(&self, block_bytes: &[u8], signature: Option<Signature>) -> Vec<u8> {
            self.envelope_with_signature(
                block_bytes,
                signature.unwrap_or_else(|| self.sign(block_bytes)),
            )
        }

        fn envelope_with_signature(&self, block_bytes: &[u8], signature: Signature) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "schema": ENVELOPE_SCHEMA,
                "deploymentDomain": self.policy.deployment_domain,
                "network": self.policy.network,
                "anchor": self.policy.anchor,
                "producerId": "producer-1",
                "canonicalBlockHex": format!("0x{}", hex::encode(block_bytes)),
                "canonicalBlockSha256": format!("0x{}", hex::encode(Sha256::digest(block_bytes))),
                "signature": format!("0x{}", hex::encode(signature.to_bytes())),
            }))
            .unwrap()
        }
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }

    fn policy_json(policy: &AuthenticationPolicy, reverse_producers: bool) -> Vec<u8> {
        let mut producer_order: Vec<_> = policy.producers.iter().collect();
        if reverse_producers {
            producer_order.reverse();
        }
        let producers: Vec<_> = producer_order
            .into_iter()
            .map(|producer| {
                json!({
                    "producerId": producer.producer_id,
                    "ed25519PublicKey": producer.ed25519_public_key,
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "schema": AUTHENTICATION_POLICY_SCHEMA,
            "deploymentDomain": policy.deployment_domain,
            "network": policy.network,
            "anchor": policy.anchor,
            "producers": producers,
        }))
        .unwrap()
    }
}
