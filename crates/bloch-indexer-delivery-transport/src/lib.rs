//! Strict, offline transport boundary for authenticated indexer deliveries.
//!
//! Callers own the actual transport. This crate opens no socket, performs no
//! file or network I/O, and has no private-key access. It only encodes and
//! decodes bounded request/response bytes and delegates payload authentication
//! to `bloch-indexer-delivery-protocol`.
//!
//! A decoded response authenticates receiver acceptance of the exact delivery.
//! It is not chain finality and never acknowledges durable state automatically.

use bloch_indexer_delivery_protocol::{
    MAX_DELIVERY_BYTES, MAX_RECEIPT_BYTES, TrustPolicy, VerifiedDelivery, VerifiedReceipt,
    verify_accepted_receipt, verify_delivery,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const REQUEST_SCHEMA: &str = "bloch.data.delivery-transport-request.v1";
pub const RESPONSE_SCHEMA: &str = "bloch.data.delivery-transport-response.v1";
pub const DELIVERY_CONTENT_TYPE: &str = "application/vnd.bloch.authenticated-delivery+json";
pub const RECEIPT_CONTENT_TYPE: &str = "application/vnd.bloch.authenticated-receipt+json";
pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_REQUEST_BYTES: usize = MAX_DELIVERY_BYTES * 2 + 4 * 1024;
pub const MAX_RESPONSE_BYTES: usize = MAX_RECEIPT_BYTES * 2 + 4 * 1024;

#[derive(Clone, Copy)]
struct Contract {
    schema: &'static str,
    content_type: &'static str,
}

const REQUEST_CONTRACT: Contract = Contract {
    schema: REQUEST_SCHEMA,
    content_type: DELIVERY_CONTENT_TYPE,
};
const RESPONSE_CONTRACT: Contract = Contract {
    schema: RESPONSE_SCHEMA,
    content_type: RECEIPT_CONTENT_TYPE,
};

/// A request accepted at the transport boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRequest {
    request_id: String,
    delivery_bytes: Vec<u8>,
    delivery: VerifiedDelivery,
}

impl VerifiedRequest {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn delivery_bytes(&self) -> &[u8] {
        &self.delivery_bytes
    }

    pub fn delivery(&self) -> &VerifiedDelivery {
        &self.delivery
    }
}

/// A response accepted at the transport boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResponse {
    request_id: String,
    receipt_bytes: Vec<u8>,
    receipt: VerifiedReceipt,
}

impl VerifiedResponse {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    pub fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }
}

/// Stable public failures for the transport boundary.
///
/// Cryptographic protocol details intentionally collapse into `InvalidDelivery`
/// or `InvalidReceipt`; callers must not make security decisions from parser or
/// signature implementation details.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("transport message is empty")]
    Empty,
    #[error("transport message exceeds its byte limit")]
    MessageTooLarge,
    #[error("transport message is not strict canonical JSON")]
    InvalidMessage,
    #[error("transport schema is unsupported")]
    UnsupportedSchema,
    #[error("transport content type is unsupported")]
    UnsupportedContentType,
    #[error("transport protocol version is unsupported")]
    UnsupportedVersion,
    #[error("transport destination domain does not match pinned policy")]
    DomainMismatch,
    #[error("transport request identifier is invalid")]
    InvalidRequestId,
    #[error("embedded payload exceeds its byte limit")]
    PayloadTooLarge,
    #[error("embedded delivery is invalid")]
    InvalidDelivery,
    #[error("embedded acceptance receipt is invalid")]
    InvalidReceipt,
    #[error("transport response does not match the expected request")]
    RequestMismatch,
}

impl TransportError {
    /// Frozen machine-readable code suitable for metrics and caller-owned
    /// transport error mapping. These codes never include parser or signature
    /// implementation details.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::MessageTooLarge => "message_too_large",
            Self::InvalidMessage => "invalid_message",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::UnsupportedVersion => "unsupported_version",
            Self::DomainMismatch => "domain_mismatch",
            Self::InvalidRequestId => "invalid_request_id",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidDelivery => "invalid_delivery",
            Self::InvalidReceipt => "invalid_receipt",
            Self::RequestMismatch => "request_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestEnvelope {
    schema: String,
    content_type: String,
    protocol_version: u16,
    destination_domain: String,
    request_id: String,
    delivery_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResponseEnvelope {
    schema: String,
    content_type: String,
    protocol_version: u16,
    destination_domain: String,
    request_id: String,
    receipt_hex: String,
}

/// Encodes a request only after authenticating the embedded delivery.
pub fn encode_request(
    request_id: &str,
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<Vec<u8>, TransportError> {
    validate_request_id(request_id)?;
    check_payload_limit(delivery_bytes, MAX_DELIVERY_BYTES)?;
    verify_delivery(delivery_bytes, policy).map_err(|_| TransportError::InvalidDelivery)?;
    encode_bounded(
        &RequestEnvelope {
            schema: REQUEST_SCHEMA.into(),
            content_type: DELIVERY_CONTENT_TYPE.into(),
            protocol_version: PROTOCOL_VERSION,
            destination_domain: policy.destination_domain.clone(),
            request_id: request_id.into(),
            delivery_hex: encode_hex(delivery_bytes),
        },
        MAX_REQUEST_BYTES,
    )
}

/// Strictly decodes a request and authenticates the embedded delivery.
pub fn decode_request(
    bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<VerifiedRequest, TransportError> {
    let envelope: RequestEnvelope = decode_envelope(bytes, MAX_REQUEST_BYTES)?;
    validate_common(
        &envelope.schema,
        &envelope.content_type,
        envelope.protocol_version,
        &envelope.destination_domain,
        policy,
        &envelope.request_id,
        REQUEST_CONTRACT,
    )?;
    let delivery_bytes = decode_hex_bounded(&envelope.delivery_hex, MAX_DELIVERY_BYTES)?;
    let delivery =
        verify_delivery(&delivery_bytes, policy).map_err(|_| TransportError::InvalidDelivery)?;
    Ok(VerifiedRequest {
        request_id: envelope.request_id,
        delivery_bytes,
        delivery,
    })
}

/// Encodes a response only after authenticating its receipt against the exact
/// delivery supplied by the caller.
pub fn encode_response(
    request_id: &str,
    receipt_bytes: &[u8],
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<Vec<u8>, TransportError> {
    validate_request_id(request_id)?;
    check_payload_limit(receipt_bytes, MAX_RECEIPT_BYTES)?;
    check_payload_limit(delivery_bytes, MAX_DELIVERY_BYTES)?;
    verify_accepted_receipt(receipt_bytes, delivery_bytes, policy)
        .map_err(|_| TransportError::InvalidReceipt)?;
    encode_bounded(
        &ResponseEnvelope {
            schema: RESPONSE_SCHEMA.into(),
            content_type: RECEIPT_CONTENT_TYPE.into(),
            protocol_version: PROTOCOL_VERSION,
            destination_domain: policy.destination_domain.clone(),
            request_id: request_id.into(),
            receipt_hex: encode_hex(receipt_bytes),
        },
        MAX_RESPONSE_BYTES,
    )
}

/// Strictly decodes a response, binds its routing identifier to the expected
/// request, and authenticates its receipt against the exact delivery.
pub fn decode_response(
    bytes: &[u8],
    expected_request_id: &str,
    delivery_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<VerifiedResponse, TransportError> {
    validate_request_id(expected_request_id)?;
    check_payload_limit(delivery_bytes, MAX_DELIVERY_BYTES)?;
    let envelope: ResponseEnvelope = decode_envelope(bytes, MAX_RESPONSE_BYTES)?;
    validate_common(
        &envelope.schema,
        &envelope.content_type,
        envelope.protocol_version,
        &envelope.destination_domain,
        policy,
        &envelope.request_id,
        RESPONSE_CONTRACT,
    )?;
    if envelope.request_id != expected_request_id {
        return Err(TransportError::RequestMismatch);
    }
    let receipt_bytes = decode_hex_bounded(&envelope.receipt_hex, MAX_RECEIPT_BYTES)?;
    let receipt = verify_accepted_receipt(&receipt_bytes, delivery_bytes, policy)
        .map_err(|_| TransportError::InvalidReceipt)?;
    Ok(VerifiedResponse {
        request_id: envelope.request_id,
        receipt_bytes,
        receipt,
    })
}

fn validate_common(
    actual_schema: &str,
    actual_content_type: &str,
    version: u16,
    destination_domain: &str,
    policy: &TrustPolicy,
    request_id: &str,
    contract: Contract,
) -> Result<(), TransportError> {
    if actual_schema != contract.schema {
        return Err(TransportError::UnsupportedSchema);
    }
    if actual_content_type != contract.content_type {
        return Err(TransportError::UnsupportedContentType);
    }
    if version != PROTOCOL_VERSION {
        return Err(TransportError::UnsupportedVersion);
    }
    if destination_domain != policy.destination_domain {
        return Err(TransportError::DomainMismatch);
    }
    validate_request_id(request_id)
}

fn validate_request_id(value: &str) -> Result<(), TransportError> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TransportError::InvalidRequestId);
    }
    Ok(())
}

fn check_payload_limit(bytes: &[u8], maximum: usize) -> Result<(), TransportError> {
    if bytes.is_empty() {
        return Err(TransportError::InvalidMessage);
    }
    if bytes.len() > maximum {
        return Err(TransportError::PayloadTooLarge);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decode_hex_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, TransportError> {
    let encoded = value
        .strip_prefix("0x")
        .ok_or(TransportError::InvalidMessage)?;
    if encoded.is_empty() || encoded.len() > maximum.saturating_mul(2) {
        return Err(if encoded.len() > maximum.saturating_mul(2) {
            TransportError::PayloadTooLarge
        } else {
            TransportError::InvalidMessage
        });
    }
    if encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(TransportError::InvalidMessage);
    }
    hex::decode(encoded).map_err(|_| TransportError::InvalidMessage)
}

fn encode_bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, TransportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| TransportError::InvalidMessage)?;
    if bytes.len() > maximum {
        return Err(TransportError::MessageTooLarge);
    }
    Ok(bytes)
}

fn decode_envelope<T>(bytes: &[u8], maximum: usize) -> Result<T, TransportError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() {
        return Err(TransportError::Empty);
    }
    if bytes.len() > maximum {
        return Err(TransportError::MessageTooLarge);
    }
    reject_duplicate_keys(bytes)?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| TransportError::InvalidMessage)?;
    if serde_json::to_vec(&value).map_err(|_| TransportError::InvalidMessage)? != bytes {
        return Err(TransportError::InvalidMessage);
    }
    Ok(value)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), TransportError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked
        .deserialize(&mut deserializer)
        .map_err(|_| TransportError::InvalidMessage)?;
    deserializer
        .end()
        .map_err(|_| TransportError::InvalidMessage)
}

struct DuplicateChecked;

impl<'de> DeserializeSeed<'de> for DuplicateChecked {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedVisitor)
    }
}

struct DuplicateCheckedVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
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

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateChecked)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(DuplicateChecked)?;
        }
        Ok(())
    }
}
