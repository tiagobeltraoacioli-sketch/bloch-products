//! Offline, transport-neutral JSON protocol and SDK types for indexer reads.
//!
//! Callers supply already received bytes and decide how (or whether) to move
//! the returned bytes. This crate opens no socket, performs no I/O, exposes no
//! write operation, and makes no finality claim.

use bloch_indexer_core::CanonicalIndexer;
use bloch_indexer_query::{
    BlockPage, BlockResponse, EventPage, PageRequest, QueryError, ReadApiV1, StatusResponse,
    TipResponse,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const REQUEST_SCHEMA: &str = "bloch.data.query-request.v1";
pub const RESPONSE_SCHEMA: &str = "bloch.data.query-response.v1";
pub const MAX_REQUEST_JSON_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REQUEST_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestEnvelope {
    pub schema: String,
    pub request_id: String,
    pub request: ReadRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub enum ReadRequest {
    Status {},
    Tip {},
    Block { height: u64 },
    Blocks { limit: u16, cursor: Option<String> },
    Events { limit: u16, cursor: Option<String> },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResponseEnvelope {
    pub schema: String,
    pub request_id: Option<String>,
    pub outcome: ResponseOutcome,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ResponseOutcome {
    Ok { result: ReadResult },
    Error { error: ErrorBody },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ReadResult {
    Status(StatusResponse),
    Tip(TipResponse),
    Block(BlockResponse),
    Blocks(BlockPage),
    Events(EventPage),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidRequest,
    InvalidLimit,
    HeightOutsideCanonicalRange,
    InvalidCursor,
    CursorKindMismatch,
    CursorNetworkMismatch,
    CursorStale,
    InternalError,
}

impl ErrorCode {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "request does not satisfy the v1 contract",
            Self::InvalidLimit => "page limit is outside the permitted range",
            Self::HeightOutsideCanonicalRange => "height is outside the canonical range",
            Self::InvalidCursor => "cursor is invalid",
            Self::CursorKindMismatch => "cursor belongs to another query kind",
            Self::CursorNetworkMismatch => "cursor belongs to another network",
            Self::CursorStale => "cursor snapshot is no longer canonical",
            Self::InternalError => "request could not be completed",
        }
    }
}

impl ErrorBody {
    fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.message().into(),
        }
    }
}

/// Dispatches one strict v1 request without performing transport or I/O.
///
/// Protocol failures are returned as bounded JSON error envelopes. The
/// request identifier is echoed only after the complete request passes strict
/// decoding and identifier validation.
pub fn dispatch(indexer: &CanonicalIndexer, bytes: &[u8]) -> Vec<u8> {
    let request = match decode_request(bytes) {
        Ok(request) => request,
        Err(_) => return encode_infallible(error_response(None, ErrorCode::InvalidRequest)),
    };
    let request_id = Some(request.request_id.clone());
    let api = ReadApiV1::new(indexer);
    let result = match request.request {
        ReadRequest::Status {} => Ok(ReadResult::Status(api.status())),
        ReadRequest::Tip {} => Ok(ReadResult::Tip(api.tip())),
        ReadRequest::Block { height } => api.block(height).map(ReadResult::Block),
        ReadRequest::Blocks { limit, cursor } => api
            .blocks(PageRequest { limit, cursor })
            .map(ReadResult::Blocks),
        ReadRequest::Events { limit, cursor } => api
            .events(PageRequest { limit, cursor })
            .map(ReadResult::Events),
    };
    let response = match result {
        Ok(result) => ResponseEnvelope {
            schema: RESPONSE_SCHEMA.into(),
            request_id,
            outcome: ResponseOutcome::Ok { result },
        },
        Err(error) => error_response(request_id, map_query_error(error)),
    };
    encode_infallible(response)
}

/// Strict SDK-side encoder for a typed request.
pub fn encode_request(request: &RequestEnvelope) -> Result<Vec<u8>, SdkError> {
    validate_request(request)?;
    let bytes = serde_json::to_vec(request).map_err(|_| SdkError::InvalidMessage)?;
    if bytes.len() > MAX_REQUEST_JSON_BYTES {
        return Err(SdkError::TooLarge);
    }
    Ok(bytes)
}

/// Strict SDK-side response decoder for bytes returned by [`dispatch`].
pub fn decode_response(bytes: &[u8]) -> Result<ResponseEnvelope, SdkError> {
    if bytes.is_empty() {
        return Err(SdkError::InvalidMessage);
    }
    if bytes.len() > MAX_RESPONSE_JSON_BYTES {
        return Err(SdkError::TooLarge);
    }
    reject_duplicate_keys(bytes)?;
    let response: ResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|_| SdkError::InvalidMessage)?;
    if response.schema != RESPONSE_SCHEMA {
        return Err(SdkError::InvalidMessage);
    }
    validate_optional_request_id(response.request_id.as_deref())?;
    match &response.outcome {
        ResponseOutcome::Ok { result } => {
            if response.request_id.is_none() {
                return Err(SdkError::InvalidMessage);
            }
            validate_result_schema(result)?;
        }
        ResponseOutcome::Error { error } if error.message != error.code.message() => {
            return Err(SdkError::InvalidMessage);
        }
        ResponseOutcome::Error { .. } => {}
    }
    Ok(response)
}

fn validate_result_schema(result: &ReadResult) -> Result<(), SdkError> {
    let valid = match result {
        ReadResult::Status(value) => value.schema == "bloch.data.read-status.v1",
        ReadResult::Tip(value) => value.schema == "bloch.data.read-tip.v1",
        ReadResult::Block(value) => value.schema == "bloch.data.read-block.v1",
        ReadResult::Blocks(value) => value.schema == "bloch.data.read-block-page.v1",
        ReadResult::Events(value) => value.schema == "bloch.data.read-event-page.v1",
    };
    valid.then_some(()).ok_or(SdkError::InvalidMessage)
}

fn decode_request(bytes: &[u8]) -> Result<RequestEnvelope, SdkError> {
    if bytes.is_empty() {
        return Err(SdkError::InvalidMessage);
    }
    if bytes.len() > MAX_REQUEST_JSON_BYTES {
        return Err(SdkError::TooLarge);
    }
    reject_duplicate_keys(bytes)?;
    let request: RequestEnvelope =
        serde_json::from_slice(bytes).map_err(|_| SdkError::InvalidMessage)?;
    validate_request(&request)?;
    Ok(request)
}

fn validate_request(request: &RequestEnvelope) -> Result<(), SdkError> {
    if request.schema != REQUEST_SCHEMA {
        return Err(SdkError::InvalidMessage);
    }
    validate_request_id(&request.request_id)
}

fn validate_optional_request_id(request_id: Option<&str>) -> Result<(), SdkError> {
    if let Some(request_id) = request_id {
        validate_request_id(request_id)?;
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), SdkError> {
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_BYTES
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SdkError::InvalidMessage);
    }
    Ok(())
}

fn map_query_error(error: QueryError) -> ErrorCode {
    match error {
        QueryError::InvalidLimit { .. } => ErrorCode::InvalidLimit,
        QueryError::HeightOutsideCanonicalRange => ErrorCode::HeightOutsideCanonicalRange,
        QueryError::InvalidCursor => ErrorCode::InvalidCursor,
        QueryError::CursorKindMismatch => ErrorCode::CursorKindMismatch,
        QueryError::CursorNetworkMismatch => ErrorCode::CursorNetworkMismatch,
        QueryError::CursorStale => ErrorCode::CursorStale,
        QueryError::InternalSerialization => ErrorCode::InternalError,
    }
}

fn error_response(request_id: Option<String>, code: ErrorCode) -> ResponseEnvelope {
    ResponseEnvelope {
        schema: RESPONSE_SCHEMA.into(),
        request_id,
        outcome: ResponseOutcome::Error {
            error: ErrorBody::new(code),
        },
    }
}

fn encode_infallible(response: ResponseEnvelope) -> Vec<u8> {
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= MAX_RESPONSE_JSON_BYTES => bytes,
        _ => br#"{"schema":"bloch.data.query-response.v1","requestId":null,"outcome":{"type":"error","error":{"code":"internalError","message":"request could not be completed"}}}"#.to_vec(),
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SdkError {
    #[error("message does not satisfy the v1 protocol")]
    InvalidMessage,
    #[error("message exceeds the v1 byte limit")]
    TooLarge,
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), SdkError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked
        .deserialize(&mut deserializer)
        .map_err(|_| SdkError::InvalidMessage)?;
    deserializer.end().map_err(|_| SdkError::InvalidMessage)
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
