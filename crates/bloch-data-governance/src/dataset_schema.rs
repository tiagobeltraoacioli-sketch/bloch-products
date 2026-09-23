use crate::{MAX_FIELDS, reject_duplicate_keys, valid_identifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DATASET_SCHEMA_SCHEMA: &str = "bloch.data.dataset-schema.v1";
pub const MAX_DATASET_SCHEMA_BYTES: usize = 256 * 1024;
pub const MAX_STRING_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARRAY_ITEMS: u64 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DatasetSchema {
    pub schema: String,
    pub schema_id: String,
    pub version: u64,
    pub fields: Vec<DatasetFieldSchema>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DatasetFieldSchema {
    pub field_id: String,
    pub required: bool,
    pub value: DatasetValueSchema,
}

/// V1 deliberately excludes objects, nulls and floating-point numbers. Arrays
/// may contain only one explicitly selected scalar type.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DatasetValueSchema {
    Boolean,
    Integer {
        minimum: i64,
        maximum: i64,
    },
    String {
        min_bytes: u64,
        max_bytes: u64,
    },
    Array {
        items: ScalarType,
        min_items: u64,
        max_items: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    Boolean,
    Integer,
    String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DatasetSchemaError {
    #[error("dataset schema input is empty")]
    Empty,
    #[error("dataset schema exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid dataset schema JSON: {0}")]
    InvalidJson(String),
    #[error("invalid dataset schema field: {0}")]
    InvalidSchema(&'static str),
    #[error("dataset schema is not canonical JSON")]
    NonCanonicalSchema,
    #[error("dataset schema digest mismatch")]
    SchemaDigestMismatch,
    #[error("record does not conform to dataset schema: {0}")]
    RecordMismatch(String),
    #[error("cannot encode dataset schema: {0}")]
    Encoding(String),
}

pub fn canonical_dataset_schema_bytes(
    schema: &DatasetSchema,
) -> Result<Vec<u8>, DatasetSchemaError> {
    validate_schema(schema)?;
    serde_json::to_vec(schema).map_err(|error| DatasetSchemaError::Encoding(error.to_string()))
}

pub fn dataset_schema_sha256(schema: &DatasetSchema) -> Result<String, DatasetSchemaError> {
    Ok(sha256(&canonical_dataset_schema_bytes(schema)?))
}

pub fn parse_dataset_schema(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<DatasetSchema, DatasetSchemaError> {
    if bytes.is_empty() {
        return Err(DatasetSchemaError::Empty);
    }
    if bytes.len() > MAX_DATASET_SCHEMA_BYTES {
        return Err(DatasetSchemaError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_DATASET_SCHEMA_BYTES,
        });
    }
    if !valid_sha256(expected_sha256) {
        return Err(DatasetSchemaError::InvalidSchema("expectedSha256"));
    }
    reject_duplicate_keys(bytes)
        .map_err(|error| DatasetSchemaError::InvalidJson(error.to_string()))?;
    let schema: DatasetSchema = serde_json::from_slice(bytes)
        .map_err(|error| DatasetSchemaError::InvalidJson(error.to_string()))?;
    validate_schema(&schema)?;
    if canonical_dataset_schema_bytes(&schema)? != bytes {
        return Err(DatasetSchemaError::NonCanonicalSchema);
    }
    if sha256(bytes) != expected_sha256 {
        return Err(DatasetSchemaError::SchemaDigestMismatch);
    }
    Ok(schema)
}

pub(crate) fn validate_record(
    schema: &DatasetSchema,
    object: &Map<String, Value>,
) -> Result<(), DatasetSchemaError> {
    validate_schema(schema)?;
    for field in &schema.fields {
        match object.get(&field.field_id) {
            Some(value) => validate_value(&field.value, value).map_err(|reason| {
                DatasetSchemaError::RecordMismatch(format!("{}:{reason}", field.field_id))
            })?,
            None if field.required => {
                return Err(DatasetSchemaError::RecordMismatch(format!(
                    "{}:required",
                    field.field_id
                )));
            }
            None => {}
        }
    }
    if let Some(unknown) = object.keys().find(|key| {
        schema
            .fields
            .binary_search_by(|field| field.field_id.cmp(key))
            .is_err()
    }) {
        return Err(DatasetSchemaError::RecordMismatch(format!(
            "{unknown}:unknown"
        )));
    }
    Ok(())
}

fn validate_schema(schema: &DatasetSchema) -> Result<(), DatasetSchemaError> {
    if schema.schema != DATASET_SCHEMA_SCHEMA {
        return invalid("schema");
    }
    if !valid_identifier(&schema.schema_id) || schema.version == 0 {
        return invalid("identity");
    }
    if schema.fields.is_empty() || schema.fields.len() > MAX_FIELDS {
        return invalid("fields");
    }
    let mut previous: Option<&str> = None;
    for field in &schema.fields {
        if !valid_identifier(&field.field_id)
            || previous.is_some_and(|prior| prior >= field.field_id.as_str())
        {
            return invalid("fieldId");
        }
        previous = Some(&field.field_id);
        match field.value {
            DatasetValueSchema::Integer { minimum, maximum } if minimum > maximum => {
                return invalid("integerBounds");
            }
            DatasetValueSchema::String {
                min_bytes,
                max_bytes,
            } if min_bytes > max_bytes || max_bytes > MAX_STRING_BYTES => {
                return invalid("stringBounds");
            }
            DatasetValueSchema::Array {
                min_items,
                max_items,
                ..
            } if min_items > max_items || max_items > MAX_ARRAY_ITEMS => {
                return invalid("arrayBounds");
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_value(schema: &DatasetValueSchema, value: &Value) -> Result<(), &'static str> {
    match schema {
        DatasetValueSchema::Boolean if value.is_boolean() => Ok(()),
        DatasetValueSchema::Integer { minimum, maximum } => value
            .as_i64()
            .filter(|value| value >= minimum && value <= maximum)
            .map(|_| ())
            .ok_or("integer_type_or_bounds"),
        DatasetValueSchema::String {
            min_bytes,
            max_bytes,
        } => value
            .as_str()
            .map(|value| value.len() as u64)
            .filter(|length| length >= min_bytes && length <= max_bytes)
            .map(|_| ())
            .ok_or("string_type_or_bounds"),
        DatasetValueSchema::Array {
            items,
            min_items,
            max_items,
        } => {
            let values = value.as_array().ok_or("array_type")?;
            let length = values.len() as u64;
            if length < *min_items || length > *max_items {
                return Err("array_bounds");
            }
            if values.iter().all(|value| match items {
                ScalarType::Boolean => value.is_boolean(),
                ScalarType::Integer => value.as_i64().is_some(),
                ScalarType::String => value.is_string(),
            }) {
                Ok(())
            } else {
                Err("array_item_type")
            }
        }
        _ => Err("type"),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !value[2..].bytes().all(|byte| byte == b'0')
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn invalid<T>(field: &'static str) -> Result<T, DatasetSchemaError> {
    Err(DatasetSchemaError::InvalidSchema(field))
}
