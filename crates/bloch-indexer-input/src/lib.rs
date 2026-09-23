//! Strict, offline decoding for canonical indexer blocks.
//!
//! This crate has no file, network, or process access. Callers retain control
//! of transport and pass an already bounded byte slice into [`parse_block`].

use bloch_indexer_core::{CanonicalBlock, IndexerError, validate_canonical_block};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use thiserror::Error;

/// Hard ingestion limit, checked before JSON parsing or allocation by serde.
pub const MAX_CANONICAL_BLOCK_JSON_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InputError {
    #[error("canonical block JSON is empty")]
    Empty,
    #[error("canonical block JSON is too large: {actual} bytes exceeds the {maximum} byte limit")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid canonical block JSON: {0}")]
    InvalidJson(String),
    #[error("invalid canonical block semantics: {0}")]
    InvalidBlock(#[from] IndexerError),
}

/// Decodes one strict canonical block and validates its core semantics.
///
/// The parser rejects duplicate keys at every object depth, unknown fields,
/// trailing JSON values, and inputs exceeding the fixed ingestion limit.
pub fn parse_block(bytes: &[u8]) -> Result<CanonicalBlock, InputError> {
    if bytes.is_empty() {
        return Err(InputError::Empty);
    }
    if bytes.len() > MAX_CANONICAL_BLOCK_JSON_BYTES {
        return Err(InputError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_CANONICAL_BLOCK_JSON_BYTES,
        });
    }

    let mut duplicate_check = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked
        .deserialize(&mut duplicate_check)
        .map_err(invalid_json)?;
    duplicate_check.end().map_err(invalid_json)?;

    let block: CanonicalBlock = serde_json::from_slice(bytes).map_err(invalid_json)?;
    validate_canonical_block(&block)?;
    Ok(block)
}

fn invalid_json(error: serde_json::Error) -> InputError {
    InputError::InvalidJson(error.to_string())
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

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateChecked)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
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
    use bloch_indexer_core::CanonicalEvent;
    use serde_json::{Value, json};

    #[test]
    fn parses_a_semantically_valid_block() {
        let expected = valid_block();
        let bytes = serde_json::to_vec(&expected).unwrap();
        assert_eq!(parse_block(&bytes).unwrap(), expected);
    }

    #[test]
    fn refuses_empty_and_oversized_inputs_before_parsing() {
        assert_eq!(parse_block(b"").unwrap_err(), InputError::Empty);

        let oversized = vec![b' '; MAX_CANONICAL_BLOCK_JSON_BYTES + 1];
        assert_eq!(
            parse_block(&oversized).unwrap_err(),
            InputError::TooLarge {
                actual: MAX_CANONICAL_BLOCK_JSON_BYTES + 1,
                maximum: MAX_CANONICAL_BLOCK_JSON_BYTES,
            }
        );
    }

    #[test]
    fn refuses_duplicate_keys_at_every_depth() {
        let top_level = valid_json_text().replacen(
            "\"schema\":\"bloch.data.canonical-block.v1\"",
            "\"schema\":\"bloch.data.canonical-block.v1\",\"schema\":\"bloch.data.canonical-block.v1\"",
            1,
        );
        assert_duplicate(&top_level, "schema");

        let nested = valid_json_text().replacen(
            "\"chainId\":700771",
            "\"chainId\":700771,\"chainId\":700771",
            1,
        );
        assert_duplicate(&nested, "chainId");

        let array_object =
            valid_json_text().replacen("\"logIndex\":0", "\"logIndex\":0,\"logIndex\":0", 1);
        assert_duplicate(&array_object, "logIndex");
    }

    #[test]
    fn refuses_unknown_fields_and_trailing_values() {
        let mut value = serde_json::to_value(valid_block()).unwrap();
        value["activate"] = Value::Bool(true);
        assert!(matches!(
            parse_block(&serde_json::to_vec(&value).unwrap()),
            Err(InputError::InvalidJson(message)) if message.contains("unknown field")
        ));

        let trailing = format!("{} {{}}", valid_json_text());
        assert!(matches!(
            parse_block(trailing.as_bytes()),
            Err(InputError::InvalidJson(_))
        ));
    }

    #[test]
    fn refuses_type_confusion_and_non_integer_numbers() {
        let string_height = valid_json_text().replacen("\"height\":101", "\"height\":\"101\"", 1);
        assert!(matches!(
            parse_block(string_height.as_bytes()),
            Err(InputError::InvalidJson(_))
        ));

        let fractional_height = valid_json_text().replacen("\"height\":101", "\"height\":101.0", 1);
        assert!(matches!(
            parse_block(fractional_height.as_bytes()),
            Err(InputError::InvalidJson(_))
        ));
    }

    #[test]
    fn delegates_semantic_validation_to_indexer_core() {
        let mut invalid_schema = valid_block();
        invalid_schema.schema = "bloch.data.canonical-block.v2".into();
        assert_eq!(
            parse_block(&serde_json::to_vec(&invalid_schema).unwrap()).unwrap_err(),
            InputError::InvalidBlock(IndexerError::InvalidBlock("schema"))
        );

        let mut invalid_event_order = valid_block();
        invalid_event_order.events.push(CanonicalEvent {
            transaction_hash: hash('e'),
            transaction_index: 1,
            log_index: 0,
            address: address('f'),
            topics: vec![],
            data: "0x".into(),
        });
        assert_eq!(
            parse_block(&serde_json::to_vec(&invalid_event_order).unwrap()).unwrap_err(),
            InputError::InvalidBlock(IndexerError::InvalidBlock("eventOrder"))
        );
    }

    #[test]
    fn refuses_json_nesting_exhaustion_without_panicking() {
        let deeply_nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(matches!(
            parse_block(deeply_nested.as_bytes()),
            Err(InputError::InvalidJson(_))
        ));
    }

    fn assert_duplicate(input: &str, key: &str) {
        assert!(matches!(
            parse_block(input.as_bytes()),
            Err(InputError::InvalidJson(message))
                if message.contains(&format!("duplicate JSON object key: {key}"))
        ));
    }

    fn valid_json_text() -> String {
        serde_json::to_string(&valid_block()).unwrap()
    }

    fn valid_block() -> CanonicalBlock {
        serde_json::from_value(json!({
            "schema": "bloch.data.canonical-block.v1",
            "network": {
                "network": "bloch-l2",
                "chainId": 700771,
                "genesisHash": hash('9'),
            },
            "height": 101,
            "blockHash": hash('2'),
            "parentHash": hash('1'),
            "stateRoot": hash('a'),
            "timestampUnixSeconds": 1790000101_u64,
            "events": [{
                "transactionHash": hash('b'),
                "transactionIndex": 0,
                "logIndex": 0,
                "address": address('c'),
                "topics": [hash('d')],
                "data": "0x",
            }],
        }))
        .unwrap()
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }

    fn address(character: char) -> String {
        format!("0x{}", character.to_string().repeat(40))
    }
}
