//! Pure, versioned read queries over an in-memory canonical indexer.
//!
//! This crate performs no I/O and makes no finality claim. Every response is
//! bound to one network and one observed canonical snapshot.

use bloch_indexer_core::{BlockAnchor, CanonicalEvent, CanonicalIndexer, ChainIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const STATUS_SCHEMA: &str = "bloch.data.read-status.v1";
const TIP_SCHEMA: &str = "bloch.data.read-tip.v1";
const BLOCK_SCHEMA: &str = "bloch.data.read-block.v1";
const BLOCK_PAGE_SCHEMA: &str = "bloch.data.read-block-page.v1";
const EVENT_PAGE_SCHEMA: &str = "bloch.data.read-event-page.v1";
const CURSOR_SCHEMA: &str = "bloch.data.read-cursor.v1";
const CURSOR_DOMAIN: &[u8] = b"bloch.data.read-cursor.v1\0";

pub const MAX_BLOCK_PAGE_SIZE: u16 = 100;
pub const MAX_EVENT_PAGE_SIZE: u16 = 100;
/// Maximum sum of serialized event-record bytes returned by one event page.
pub const MAX_EVENT_PAGE_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug)]
pub struct ReadApiV1<'a> {
    indexer: &'a CanonicalIndexer,
}

impl<'a> ReadApiV1<'a> {
    pub fn new(indexer: &'a CanonicalIndexer) -> Self {
        Self { indexer }
    }

    pub fn status(&self) -> StatusResponse {
        StatusResponse {
            schema: STATUS_SCHEMA.into(),
            network: self.indexer.network().clone(),
            anchor: self.indexer.anchor().clone(),
            tip: self.tip_view(),
            finality: FinalityStatus::NotEstablished,
        }
    }

    pub fn tip(&self) -> TipResponse {
        TipResponse {
            schema: TIP_SCHEMA.into(),
            network: self.indexer.network().clone(),
            tip: self.tip_view(),
            finality: FinalityStatus::NotEstablished,
        }
    }

    pub fn block(&self, height: u64) -> Result<BlockResponse, QueryError> {
        if height <= self.indexer.anchor().height {
            return Err(QueryError::HeightOutsideCanonicalRange);
        }
        let block = self
            .indexer
            .block(height)
            .ok_or(QueryError::HeightOutsideCanonicalRange)?;
        Ok(BlockResponse {
            schema: BLOCK_SCHEMA.into(),
            network: self.indexer.network().clone(),
            snapshot: self.tip_view(),
            block: BlockView::from_block(block),
            finality: FinalityStatus::NotEstablished,
        })
    }

    pub fn blocks(&self, request: PageRequest) -> Result<BlockPage, QueryError> {
        validate_limit(request.limit, MAX_BLOCK_PAGE_SIZE)?;
        let position = self.position(request.cursor.as_deref(), CursorKind::Blocks)?;
        let mut blocks = Vec::with_capacity(usize::from(request.limit));
        let mut next_cursor = None;

        for height in position.next_height..=position.snapshot.height {
            let block = self.indexer.block(height).ok_or(QueryError::CursorStale)?;
            if blocks.len() == usize::from(request.limit) {
                next_cursor = Some(encode_cursor(CursorPayload {
                    schema: CURSOR_SCHEMA.into(),
                    kind: CursorKind::Blocks,
                    network: self.indexer.network().clone(),
                    snapshot: position.snapshot.clone(),
                    next_height: height,
                    next_event_index: 0,
                })?);
                break;
            }
            blocks.push(BlockView::from_block(block));
        }

        Ok(BlockPage {
            schema: BLOCK_PAGE_SCHEMA.into(),
            network: self.indexer.network().clone(),
            snapshot: position.snapshot,
            blocks,
            next_cursor,
            finality: FinalityStatus::NotEstablished,
        })
    }

    pub fn events(&self, request: PageRequest) -> Result<EventPage, QueryError> {
        validate_limit(request.limit, MAX_EVENT_PAGE_SIZE)?;
        let position = self.position(request.cursor.as_deref(), CursorKind::Events)?;
        let mut events = Vec::with_capacity(usize::from(request.limit));
        let mut payload_bytes = 0usize;
        let mut next_cursor = None;

        'blocks: for height in position.next_height..=position.snapshot.height {
            let block = self.indexer.block(height).ok_or(QueryError::CursorStale)?;
            let start_index = if height == position.next_height {
                position.next_event_index
            } else {
                0
            };
            if start_index > block.events.len() {
                return Err(QueryError::InvalidCursor);
            }
            for (event_index, event) in block.events.iter().enumerate().skip(start_index) {
                let record = EventView {
                    height,
                    block_hash: block.block_hash.clone(),
                    event: event.clone(),
                };
                let record_bytes = serde_json::to_vec(&record)
                    .map_err(|_| QueryError::InternalSerialization)?
                    .len();
                let size_exceeded = payload_bytes
                    .checked_add(record_bytes)
                    .is_none_or(|size| size > MAX_EVENT_PAGE_PAYLOAD_BYTES);
                if events.len() == usize::from(request.limit)
                    || (size_exceeded && !events.is_empty())
                {
                    next_cursor = Some(encode_cursor(CursorPayload {
                        schema: CURSOR_SCHEMA.into(),
                        kind: CursorKind::Events,
                        network: self.indexer.network().clone(),
                        snapshot: position.snapshot.clone(),
                        next_height: height,
                        next_event_index: u32::try_from(event_index)
                            .map_err(|_| QueryError::InternalSerialization)?,
                    })?);
                    break 'blocks;
                }
                payload_bytes = payload_bytes
                    .checked_add(record_bytes)
                    .ok_or(QueryError::InternalSerialization)?;
                events.push(record);
            }
        }

        Ok(EventPage {
            schema: EVENT_PAGE_SCHEMA.into(),
            network: self.indexer.network().clone(),
            snapshot: position.snapshot,
            events,
            next_cursor,
            finality: FinalityStatus::NotEstablished,
        })
    }

    fn position(&self, cursor: Option<&str>, kind: CursorKind) -> Result<Position, QueryError> {
        let anchor = self.indexer.anchor();
        let (tip_height, tip_hash) = self.indexer.tip();
        let Some(cursor) = cursor else {
            return Ok(Position {
                snapshot: TipView {
                    height: tip_height,
                    block_hash: tip_hash.into(),
                },
                next_height: anchor
                    .height
                    .checked_add(1)
                    .ok_or(QueryError::HeightOutsideCanonicalRange)?,
                next_event_index: 0,
            });
        };

        let payload = decode_cursor(cursor)?;
        if payload.kind != kind {
            return Err(QueryError::CursorKindMismatch);
        }
        if payload.network != *self.indexer.network() {
            return Err(QueryError::CursorNetworkMismatch);
        }
        if payload.snapshot.height <= anchor.height
            || payload.next_height <= anchor.height
            || payload.next_height > payload.snapshot.height
        {
            return Err(QueryError::InvalidCursor);
        }
        let snapshot = self
            .indexer
            .block(payload.snapshot.height)
            .filter(|block| block.block_hash == payload.snapshot.block_hash)
            .ok_or(QueryError::CursorStale)?;
        if snapshot.height > tip_height {
            return Err(QueryError::CursorStale);
        }
        let next = self
            .indexer
            .block(payload.next_height)
            .ok_or(QueryError::CursorStale)?;
        if kind == CursorKind::Blocks && payload.next_event_index != 0 {
            return Err(QueryError::InvalidCursor);
        }
        let next_event_index =
            usize::try_from(payload.next_event_index).map_err(|_| QueryError::InvalidCursor)?;
        if kind == CursorKind::Events && next_event_index >= next.events.len() {
            return Err(QueryError::InvalidCursor);
        }
        Ok(Position {
            snapshot: payload.snapshot,
            next_height: payload.next_height,
            next_event_index,
        })
    }

    fn tip_view(&self) -> TipView {
        let (height, block_hash) = self.indexer.tip();
        TipView {
            height,
            block_hash: block_hash.into(),
        }
    }
}

fn validate_limit(limit: u16, maximum: u16) -> Result<(), QueryError> {
    if limit == 0 || limit > maximum {
        return Err(QueryError::InvalidLimit { maximum });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageRequest {
    pub limit: u16,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FinalityStatus {
    NotEstablished,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TipView {
    pub height: u64,
    pub block_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusResponse {
    pub schema: String,
    pub network: ChainIdentity,
    pub anchor: BlockAnchor,
    pub tip: TipView,
    pub finality: FinalityStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TipResponse {
    pub schema: String,
    pub network: ChainIdentity,
    pub tip: TipView,
    pub finality: FinalityStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockView {
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub state_root: String,
    pub timestamp_unix_seconds: u64,
    pub event_count: u32,
}

impl BlockView {
    fn from_block(block: &bloch_indexer_core::CanonicalBlock) -> Self {
        Self {
            height: block.height,
            block_hash: block.block_hash.clone(),
            parent_hash: block.parent_hash.clone(),
            state_root: block.state_root.clone(),
            timestamp_unix_seconds: block.timestamp_unix_seconds,
            event_count: u32::try_from(block.events.len()).expect("event limit fits u32"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockResponse {
    pub schema: String,
    pub network: ChainIdentity,
    pub snapshot: TipView,
    pub block: BlockView,
    pub finality: FinalityStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockPage {
    pub schema: String,
    pub network: ChainIdentity,
    pub snapshot: TipView,
    pub blocks: Vec<BlockView>,
    pub next_cursor: Option<String>,
    pub finality: FinalityStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventView {
    pub height: u64,
    pub block_hash: String,
    pub event: CanonicalEvent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventPage {
    pub schema: String,
    pub network: ChainIdentity,
    pub snapshot: TipView,
    pub events: Vec<EventView>,
    pub next_cursor: Option<String>,
    pub finality: FinalityStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum CursorKind {
    Blocks,
    Events,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CursorPayload {
    schema: String,
    kind: CursorKind,
    network: ChainIdentity,
    snapshot: TipView,
    next_height: u64,
    next_event_index: u32,
}

struct Position {
    snapshot: TipView,
    next_height: u64,
    next_event_index: usize,
}

fn encode_cursor(payload: CursorPayload) -> Result<String, QueryError> {
    let bytes = serde_json::to_vec(&payload).map_err(|_| QueryError::InternalSerialization)?;
    let mut hasher = Sha256::new();
    hasher.update(CURSOR_DOMAIN);
    hasher.update(&bytes);
    let checksum = hasher.finalize();
    Ok(format!(
        "v1.{}.{}",
        hex::encode(bytes),
        hex::encode(checksum)
    ))
}

fn decode_cursor(cursor: &str) -> Result<CursorPayload, QueryError> {
    if cursor.len() > MAX_CURSOR_BYTES {
        return Err(QueryError::InvalidCursor);
    }
    let mut parts = cursor.split('.');
    if parts.next() != Some("v1") {
        return Err(QueryError::InvalidCursor);
    }
    let payload_hex = parts.next().ok_or(QueryError::InvalidCursor)?;
    let checksum_hex = parts.next().ok_or(QueryError::InvalidCursor)?;
    if parts.next().is_some() {
        return Err(QueryError::InvalidCursor);
    }
    let bytes = hex::decode(payload_hex).map_err(|_| QueryError::InvalidCursor)?;
    let supplied_checksum = hex::decode(checksum_hex).map_err(|_| QueryError::InvalidCursor)?;
    let mut hasher = Sha256::new();
    hasher.update(CURSOR_DOMAIN);
    hasher.update(&bytes);
    let expected_checksum = hasher.finalize();
    if supplied_checksum.as_slice() != expected_checksum.as_slice() {
        return Err(QueryError::InvalidCursor);
    }
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| QueryError::InvalidCursor)?;
    let canonical = serde_json::to_vec(&payload).map_err(|_| QueryError::InvalidCursor)?;
    if canonical != bytes || payload.schema != CURSOR_SCHEMA {
        return Err(QueryError::InvalidCursor);
    }
    Ok(payload)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("page limit must be between 1 and {maximum}")]
    InvalidLimit { maximum: u16 },
    #[error("height is outside the retained canonical range")]
    HeightOutsideCanonicalRange,
    #[error("cursor is malformed or violates the v1 contract")]
    InvalidCursor,
    #[error("cursor belongs to another query kind")]
    CursorKindMismatch,
    #[error("cursor belongs to another network")]
    CursorNetworkMismatch,
    #[error("cursor snapshot is no longer canonical")]
    CursorStale,
    #[error("query response could not be serialized")]
    InternalSerialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_indexer_core::{ApplyOutcome, CanonicalBlock};

    #[test]
    fn status_tip_and_block_are_network_bound_and_never_claim_finality() {
        let indexer = indexer_with_blocks(2, "bloch-l2");
        let api = ReadApiV1::new(&indexer);

        let status = api.status();
        assert_eq!(status.schema, STATUS_SCHEMA);
        assert_eq!(status.network.chain_id, 700_771);
        assert_eq!(status.tip.height, 102);
        assert_eq!(status.finality, FinalityStatus::NotEstablished);

        let tip = api.tip();
        assert_eq!(tip.tip, status.tip);
        assert_eq!(tip.finality, FinalityStatus::NotEstablished);

        let block = api.block(101).unwrap();
        assert_eq!(block.block.height, 101);
        assert_eq!(block.block.event_count, 2);
        assert_eq!(block.snapshot.height, 102);
        assert_eq!(block.finality, FinalityStatus::NotEstablished);
        assert_eq!(
            api.block(100).unwrap_err(),
            QueryError::HeightOutsideCanonicalRange
        );
        assert_eq!(
            api.block(103).unwrap_err(),
            QueryError::HeightOutsideCanonicalRange
        );
    }

    #[test]
    fn block_cursor_is_stable_across_append_and_excludes_newer_blocks() {
        let mut indexer = indexer_with_blocks(3, "bloch-l2");
        let first = ReadApiV1::new(&indexer)
            .blocks(PageRequest {
                limit: 1,
                cursor: None,
            })
            .unwrap();
        assert_eq!(heights(&first), vec![101]);
        let cursor = first.next_cursor.unwrap();

        let parent = hash_for_height(103);
        assert!(matches!(
            indexer.apply(block(104, hash_for_height(104), parent, "bloch-l2", 1)),
            Ok(ApplyOutcome::Applied { .. })
        ));
        let second = ReadApiV1::new(&indexer)
            .blocks(PageRequest {
                limit: 100,
                cursor: Some(cursor),
            })
            .unwrap();
        assert_eq!(heights(&second), vec![102, 103]);
        assert_eq!(second.snapshot.height, 103);
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn reorg_makes_snapshot_cursor_stale() {
        let mut indexer = indexer_with_blocks(3, "bloch-l2");
        let cursor = ReadApiV1::new(&indexer)
            .blocks(PageRequest {
                limit: 1,
                cursor: None,
            })
            .unwrap()
            .next_cursor
            .unwrap();

        indexer
            .apply(block(102, hash('e'), hash_for_height(101), "bloch-l2", 1))
            .unwrap();
        assert_eq!(
            ReadApiV1::new(&indexer)
                .blocks(PageRequest {
                    limit: 1,
                    cursor: Some(cursor),
                })
                .unwrap_err(),
            QueryError::CursorStale
        );
    }

    #[test]
    fn cursor_rejects_network_kind_tampering_and_noncanonical_encoding() {
        let indexer = indexer_with_blocks(3, "bloch-l2");
        let api = ReadApiV1::new(&indexer);
        let cursor = api
            .blocks(PageRequest {
                limit: 1,
                cursor: None,
            })
            .unwrap()
            .next_cursor
            .unwrap();

        assert_eq!(
            api.events(PageRequest {
                limit: 1,
                cursor: Some(cursor.clone()),
            })
            .unwrap_err(),
            QueryError::CursorKindMismatch
        );
        let other = indexer_with_blocks(3, "other-l2");
        assert_eq!(
            ReadApiV1::new(&other)
                .blocks(PageRequest {
                    limit: 1,
                    cursor: Some(cursor.clone()),
                })
                .unwrap_err(),
            QueryError::CursorNetworkMismatch
        );

        let mut tampered = cursor.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert_eq!(
            api.blocks(PageRequest {
                limit: 1,
                cursor: Some(String::from_utf8(tampered).unwrap()),
            })
            .unwrap_err(),
            QueryError::InvalidCursor
        );
        assert_eq!(
            decode_cursor("v1.00.00").unwrap_err(),
            QueryError::InvalidCursor
        );

        let duplicate = br#"{"schema":"bloch.data.read-cursor.v1","schema":"bloch.data.read-cursor.v1","kind":"blocks","network":{"network":"bloch-l2","chainId":700771,"genesisHash":"x"},"snapshot":{"height":103,"blockHash":"x"},"nextHeight":102,"nextEventIndex":0}"#;
        let mut hasher = Sha256::new();
        hasher.update(CURSOR_DOMAIN);
        hasher.update(duplicate);
        let duplicate_cursor = format!(
            "v1.{}.{}",
            hex::encode(duplicate),
            hex::encode(hasher.finalize())
        );
        assert_eq!(
            decode_cursor(&duplicate_cursor).unwrap_err(),
            QueryError::InvalidCursor
        );
    }

    #[test]
    fn limits_and_strict_request_shape_fail_closed() {
        let indexer = indexer_with_blocks(1, "bloch-l2");
        let api = ReadApiV1::new(&indexer);
        assert_eq!(
            api.blocks(PageRequest {
                limit: 0,
                cursor: None,
            })
            .unwrap_err(),
            QueryError::InvalidLimit {
                maximum: MAX_BLOCK_PAGE_SIZE
            }
        );
        assert_eq!(
            api.events(PageRequest {
                limit: MAX_EVENT_PAGE_SIZE + 1,
                cursor: None,
            })
            .unwrap_err(),
            QueryError::InvalidLimit {
                maximum: MAX_EVENT_PAGE_SIZE
            }
        );
        assert!(
            serde_json::from_str::<PageRequest>(r#"{"limit":1,"cursor":null,"unexpected":true}"#)
                .is_err()
        );

        let mut value = serde_json::to_value(api.status()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("finalized".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<StatusResponse>(value).is_err());
    }

    #[test]
    fn event_pages_preserve_order_and_enforce_payload_budget() {
        let mut indexer = empty_indexer("bloch-l2");
        let large_data = format!("0x{}", "ab".repeat(240 * 1024));
        let mut candidate = block(101, hash_for_height(101), hash('1'), "bloch-l2", 5);
        for event in &mut candidate.events {
            event.data.clone_from(&large_data);
        }
        indexer.apply(candidate).unwrap();
        let api = ReadApiV1::new(&indexer);

        let first = api
            .events(PageRequest {
                limit: 100,
                cursor: None,
            })
            .unwrap();
        assert_eq!(first.events.len(), 2);
        assert!(
            first
                .events
                .iter()
                .map(|event| serde_json::to_vec(event).unwrap().len())
                .sum::<usize>()
                <= MAX_EVENT_PAGE_PAYLOAD_BYTES
        );
        let second = api
            .events(PageRequest {
                limit: 100,
                cursor: first.next_cursor,
            })
            .unwrap();
        assert_eq!(second.events.len(), 2);
        let third = api
            .events(PageRequest {
                limit: 100,
                cursor: second.next_cursor,
            })
            .unwrap();
        assert_eq!(third.events.len(), 1);
        assert!(third.next_cursor.is_none());

        let indexes = first
            .events
            .into_iter()
            .chain(second.events)
            .chain(third.events)
            .map(|record| record.event.log_index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn empty_indexer_returns_empty_bounded_pages() {
        let indexer = empty_indexer("bloch-l2");
        let api = ReadApiV1::new(&indexer);
        let blocks = api
            .blocks(PageRequest {
                limit: 1,
                cursor: None,
            })
            .unwrap();
        let events = api
            .events(PageRequest {
                limit: 1,
                cursor: None,
            })
            .unwrap();
        assert!(blocks.blocks.is_empty());
        assert!(events.events.is_empty());
        assert!(blocks.next_cursor.is_none());
        assert!(events.next_cursor.is_none());
    }

    fn heights(page: &BlockPage) -> Vec<u64> {
        page.blocks.iter().map(|block| block.height).collect()
    }

    fn indexer_with_blocks(count: u64, network: &str) -> CanonicalIndexer {
        let mut indexer = empty_indexer(network);
        let mut parent = hash('1');
        for offset in 1..=count {
            let height = 100 + offset;
            let block_hash = hash_for_height(height);
            indexer
                .apply(block(height, block_hash.clone(), parent, network, 2))
                .unwrap();
            parent = block_hash;
        }
        indexer
    }

    fn empty_indexer(network: &str) -> CanonicalIndexer {
        CanonicalIndexer::new(
            ChainIdentity {
                network: network.into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('a'),
            },
            8,
        )
        .unwrap()
    }

    fn block(
        height: u64,
        block_hash: String,
        parent_hash: String,
        network: &str,
        event_count: u32,
    ) -> CanonicalBlock {
        CanonicalBlock {
            schema: "bloch.data.canonical-block.v1".into(),
            network: ChainIdentity {
                network: network.into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            height,
            block_hash,
            parent_hash,
            state_root: hash('a'),
            timestamp_unix_seconds: 1_790_000_000 + height,
            events: (0..event_count)
                .map(|index| CanonicalEvent {
                    transaction_hash: hash(char::from_digit(index + 2, 16).unwrap()),
                    transaction_index: index,
                    log_index: index,
                    address: format!("0x{}", "c".repeat(40)),
                    topics: vec![hash('d')],
                    data: "0x".into(),
                })
                .collect(),
        }
    }

    fn hash_for_height(height: u64) -> String {
        let character = match height {
            101 => '2',
            102 => '3',
            103 => '4',
            104 => '5',
            _ => '6',
        };
        hash(character)
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }
}
