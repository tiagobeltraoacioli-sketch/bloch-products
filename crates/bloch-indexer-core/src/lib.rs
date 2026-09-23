use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const BLOCK_SCHEMA: &str = "bloch.data.canonical-block.v1";
const MAX_EVENTS_PER_BLOCK: usize = 10_000;
const MAX_DATA_BYTES: usize = 262_144;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChainIdentity {
    pub network: String,
    pub chain_id: u64,
    pub genesis_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockAnchor {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CanonicalBlock {
    pub schema: String,
    pub network: ChainIdentity,
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub state_root: String,
    pub timestamp_unix_seconds: u64,
    pub events: Vec<CanonicalEvent>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CanonicalEvent {
    pub transaction_hash: String,
    pub transaction_index: u32,
    pub log_index: u32,
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied {
        height: u64,
        block_hash: String,
    },
    Idempotent {
        height: u64,
        block_hash: String,
    },
    Reorganized {
        height: u64,
        block_hash: String,
        removed_block_hashes: Vec<String>,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IndexerError {
    #[error("invalid indexer configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid block field: {0}")]
    InvalidBlock(&'static str),
    #[error("block belongs to a different network")]
    NetworkMismatch,
    #[error("block does not extend a known canonical parent")]
    UnknownParent,
    #[error("block conflicts with the immutable anchor")]
    AnchorConflict,
    #[error("reorganization depth {depth} exceeds configured maximum {maximum}")]
    ReorgTooDeep { depth: usize, maximum: usize },
    #[error("a block hash was reused with different content")]
    HashCollision,
}

#[derive(Clone, Debug)]
pub struct CanonicalIndexer {
    network: ChainIdentity,
    anchor: BlockAnchor,
    maximum_reorg_depth: usize,
    blocks: BTreeMap<u64, CanonicalBlock>,
    seen_blocks: BTreeMap<String, CanonicalBlock>,
}

impl CanonicalIndexer {
    pub fn new(
        network: ChainIdentity,
        anchor: BlockAnchor,
        maximum_reorg_depth: usize,
    ) -> Result<Self, IndexerError> {
        validate_network(&network)?;
        validate_anchor(&anchor)?;
        if anchor.height == 0 && anchor.block_hash != network.genesis_hash {
            return Err(IndexerError::InvalidConfiguration("genesisAnchor"));
        }
        if maximum_reorg_depth == 0 || maximum_reorg_depth > 4_096 {
            return Err(IndexerError::InvalidConfiguration("maximumReorgDepth"));
        }
        Ok(Self {
            network,
            anchor,
            maximum_reorg_depth,
            blocks: BTreeMap::new(),
            seen_blocks: BTreeMap::new(),
        })
    }

    pub fn apply(&mut self, block: CanonicalBlock) -> Result<ApplyOutcome, IndexerError> {
        validate_block(&block)?;
        if block.network != self.network {
            return Err(IndexerError::NetworkMismatch);
        }
        if block.height <= self.anchor.height {
            return Err(IndexerError::AnchorConflict);
        }
        if block.block_hash == self.anchor.block_hash {
            return Err(IndexerError::HashCollision);
        }
        if let Some(seen) = self.seen_blocks.get(&block.block_hash) {
            if seen != &block {
                return Err(IndexerError::HashCollision);
            }
            if self.blocks.get(&block.height) == Some(&block) {
                return Ok(ApplyOutcome::Idempotent {
                    height: block.height,
                    block_hash: block.block_hash,
                });
            }
        }

        let (tip_height, _) = self.tip();
        let append_height = tip_height
            .checked_add(1)
            .ok_or(IndexerError::InvalidConfiguration("tipHeight"))?;
        if block.height > append_height {
            return Err(IndexerError::UnknownParent);
        }
        let parent_height = block
            .height
            .checked_sub(1)
            .ok_or(IndexerError::AnchorConflict)?;
        let expected_parent = self
            .canonical_hash(parent_height)
            .ok_or(IndexerError::UnknownParent)?;
        if block.parent_hash != expected_parent {
            return Err(IndexerError::UnknownParent);
        }
        if self
            .blocks
            .get(&parent_height)
            .is_some_and(|parent| parent.timestamp_unix_seconds >= block.timestamp_unix_seconds)
        {
            return Err(IndexerError::InvalidBlock("timestamp"));
        }

        if block.height == append_height {
            let outcome = ApplyOutcome::Applied {
                height: block.height,
                block_hash: block.block_hash.clone(),
            };
            self.seen_blocks
                .insert(block.block_hash.clone(), block.clone());
            self.blocks.insert(block.height, block);
            return Ok(outcome);
        }

        let depth_u64 = tip_height
            .checked_sub(block.height)
            .and_then(|value| value.checked_add(1))
            .ok_or(IndexerError::AnchorConflict)?;
        let depth = usize::try_from(depth_u64)
            .map_err(|_| IndexerError::InvalidConfiguration("reorgDepth"))?;
        if depth > self.maximum_reorg_depth {
            return Err(IndexerError::ReorgTooDeep {
                depth,
                maximum: self.maximum_reorg_depth,
            });
        }
        let removed_block_hashes = self
            .blocks
            .range(block.height..)
            .rev()
            .map(|(_, old)| old.block_hash.clone())
            .collect::<Vec<_>>();
        self.blocks.retain(|height, _| *height < block.height);
        let outcome = ApplyOutcome::Reorganized {
            height: block.height,
            block_hash: block.block_hash.clone(),
            removed_block_hashes,
        };
        self.seen_blocks
            .insert(block.block_hash.clone(), block.clone());
        self.blocks.insert(block.height, block);
        Ok(outcome)
    }

    pub fn tip(&self) -> (u64, &str) {
        self.blocks.last_key_value().map_or(
            (self.anchor.height, self.anchor.block_hash.as_str()),
            |(_, block)| (block.height, block.block_hash.as_str()),
        )
    }

    pub fn block(&self, height: u64) -> Option<&CanonicalBlock> {
        self.blocks.get(&height)
    }

    pub fn anchor(&self) -> &BlockAnchor {
        &self.anchor
    }

    fn canonical_hash(&self, height: u64) -> Option<&str> {
        if height == self.anchor.height {
            Some(&self.anchor.block_hash)
        } else {
            self.blocks
                .get(&height)
                .map(|block| block.block_hash.as_str())
        }
    }
}

fn validate_network(network: &ChainIdentity) -> Result<(), IndexerError> {
    if !valid_identifier(&network.network)
        || network.chain_id == 0
        || !valid_hash(&network.genesis_hash, true)
    {
        return Err(IndexerError::InvalidConfiguration("network"));
    }
    Ok(())
}

fn validate_anchor(anchor: &BlockAnchor) -> Result<(), IndexerError> {
    if !valid_hash(&anchor.block_hash, true) || !valid_hash(&anchor.state_root, true) {
        return Err(IndexerError::InvalidConfiguration("anchor"));
    }
    Ok(())
}

fn validate_block(block: &CanonicalBlock) -> Result<(), IndexerError> {
    if block.schema != BLOCK_SCHEMA {
        return Err(IndexerError::InvalidBlock("schema"));
    }
    validate_network(&block.network).map_err(|_| IndexerError::InvalidBlock("network"))?;
    if block.height == 0 || block.timestamp_unix_seconds == 0 {
        return Err(IndexerError::InvalidBlock("heightOrTimestamp"));
    }
    if !valid_hash(&block.block_hash, true)
        || !valid_hash(&block.parent_hash, false)
        || !valid_hash(&block.state_root, true)
        || block.block_hash == block.parent_hash
    {
        return Err(IndexerError::InvalidBlock("header"));
    }
    if block.events.len() > MAX_EVENTS_PER_BLOCK {
        return Err(IndexerError::InvalidBlock("events"));
    }
    let mut identifiers = BTreeSet::new();
    let mut previous_order = None;
    let mut previous_log_index = None;
    for event in &block.events {
        validate_event(event)?;
        let identifier = (event.transaction_hash.as_str(), event.log_index);
        if !identifiers.insert(identifier) {
            return Err(IndexerError::InvalidBlock("eventIdentity"));
        }
        let order = (event.transaction_index, event.log_index);
        if previous_order.is_some_and(|previous| previous >= order)
            || previous_log_index.is_some_and(|previous| previous >= event.log_index)
        {
            return Err(IndexerError::InvalidBlock("eventOrder"));
        }
        previous_order = Some(order);
        previous_log_index = Some(event.log_index);
    }
    Ok(())
}

fn validate_event(event: &CanonicalEvent) -> Result<(), IndexerError> {
    if !valid_hash(&event.transaction_hash, true)
        || !valid_fixed_hex(&event.address, 20, false)
        || event.topics.len() > 4
        || event.topics.iter().any(|topic| !valid_hash(topic, false))
        || !valid_data(&event.data)
    {
        return Err(IndexerError::InvalidBlock("event"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_hash(value: &str, reject_zero: bool) -> bool {
    valid_fixed_hex(value, 32, reject_zero)
}

fn valid_fixed_hex(value: &str, bytes: usize, reject_zero: bool) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == bytes * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (!reject_zero || hex.bytes().any(|byte| byte != b'0'))
}

fn valid_data(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() % 2 == 0
        && hex.len() <= MAX_DATA_BYTES * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_replay_are_deterministic() {
        let mut indexer = indexer(4);
        let first = block(101, '2', '1');
        assert!(matches!(
            indexer.apply(first.clone()).unwrap(),
            ApplyOutcome::Applied { height: 101, .. }
        ));
        assert!(matches!(
            indexer.apply(first).unwrap(),
            ApplyOutcome::Idempotent { height: 101, .. }
        ));
        assert_eq!(indexer.tip(), (101, hash('2').as_str()));
    }

    #[test]
    fn bounded_reorg_removes_descendants_in_reverse_order() {
        let mut indexer = indexer(2);
        indexer.apply(block(101, '2', '1')).unwrap();
        indexer.apply(block(102, '3', '2')).unwrap();
        let replacement = block(101, '4', '1');
        assert_eq!(
            indexer.apply(replacement).unwrap(),
            ApplyOutcome::Reorganized {
                height: 101,
                block_hash: hash('4'),
                removed_block_hashes: vec![hash('3'), hash('2')],
            }
        );
        assert_eq!(indexer.tip(), (101, hash('4').as_str()));
        assert!(indexer.block(102).is_none());
    }

    #[test]
    fn anchor_gap_and_deep_reorg_fail_closed() {
        let mut indexer = indexer(1);
        assert_eq!(
            indexer.apply(block(100, '8', '0')).unwrap_err(),
            IndexerError::AnchorConflict
        );
        assert_eq!(
            indexer.apply(block(102, '3', '2')).unwrap_err(),
            IndexerError::UnknownParent
        );
        indexer.apply(block(101, '2', '1')).unwrap();
        indexer.apply(block(102, '3', '2')).unwrap();
        assert_eq!(
            indexer.apply(block(101, '4', '1')).unwrap_err(),
            IndexerError::ReorgTooDeep {
                depth: 2,
                maximum: 1
            }
        );
        assert_eq!(indexer.tip(), (102, hash('3').as_str()));
    }

    #[test]
    fn hash_collision_and_noncanonical_events_are_refused() {
        let mut indexer = indexer(2);
        let first = block(101, '2', '1');
        indexer.apply(first.clone()).unwrap();
        let mut collision = first;
        collision.timestamp_unix_seconds += 1;
        assert_eq!(
            indexer.apply(collision).unwrap_err(),
            IndexerError::HashCollision
        );

        let mut invalid = block(102, '3', '2');
        invalid.events.push(invalid.events[0].clone());
        assert_eq!(
            indexer.apply(invalid).unwrap_err(),
            IndexerError::InvalidBlock("eventIdentity")
        );
    }

    #[test]
    fn orphan_hash_reuse_timestamp_regression_and_network_substitution_are_refused() {
        let mut indexer = indexer(3);
        indexer.apply(block(101, '2', '1')).unwrap();
        indexer.apply(block(102, '3', '2')).unwrap();
        indexer.apply(block(101, '4', '1')).unwrap();

        let orphan_hash_with_new_parent = block(102, '3', '4');
        assert_eq!(
            indexer.apply(orphan_hash_with_new_parent).unwrap_err(),
            IndexerError::HashCollision
        );

        let mut regressed = block(102, '5', '4');
        regressed.timestamp_unix_seconds = indexer.block(101).unwrap().timestamp_unix_seconds;
        assert_eq!(
            indexer.apply(regressed).unwrap_err(),
            IndexerError::InvalidBlock("timestamp")
        );

        let mut substituted = block(102, '5', '4');
        substituted.network.genesis_hash = hash('8');
        assert_eq!(
            indexer.apply(substituted).unwrap_err(),
            IndexerError::NetworkMismatch
        );
        assert_eq!(indexer.tip(), (101, hash('4').as_str()));
    }

    #[test]
    fn event_order_must_be_canonical() {
        let mut indexer = indexer(2);
        let mut candidate = block(101, '2', '1');
        candidate.events = vec![
            CanonicalEvent {
                transaction_hash: hash('c'),
                transaction_index: 0,
                log_index: 2,
                address: format!("0x{}", "c".repeat(40)),
                topics: vec![],
                data: "0x".into(),
            },
            CanonicalEvent {
                transaction_hash: hash('d'),
                transaction_index: 1,
                log_index: 1,
                address: format!("0x{}", "d".repeat(40)),
                topics: vec![],
                data: "0x".into(),
            },
        ];
        assert_eq!(
            indexer.apply(candidate).unwrap_err(),
            IndexerError::InvalidBlock("eventOrder")
        );
    }

    #[test]
    fn genesis_anchor_must_match_network_identity() {
        let network = ChainIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: hash('9'),
        };
        assert_eq!(
            CanonicalIndexer::new(
                network,
                BlockAnchor {
                    height: 0,
                    block_hash: hash('8'),
                    state_root: hash('a'),
                },
                16,
            )
            .unwrap_err(),
            IndexerError::InvalidConfiguration("genesisAnchor")
        );
    }

    fn indexer(maximum_reorg_depth: usize) -> CanonicalIndexer {
        CanonicalIndexer::new(
            ChainIdentity {
                network: "bloch-l2".into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('a'),
            },
            maximum_reorg_depth,
        )
        .unwrap()
    }

    fn block(height: u64, block_hash: char, parent_hash: char) -> CanonicalBlock {
        CanonicalBlock {
            schema: BLOCK_SCHEMA.into(),
            network: ChainIdentity {
                network: "bloch-l2".into(),
                chain_id: 700_771,
                genesis_hash: hash('9'),
            },
            height,
            block_hash: hash(block_hash),
            parent_hash: hash(parent_hash),
            state_root: hash('a'),
            timestamp_unix_seconds: 1_790_000_000 + height,
            events: vec![CanonicalEvent {
                transaction_hash: hash('b'),
                transaction_index: 0,
                log_index: 0,
                address: format!("0x{}", "c".repeat(40)),
                topics: vec![hash('d')],
                data: "0x".into(),
            }],
        }
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }
}
