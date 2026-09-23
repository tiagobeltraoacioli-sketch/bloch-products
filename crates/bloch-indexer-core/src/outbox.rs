use super::{CanonicalBlock, ChainIdentity, valid_hash, validate_block, validate_network};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const OUTBOX_BATCH_SCHEMA: &str = "bloch.data.outbox-batch.v1";
pub const OUTBOX_QUEUE_SCHEMA: &str = "bloch.data.outbox-queue.v1";
pub const OUTBOX_RECORD_SCHEMA: &str = "bloch.data.webhook-record.v1";
const MAX_REVERTED_BLOCKS: usize = 4_096;
const MAX_PENDING_BATCHES: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutboxQueue {
    pub schema: String,
    pub batches: Vec<OutboxBatch>,
}

impl Default for OutboxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboxQueue {
    pub fn new() -> Self {
        Self {
            schema: OUTBOX_QUEUE_SCHEMA.into(),
            batches: Vec::new(),
        }
    }

    /// Validates the complete deserialized queue before it is trusted.
    pub fn validate(&self) -> Result<(), OutboxError> {
        if self.schema != OUTBOX_QUEUE_SCHEMA || self.batches.len() > MAX_PENDING_BATCHES {
            return Err(OutboxError::InvalidQueue("schemaOrSize"));
        }
        let mut transitions = BTreeSet::new();
        let mut records = BTreeSet::new();
        let mut queue_network = None;
        let mut expected_previous_tip: Option<&str> = None;
        for batch in &self.batches {
            validate_batch(batch)?;
            let batch_network = &batch
                .records
                .last()
                .ok_or(OutboxError::InvalidQueue("emptyBatch"))?
                .network;
            if queue_network.is_some_and(|network| network != batch_network) {
                return Err(OutboxError::InvalidQueue("networkContinuity"));
            }
            if expected_previous_tip
                .is_some_and(|expected| expected != batch.previous_tip_hash.as_str())
            {
                return Err(OutboxError::InvalidQueue("tipContinuity"));
            }
            queue_network = Some(batch_network);
            expected_previous_tip = Some(batch.new_tip_hash.as_str());
            if !transitions.insert(batch.transition_id.as_str()) {
                return Err(OutboxError::InvalidQueue("duplicateTransition"));
            }
            for record in &batch.records {
                if !records.insert(record.id.as_str()) {
                    return Err(OutboxError::InvalidQueue("duplicateRecord"));
                }
            }
        }
        Ok(())
    }

    /// Adds a complete transition or recognizes an exact replay.
    /// Validation happens before mutation, so a rejected batch leaves the queue unchanged.
    pub fn enqueue(&mut self, batch: OutboxBatch) -> Result<EnqueueOutcome, OutboxError> {
        self.validate()?;
        validate_batch(&batch)?;
        if let Some(existing) = self
            .batches
            .iter()
            .find(|existing| existing.transition_id == batch.transition_id)
        {
            return if existing == &batch {
                Ok(EnqueueOutcome::Idempotent)
            } else {
                Err(OutboxError::InvalidQueue("transitionCollision"))
            };
        }
        if self.batches.len() == MAX_PENDING_BATCHES {
            return Err(OutboxError::InvalidQueue("capacity"));
        }
        let existing_record_ids = self
            .batches
            .iter()
            .flat_map(|existing| existing.records.iter())
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        if batch
            .records
            .iter()
            .any(|record| existing_record_ids.contains(record.id.as_str()))
        {
            return Err(OutboxError::InvalidQueue("recordCollision"));
        }
        if let Some(previous) = self.batches.last() {
            if batch.previous_tip_hash != previous.new_tip_hash {
                return Err(OutboxError::InvalidQueue("tipContinuity"));
            }
            if batch.records.last().map(|record| &record.network)
                != previous.records.last().map(|record| &record.network)
            {
                return Err(OutboxError::InvalidQueue("networkContinuity"));
            }
        }
        self.batches.push(batch);
        Ok(EnqueueOutcome::Added)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Added,
    Idempotent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutboxBatch {
    pub schema: String,
    pub transition_id: String,
    pub previous_tip_hash: String,
    pub new_tip_hash: String,
    /// Delivery order. Positions are contiguous and start at zero.
    pub records: Vec<OutboxRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutboxRecord {
    pub schema: String,
    pub id: String,
    pub transition_id: String,
    pub position: u32,
    pub network: ChainIdentity,
    pub action: OutboxAction,
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboxAction {
    BlockReverted,
    BlockApplied,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OutboxError {
    #[error("invalid outbox transition field: {0}")]
    InvalidTransition(&'static str),
    #[error("invalid outbox batch field: {0}")]
    InvalidBatch(&'static str),
    #[error("invalid outbox queue field: {0}")]
    InvalidQueue(&'static str),
}

/// Builds delivery-neutral records for one canonical state transition.
///
/// `removed_blocks` must be ordered from the previous tip backwards. The
/// returned records preserve that order and append the newly canonical block.
/// This model contains no endpoint, secret, retry state or network operation.
pub fn build_outbox(
    network: &ChainIdentity,
    previous_tip_hash: &str,
    applied_block: &CanonicalBlock,
    removed_blocks: &[CanonicalBlock],
) -> Result<OutboxBatch, OutboxError> {
    validate_network(network).map_err(|_| OutboxError::InvalidTransition("network"))?;
    validate_block(applied_block).map_err(|_| OutboxError::InvalidTransition("appliedBlock"))?;
    if applied_block.network != *network {
        return Err(OutboxError::InvalidTransition("network"));
    }
    if !valid_hash(previous_tip_hash, true) {
        return Err(OutboxError::InvalidTransition("previousTipHash"));
    }
    if removed_blocks.len() > MAX_REVERTED_BLOCKS {
        return Err(OutboxError::InvalidTransition("removedBlocks"));
    }

    validate_transition_shape(network, previous_tip_hash, applied_block, removed_blocks)?;

    let transition_id = transition_id(network, previous_tip_hash, applied_block, removed_blocks);
    let mut records = Vec::with_capacity(removed_blocks.len() + 1);
    for block in removed_blocks {
        records.push(record(
            &transition_id,
            u32::try_from(records.len())
                .map_err(|_| OutboxError::InvalidTransition("recordPosition"))?,
            network,
            OutboxAction::BlockReverted,
            block,
        ));
    }
    records.push(record(
        &transition_id,
        u32::try_from(records.len())
            .map_err(|_| OutboxError::InvalidTransition("recordPosition"))?,
        network,
        OutboxAction::BlockApplied,
        applied_block,
    ));

    Ok(OutboxBatch {
        schema: OUTBOX_BATCH_SCHEMA.into(),
        transition_id,
        previous_tip_hash: previous_tip_hash.into(),
        new_tip_hash: applied_block.block_hash.clone(),
        records,
    })
}

/// Revalidates a serialized batch, including every deterministic identifier.
pub fn validate_batch(batch: &OutboxBatch) -> Result<(), OutboxError> {
    if batch.schema != OUTBOX_BATCH_SCHEMA
        || !valid_hash(&batch.transition_id, true)
        || !valid_hash(&batch.previous_tip_hash, true)
        || !valid_hash(&batch.new_tip_hash, true)
        || batch.records.is_empty()
        || batch.records.len() > MAX_REVERTED_BLOCKS + 1
    {
        return Err(OutboxError::InvalidBatch("shape"));
    }
    let applied = batch
        .records
        .last()
        .ok_or(OutboxError::InvalidBatch("records"))?;
    if applied.action != OutboxAction::BlockApplied || applied.block_hash != batch.new_tip_hash {
        return Err(OutboxError::InvalidBatch("appliedRecord"));
    }
    let network = &applied.network;
    validate_network(network).map_err(|_| OutboxError::InvalidBatch("network"))?;
    let mut record_ids = BTreeSet::new();
    for (position, record) in batch.records.iter().enumerate() {
        let expected_position =
            u32::try_from(position).map_err(|_| OutboxError::InvalidBatch("position"))?;
        if record.schema != OUTBOX_RECORD_SCHEMA
            || record.transition_id != batch.transition_id
            || record.position != expected_position
            || record.network != *network
            || record.height == 0
            || !valid_hash(&record.block_hash, true)
            || !valid_hash(&record.parent_hash, false)
            || record.block_hash == record.parent_hash
            || !record_ids.insert(record.id.as_str())
            || record.id != record_id(record)
        {
            return Err(OutboxError::InvalidBatch("record"));
        }
        if position + 1 < batch.records.len() && record.action != OutboxAction::BlockReverted {
            return Err(OutboxError::InvalidBatch("actionOrder"));
        }
    }

    let reverted = &batch.records[..batch.records.len() - 1];
    if reverted.is_empty() {
        if applied.parent_hash != batch.previous_tip_hash {
            return Err(OutboxError::InvalidBatch("appendParent"));
        }
    } else {
        if reverted[0].block_hash != batch.previous_tip_hash {
            return Err(OutboxError::InvalidBatch("removedTip"));
        }
        for pair in reverted.windows(2) {
            if pair[0].height.checked_sub(1) != Some(pair[1].height)
                || pair[0].parent_hash != pair[1].block_hash
            {
                return Err(OutboxError::InvalidBatch("removedOrder"));
            }
        }
        let fork_child = reverted
            .last()
            .ok_or(OutboxError::InvalidBatch("records"))?;
        if fork_child.height != applied.height || fork_child.parent_hash != applied.parent_hash {
            return Err(OutboxError::InvalidBatch("replacementBlock"));
        }
    }

    let expected_transition = transition_id_from_parts(
        network,
        &batch.previous_tip_hash,
        &applied.block_hash,
        reverted.iter().map(|record| record.block_hash.as_str()),
        reverted.len(),
    );
    if batch.transition_id != expected_transition {
        return Err(OutboxError::InvalidBatch("transitionId"));
    }
    Ok(())
}

fn validate_transition_shape(
    network: &ChainIdentity,
    previous_tip_hash: &str,
    applied_block: &CanonicalBlock,
    removed_blocks: &[CanonicalBlock],
) -> Result<(), OutboxError> {
    if removed_blocks.is_empty() {
        if applied_block.parent_hash != previous_tip_hash {
            return Err(OutboxError::InvalidTransition("appendParent"));
        }
        return Ok(());
    }

    if removed_blocks[0].block_hash != previous_tip_hash {
        return Err(OutboxError::InvalidTransition("removedTip"));
    }
    let mut hashes = BTreeSet::new();
    for (position, block) in removed_blocks.iter().enumerate() {
        validate_block(block).map_err(|_| OutboxError::InvalidTransition("removedBlock"))?;
        if block.network != *network || !hashes.insert(block.block_hash.as_str()) {
            return Err(OutboxError::InvalidTransition("removedBlock"));
        }
        if let Some(parent) = removed_blocks.get(position + 1)
            && (block.height.checked_sub(1) != Some(parent.height)
                || block.parent_hash != parent.block_hash)
        {
            return Err(OutboxError::InvalidTransition("removedOrder"));
        }
    }

    let fork_child = removed_blocks
        .last()
        .ok_or(OutboxError::InvalidTransition("removedBlocks"))?;
    if fork_child.height != applied_block.height
        || fork_child.parent_hash != applied_block.parent_hash
        || hashes.contains(applied_block.block_hash.as_str())
    {
        return Err(OutboxError::InvalidTransition("replacementBlock"));
    }
    Ok(())
}

fn transition_id(
    network: &ChainIdentity,
    previous_tip_hash: &str,
    applied_block: &CanonicalBlock,
    removed_blocks: &[CanonicalBlock],
) -> String {
    transition_id_from_parts(
        network,
        previous_tip_hash,
        &applied_block.block_hash,
        removed_blocks.iter().map(|block| block.block_hash.as_str()),
        removed_blocks.len(),
    )
}

fn transition_id_from_parts<'a>(
    network: &ChainIdentity,
    previous_tip_hash: &str,
    applied_block_hash: &str,
    removed_hashes: impl IntoIterator<Item = &'a str>,
    removed_count: usize,
) -> String {
    let mut digest = StableDigest::new("bloch.data.outbox-transition.v1");
    digest.text(&network.network);
    digest.number(network.chain_id);
    digest.text(&network.genesis_hash);
    digest.text(previous_tip_hash);
    digest.text(applied_block_hash);
    digest.number(removed_count as u64);
    for block_hash in removed_hashes {
        digest.text(block_hash);
    }
    digest.finish()
}

fn record(
    transition_id: &str,
    position: u32,
    network: &ChainIdentity,
    action: OutboxAction,
    block: &CanonicalBlock,
) -> OutboxRecord {
    let mut record = OutboxRecord {
        schema: OUTBOX_RECORD_SCHEMA.into(),
        id: String::new(),
        transition_id: transition_id.into(),
        position,
        network: network.clone(),
        action,
        height: block.height,
        block_hash: block.block_hash.clone(),
        parent_hash: block.parent_hash.clone(),
    };
    record.id = record_id(&record);
    record
}

fn record_id(record: &OutboxRecord) -> String {
    let mut digest = StableDigest::new("bloch.data.outbox-record.v1");
    digest.text(&record.transition_id);
    digest.number(u64::from(record.position));
    digest.text(match record.action {
        OutboxAction::BlockReverted => "block_reverted",
        OutboxAction::BlockApplied => "block_applied",
    });
    digest.number(record.height);
    digest.text(&record.block_hash);
    digest.text(&record.parent_hash);
    digest.finish()
}

struct StableDigest(Sha256);

impl StableDigest {
    fn new(domain: &str) -> Self {
        let mut value = Self(Sha256::new());
        value.text(domain);
        value
    }

    fn text(&mut self, value: &str) {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
    }

    fn number(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn finish(self) -> String {
        format!("0x{:x}", self.0.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockAnchor, CanonicalEvent, CanonicalIndexer};

    #[test]
    fn append_is_stable_across_process_equivalents() {
        let candidate = block(101, '2', '1');
        let first = build_outbox(&network(), &hash('1'), &candidate, &[]).unwrap();
        let second = build_outbox(&network(), &hash('1'), &candidate, &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].position, 0);
        assert_eq!(first.records[0].action, OutboxAction::BlockApplied);
        assert_eq!(first.previous_tip_hash, hash('1'));
        assert_eq!(first.new_tip_hash, hash('2'));
    }

    #[test]
    fn reorg_reverts_tip_to_fork_then_applies_replacement() {
        let removed = vec![block(102, '3', '2'), block(101, '2', '1')];
        let batch = build_outbox(&network(), &hash('3'), &block(101, '4', '1'), &removed).unwrap();
        assert_eq!(
            batch
                .records
                .iter()
                .map(|record| (record.position, record.action, record.block_hash.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0, OutboxAction::BlockReverted, hash('3')),
                (1, OutboxAction::BlockReverted, hash('2')),
                (2, OutboxAction::BlockApplied, hash('4')),
            ]
        );
        assert_eq!(
            batch
                .records
                .iter()
                .map(|record| &record.id)
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn returning_block_has_a_new_transition_identity() {
        let original = block(101, '2', '1');
        let initial = build_outbox(&network(), &hash('1'), &original, &[]).unwrap();
        let returned =
            build_outbox(&network(), &hash('4'), &original, &[block(101, '4', '1')]).unwrap();
        assert_ne!(initial.transition_id, returned.transition_id);
        assert_ne!(initial.records[0].id, returned.records.last().unwrap().id);
    }

    #[test]
    fn malformed_transitions_fail_closed() {
        let network = network();
        let reversed = vec![block(101, '2', '1'), block(102, '3', '2')];
        assert_eq!(
            build_outbox(&network, &hash('3'), &block(101, '4', '1'), &reversed).unwrap_err(),
            OutboxError::InvalidTransition("removedTip")
        );

        let removed = vec![block(102, '3', '2'), block(101, '2', '1')];
        let mut replacement = block(101, '4', '1');
        replacement.network.genesis_hash = hash('8');
        assert_eq!(
            build_outbox(&network, &hash('3'), &replacement, &removed).unwrap_err(),
            OutboxError::InvalidTransition("network")
        );
    }

    #[test]
    fn queue_enqueue_is_atomic_and_idempotent() {
        let batch = build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap();
        let mut queue = OutboxQueue::new();
        assert_eq!(queue.enqueue(batch.clone()).unwrap(), EnqueueOutcome::Added);
        assert_eq!(queue.enqueue(batch).unwrap(), EnqueueOutcome::Idempotent);
        assert_eq!(queue.batches.len(), 1);
        queue.validate().unwrap();
    }

    #[test]
    fn deserialized_queue_tampering_is_refused() {
        let batch = build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap();
        let mut queue = OutboxQueue::new();
        queue.enqueue(batch).unwrap();
        queue.batches[0].records[0].block_hash = hash('8');
        let before = queue.clone();
        assert_eq!(
            queue.validate().unwrap_err(),
            OutboxError::InvalidBatch("appliedRecord")
        );
        let valid = build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap();
        assert!(queue.enqueue(valid).is_err());
        assert_eq!(queue, before);
    }

    #[test]
    fn queue_reordering_is_refused() {
        let first = build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap();
        let second = build_outbox(&network(), &hash('2'), &block(102, '3', '2'), &[]).unwrap();
        let queue = OutboxQueue {
            schema: OUTBOX_QUEUE_SCHEMA.into(),
            batches: vec![second, first],
        };
        assert_eq!(
            queue.validate().unwrap_err(),
            OutboxError::InvalidQueue("tipContinuity")
        );
    }

    #[test]
    fn queue_network_mixing_is_refused() {
        let first = build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap();
        let other_network = ChainIdentity {
            network: "other-l2".into(),
            chain_id: 700_772,
            genesis_hash: hash('8'),
        };
        let mut other_block = block(102, '3', '2');
        other_block.network = other_network.clone();
        let second = build_outbox(&other_network, &hash('2'), &other_block, &[]).unwrap();
        let queue = OutboxQueue {
            schema: OUTBOX_QUEUE_SCHEMA.into(),
            batches: vec![first, second],
        };
        assert_eq!(
            queue.validate().unwrap_err(),
            OutboxError::InvalidQueue("networkContinuity")
        );
    }

    #[test]
    fn transition_input_matches_indexer_reorg_outcome() {
        let mut indexer = CanonicalIndexer::new(
            network(),
            BlockAnchor {
                height: 100,
                block_hash: hash('1'),
                state_root: hash('a'),
            },
            8,
        )
        .unwrap();
        let first = block(101, '2', '1');
        let second = block(102, '3', '2');
        indexer.apply(first.clone()).unwrap();
        indexer.apply(second.clone()).unwrap();
        let replacement = block(101, '4', '1');
        indexer.apply(replacement.clone()).unwrap();
        let previous_tip_hash = second.block_hash.clone();

        let batch = build_outbox(
            &network(),
            &previous_tip_hash,
            &replacement,
            &[second, first],
        )
        .unwrap();
        assert_eq!(batch.records.len(), 3);
        assert_eq!(indexer.tip(), (101, hash('4').as_str()));
    }

    fn network() -> ChainIdentity {
        ChainIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: hash('9'),
        }
    }

    fn block(height: u64, block_hash: char, parent_hash: char) -> CanonicalBlock {
        CanonicalBlock {
            schema: super::super::BLOCK_SCHEMA.into(),
            network: network(),
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
