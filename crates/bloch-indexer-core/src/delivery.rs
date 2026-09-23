//! Offline state machine for ordered, at-least-once outbox delivery.
//!
//! This module performs no I/O. A caller claims the next record, performs the
//! external operation using the stable record id as its idempotency key, then
//! durably acknowledges success or schedules a retry through `storage`.

use crate::outbox::{OutboxQueue, OutboxRecord};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OUTBOX_DELIVERY_SCHEMA: &str = "bloch.data.outbox-delivery.v1";
const MAX_LEASE_SECONDS: u64 = 3_600;
const MAX_RETRY_DELAY_SECONDS: u64 = 86_400;
const MAX_ATTEMPTS_PER_RECORD: u32 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutboxDelivery {
    pub schema: String,
    batch_cursor: usize,
    record_cursor: usize,
    attempts: u32,
    next_attempt_unix_seconds: u64,
    next_generation: u64,
    clock_watermark_unix_seconds: u64,
    active_claim: Option<DeliveryClaim>,
    last_resolution: Option<ClaimResolution>,
}

impl Default for OutboxDelivery {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboxDelivery {
    pub fn new() -> Self {
        Self {
            schema: OUTBOX_DELIVERY_SCHEMA.into(),
            batch_cursor: 0,
            record_cursor: 0,
            attempts: 0,
            next_attempt_unix_seconds: 0,
            next_generation: 1,
            clock_watermark_unix_seconds: 0,
            active_claim: None,
            last_resolution: None,
        }
    }

    pub fn validate(&self, queue: &OutboxQueue) -> Result<(), DeliveryError> {
        queue
            .validate()
            .map_err(|_| DeliveryError::InvalidState("queue"))?;
        if self.schema != OUTBOX_DELIVERY_SCHEMA || self.next_generation == 0 {
            return Err(DeliveryError::InvalidState("schemaOrGeneration"));
        }
        let current = self.current_record(queue)?;
        if current.is_none()
            && (self.record_cursor != 0
                || self.attempts != 0
                || self.next_attempt_unix_seconds != 0
                || self.active_claim.is_some())
        {
            return Err(DeliveryError::InvalidState("completedCursor"));
        }
        if self.attempts > MAX_ATTEMPTS_PER_RECORD {
            return Err(DeliveryError::InvalidState("attempts"));
        }
        if let Some(claim) = &self.active_claim {
            let record = current.ok_or(DeliveryError::InvalidState("claimCursor"))?;
            validate_claim(claim, record)?;
            if claim.attempt != self.attempts
                || claim.generation >= self.next_generation
                || claim.claimed_at_unix_seconds > claim.expires_at_unix_seconds
                || claim.expires_at_unix_seconds - claim.claimed_at_unix_seconds > MAX_LEASE_SECONDS
                || claim.claimed_at_unix_seconds > self.clock_watermark_unix_seconds
                || self.next_attempt_unix_seconds > claim.claimed_at_unix_seconds
            {
                return Err(DeliveryError::InvalidState("claim"));
            }
        }
        if let Some(resolution) = &self.last_resolution {
            let expected_record = match resolution.disposition {
                ClaimDisposition::Acknowledged => self.previous_record(queue),
                ClaimDisposition::Retry { .. } => current,
            }
            .ok_or(DeliveryError::InvalidState("resolutionCursor"))?;
            validate_claim(&resolution.claim, expected_record)?;
            if resolution.claim.generation >= self.next_generation
                || resolution.resolved_at_unix_seconds > self.clock_watermark_unix_seconds
            {
                return Err(DeliveryError::InvalidState("resolution"));
            }
            if let ClaimDisposition::Retry {
                retry_at_unix_seconds,
            } = resolution.disposition
                && (retry_at_unix_seconds < resolution.resolved_at_unix_seconds
                    || retry_at_unix_seconds != self.next_attempt_unix_seconds
                    || resolution.claim.attempt > self.attempts)
            {
                return Err(DeliveryError::InvalidState("retry"));
            }
        }
        if self.attempts == 0 && self.next_attempt_unix_seconds != 0 {
            return Err(DeliveryError::InvalidState("retryWithoutAttempt"));
        }
        if self.attempts > 0
            && self.active_claim.is_none()
            && !self.last_resolution.as_ref().is_some_and(|resolution| {
                matches!(resolution.disposition, ClaimDisposition::Retry { .. })
            })
        {
            return Err(DeliveryError::InvalidState("unresolvedAttempt"));
        }
        Ok(())
    }

    pub fn claim_next(
        &mut self,
        queue: &OutboxQueue,
        now_unix_seconds: u64,
        lease_seconds: u64,
        claim_token: &str,
    ) -> Result<ClaimOutcome, DeliveryError> {
        self.validate(queue)?;
        if lease_seconds == 0 || lease_seconds > MAX_LEASE_SECONDS || !valid_token(claim_token) {
            return Err(DeliveryError::InvalidRequest("leaseOrToken"));
        }
        self.check_time(now_unix_seconds)?;
        let Some(record) = self.current_record(queue)?.cloned() else {
            self.clock_watermark_unix_seconds = now_unix_seconds;
            return Ok(ClaimOutcome::Empty);
        };
        if let Some(claim) = &self.active_claim
            && now_unix_seconds < claim.expires_at_unix_seconds
        {
            self.clock_watermark_unix_seconds = now_unix_seconds;
            return if claim.token == claim_token {
                Ok(ClaimOutcome::Claimed {
                    claim: claim.clone(),
                    record: Box::new(record),
                    replayed: true,
                })
            } else {
                Ok(ClaimOutcome::Unavailable {
                    retry_at_unix_seconds: claim.expires_at_unix_seconds,
                })
            };
        }
        if now_unix_seconds < self.next_attempt_unix_seconds {
            self.clock_watermark_unix_seconds = now_unix_seconds;
            return Ok(ClaimOutcome::Unavailable {
                retry_at_unix_seconds: self.next_attempt_unix_seconds,
            });
        }
        let attempt = self
            .attempts
            .checked_add(1)
            .filter(|attempt| *attempt <= MAX_ATTEMPTS_PER_RECORD)
            .ok_or(DeliveryError::AttemptsExhausted)?;
        let generation = self.next_generation;
        let next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(DeliveryError::GenerationExhausted)?;
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(lease_seconds)
            .ok_or(DeliveryError::InvalidRequest("leaseOverflow"))?;
        let claim = DeliveryClaim {
            token: claim_token.into(),
            generation,
            record_id: record.id.clone(),
            attempt,
            claimed_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
        };
        self.attempts = attempt;
        self.next_generation = next_generation;
        self.clock_watermark_unix_seconds = now_unix_seconds;
        self.active_claim = Some(claim.clone());
        Ok(ClaimOutcome::Claimed {
            claim,
            record: Box::new(record),
            replayed: false,
        })
    }

    pub fn acknowledge(
        &mut self,
        queue: &OutboxQueue,
        claim: &DeliveryClaim,
        now_unix_seconds: u64,
    ) -> Result<ResolutionOutcome, DeliveryError> {
        self.validate(queue)?;
        self.check_time(now_unix_seconds)?;
        if self.resolution_matches(claim, ClaimDisposition::Acknowledged) {
            self.clock_watermark_unix_seconds = now_unix_seconds;
            return Ok(ResolutionOutcome::Idempotent);
        }
        self.require_active(claim, now_unix_seconds)?;
        self.clock_watermark_unix_seconds = now_unix_seconds;
        self.advance(queue)?;
        self.last_resolution = Some(ClaimResolution {
            claim: claim.clone(),
            resolved_at_unix_seconds: now_unix_seconds,
            disposition: ClaimDisposition::Acknowledged,
        });
        Ok(ResolutionOutcome::Applied)
    }

    pub fn schedule_retry(
        &mut self,
        queue: &OutboxQueue,
        claim: &DeliveryClaim,
        now_unix_seconds: u64,
        retry_delay_seconds: u64,
    ) -> Result<ResolutionOutcome, DeliveryError> {
        self.validate(queue)?;
        if retry_delay_seconds == 0 || retry_delay_seconds > MAX_RETRY_DELAY_SECONDS {
            return Err(DeliveryError::InvalidRequest("retryDelay"));
        }
        self.check_time(now_unix_seconds)?;
        let retry_at = now_unix_seconds
            .checked_add(retry_delay_seconds)
            .ok_or(DeliveryError::InvalidRequest("retryOverflow"))?;
        let disposition = ClaimDisposition::Retry {
            retry_at_unix_seconds: retry_at,
        };
        if self.resolution_matches(claim, disposition) {
            self.clock_watermark_unix_seconds = now_unix_seconds;
            return Ok(ResolutionOutcome::Idempotent);
        }
        self.require_active(claim, now_unix_seconds)?;
        self.clock_watermark_unix_seconds = now_unix_seconds;
        self.active_claim = None;
        self.next_attempt_unix_seconds = retry_at;
        self.last_resolution = Some(ClaimResolution {
            claim: claim.clone(),
            resolved_at_unix_seconds: now_unix_seconds,
            disposition,
        });
        Ok(ResolutionOutcome::Applied)
    }

    pub fn pending_position(&self) -> (usize, usize) {
        (self.batch_cursor, self.record_cursor)
    }

    /// Rebases cursors after storage removes a prefix consisting exclusively
    /// of fully acknowledged batches. The caller must validate against the
    /// compacted queue before committing the containing durable state.
    pub(crate) fn rebase_after_compaction(
        &mut self,
        removed_batches: usize,
    ) -> Result<(), DeliveryError> {
        if removed_batches == 0 || removed_batches > self.batch_cursor {
            return Err(DeliveryError::InvalidState("compactionCursor"));
        }
        let old_batch_cursor = self.batch_cursor;
        self.batch_cursor -= removed_batches;
        if removed_batches == old_batch_cursor
            && self.last_resolution.as_ref().is_some_and(|resolution| {
                matches!(resolution.disposition, ClaimDisposition::Acknowledged)
            })
        {
            // The idempotent ACK replay window referred to the last removed
            // record. Its transition tombstone now lives in the checkpoint.
            self.last_resolution = None;
        }
        Ok(())
    }

    fn current_record<'a>(
        &self,
        queue: &'a OutboxQueue,
    ) -> Result<Option<&'a OutboxRecord>, DeliveryError> {
        if self.batch_cursor > queue.batches.len() {
            return Err(DeliveryError::InvalidState("batchCursor"));
        }
        let Some(batch) = queue.batches.get(self.batch_cursor) else {
            return Ok(None);
        };
        batch
            .records
            .get(self.record_cursor)
            .map(Some)
            .ok_or(DeliveryError::InvalidState("recordCursor"))
    }

    fn previous_record<'a>(&self, queue: &'a OutboxQueue) -> Option<&'a OutboxRecord> {
        if self.record_cursor > 0 {
            return queue
                .batches
                .get(self.batch_cursor)?
                .records
                .get(self.record_cursor - 1);
        }
        self.batch_cursor
            .checked_sub(1)
            .and_then(|index| queue.batches.get(index))
            .and_then(|batch| batch.records.last())
    }

    fn check_time(&self, now: u64) -> Result<(), DeliveryError> {
        if now < self.clock_watermark_unix_seconds {
            return Err(DeliveryError::ClockRollback);
        }
        Ok(())
    }

    fn require_active(&self, claim: &DeliveryClaim, now: u64) -> Result<(), DeliveryError> {
        let active = self
            .active_claim
            .as_ref()
            .ok_or(DeliveryError::StaleClaim)?;
        if active != claim || now >= active.expires_at_unix_seconds {
            return Err(DeliveryError::StaleClaim);
        }
        Ok(())
    }

    fn resolution_matches(&self, claim: &DeliveryClaim, disposition: ClaimDisposition) -> bool {
        self.last_resolution
            .as_ref()
            .is_some_and(|last| last.claim == *claim && last.disposition == disposition)
    }

    fn advance(&mut self, queue: &OutboxQueue) -> Result<(), DeliveryError> {
        let batch = queue
            .batches
            .get(self.batch_cursor)
            .ok_or(DeliveryError::InvalidState("advanceCursor"))?;
        self.record_cursor += 1;
        if self.record_cursor == batch.records.len() {
            self.batch_cursor += 1;
            self.record_cursor = 0;
        }
        self.attempts = 0;
        self.next_attempt_unix_seconds = 0;
        self.active_claim = None;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeliveryClaim {
    pub token: String,
    pub generation: u64,
    pub record_id: String,
    pub attempt: u32,
    pub claimed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaimResolution {
    claim: DeliveryClaim,
    resolved_at_unix_seconds: u64,
    disposition: ClaimDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClaimDisposition {
    Acknowledged,
    Retry { retry_at_unix_seconds: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed {
        claim: DeliveryClaim,
        record: Box<OutboxRecord>,
        replayed: bool,
    },
    Unavailable {
        retry_at_unix_seconds: u64,
    },
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionOutcome {
    Applied,
    Idempotent,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DeliveryError {
    #[error("invalid delivery state: {0}")]
    InvalidState(&'static str),
    #[error("invalid delivery request: {0}")]
    InvalidRequest(&'static str),
    #[error("delivery clock moved backwards")]
    ClockRollback,
    #[error("claim is stale, absent, or expired")]
    StaleClaim,
    #[error("maximum attempts reached for the current record")]
    AttemptsExhausted,
    #[error("claim generation exhausted")]
    GenerationExhausted,
}

fn validate_claim(claim: &DeliveryClaim, record: &OutboxRecord) -> Result<(), DeliveryError> {
    if !valid_token(&claim.token)
        || claim.generation == 0
        || claim.record_id != record.id
        || claim.attempt == 0
        || claim.attempt > MAX_ATTEMPTS_PER_RECORD
    {
        return Err(DeliveryError::InvalidState("claimFields"));
    }
    Ok(())
}

fn valid_token(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalBlock, CanonicalEvent, ChainIdentity, outbox::build_outbox};

    #[test]
    fn records_are_claimed_and_acknowledged_in_global_order() {
        let queue = queue_with_reorg();
        let mut delivery = OutboxDelivery::new();
        let expected = queue
            .batches
            .iter()
            .flat_map(|batch| &batch.records)
            .map(|record| (record.id.clone(), record.action))
            .collect::<Vec<_>>();

        for (position, (expected_id, expected_action)) in expected.iter().enumerate() {
            let now = 1_800_000_000 + position as u64;
            let (claim, record) =
                claimed(delivery.claim_next(&queue, now, 30, &token((position + 1) as u8)));
            assert_eq!(&record.id, expected_id);
            assert_eq!(record.action, *expected_action);
            assert_eq!(claim.attempt, 1);
            assert_eq!(
                delivery.acknowledge(&queue, &claim, now).unwrap(),
                ResolutionOutcome::Applied
            );
            assert_eq!(
                delivery.acknowledge(&queue, &claim, now).unwrap(),
                ResolutionOutcome::Idempotent
            );
        }
        assert_eq!(
            delivery
                .claim_next(&queue, 1_800_000_100, 30, &token(9))
                .unwrap(),
            ClaimOutcome::Empty
        );
        delivery.validate(&queue).unwrap();
    }

    #[test]
    fn active_lease_retry_and_expiry_never_skip_the_head_record() {
        let queue = queue_with_reorg();
        let mut delivery = OutboxDelivery::new();
        let (first, record) = claimed(delivery.claim_next(&queue, 100, 10, &token(1)));
        let replay = delivery.claim_next(&queue, 101, 10, &token(1)).unwrap();
        assert!(matches!(
            replay,
            ClaimOutcome::Claimed { replayed: true, .. }
        ));
        assert_eq!(
            delivery.claim_next(&queue, 102, 10, &token(2)).unwrap(),
            ClaimOutcome::Unavailable {
                retry_at_unix_seconds: 110
            }
        );
        assert_eq!(
            delivery.schedule_retry(&queue, &first, 103, 20).unwrap(),
            ResolutionOutcome::Applied
        );
        assert_eq!(
            delivery.schedule_retry(&queue, &first, 103, 20).unwrap(),
            ResolutionOutcome::Idempotent
        );
        assert_eq!(
            delivery.claim_next(&queue, 122, 10, &token(3)).unwrap(),
            ClaimOutcome::Unavailable {
                retry_at_unix_seconds: 123
            }
        );
        let (second, retried_record) = claimed(delivery.claim_next(&queue, 123, 10, &token(3)));
        assert_eq!(record.id, retried_record.id);
        assert_eq!(second.attempt, 2);
        assert_ne!(first.generation, second.generation);
        assert_eq!(
            delivery.acknowledge(&queue, &first, 124).unwrap_err(),
            DeliveryError::StaleClaim
        );
        delivery.acknowledge(&queue, &second, 124).unwrap();
    }

    #[test]
    fn expired_and_forged_claims_cannot_acknowledge() {
        let queue = queue_with_reorg();
        let mut delivery = OutboxDelivery::new();
        let (claim, _) = claimed(delivery.claim_next(&queue, 200, 10, &token(1)));
        let before = delivery.clone();
        assert_eq!(
            delivery.acknowledge(&queue, &claim, 210).unwrap_err(),
            DeliveryError::StaleClaim
        );
        assert_eq!(delivery, before);

        let mut forged = claim.clone();
        forged.generation += 1;
        assert_eq!(
            delivery.acknowledge(&queue, &forged, 209).unwrap_err(),
            DeliveryError::StaleClaim
        );
        assert_eq!(delivery, before);
    }

    #[test]
    fn rejected_requests_and_clock_rollback_are_atomic() {
        let queue = queue_with_reorg();
        let mut delivery = OutboxDelivery::new();
        let (claim, _) = claimed(delivery.claim_next(&queue, 300, 10, &token(1)));
        let before = delivery.clone();
        assert_eq!(
            delivery
                .schedule_retry(&queue, &claim, 301, MAX_RETRY_DELAY_SECONDS + 1)
                .unwrap_err(),
            DeliveryError::InvalidRequest("retryDelay")
        );
        assert_eq!(delivery, before);
        assert_eq!(
            delivery.claim_next(&queue, 299, 10, &token(2)).unwrap_err(),
            DeliveryError::ClockRollback
        );
        assert_eq!(delivery, before);
    }

    #[test]
    fn tampered_cursor_claim_and_queue_fail_closed() {
        let queue = queue_with_reorg();
        let mut delivery = OutboxDelivery::new();
        claimed(delivery.claim_next(&queue, 400, 10, &token(1)));

        let mut bad_cursor = delivery.clone();
        bad_cursor.record_cursor = usize::MAX;
        assert_eq!(
            bad_cursor.validate(&queue).unwrap_err(),
            DeliveryError::InvalidState("recordCursor")
        );
        let mut bad_claim = delivery.clone();
        bad_claim.active_claim.as_mut().unwrap().record_id = hash('f');
        assert_eq!(
            bad_claim.validate(&queue).unwrap_err(),
            DeliveryError::InvalidState("claimFields")
        );
        let (claim, _) = claimed(delivery.claim_next(&queue, 410, 10, &token(2)));
        delivery.acknowledge(&queue, &claim, 411).unwrap();
        delivery.last_resolution.as_mut().unwrap().claim.record_id =
            queue.batches[1].records[0].id.clone();
        assert_eq!(
            delivery.validate(&queue).unwrap_err(),
            DeliveryError::InvalidState("claimFields")
        );
        let mut bad_queue = queue.clone();
        bad_queue.batches.swap(0, 1);
        assert_eq!(
            OutboxDelivery::new().validate(&bad_queue).unwrap_err(),
            DeliveryError::InvalidState("queue")
        );
    }

    fn claimed(result: Result<ClaimOutcome, DeliveryError>) -> (DeliveryClaim, OutboxRecord) {
        match result.unwrap() {
            ClaimOutcome::Claimed {
                claim,
                record,
                replayed: false,
            } => (claim, *record),
            other => panic!("expected new claim, got {other:?}"),
        }
    }

    fn queue_with_reorg() -> OutboxQueue {
        let mut queue = OutboxQueue::new();
        queue
            .enqueue(build_outbox(&network(), &hash('1'), &block(101, '2', '1'), &[]).unwrap())
            .unwrap();
        queue
            .enqueue(
                build_outbox(
                    &network(),
                    &hash('2'),
                    &block(101, '3', '1'),
                    &[block(101, '2', '1')],
                )
                .unwrap(),
            )
            .unwrap();
        queue
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
            schema: "bloch.data.canonical-block.v1".into(),
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

    fn token(byte: u8) -> String {
        format!("0x{byte:064x}")
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }
}
