//! Fail-closed coordination between authenticated acceptance receipts and
//! durable outbox acknowledgement.
//!
//! This crate performs no network access, owns no private keys, and makes no
//! chain-finality claim. It first authenticates an exact delivery/receipt pair
//! against pinned trust policy and the caller's exact lease claim. Only then
//! does it delegate to the core's lock-and-reload durable acknowledgement.

use bloch_indexer_core::{
    delivery::{AcknowledgementEvidence, DeliveryClaim, ResolutionOutcome},
    storage::{DurableState, StorageError, acknowledge_with_evidence_and_persist},
};
use bloch_indexer_delivery_protocol::{
    ProtocolError, TrustPolicy, trust_policy_sha256, verify_accepted_receipt_for_claim,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedAcknowledgement {
    pub outcome: ResolutionOutcome,
    pub authorization: AuthorizationEvidence,
}

/// Canonical evidence returned together with a successful durable resolution.
///
/// Its transport-neutral digest subset is retained atomically in the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationEvidence {
    pub durable: AcknowledgementEvidence,
    pub record_id: String,
    pub attempt: u32,
    pub generation: u64,
}

#[derive(Debug, Error)]
pub enum ReceiptAckError {
    #[error("authenticated receipt verification failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("durable acknowledgement failed: {0}")]
    Storage(#[from] StorageError),
}

/// Authenticates `delivery_bytes` and `receipt_bytes` for the exact claim,
/// then durably acknowledges that claim under the snapshot writer lock.
///
/// A protocol failure cannot mutate state. A storage failure preserves the
/// caller's in-memory state. Replaying the exact successfully persisted claim
/// is safe and returns [`ResolutionOutcome::Idempotent`].
pub fn acknowledge_authenticated_receipt_and_persist(
    state: &mut DurableState,
    snapshot_path: &Path,
    expected_claim: &DeliveryClaim,
    now_unix_seconds: u64,
    delivery_bytes: &[u8],
    receipt_bytes: &[u8],
    policy: &TrustPolicy,
) -> Result<AuthenticatedAcknowledgement, ReceiptAckError> {
    let verified =
        verify_accepted_receipt_for_claim(receipt_bytes, delivery_bytes, policy, expected_claim)?;
    let durable = AcknowledgementEvidence {
        receiver_id: verified.receiver_id().to_owned(),
        trust_policy_sha256: trust_policy_sha256(policy)?,
        delivery_sha256: verified.delivery().sha256().to_owned(),
        receipt_sha256: format!("0x{}", hex::encode(Sha256::digest(receipt_bytes))),
    };
    let outcome = acknowledge_with_evidence_and_persist(
        state,
        snapshot_path,
        expected_claim,
        &durable,
        now_unix_seconds,
    )?;
    Ok(AuthenticatedAcknowledgement {
        outcome,
        authorization: AuthorizationEvidence {
            durable,
            record_id: expected_claim.record_id.clone(),
            attempt: expected_claim.attempt,
            generation: expected_claim.generation,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_indexer_core::{
        BlockAnchor, CanonicalBlock, CanonicalEvent, CanonicalIndexer, ChainIdentity,
        delivery::{ClaimOutcome, DeliveryError},
        storage::{apply_and_persist, claim_and_persist, load_snapshot},
    };
    use bloch_indexer_delivery_protocol::{
        TrustedSigner, build_delivery_signature_message, build_receipt_signature_message,
        canonical_record_bytes, encode_accepted_receipt, encode_delivery, verify_delivery,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fs, path::PathBuf};

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
        state: DurableState,
        claim: DeliveryClaim,
        policy: TrustPolicy,
        delivery: Vec<u8>,
        receipt: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = private_directory();
            let path = directory.join("snapshot.json");
            let network = network();
            let indexer = CanonicalIndexer::new(
                network.clone(),
                BlockAnchor {
                    height: 100,
                    block_hash: hash('1'),
                    state_root: hash('a'),
                },
                16,
            )
            .unwrap();
            let mut state = DurableState::new(indexer);
            apply_and_persist(&mut state, block(network.clone()), &path).unwrap();
            let (claim, record) = match claim_and_persist(
                &mut state,
                &path,
                1_800_000_000,
                60,
                &hash('9'),
            )
            .unwrap()
            {
                ClaimOutcome::Claimed { claim, record, .. } => (claim, *record),
                other => panic!("expected claim, got {other:?}"),
            };

            let sender = SigningKey::from_bytes(&[7; 32]);
            let receiver = SigningKey::from_bytes(&[8; 32]);
            let policy = TrustPolicy {
                destination_domain: "bloch-indexer-receiver".into(),
                network: network.clone(),
                senders: vec![TrustedSigner {
                    signer_id: "sender-1".into(),
                    ed25519_public_key: key(&sender),
                }],
                receivers: vec![TrustedSigner {
                    signer_id: "receiver-1".into(),
                    ed25519_public_key: key(&receiver),
                }],
            };
            let record_bytes = canonical_record_bytes(&record).unwrap();
            let message = build_delivery_signature_message(
                &policy.destination_domain,
                &network,
                "sender-1",
                claim.attempt,
                claim.generation,
                &record_bytes,
            )
            .unwrap();
            let delivery = encode_delivery(
                &policy.destination_domain,
                &network,
                "sender-1",
                claim.attempt,
                claim.generation,
                &record_bytes,
                &sender.sign(&message).to_bytes(),
            )
            .unwrap();
            let verified = verify_delivery(&delivery, &policy).unwrap();
            let receipt_message = build_receipt_signature_message(
                &policy.destination_domain,
                &network,
                "receiver-1",
                verified.sha256(),
                &record.id,
                claim.attempt,
                claim.generation,
            )
            .unwrap();
            let receipt = encode_accepted_receipt(
                &policy.destination_domain,
                &network,
                "receiver-1",
                &verified,
                &receiver.sign(&receipt_message).to_bytes(),
            )
            .unwrap();
            Self {
                directory,
                path,
                state,
                claim,
                policy,
                delivery,
                receipt,
            }
        }

        fn acknowledge(
            &mut self,
            now: u64,
        ) -> Result<AuthenticatedAcknowledgement, ReceiptAckError> {
            acknowledge_authenticated_receipt_and_persist(
                &mut self.state,
                &self.path,
                &self.claim,
                now,
                &self.delivery,
                &self.receipt,
                &self.policy,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn valid_receipt_is_the_only_path_to_durable_acknowledgement() {
        let mut fixture = Fixture::new();
        let result = fixture.acknowledge(1_800_000_001).unwrap();
        assert_eq!(result.outcome, ResolutionOutcome::Applied);
        assert_eq!(result.authorization.durable.receiver_id, "receiver-1");
        assert_eq!(result.authorization.record_id, fixture.claim.record_id);
        assert_eq!(result.authorization.attempt, fixture.claim.attempt);
        assert_eq!(result.authorization.generation, fixture.claim.generation);
        assert_eq!(result.authorization.durable.trust_policy_sha256.len(), 66);
        assert_eq!(result.authorization.durable.delivery_sha256.len(), 66);
        assert_eq!(result.authorization.durable.receipt_sha256.len(), 66);
        assert_eq!(
            load_snapshot(&fixture.path)
                .unwrap()
                .delivery
                .last_acknowledgement_evidence(),
            Some(&result.authorization.durable)
        );
        assert_eq!(
            load_snapshot(&fixture.path)
                .unwrap()
                .delivery
                .pending_position(),
            (1, 0)
        );
    }

    #[test]
    fn wrong_receipt_fails_before_state_mutation() {
        let mut fixture = Fixture::new();
        let before = fs::read(&fixture.path).unwrap();
        let last = fixture.receipt.len() - 2;
        fixture.receipt[last] ^= 1;
        assert!(matches!(
            fixture.acknowledge(1_800_000_001),
            Err(ReceiptAckError::Protocol(_))
        ));
        assert_eq!(fs::read(&fixture.path).unwrap(), before);
        assert_eq!(fixture.state.delivery.pending_position(), (0, 0));
    }

    #[test]
    fn stale_claim_is_rejected_before_acknowledgement() {
        let mut fixture = Fixture::new();
        let before = fs::read(&fixture.path).unwrap();
        fixture.claim.generation += 1;
        assert!(matches!(
            fixture.acknowledge(1_800_000_001),
            Err(ReceiptAckError::Protocol(ProtocolError::ClaimMismatch))
        ));
        assert_eq!(fs::read(&fixture.path).unwrap(), before);
    }

    #[test]
    fn exact_receipt_replay_is_idempotent_and_never_skips() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.acknowledge(1_800_000_001).unwrap().outcome,
            ResolutionOutcome::Applied
        );
        assert_eq!(
            fixture.acknowledge(1_800_000_002).unwrap().outcome,
            ResolutionOutcome::Idempotent
        );
        assert_eq!(fixture.state.delivery.pending_position(), (1, 0));
        assert_eq!(
            load_snapshot(&fixture.path)
                .unwrap()
                .delivery
                .pending_position(),
            (1, 0)
        );
    }

    #[test]
    fn persisted_resolution_refuses_different_evidence_on_replay() {
        let mut fixture = Fixture::new();
        let result = fixture.acknowledge(1_800_000_001).unwrap();
        let before = fs::read(&fixture.path).unwrap();
        let mut changed = result.authorization.durable;
        changed.receipt_sha256 = hash('f');
        let error = acknowledge_with_evidence_and_persist(
            &mut fixture.state,
            &fixture.path,
            &fixture.claim,
            &changed,
            1_800_000_002,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StorageError::Delivery(DeliveryError::InvalidRequest(
                "acknowledgementEvidenceMismatch"
            ))
        ));
        assert_eq!(fs::read(&fixture.path).unwrap(), before);
    }

    #[test]
    fn persistence_failure_does_not_advance_in_memory_state() {
        let mut fixture = Fixture::new();
        let missing = fixture.directory.join("missing").join("snapshot.json");
        let before = fixture.state.delivery.clone();
        let error = acknowledge_authenticated_receipt_and_persist(
            &mut fixture.state,
            &missing,
            &fixture.claim,
            1_800_000_001,
            &fixture.delivery,
            &fixture.receipt,
            &fixture.policy,
        )
        .unwrap_err();
        assert!(matches!(error, ReceiptAckError::Storage(_)));
        assert_eq!(fixture.state.delivery, before);
        assert_eq!(fixture.state.delivery.pending_position(), (0, 0));
        assert_eq!(
            load_snapshot(&fixture.path)
                .unwrap()
                .delivery
                .pending_position(),
            (0, 0)
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_transition_replace_failure_keeps_memory_and_snapshot_unacknowledged() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        let before_state = fixture.state.delivery.clone();
        let before_snapshot = fs::read(&fixture.path).unwrap();
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o500)).unwrap();
        let result = fixture.acknowledge(1_800_000_001);
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(ReceiptAckError::Storage(_))));
        assert_eq!(fixture.state.delivery, before_state);
        assert_eq!(fs::read(&fixture.path).unwrap(), before_snapshot);
        assert_eq!(
            load_snapshot(&fixture.path)
                .unwrap()
                .delivery
                .pending_position(),
            (0, 0)
        );
    }

    #[test]
    fn authenticated_but_expired_claim_remains_fail_closed() {
        let mut fixture = Fixture::new();
        let error = fixture
            .acknowledge(fixture.claim.expires_at_unix_seconds)
            .unwrap_err();
        assert!(matches!(
            error,
            ReceiptAckError::Storage(StorageError::Delivery(DeliveryError::StaleClaim))
        ));
        assert_eq!(fixture.state.delivery.pending_position(), (0, 0));
    }

    fn network() -> ChainIdentity {
        ChainIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: hash('a'),
        }
    }

    fn block(network: ChainIdentity) -> CanonicalBlock {
        CanonicalBlock {
            schema: "bloch.data.canonical-block.v1".into(),
            network,
            height: 101,
            block_hash: hash('2'),
            parent_hash: hash('1'),
            state_root: hash('b'),
            timestamp_unix_seconds: 1_800_000_000,
            events: vec![CanonicalEvent {
                transaction_hash: hash('3'),
                transaction_index: 0,
                log_index: 0,
                address: format!("0x{}", "4".repeat(40)),
                topics: vec![hash('5')],
                data: "0x".into(),
            }],
        }
    }

    fn hash(character: char) -> String {
        format!("0x{}", character.to_string().repeat(64))
    }

    fn key(signing: &SigningKey) -> String {
        format!("0x{}", hex::encode(signing.verifying_key().to_bytes()))
    }

    fn private_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bloch-receipt-ack-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }
}
