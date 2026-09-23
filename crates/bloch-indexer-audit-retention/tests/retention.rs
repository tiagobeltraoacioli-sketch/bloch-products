#![cfg(unix)]

use bloch_indexer_audit::{
    AuditSigner, AuditTrustPolicy, audit_trust_policy_sha256, canonical_audit_trust_policy_bytes,
    detached_signature_message, export_audit_artifact, verify_audit_artifact,
};
use bloch_indexer_audit_retention::{
    ReplicaSetError, ReplicaStatus, ReplicaVerificationInput, RetentionCheckpointError,
    RetentionCheckpointPolicy, RetentionCheckpointSigner, RetentionError, RetentionExpectation,
    append_audit_entry, canonical_retention_checkpoint_policy_bytes, export_retention_checkpoint,
    parse_replica_manifest, retention_checkpoint_policy_sha256,
    retention_checkpoint_signature_message, verify_audit_ledger,
    verify_audit_ledger_with_expectation, verify_audit_replicas, verify_retention_checkpoint,
    verify_retention_checkpoint_against_ledger,
};
use bloch_indexer_core::{
    ChainIdentity,
    outbox::{
        OUTBOX_CHECKPOINT_LINK_SCHEMA, OUTBOX_CHECKPOINT_SCHEMA, OutboxCheckpoint,
        OutboxCheckpointLink,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}

struct StableDigest(Sha256);

impl StableDigest {
    fn new(domain: &str) -> Self {
        let mut digest = Self(Sha256::new());
        digest.text(domain);
        digest
    }
    fn text(&mut self, value: &str) {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
    }
    fn number(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }
    fn finish(self) -> String {
        format!("0x{}", hex::encode(self.0.finalize()))
    }
}

fn network() -> ChainIdentity {
    ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('a'),
    }
}

fn checkpoint(tip: char) -> OutboxCheckpoint {
    let network = network();
    let anchor = hash('1');
    let new_tip = hash(tip);
    let transition_id = hash('3');
    let batch_hash = hash('4');
    let mut genesis = StableDigest::new("bloch.data.outbox-checkpoint-genesis.v1");
    genesis.text(&network.network);
    genesis.number(network.chain_id);
    genesis.text(&network.genesis_hash);
    genesis.text(&anchor);
    let initial = genesis.finish();
    let mut link = StableDigest::new("bloch.data.outbox-checkpoint-link.v1");
    link.text(&initial);
    link.text(&transition_id);
    link.text(&anchor);
    link.text(&new_tip);
    link.number(2);
    link.text(&batch_hash);
    let chain_hash = link.finish();
    OutboxCheckpoint {
        schema: OUTBOX_CHECKPOINT_SCHEMA.into(),
        network,
        anchor_tip_hash: anchor.clone(),
        compacted_tip_hash: new_tip.clone(),
        batch_count: 1,
        record_count: 2,
        chain_hash: chain_hash.clone(),
        links: vec![OutboxCheckpointLink {
            schema: OUTBOX_CHECKPOINT_LINK_SCHEMA.into(),
            transition_id,
            previous_tip_hash: anchor,
            new_tip_hash: new_tip,
            record_count: 2,
            batch_hash,
            chain_hash,
        }],
    }
}

struct Fixture {
    key: SigningKey,
    policy: AuditTrustPolicy,
    policy_bytes: Vec<u8>,
    policy_sha256: String,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let policy = AuditTrustPolicy {
            audit_domain: "bloch-prod-outbox-audit-1".into(),
            network: network(),
            anchor_tip_hash: hash('1'),
            signers: vec![AuditSigner {
                signer_id: "auditor-1".into(),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
            }],
        };
        let policy_bytes = canonical_audit_trust_policy_bytes(&policy).unwrap();
        let policy_sha256 = audit_trust_policy_sha256(&policy).unwrap();
        Self {
            key,
            policy,
            policy_bytes,
            policy_sha256,
        }
    }

    fn signed_artifact(&self, tip: char) -> (Vec<u8>, [u8; 64]) {
        let bytes = export_audit_artifact(&checkpoint(tip)).unwrap();
        let verified = verify_audit_artifact(&bytes, None).unwrap();
        let message = detached_signature_message(&verified, "auditor-1", &self.policy).unwrap();
        (bytes, self.key.sign(&message).to_bytes())
    }
}

#[test]
fn appends_and_replays_a_canonical_authenticated_chain() {
    let root = private_temp_directory();
    let fixture = Fixture::new(7);
    for tip in ['2', '5'] {
        let (artifact, signature) = fixture.signed_artifact(tip);
        append_audit_entry(
            &root,
            &artifact,
            None,
            "auditor-1",
            &signature,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
        )
        .unwrap();
    }
    let entries =
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, 1);
    assert_eq!(entries[1].previous_entry_sha256, entries[0].entry_sha256);
    verify_audit_ledger_with_expectation(
        &root,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        Some(&RetentionExpectation {
            entry_count: 2,
            head_sha256: entries[1].entry_sha256.clone(),
        }),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(root.join("00000000000000000001.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    cleanup(root);
}

#[test]
fn refuses_wrong_pin_signature_and_policy_without_creating_an_entry() {
    let root = private_temp_directory();
    let fixture = Fixture::new(7);
    let (artifact, signature) = fixture.signed_artifact('2');
    assert!(matches!(
        append_audit_entry(
            &root,
            &artifact,
            None,
            "auditor-1",
            &signature,
            &fixture.policy_bytes,
            &hash('9'),
        ),
        Err(RetentionError::Audit(_))
    ));
    let mut bad_signature = signature;
    bad_signature[0] ^= 1;
    assert!(matches!(
        append_audit_entry(
            &root,
            &artifact,
            None,
            "auditor-1",
            &bad_signature,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
        ),
        Err(RetentionError::Audit(_))
    ));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);

    let other = Fixture::new(8);
    assert!(verify_audit_ledger(&root, &other.policy_bytes, &fixture.policy_sha256).is_err());
    cleanup(root);
}

#[test]
fn detects_content_tampering_deletion_and_unexpected_files() {
    let fixture = Fixture::new(7);

    let tampered = populated_ledger(&fixture, 2);
    let first = tampered.join("00000000000000000001.json");
    let mut bytes = fs::read(&first).unwrap();
    let position = bytes.iter().position(|byte| *byte == b'2').unwrap();
    bytes[position] = b'3';
    fs::write(&first, bytes).unwrap();
    assert!(verify_audit_ledger(&tampered, &fixture.policy_bytes, &fixture.policy_sha256).is_err());
    cleanup(tampered);

    let missing = populated_ledger(&fixture, 2);
    fs::remove_file(missing.join("00000000000000000001.json")).unwrap();
    assert!(matches!(
        verify_audit_ledger(&missing, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::ChainDiscontinuity)
    ));
    cleanup(missing);

    let unexpected = private_temp_directory();
    fs::write(unexpected.join("notes.txt"), b"not an entry").unwrap();
    assert!(matches!(
        verify_audit_ledger(&unexpected, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::InvalidEntryName)
    ));
    cleanup(unexpected);
}

#[test]
fn an_external_head_detects_valid_tail_truncation() {
    let fixture = Fixture::new(7);
    let root = populated_ledger(&fixture, 2);
    let entries =
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).unwrap();
    let expected = RetentionExpectation {
        entry_count: 2,
        head_sha256: entries[1].entry_sha256.clone(),
    };
    fs::remove_file(root.join("00000000000000000002.json")).unwrap();
    assert!(verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).is_ok());
    assert!(matches!(
        verify_audit_ledger_with_expectation(
            &root,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            Some(&expected),
        ),
        Err(RetentionError::InvalidEntry("ledgerExpectation"))
    ));
    cleanup(root);
}

#[test]
fn rejects_noncanonical_and_relinked_entry_bytes() {
    let fixture = Fixture::new(7);
    let root = populated_ledger(&fixture, 1);
    let entry = root.join("00000000000000000001.json");
    let original = fs::read(&entry).unwrap();
    let mut whitespace = Vec::with_capacity(original.len() + 1);
    whitespace.push(b' ');
    whitespace.extend(original);
    fs::write(&entry, whitespace).unwrap();
    assert!(matches!(
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::NonCanonicalEntry)
    ));
    cleanup(root);

    let root = populated_ledger(&fixture, 1);
    let entry = root.join("00000000000000000001.json");
    let second = root.join("00000000000000000002.json");
    fs::hard_link(&entry, &second).unwrap();
    assert!(verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).is_err());
    cleanup(root);
}

#[test]
fn rejects_unsafe_directories_and_entry_links_or_permissions() {
    let fixture = Fixture::new(7);
    let root = private_temp_directory();
    let alias = root.with_extension("alias");
    symlink(&root, &alias).unwrap();
    assert!(matches!(
        verify_audit_ledger(&alias, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::UnsafeLedger(_))
    ));
    fs::remove_file(alias).unwrap();

    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::UnsafeLedger(_))
    ));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    cleanup(root);

    let root = populated_ledger(&fixture, 1);
    let entry = root.join("00000000000000000001.json");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256),
        Err(RetentionError::UnsafeLedger(_))
    ));
    cleanup(root);
}

#[test]
fn signed_checkpoint_authenticates_a_path_independent_ledger_boundary() {
    let fixture = Fixture::new(7);
    let root = populated_ledger(&fixture, 2);
    let entries =
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).unwrap();
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let (checkpoint, signature) = signed_retention_checkpoint(
        &checkpoint_key,
        &policy,
        &fixture.policy_sha256,
        RetentionExpectation {
            entry_count: 2,
            head_sha256: entries[1].entry_sha256.clone(),
        },
    );

    let verified = verify_retention_checkpoint_against_ledger(
        &root,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        &checkpoint,
        "checkpoint-auditor-1",
        &signature,
        &policy_bytes,
        &policy_sha256,
        None,
    )
    .unwrap();
    assert_eq!(verified.ledger_id(), "bloch-prod-retention-ledger-1");
    assert_eq!(verified.entry_count(), 2);

    let moved = root.with_extension("moved");
    fs::rename(&root, &moved).unwrap();
    verify_retention_checkpoint_against_ledger(
        &moved,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        &checkpoint,
        "checkpoint-auditor-1",
        &signature,
        &policy_bytes,
        &policy_sha256,
        None,
    )
    .unwrap();
    cleanup(moved);
}

#[test]
fn checkpoint_rejects_wrong_pin_domain_signer_and_noncanonical_bytes() {
    let fixture = Fixture::new(7);
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let (checkpoint, signature) = signed_retention_checkpoint(
        &checkpoint_key,
        &policy,
        &fixture.policy_sha256,
        RetentionExpectation {
            entry_count: 1,
            head_sha256: hash('b'),
        },
    );
    assert!(matches!(
        verify_retention_checkpoint(
            &checkpoint,
            "checkpoint-auditor-1",
            &signature,
            &policy_bytes,
            &hash('9'),
        ),
        Err(RetentionCheckpointError::PolicyDigestMismatch)
    ));
    assert!(matches!(
        verify_retention_checkpoint(
            &checkpoint,
            "unknown",
            &signature,
            &policy_bytes,
            &policy_sha256,
        ),
        Err(RetentionCheckpointError::UntrustedSigner)
    ));
    let mut bad_signature = signature;
    bad_signature[0] ^= 1;
    assert!(matches!(
        verify_retention_checkpoint(
            &checkpoint,
            "checkpoint-auditor-1",
            &bad_signature,
            &policy_bytes,
            &policy_sha256,
        ),
        Err(RetentionCheckpointError::InvalidSignature)
    ));

    let mut other_domain = policy.clone();
    other_domain.checkpoint_domain = "bloch-prod-retention-checkpoint-2".into();
    let other_bytes = canonical_retention_checkpoint_policy_bytes(&other_domain).unwrap();
    let other_pin = retention_checkpoint_policy_sha256(&other_domain).unwrap();
    assert!(
        verify_retention_checkpoint(
            &checkpoint,
            "checkpoint-auditor-1",
            &signature,
            &other_bytes,
            &other_pin,
        )
        .is_err()
    );

    let mut noncanonical = checkpoint;
    noncanonical.push(b'\n');
    assert!(matches!(
        verify_retention_checkpoint(
            &noncanonical,
            "checkpoint-auditor-1",
            &signature,
            &policy_bytes,
            &policy_sha256,
        ),
        Err(RetentionCheckpointError::NonCanonicalCheckpoint)
    ));

    let text = String::from_utf8(noncanonical[..noncanonical.len() - 1].to_vec()).unwrap();
    let duplicate = text.replacen(
        "\"ledgerId\":",
        "\"ledgerId\":\"substitution\",\"ledgerId\":",
        1,
    );
    assert!(matches!(
        verify_retention_checkpoint(
            duplicate.as_bytes(),
            "checkpoint-auditor-1",
            &signature,
            &policy_bytes,
            &policy_sha256,
        ),
        Err(RetentionCheckpointError::InvalidJson(_))
    ));
    let unknown = text.replacen('{', "{\"unexpected\":true,", 1);
    assert!(matches!(
        verify_retention_checkpoint(
            unknown.as_bytes(),
            "checkpoint-auditor-1",
            &signature,
            &policy_bytes,
            &policy_sha256,
        ),
        Err(RetentionCheckpointError::InvalidJson(_))
    ));
}

#[test]
fn checkpoint_boundary_enforces_genesis_and_nonzero_populated_heads() {
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let audit_policy_sha256 = hash('a');
    let genesis = RetentionExpectation {
        entry_count: 0,
        head_sha256: hash('0'),
    };
    assert!(export_retention_checkpoint(&genesis, &audit_policy_sha256, &policy).is_ok());
    assert!(matches!(
        export_retention_checkpoint(
            &RetentionExpectation {
                entry_count: 0,
                head_sha256: hash('b'),
            },
            &audit_policy_sha256,
            &policy,
        ),
        Err(RetentionCheckpointError::InvalidCheckpoint("boundary"))
    ));
    assert!(matches!(
        export_retention_checkpoint(
            &RetentionExpectation {
                entry_count: 1,
                head_sha256: hash('0'),
            },
            &audit_policy_sha256,
            &policy,
        ),
        Err(RetentionCheckpointError::InvalidCheckpoint("boundary"))
    ));
}

#[test]
fn previous_authenticated_boundary_detects_rollback_and_history_replacement() {
    let fixture = Fixture::new(7);
    let root = populated_ledger(&fixture, 2);
    let entries =
        verify_audit_ledger(&root, &fixture.policy_bytes, &fixture.policy_sha256).unwrap();
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let (first_bytes, first_signature) = signed_retention_checkpoint(
        &checkpoint_key,
        &policy,
        &fixture.policy_sha256,
        RetentionExpectation {
            entry_count: 1,
            head_sha256: entries[0].entry_sha256.clone(),
        },
    );
    let first = verify_retention_checkpoint(
        &first_bytes,
        "checkpoint-auditor-1",
        &first_signature,
        &policy_bytes,
        &policy_sha256,
    )
    .unwrap();
    let (second_bytes, second_signature) = signed_retention_checkpoint(
        &checkpoint_key,
        &policy,
        &fixture.policy_sha256,
        RetentionExpectation {
            entry_count: 2,
            head_sha256: entries[1].entry_sha256.clone(),
        },
    );
    let second = verify_retention_checkpoint_against_ledger(
        &root,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        &second_bytes,
        "checkpoint-auditor-1",
        &second_signature,
        &policy_bytes,
        &policy_sha256,
        Some(&first),
    )
    .unwrap();

    fs::remove_file(root.join("00000000000000000002.json")).unwrap();
    assert!(matches!(
        verify_retention_checkpoint_against_ledger(
            &root,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &first_bytes,
            "checkpoint-auditor-1",
            &first_signature,
            &policy_bytes,
            &policy_sha256,
            Some(&second),
        ),
        Err(RetentionCheckpointError::RollbackDetected)
    ));

    let (replacement_bytes, replacement_signature) = signed_retention_checkpoint(
        &checkpoint_key,
        &policy,
        &fixture.policy_sha256,
        RetentionExpectation {
            entry_count: 1,
            head_sha256: hash('c'),
        },
    );
    let replaced = verify_retention_checkpoint(
        &replacement_bytes,
        "checkpoint-auditor-1",
        &replacement_signature,
        &policy_bytes,
        &policy_sha256,
    )
    .unwrap();
    assert!(matches!(
        verify_retention_checkpoint_against_ledger(
            &root,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &first_bytes,
            "checkpoint-auditor-1",
            &first_signature,
            &policy_bytes,
            &policy_sha256,
            Some(&replaced),
        ),
        Err(RetentionCheckpointError::RollbackDetected)
    ));
    cleanup(root);
}

#[test]
fn replica_quorum_replays_matching_independent_directories() {
    let fixture = Fixture::new(7);
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let first = populated_ledger(&fixture, 2);
    let second = populated_ledger(&fixture, 2);
    let replicas = vec![
        replica_input("replica-a", &first, &fixture, &checkpoint_key, &policy),
        replica_input("replica-b", &second, &fixture, &checkpoint_key, &policy),
    ];
    let report = verify_audit_replicas(
        &replicas,
        2,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        &policy_bytes,
        &policy_sha256,
        None,
    )
    .unwrap();
    assert_eq!(report.agreeing_current_replicas, 2);
    assert_eq!(report.current_count, 2);
    assert!(
        report
            .replicas
            .iter()
            .all(|replica| replica.status == ReplicaStatus::Current)
    );
    cleanup(first);
    cleanup(second);
}

#[test]
fn replica_quorum_marks_ancestral_replica_stale_and_bounds_quorum() {
    let fixture = Fixture::new(7);
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let current_a = populated_ledger(&fixture, 2);
    let current_b = populated_ledger(&fixture, 2);
    let stale = populated_ledger(&fixture, 1);
    let replicas = vec![
        replica_input("replica-a", &current_a, &fixture, &checkpoint_key, &policy),
        replica_input("replica-b", &current_b, &fixture, &checkpoint_key, &policy),
        replica_input("replica-c", &stale, &fixture, &checkpoint_key, &policy),
    ];
    let report = verify_audit_replicas(
        &replicas,
        2,
        &fixture.policy_bytes,
        &fixture.policy_sha256,
        &policy_bytes,
        &policy_sha256,
        None,
    )
    .unwrap();
    assert_eq!(report.replicas[2].status, ReplicaStatus::Stale);
    assert!(matches!(
        verify_audit_replicas(
            &replicas,
            3,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &policy_bytes,
            &policy_sha256,
            None,
        ),
        Err(ReplicaSetError::QuorumNotMet {
            required: 3,
            observed: 2
        })
    ));
    for path in [current_a, current_b, stale] {
        cleanup(path);
    }
}

#[test]
fn replica_comparison_detects_split_brain_and_duplicate_storage() {
    let fixture = Fixture::new(7);
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let first = populated_ledger_with_tips(&fixture, &['2']);
    let fork = populated_ledger_with_tips(&fixture, &['5']);
    let replicas = vec![
        replica_input("replica-a", &first, &fixture, &checkpoint_key, &policy),
        replica_input("replica-b", &fork, &fixture, &checkpoint_key, &policy),
    ];
    assert!(matches!(
        verify_audit_replicas(
            &replicas,
            2,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &policy_bytes,
            &policy_sha256,
            None,
        ),
        Err(ReplicaSetError::SplitBrain { sequence: 1, .. })
    ));
    let duplicate = vec![
        replica_input("replica-a", &first, &fixture, &checkpoint_key, &policy),
        replica_input("replica-b", &first, &fixture, &checkpoint_key, &policy),
    ];
    assert!(matches!(
        verify_audit_replicas(
            &duplicate,
            2,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &policy_bytes,
            &policy_sha256,
            None,
        ),
        Err(ReplicaSetError::DuplicateLedger { .. })
    ));
    cleanup(first);
    cleanup(fork);
}

#[test]
fn replica_comparison_detects_authenticated_rollback_and_policy_substitution() {
    let fixture = Fixture::new(7);
    let checkpoint_key = SigningKey::from_bytes(&[41; 32]);
    let policy = checkpoint_policy(&checkpoint_key);
    let policy_bytes = canonical_retention_checkpoint_policy_bytes(&policy).unwrap();
    let policy_sha256 = retention_checkpoint_policy_sha256(&policy).unwrap();
    let full = populated_ledger(&fixture, 2);
    let prior_input = replica_input("replica-a", &full, &fixture, &checkpoint_key, &policy);
    let prior = verify_retention_checkpoint(
        &prior_input.checkpoint_bytes,
        &prior_input.signer_id,
        &prior_input.signature_bytes,
        &policy_bytes,
        &policy_sha256,
    )
    .unwrap();
    let stale_a = populated_ledger(&fixture, 1);
    let stale_b = populated_ledger(&fixture, 1);
    let stale = vec![
        replica_input("replica-a", &stale_a, &fixture, &checkpoint_key, &policy),
        replica_input("replica-b", &stale_b, &fixture, &checkpoint_key, &policy),
    ];
    assert!(matches!(
        verify_audit_replicas(
            &stale,
            2,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
            &policy_bytes,
            &policy_sha256,
            Some(&prior),
        ),
        Err(ReplicaSetError::Rollback(_))
    ));
    assert!(matches!(
        verify_audit_replicas(
            &stale,
            2,
            &fixture.policy_bytes,
            &hash('9'),
            &policy_bytes,
            &policy_sha256,
            None,
        ),
        Err(ReplicaSetError::Substitution(_))
    ));
    for path in [full, stale_a, stale_b] {
        cleanup(path);
    }
}

#[test]
fn replica_manifest_is_strict_and_bounded() {
    let valid = br#"{"requiredQuorum":2,"replicas":[{"replicaId":"replica-a","ledgerPath":"/a","checkpointPath":"/c1","signerId":"signer-1","signaturePath":"/s1"},{"replicaId":"replica-b","ledgerPath":"/b","checkpointPath":"/c2","signerId":"signer-1","signaturePath":"/s2"}]}"#;
    assert!(parse_replica_manifest(valid).is_ok());
    let duplicate = br#"{"requiredQuorum":2,"requiredQuorum":2,"replicas":[]}"#;
    assert!(matches!(
        parse_replica_manifest(duplicate),
        Err(ReplicaSetError::InvalidManifest(_))
    ));
    let unknown = br#"{"requiredQuorum":2,"unexpected":true,"replicas":[]}"#;
    assert!(matches!(
        parse_replica_manifest(unknown),
        Err(ReplicaSetError::InvalidManifest(_))
    ));
    let one = br#"{"requiredQuorum":1,"replicas":[{"replicaId":"replica-a","ledgerPath":"/a","checkpointPath":"/c","signerId":"s","signaturePath":"/s"}]}"#;
    assert!(matches!(
        parse_replica_manifest(one),
        Err(ReplicaSetError::InvalidConfiguration(_))
    ));
}

fn checkpoint_policy(key: &SigningKey) -> RetentionCheckpointPolicy {
    RetentionCheckpointPolicy {
        checkpoint_domain: "bloch-prod-retention-checkpoint-1".into(),
        ledger_id: "bloch-prod-retention-ledger-1".into(),
        signers: vec![RetentionCheckpointSigner {
            signer_id: "checkpoint-auditor-1".into(),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
        }],
    }
}

fn signed_retention_checkpoint(
    key: &SigningKey,
    policy: &RetentionCheckpointPolicy,
    audit_policy_sha256: &str,
    boundary: RetentionExpectation,
) -> (Vec<u8>, [u8; 64]) {
    let bytes = export_retention_checkpoint(&boundary, audit_policy_sha256, policy).unwrap();
    let message =
        retention_checkpoint_signature_message(&bytes, "checkpoint-auditor-1", policy).unwrap();
    (bytes, key.sign(&message).to_bytes())
}

fn replica_input(
    replica_id: &str,
    ledger: &Path,
    fixture: &Fixture,
    checkpoint_key: &SigningKey,
    policy: &RetentionCheckpointPolicy,
) -> ReplicaVerificationInput {
    let entries =
        verify_audit_ledger(ledger, &fixture.policy_bytes, &fixture.policy_sha256).unwrap();
    let boundary = RetentionExpectation {
        entry_count: entries.len() as u64,
        head_sha256: entries
            .last()
            .map(|entry| entry.entry_sha256.clone())
            .unwrap_or_else(|| hash('0')),
    };
    let (checkpoint_bytes, signature) =
        signed_retention_checkpoint(checkpoint_key, policy, &fixture.policy_sha256, boundary);
    ReplicaVerificationInput {
        replica_id: replica_id.into(),
        ledger: ledger.to_owned(),
        checkpoint_bytes,
        signer_id: "checkpoint-auditor-1".into(),
        signature_bytes: signature.to_vec(),
    }
}

fn populated_ledger_with_tips(fixture: &Fixture, tips: &[char]) -> PathBuf {
    let root = private_temp_directory();
    for tip in tips {
        let (artifact, signature) = fixture.signed_artifact(*tip);
        append_audit_entry(
            &root,
            &artifact,
            None,
            "auditor-1",
            &signature,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
        )
        .unwrap();
    }
    root
}

fn populated_ledger(fixture: &Fixture, count: usize) -> PathBuf {
    let root = private_temp_directory();
    for tip in ['2', '5'].into_iter().take(count) {
        let (artifact, signature) = fixture.signed_artifact(tip);
        append_audit_entry(
            &root,
            &artifact,
            None,
            "auditor-1",
            &signature,
            &fixture.policy_bytes,
            &fixture.policy_sha256,
        )
        .unwrap();
    }
    root
}

fn private_temp_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bloch-audit-retention-{}-{nonce}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn cleanup(path: impl AsRef<Path>) {
    fs::remove_dir_all(path).unwrap();
}
