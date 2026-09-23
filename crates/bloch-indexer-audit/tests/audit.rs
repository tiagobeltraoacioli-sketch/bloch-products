use bloch_indexer_audit::{
    AUDIT_ARTIFACT_SCHEMA, AuditError, AuditExpectation, AuditSigner, AuditTrustPolicy,
    audit_trust_policy_sha256, canonical_audit_trust_policy_bytes, detached_signature_message,
    export_audit_artifact, parse_audit_trust_policy, verify_audit_artifact,
    verify_detached_signature,
};
use bloch_indexer_core::{
    ChainIdentity,
    outbox::{
        OUTBOX_CHECKPOINT_LINK_SCHEMA, OUTBOX_CHECKPOINT_SCHEMA, OutboxCheckpoint,
        OutboxCheckpointLink,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

fn checkpoint_with_tip(tip: char) -> OutboxCheckpoint {
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
    let mut link_digest = StableDigest::new("bloch.data.outbox-checkpoint-link.v1");
    link_digest.text(&initial);
    link_digest.text(&transition_id);
    link_digest.text(&anchor);
    link_digest.text(&new_tip);
    link_digest.number(2);
    link_digest.text(&batch_hash);
    let chain_hash = link_digest.finish();
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

fn expectation(checkpoint: &OutboxCheckpoint) -> AuditExpectation {
    AuditExpectation {
        network: checkpoint.network.clone(),
        anchor_tip_hash: checkpoint.anchor_tip_hash.clone(),
        compacted_tip_hash: checkpoint.compacted_tip_hash.clone(),
        batch_count: checkpoint.batch_count,
        record_count: checkpoint.record_count,
        chain_hash: checkpoint.chain_hash.clone(),
    }
}

fn signer_and_policy() -> (SigningKey, AuditTrustPolicy) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let policy = AuditTrustPolicy {
        audit_domain: "bloch-prod-outbox-audit-1".into(),
        network: network(),
        anchor_tip_hash: hash('1'),
        signers: vec![AuditSigner {
            signer_id: "auditor-1".into(),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
        }],
    };
    (key, policy)
}

#[test]
fn exports_and_verifies_all_checkpoint_commitments() {
    let checkpoint = checkpoint_with_tip('2');
    let bytes = export_audit_artifact(&checkpoint).unwrap();
    let verified = verify_audit_artifact(&bytes, Some(&expectation(&checkpoint))).unwrap();
    assert_eq!(verified.checkpoint, checkpoint);
    assert!(verified.canonical_sha256.starts_with("0x"));
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], AUDIT_ARTIFACT_SCHEMA);
}

#[test]
fn checksum_is_not_an_external_expectation_or_authenticity_claim() {
    let reviewed = checkpoint_with_tip('2');
    let attacker_selected = checkpoint_with_tip('5');
    let self_consistent = export_audit_artifact(&attacker_selected).unwrap();
    assert!(verify_audit_artifact(&self_consistent, None).is_ok());
    assert_eq!(
        verify_audit_artifact(&self_consistent, Some(&expectation(&reviewed))),
        Err(AuditError::ExpectationMismatch)
    );
}

#[test]
fn rejects_digest_checkpoint_shape_unknown_and_duplicate_fields() {
    let checkpoint = checkpoint_with_tip('2');
    let bytes = export_audit_artifact(&checkpoint).unwrap();
    let mut document: Value = serde_json::from_slice(&bytes).unwrap();
    document["canonicalSha256"] = Value::String(hash('9'));
    assert_eq!(
        verify_audit_artifact(&serde_json::to_vec(&document).unwrap(), None),
        Err(AuditError::ArtifactDigestMismatch)
    );

    let mut broken = checkpoint.clone();
    broken.links[0].record_count = 3;
    let mut document: Value = serde_json::from_slice(&bytes).unwrap();
    document["checkpoint"] = serde_json::to_value(broken).unwrap();
    assert_eq!(
        verify_audit_artifact(&serde_json::to_vec(&document).unwrap(), None),
        Err(AuditError::InvalidArtifact("checkpoint"))
    );

    let mut unknown: Value = serde_json::from_slice(&bytes).unwrap();
    unknown["finalized"] = Value::Bool(true);
    assert!(matches!(
        verify_audit_artifact(&serde_json::to_vec(&unknown).unwrap(), None),
        Err(AuditError::InvalidJson(_))
    ));

    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen(
        &format!("\"schema\":\"{AUDIT_ARTIFACT_SCHEMA}\""),
        &format!("\"schema\":\"{AUDIT_ARTIFACT_SCHEMA}\",\"schema\":\"{AUDIT_ARTIFACT_SCHEMA}\""),
        1,
    );
    assert!(matches!(
        verify_audit_artifact(duplicate.as_bytes(), None),
        Err(AuditError::InvalidJson(message)) if message.contains("duplicate")
    ));
}

#[test]
fn pinned_policy_is_canonical_and_rejects_wrong_pin() {
    let (_, policy) = signer_and_policy();
    let canonical = canonical_audit_trust_policy_bytes(&policy).unwrap();
    let digest = audit_trust_policy_sha256(&policy).unwrap();
    let parsed = parse_audit_trust_policy(&canonical, &digest).unwrap();
    assert_eq!(parsed, policy);
    assert_eq!(
        parse_audit_trust_policy(&canonical, &hash('8')),
        Err(AuditError::PolicyDigestMismatch)
    );

    let mut duplicate = policy.clone();
    duplicate.signers.push(duplicate.signers[0].clone());
    assert_eq!(
        canonical_audit_trust_policy_bytes(&duplicate),
        Err(AuditError::InvalidPolicy("duplicateSigner"))
    );
}

#[test]
fn detached_signature_authenticates_exact_artifact_and_context() {
    let (key, policy) = signer_and_policy();
    let checkpoint = checkpoint_with_tip('2');
    let bytes = export_audit_artifact(&checkpoint).unwrap();
    let artifact = verify_audit_artifact(&bytes, Some(&expectation(&checkpoint))).unwrap();
    let message = detached_signature_message(&artifact, "auditor-1", &policy).unwrap();
    let signature = key.sign(&message).to_bytes();
    verify_detached_signature(&artifact, "auditor-1", &signature, &policy).unwrap();

    let changed = checkpoint_with_tip('5');
    let changed = verify_audit_artifact(&export_audit_artifact(&changed).unwrap(), None).unwrap();
    assert_eq!(
        verify_detached_signature(&changed, "auditor-1", &signature, &policy),
        Err(AuditError::InvalidSignature)
    );

    let mut other_domain = policy.clone();
    other_domain.audit_domain = "bloch-prod-outbox-audit-2".into();
    assert_eq!(
        verify_detached_signature(&artifact, "auditor-1", &signature, &other_domain),
        Err(AuditError::InvalidSignature)
    );

    let second_key = SigningKey::from_bytes(&[8; 32]);
    let mut expanded_policy = policy.clone();
    expanded_policy.signers.push(AuditSigner {
        signer_id: "auditor-2".into(),
        ed25519_public_key: format!("0x{}", hex::encode(second_key.verifying_key().to_bytes())),
    });
    assert_eq!(
        verify_detached_signature(&artifact, "auditor-1", &signature, &expanded_policy),
        Err(AuditError::InvalidSignature)
    );
}

#[test]
fn signature_verification_rejects_untrusted_signer_context_and_length() {
    let (key, policy) = signer_and_policy();
    let checkpoint = checkpoint_with_tip('2');
    let artifact =
        verify_audit_artifact(&export_audit_artifact(&checkpoint).unwrap(), None).unwrap();
    assert_eq!(
        detached_signature_message(&artifact, "intruder", &policy),
        Err(AuditError::UntrustedSigner)
    );
    assert_eq!(
        verify_detached_signature(&artifact, "auditor-1", &[0; 63], &policy),
        Err(AuditError::InvalidSignature)
    );

    let message = detached_signature_message(&artifact, "auditor-1", &policy).unwrap();
    let signature = key.sign(&message).to_bytes();
    let mut wrong_anchor = policy.clone();
    wrong_anchor.anchor_tip_hash = hash('6');
    assert_eq!(
        verify_detached_signature(&artifact, "auditor-1", &signature, &wrong_anchor),
        Err(AuditError::TrustContextMismatch)
    );
}

#[test]
fn policy_parser_rejects_duplicate_keys_and_unbounded_input() {
    let (_, policy) = signer_and_policy();
    let bytes = canonical_audit_trust_policy_bytes(&policy).unwrap();
    let digest = audit_trust_policy_sha256(&policy).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen(
        "\"auditDomain\":",
        "\"auditDomain\":\"shadow\",\"auditDomain\":",
        1,
    );
    assert!(matches!(
        parse_audit_trust_policy(duplicate.as_bytes(), &digest),
        Err(AuditError::InvalidJson(message)) if message.contains("duplicate")
    ));
    let oversized = vec![b' '; bloch_indexer_audit::MAX_AUDIT_POLICY_BYTES + 1];
    assert!(matches!(
        parse_audit_trust_policy(&oversized, &digest),
        Err(AuditError::PolicyTooLarge { .. })
    ));
}

#[test]
fn policy_does_not_accept_self_asserted_finality_fields() {
    let (_, policy) = signer_and_policy();
    let digest = audit_trust_policy_sha256(&policy).unwrap();
    let mut document: Value =
        serde_json::from_slice(&canonical_audit_trust_policy_bytes(&policy).unwrap()).unwrap();
    document["finality"] = json!("proven");
    assert!(matches!(
        parse_audit_trust_policy(&serde_json::to_vec(&document).unwrap(), &digest),
        Err(AuditError::InvalidJson(_))
    ));
}
