use bloch_evm_consensus_finality::{
    CONSENSUS_FINALITY_POLICY_SCHEMA, ConsensusCheckpoint, ConsensusFinalityPolicy,
    PINNED_VALIDATOR_SET_MODE, TRANSITIONED_VALIDATOR_SET_MODE, TransitionedConsensusFinalityError,
    VALIDATOR_SET_MANIFEST_SCHEMA, Validator, ValidatorSetManifest,
    ValidatorSetTransitionSignatures, ValidatorSetTransitionSource, ValidatorSignature,
    consensus_finality_policy_sha256, create_transitioned_consensus_finality_certificate,
    create_validator_set_transition_certificate, transitioned_consensus_finality_signing_message,
    validator_set_transition_signing_messages, verify_transitioned_consensus_finality,
    verify_validator_set_transition,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

const REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    old_keys: Vec<SigningKey>,
    new_keys: Vec<SigningKey>,
    time_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_policy_pin: String,
    policy: ConsensusFinalityPolicy,
    policy_pin: String,
    time: VerifiedTrustedTime,
}

impl Fixture {
    fn new() -> Self {
        let old_keys = keys(&[1, 2, 3]);
        let new_keys = keys(&[4, 5, 6]);
        let time_keys = keys(&[11, 12, 13]);
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "transitioned-finality-time".into(),
            signature_domain: "bloch:l2:transitioned-finality:time".into(),
            state_identity: "bloch-l2:700771:finality".into(),
            remote_cursor_policy_sha256: REMOTE_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_token_lifetime_seconds: 100,
            authorities: time_keys
                .iter()
                .enumerate()
                .map(|(index, key)| TrustedTimeAuthority {
                    authority_id: format!("time-{}", index + 1),
                    ed25519_public_key: hex_key(key),
                })
                .collect(),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let time_message =
            trusted_time_signature_message(&time_policy, &time_pin, NONCE, 200, 250).unwrap();
        let time_signatures = time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", index + 1),
                signature: hex_signature(key, &time_message),
            })
            .collect::<Vec<_>>();
        let token =
            create_trusted_time_token(&time_policy, &time_pin, NONCE, 200, 250, &time_signatures)
                .unwrap();
        let time = verify_trusted_time_token(&token, &time_policy, &time_pin, NONCE, None).unwrap();
        let policy = ConsensusFinalityPolicy {
            schema: CONSENSUS_FINALITY_POLICY_SCHEMA.into(),
            policy_id: "bloch-l2-finality-root".into(),
            signature_domain: "bloch:l2:consensus-finality".into(),
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_block_hash: hash('1'),
            validator_set_mode: PINNED_VALIDATOR_SET_MODE.into(),
            validator_set_generation: 1,
            quorum_weight: 7,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 400,
            max_checkpoint_age_seconds: 100,
            trusted_time_policy_sha256: time_pin.clone(),
            trusted_time_state_identity: "bloch-l2:700771:finality".into(),
            trusted_time_remote_cursor_policy_sha256: REMOTE_PIN.into(),
            validators: validators(&old_keys, "old"),
        };
        let policy_pin = consensus_finality_policy_sha256(&policy).unwrap();
        Self {
            old_keys,
            new_keys,
            time_keys,
            time_policy,
            time_policy_pin: time_pin,
            policy,
            policy_pin,
            time,
        }
    }

    fn source(&self) -> ValidatorSetTransitionSource<'_> {
        ValidatorSetTransitionSource::PinnedV1 {
            policy: &self.policy,
            expected_policy_sha256: &self.policy_pin,
        }
    }

    fn manifest(&self) -> ValidatorSetManifest {
        ValidatorSetManifest {
            schema: VALIDATOR_SET_MANIFEST_SCHEMA.into(),
            validator_set_id: "bloch-l2-validator-set-2".into(),
            signature_domain: self.policy.signature_domain.clone(),
            network: self.policy.network.clone(),
            chain_id: self.policy.chain_id,
            genesis_block_hash: self.policy.genesis_block_hash.clone(),
            validator_set_mode: TRANSITIONED_VALIDATOR_SET_MODE.into(),
            validator_set_generation: 2,
            quorum_weight: 7,
            effective_at_unix_seconds: 180,
            expires_at_unix_seconds: 390,
            max_checkpoint_age_seconds: 100,
            trusted_time_policy_sha256: self.policy.trusted_time_policy_sha256.clone(),
            trusted_time_state_identity: self.policy.trusted_time_state_identity.clone(),
            trusted_time_remote_cursor_policy_sha256: self
                .policy
                .trusted_time_remote_cursor_policy_sha256
                .clone(),
            validators: validators(&self.new_keys, "new"),
        }
    }

    fn transition(&self) -> bloch_evm_consensus_finality::VerifiedValidatorSetTransition {
        let manifest = self.manifest();
        let messages = validator_set_transition_signing_messages(
            self.source(),
            "transition-1-to-2",
            &manifest,
            240,
        )
        .unwrap();
        let signatures = ValidatorSetTransitionSignatures {
            old_set_signatures: sign(&self.old_keys, "old", &messages.old_set_message, &[0, 1]),
            new_set_signatures: sign(&self.new_keys, "new", &messages.new_set_message, &[0, 1]),
        };
        let certificate = create_validator_set_transition_certificate(
            self.source(),
            "transition-1-to-2",
            &manifest,
            240,
            signatures,
        )
        .unwrap();
        verify_validator_set_transition(&certificate, self.source(), &self.time).unwrap()
    }

    fn checkpoint(&self) -> ConsensusCheckpoint {
        ConsensusCheckpoint {
            block_number: 72,
            block_hash: hash('2'),
            state_root: hash('3'),
            receipts_root: hash('4'),
            finalized_at_unix_seconds: 195,
        }
    }

    fn alternate_time(&self) -> VerifiedTrustedTime {
        let nonce = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let message = trusted_time_signature_message(
            &self.time_policy,
            &self.time_policy_pin,
            nonce,
            201,
            245,
        )
        .unwrap();
        let signatures = self
            .time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", index + 1),
                signature: hex_signature(key, &message),
            })
            .collect::<Vec<_>>();
        let token = create_trusted_time_token(
            &self.time_policy,
            &self.time_policy_pin,
            nonce,
            201,
            245,
            &signatures,
        )
        .unwrap();
        verify_trusted_time_token(
            &token,
            &self.time_policy,
            &self.time_policy_pin,
            nonce,
            None,
        )
        .unwrap()
    }
}

#[test]
fn verifies_checkpoint_bound_to_complete_transition_chain_and_time_token() {
    let fixture = Fixture::new();
    let transition = fixture.transition();
    let checkpoint = fixture.checkpoint();
    let message =
        transitioned_consensus_finality_signing_message(&transition, &fixture.time, &checkpoint)
            .unwrap();
    let signatures = sign(&fixture.new_keys, "new", &message, &[0, 1]);
    let certificate = create_transitioned_consensus_finality_certificate(
        &transition,
        &fixture.time,
        &checkpoint,
        signatures,
    )
    .unwrap();
    let verified =
        verify_transitioned_consensus_finality(&certificate, &transition, &fixture.time).unwrap();

    assert_eq!(verified.root_finality_policy_sha256(), fixture.policy_pin);
    assert_eq!(
        verified.transition_certificate_sha256(),
        transition.certificate_sha256()
    );
    assert_eq!(
        verified.transition_previous_authority_sha256(),
        fixture.policy_pin
    );
    assert_eq!(
        verified.validator_set_manifest_sha256(),
        transition.new_validator_set_sha256()
    );
    assert_eq!(verified.network(), "bloch-l2");
    assert_eq!(verified.chain_id(), 700_771);
    assert_eq!(verified.genesis_block_hash(), hash('1'));
    assert_eq!(verified.validator_set_generation(), 2);
    assert_eq!(verified.checkpoint(), &checkpoint);
    assert_eq!(verified.signed_weight(), 7);
    assert_eq!(verified.validator_ids(), ["new-1", "new-2"]);
    assert_eq!(
        verified.trusted_time_policy_sha256(),
        fixture.time.trusted_time_policy_sha256()
    );
    assert_eq!(
        verified.trusted_time_state_identity(),
        fixture.time.state_identity()
    );
    assert_eq!(
        verified.trusted_time_remote_cursor_policy_sha256(),
        fixture.time.remote_cursor_policy_sha256()
    );
    assert_eq!(
        verified.trusted_time_token_sha256(),
        fixture.time.token_sha256()
    );
    assert_eq!(verified.deadline_unix_seconds(), 240);
    assert!(verified.validator_set_transition_proven());
    assert!(!verified.consensus_installation_proven());
    assert!(!verified.settlement_qualified());
    verified.ensure_monotonic_freshness().unwrap();
}

#[test]
fn rejects_wrong_transition_chain_even_with_same_validator_keys() {
    let fixture = Fixture::new();
    let transition = fixture.transition();
    let checkpoint = fixture.checkpoint();
    let message =
        transitioned_consensus_finality_signing_message(&transition, &fixture.time, &checkpoint)
            .unwrap();
    let certificate = create_transitioned_consensus_finality_certificate(
        &transition,
        &fixture.time,
        &checkpoint,
        sign(&fixture.new_keys, "new", &message, &[0, 1]),
    )
    .unwrap();

    let manifest = fixture.manifest();
    let messages = validator_set_transition_signing_messages(
        fixture.source(),
        "sibling-transition",
        &manifest,
        240,
    )
    .unwrap();
    let sibling_bytes = create_validator_set_transition_certificate(
        fixture.source(),
        "sibling-transition",
        &manifest,
        240,
        ValidatorSetTransitionSignatures {
            old_set_signatures: sign(&fixture.old_keys, "old", &messages.old_set_message, &[0, 1]),
            new_set_signatures: sign(&fixture.new_keys, "new", &messages.new_set_message, &[0, 1]),
        },
    )
    .unwrap();
    let sibling =
        verify_validator_set_transition(&sibling_bytes, fixture.source(), &fixture.time).unwrap();
    assert_eq!(
        verify_transitioned_consensus_finality(&certificate, &sibling, &fixture.time).unwrap_err(),
        TransitionedConsensusFinalityError::AudienceMismatch,
    );
}

#[test]
fn rejects_substituted_trusted_time_token_with_the_same_audience() {
    let fixture = Fixture::new();
    let transition = fixture.transition();
    let checkpoint = fixture.checkpoint();
    let message =
        transitioned_consensus_finality_signing_message(&transition, &fixture.time, &checkpoint)
            .unwrap();
    let certificate = create_transitioned_consensus_finality_certificate(
        &transition,
        &fixture.time,
        &checkpoint,
        sign(&fixture.new_keys, "new", &message, &[0, 1]),
    )
    .unwrap();
    let alternate_time = fixture.alternate_time();
    assert_eq!(
        verify_transitioned_consensus_finality(&certificate, &transition, &alternate_time)
            .unwrap_err(),
        TransitionedConsensusFinalityError::AudienceMismatch,
    );
}

#[test]
fn rejects_checkpoint_tampering_and_below_quorum() {
    let fixture = Fixture::new();
    let transition = fixture.transition();
    let checkpoint = fixture.checkpoint();
    let message =
        transitioned_consensus_finality_signing_message(&transition, &fixture.time, &checkpoint)
            .unwrap();
    assert_eq!(
        create_transitioned_consensus_finality_certificate(
            &transition,
            &fixture.time,
            &checkpoint,
            sign(&fixture.new_keys, "new", &message, &[0]),
        )
        .unwrap_err(),
        TransitionedConsensusFinalityError::InsufficientWeight,
    );
    let certificate = create_transitioned_consensus_finality_certificate(
        &transition,
        &fixture.time,
        &checkpoint,
        sign(&fixture.new_keys, "new", &message, &[0, 1]),
    )
    .unwrap();
    let tampered = String::from_utf8(certificate)
        .unwrap()
        .replacen(&hash('2'), &hash('9'), 1)
        .into_bytes();
    assert_eq!(
        verify_transitioned_consensus_finality(&tampered, &transition, &fixture.time).unwrap_err(),
        TransitionedConsensusFinalityError::InvalidSignature,
    );
}

#[test]
fn rejects_noncanonical_and_duplicate_signatures() {
    let fixture = Fixture::new();
    let transition = fixture.transition();
    let checkpoint = fixture.checkpoint();
    let message =
        transitioned_consensus_finality_signing_message(&transition, &fixture.time, &checkpoint)
            .unwrap();
    let one = sign(&fixture.new_keys, "new", &message, &[0])
        .pop()
        .unwrap();
    assert_eq!(
        create_transitioned_consensus_finality_certificate(
            &transition,
            &fixture.time,
            &checkpoint,
            vec![one.clone(), one],
        )
        .unwrap_err(),
        TransitionedConsensusFinalityError::DuplicateSignature,
    );
    let valid = create_transitioned_consensus_finality_certificate(
        &transition,
        &fixture.time,
        &checkpoint,
        sign(&fixture.new_keys, "new", &message, &[0, 1]),
    )
    .unwrap();
    let noncanonical = [b" ".as_slice(), valid.as_slice()].concat();
    assert_eq!(
        verify_transitioned_consensus_finality(&noncanonical, &transition, &fixture.time)
            .unwrap_err(),
        TransitionedConsensusFinalityError::InvalidCertificate,
    );
}

fn keys(seeds: &[u8]) -> Vec<SigningKey> {
    seeds
        .iter()
        .map(|seed| SigningKey::from_bytes(&[*seed; 32]))
        .collect()
}
fn validators(keys: &[SigningKey], prefix: &str) -> Vec<Validator> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| Validator {
            validator_id: format!("{prefix}-{}", index + 1),
            ed25519_public_key: hex_key(key),
            weight: [4, 3, 3][index],
        })
        .collect()
}
fn sign(
    keys: &[SigningKey],
    prefix: &str,
    message: &[u8],
    indexes: &[usize],
) -> Vec<ValidatorSignature> {
    indexes
        .iter()
        .map(|index| ValidatorSignature {
            validator_id: format!("{prefix}-{}", index + 1),
            signature: hex_signature(&keys[*index], message),
        })
        .collect()
}
fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
}
fn hex_signature(key: &SigningKey, message: &[u8]) -> String {
    format!("0x{}", hex::encode(key.sign(message).to_bytes()))
}
fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
