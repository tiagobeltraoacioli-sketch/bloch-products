use bloch_evm_consensus_finality::{
    CONSENSUS_FINALITY_POLICY_SCHEMA, ConsensusCheckpoint, ConsensusFinalityError,
    ConsensusFinalityPolicy, PINNED_VALIDATOR_SET_MODE, Validator, ValidatorSignature,
    consensus_finality_policy_sha256, consensus_finality_signing_message,
    create_consensus_finality_certificate, verify_consensus_finality,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

const TIME_REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    keys: Vec<SigningKey>,
    policy: ConsensusFinalityPolicy,
    policy_pin: String,
    time: VerifiedTrustedTime,
}

impl Fixture {
    fn new() -> Self {
        let keys: Vec<_> = [1_u8, 2, 3]
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .into();
        let time_keys: Vec<_> = [11_u8, 12, 13]
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .into();
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "l2-finality-time".into(),
            signature_domain: "bloch:l2:finality:time".into(),
            state_identity: "bloch-l2:700771:finality".into(),
            remote_cursor_policy_sha256: TIME_REMOTE_PIN.into(),
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
        let message =
            trusted_time_signature_message(&time_policy, &time_pin, NONCE, 200, 250).unwrap();
        let signatures: Vec<_> = time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", index + 1),
                signature: hex_signature(key, &message),
            })
            .collect();
        let token =
            create_trusted_time_token(&time_policy, &time_pin, NONCE, 200, 250, &signatures)
                .unwrap();
        let time = verify_trusted_time_token(&token, &time_policy, &time_pin, NONCE, None).unwrap();
        let policy = ConsensusFinalityPolicy {
            schema: CONSENSUS_FINALITY_POLICY_SCHEMA.into(),
            policy_id: "bloch-l2-finality-v1".into(),
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
            trusted_time_policy_sha256: time_pin,
            trusted_time_state_identity: "bloch-l2:700771:finality".into(),
            trusted_time_remote_cursor_policy_sha256: TIME_REMOTE_PIN.into(),
            validators: keys
                .iter()
                .enumerate()
                .map(|(index, key)| Validator {
                    validator_id: format!("validator-{}", index + 1),
                    ed25519_public_key: hex_key(key),
                    weight: [4, 3, 3][index],
                })
                .collect(),
        };
        let policy_pin = consensus_finality_policy_sha256(&policy).unwrap();
        Self {
            keys,
            policy,
            policy_pin,
            time,
        }
    }

    fn checkpoint(&self) -> ConsensusCheckpoint {
        ConsensusCheckpoint {
            block_number: 42,
            block_hash: hash('2'),
            state_root: hash('3'),
            receipts_root: hash('4'),
            finalized_at_unix_seconds: 190,
        }
    }

    fn signatures(
        &self,
        checkpoint: &ConsensusCheckpoint,
        indexes: &[usize],
    ) -> Vec<ValidatorSignature> {
        let message =
            consensus_finality_signing_message(&self.policy, &self.policy_pin, checkpoint).unwrap();
        indexes
            .iter()
            .map(|index| ValidatorSignature {
                validator_id: format!("validator-{}", index + 1),
                signature: hex_signature(&self.keys[*index], &message),
            })
            .collect()
    }

    fn certificate(&self) -> Vec<u8> {
        let checkpoint = self.checkpoint();
        create_consensus_finality_certificate(
            &self.policy,
            &self.policy_pin,
            &checkpoint,
            self.signatures(&checkpoint, &[0, 1]),
        )
        .unwrap()
    }
}

#[test]
fn verifies_exact_weighted_checkpoint_as_an_opaque_capability() {
    let fixture = Fixture::new();
    let verified = verify_consensus_finality(
        &fixture.certificate(),
        &fixture.policy,
        &fixture.policy_pin,
        &fixture.time,
    )
    .unwrap();
    assert_eq!(verified.network(), "bloch-l2");
    assert_eq!(verified.chain_id(), 700_771);
    assert_eq!(verified.validator_set_generation(), 1);
    assert_eq!(verified.checkpoint(), &fixture.checkpoint());
    assert_eq!(verified.signed_weight(), 7);
    assert_eq!(verified.validator_ids(), ["validator-1", "validator-2"]);
    assert_eq!(
        verified.trusted_time_policy_sha256(),
        fixture.time.trusted_time_policy_sha256()
    );
    assert_eq!(
        verified.trusted_time_token_sha256(),
        fixture.time.token_sha256()
    );
    assert_eq!(verified.deadline_unix_seconds(), 250);
    verified.ensure_monotonic_freshness().unwrap();
    assert!(!verified.validator_set_transition_proven());
    assert!(!verified.ancestry_proven());
    assert!(!verified.organizational_independence_proven());
    assert!(!verified.settlement_qualified());
}

#[test]
fn rejects_duplicate_validator_key_and_non_v1_generation() {
    let mut fixture = Fixture::new();
    fixture.policy.validators[1].ed25519_public_key =
        fixture.policy.validators[0].ed25519_public_key.clone();
    assert_eq!(
        consensus_finality_policy_sha256(&fixture.policy).unwrap_err(),
        ConsensusFinalityError::InvalidPolicy,
    );
    let mut fixture = Fixture::new();
    fixture.policy.validator_set_generation = 2;
    assert_eq!(
        consensus_finality_policy_sha256(&fixture.policy).unwrap_err(),
        ConsensusFinalityError::InvalidPolicy,
    );
}

#[test]
fn rejects_duplicate_signature_and_insufficient_weight() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint();
    let one = fixture.signatures(&checkpoint, &[0]).pop().unwrap();
    assert_eq!(
        create_consensus_finality_certificate(
            &fixture.policy,
            &fixture.policy_pin,
            &checkpoint,
            vec![one.clone(), one],
        )
        .unwrap_err(),
        ConsensusFinalityError::DuplicateSignature,
    );
    assert_eq!(
        create_consensus_finality_certificate(
            &fixture.policy,
            &fixture.policy_pin,
            &checkpoint,
            fixture.signatures(&checkpoint, &[0]),
        )
        .unwrap_err(),
        ConsensusFinalityError::InsufficientWeight,
    );
}

#[test]
fn rejects_validator_or_policy_substitution() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint();
    let message =
        consensus_finality_signing_message(&fixture.policy, &fixture.policy_pin, &checkpoint)
            .unwrap();
    let signatures = vec![
        ValidatorSignature {
            validator_id: "validator-1".into(),
            signature: hex_signature(&fixture.keys[2], &message),
        },
        ValidatorSignature {
            validator_id: "validator-2".into(),
            signature: hex_signature(&fixture.keys[1], &message),
        },
    ];
    assert_eq!(
        create_consensus_finality_certificate(
            &fixture.policy,
            &fixture.policy_pin,
            &checkpoint,
            signatures,
        )
        .unwrap_err(),
        ConsensusFinalityError::InvalidSignature,
    );
    let mut substituted = fixture.policy.clone();
    substituted.policy_id = "substituted-policy".into();
    assert_eq!(
        verify_consensus_finality(
            &fixture.certificate(),
            &substituted,
            &fixture.policy_pin,
            &fixture.time,
        )
        .unwrap_err(),
        ConsensusFinalityError::PolicyPinMismatch,
    );
}

#[test]
fn rejects_wrong_network_and_checkpoint() {
    let fixture = Fixture::new();
    let certificate = String::from_utf8(fixture.certificate()).unwrap();
    let wrong_network = certificate.replacen("bloch-l2", "other-l2", 1).into_bytes();
    assert_eq!(
        verify_consensus_finality(
            &wrong_network,
            &fixture.policy,
            &fixture.policy_pin,
            &fixture.time,
        )
        .unwrap_err(),
        ConsensusFinalityError::AudienceMismatch,
    );
    let wrong_checkpoint = certificate.replacen(&hash('2'), &hash('9'), 1).into_bytes();
    assert_eq!(
        verify_consensus_finality(
            &wrong_checkpoint,
            &fixture.policy,
            &fixture.policy_pin,
            &fixture.time,
        )
        .unwrap_err(),
        ConsensusFinalityError::InvalidSignature,
    );
}

#[test]
fn rejects_expired_policy_and_wrong_trusted_time_audience() {
    let fixture = Fixture::new();
    let mut expired = fixture.policy.clone();
    expired.expires_at_unix_seconds = 200;
    expired.max_checkpoint_age_seconds = 90;
    let expired_pin = consensus_finality_policy_sha256(&expired).unwrap();
    let checkpoint = fixture.checkpoint();
    let message = consensus_finality_signing_message(&expired, &expired_pin, &checkpoint).unwrap();
    let signatures = fixture
        .keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| ValidatorSignature {
            validator_id: format!("validator-{}", index + 1),
            signature: hex_signature(key, &message),
        })
        .collect();
    let certificate =
        create_consensus_finality_certificate(&expired, &expired_pin, &checkpoint, signatures)
            .unwrap();
    assert_eq!(
        verify_consensus_finality(&certificate, &expired, &expired_pin, &fixture.time,)
            .unwrap_err(),
        ConsensusFinalityError::PolicyNotEffective,
    );
    let mut wrong_audience = fixture.policy.clone();
    wrong_audience.trusted_time_state_identity = "other-network:finality".into();
    let wrong_pin = consensus_finality_policy_sha256(&wrong_audience).unwrap();
    assert_eq!(
        verify_consensus_finality(
            &fixture.certificate(),
            &wrong_audience,
            &wrong_pin,
            &fixture.time,
        )
        .unwrap_err(),
        ConsensusFinalityError::TrustedTimeAudienceMismatch,
    );
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
