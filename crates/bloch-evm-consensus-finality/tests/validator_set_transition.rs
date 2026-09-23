use bloch_evm_consensus_finality::{
    CONSENSUS_FINALITY_POLICY_SCHEMA, ConsensusFinalityPolicy, PINNED_VALIDATOR_SET_MODE,
    TRANSITIONED_VALIDATOR_SET_MODE, VALIDATOR_SET_MANIFEST_SCHEMA, Validator,
    ValidatorSetManifest, ValidatorSetTransitionError, ValidatorSetTransitionSignatures,
    ValidatorSetTransitionSource, ValidatorSignature, consensus_finality_policy_sha256,
    consensus_validator_set_manifest, create_validator_set_transition_certificate,
    parse_validator_set_manifest, validator_set_manifest_sha256,
    validator_set_transition_signing_messages, verify_validator_set_transition,
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
    old_keys: Vec<SigningKey>,
    new_keys: Vec<SigningKey>,
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
            policy_id: "transition-time".into(),
            signature_domain: "bloch:l2:transition:time".into(),
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
        let time_message =
            trusted_time_signature_message(&time_policy, &time_pin, NONCE, 200, 250).unwrap();
        let time_signatures: Vec<_> = time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", index + 1),
                signature: hex_signature(key, &time_message),
            })
            .collect();
        let time_token =
            create_trusted_time_token(&time_policy, &time_pin, NONCE, 200, 250, &time_signatures)
                .unwrap();
        let time =
            verify_trusted_time_token(&time_token, &time_policy, &time_pin, NONCE, None).unwrap();
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
            validators: validators(&old_keys, "old"),
        };
        let policy_pin = consensus_finality_policy_sha256(&policy).unwrap();
        Self {
            old_keys,
            new_keys,
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

    fn generation_two(&self) -> ValidatorSetManifest {
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

    fn certificate(&self, new_manifest: &ValidatorSetManifest) -> Vec<u8> {
        certificate(
            self.source(),
            "transition-1-to-2",
            new_manifest,
            240,
            SignedSet::quorum(&self.old_keys, "old"),
            SignedSet::quorum(&self.new_keys, "new"),
        )
        .unwrap()
    }
}

#[test]
fn verifies_dual_quorum_and_binds_every_transition_identity() {
    let fixture = Fixture::new();
    let new_manifest = fixture.generation_two();
    let certificate = fixture.certificate(&new_manifest);
    let verified =
        verify_validator_set_transition(&certificate, fixture.source(), &fixture.time).unwrap();

    let old_manifest =
        consensus_validator_set_manifest(&fixture.policy, &fixture.policy_pin).unwrap();
    let canonical_manifest = serde_json::to_vec(&new_manifest).unwrap();
    assert_eq!(
        parse_validator_set_manifest(
            &canonical_manifest,
            &validator_set_manifest_sha256(&new_manifest).unwrap(),
        )
        .unwrap(),
        new_manifest,
    );
    assert_eq!(verified.root_finality_policy_sha256(), fixture.policy_pin);
    assert_eq!(verified.previous_authority_sha256(), fixture.policy_pin);
    assert_eq!(
        verified.old_validator_set_sha256(),
        validator_set_manifest_sha256(&old_manifest).unwrap()
    );
    assert_eq!(
        verified.new_validator_set_sha256(),
        validator_set_manifest_sha256(&new_manifest).unwrap()
    );
    assert_eq!(verified.new_validator_set().validator_set_generation, 2);
    assert_eq!(verified.old_signed_weight(), 7);
    assert_eq!(verified.new_signed_weight(), 7);
    assert_eq!(verified.deadline_unix_seconds(), 240);
    assert!(verified.validator_set_transition_proven());
    assert!(!verified.consensus_installation_proven());
    verified.ensure_monotonic_freshness().unwrap();
}

#[test]
fn chains_only_from_exact_verified_predecessor() {
    let fixture = Fixture::new();
    let generation_two = fixture.generation_two();
    let certificate_two = fixture.certificate(&generation_two);
    let verified_two =
        verify_validator_set_transition(&certificate_two, fixture.source(), &fixture.time).unwrap();

    let generation_three_keys = keys(&[7, 8, 9]);
    let mut generation_three = generation_two.clone();
    generation_three.validator_set_id = "bloch-l2-validator-set-3".into();
    generation_three.validator_set_generation = 3;
    generation_three.effective_at_unix_seconds = 195;
    generation_three.expires_at_unix_seconds = 235;
    generation_three.max_checkpoint_age_seconds = 20;
    generation_three.validators = validators(&generation_three_keys, "third");
    let certificate_three = certificate(
        ValidatorSetTransitionSource::Verified(&verified_two),
        "transition-2-to-3",
        &generation_three,
        230,
        SignedSet::quorum(&fixture.new_keys, "new"),
        SignedSet::quorum(&generation_three_keys, "third"),
    )
    .unwrap();
    let verified_three = verify_validator_set_transition(
        &certificate_three,
        ValidatorSetTransitionSource::Verified(&verified_two),
        &fixture.time,
    )
    .unwrap();
    assert_eq!(
        verified_three.previous_authority_sha256(),
        verified_two.certificate_sha256()
    );
    assert_eq!(
        verified_three.new_validator_set().validator_set_generation,
        3
    );

    assert_eq!(
        validator_set_transition_signing_messages(
            ValidatorSetTransitionSource::Verified(&verified_two),
            "deadline-extension",
            &generation_three,
            245,
        )
        .unwrap_err(),
        ValidatorSetTransitionError::InvalidCertificate,
    );

    let sibling_keys = keys(&[21, 22, 23]);
    let mut sibling = generation_two;
    sibling.validator_set_id = "sibling-generation-2".into();
    sibling.validators = validators(&sibling_keys, "sibling");
    let sibling_certificate = certificate(
        fixture.source(),
        "sibling-1-to-2",
        &sibling,
        240,
        SignedSet::quorum(&fixture.old_keys, "old"),
        SignedSet::quorum(&sibling_keys, "sibling"),
    )
    .unwrap();
    let sibling_verified =
        verify_validator_set_transition(&sibling_certificate, fixture.source(), &fixture.time)
            .unwrap();
    assert_eq!(
        verify_validator_set_transition(
            &certificate_three,
            ValidatorSetTransitionSource::Verified(&sibling_verified),
            &fixture.time,
        )
        .unwrap_err(),
        ValidatorSetTransitionError::AudienceMismatch,
    );
}

#[test]
fn rejects_skipped_generation_and_cross_network_manifest() {
    let fixture = Fixture::new();
    let mut skipped = fixture.generation_two();
    skipped.validator_set_generation = 3;
    assert_eq!(
        validator_set_transition_signing_messages(fixture.source(), "skip", &skipped, 240)
            .unwrap_err(),
        ValidatorSetTransitionError::NonContiguousGeneration,
    );
    let mut other_network = fixture.generation_two();
    other_network.network = "other-l2".into();
    assert_eq!(
        validator_set_transition_signing_messages(
            fixture.source(),
            "cross-network",
            &other_network,
            240
        )
        .unwrap_err(),
        ValidatorSetTransitionError::AudienceMismatch,
    );
}

#[test]
fn rejects_insufficient_old_or_new_quorum_and_role_reuse() {
    let fixture = Fixture::new();
    let new_manifest = fixture.generation_two();
    assert_eq!(
        certificate(
            fixture.source(),
            "weak-old",
            &new_manifest,
            240,
            SignedSet::one(&fixture.old_keys, "old"),
            SignedSet::quorum(&fixture.new_keys, "new"),
        )
        .unwrap_err(),
        ValidatorSetTransitionError::InsufficientOldWeight,
    );
    assert_eq!(
        certificate(
            fixture.source(),
            "weak-new",
            &new_manifest,
            240,
            SignedSet::quorum(&fixture.old_keys, "old"),
            SignedSet::one(&fixture.new_keys, "new"),
        )
        .unwrap_err(),
        ValidatorSetTransitionError::InsufficientNewWeight,
    );

    let messages = validator_set_transition_signing_messages(
        fixture.source(),
        "role-separated",
        &new_manifest,
        240,
    )
    .unwrap();
    let signatures = ValidatorSetTransitionSignatures {
        old_set_signatures: sign(&fixture.old_keys, &[0, 1], "old", &messages.old_set_message),
        new_set_signatures: sign(&fixture.new_keys, &[0, 1], "new", &messages.old_set_message),
    };
    assert_eq!(
        create_validator_set_transition_certificate(
            fixture.source(),
            "role-separated",
            &new_manifest,
            240,
            signatures,
        )
        .unwrap_err(),
        ValidatorSetTransitionError::InvalidSignature,
    );
}

#[test]
fn rejects_tampering_duplicate_signatures_and_noncanonical_bytes() {
    let fixture = Fixture::new();
    let new_manifest = fixture.generation_two();
    let messages = validator_set_transition_signing_messages(
        fixture.source(),
        "duplicates",
        &new_manifest,
        240,
    )
    .unwrap();
    let one = sign(&fixture.old_keys, &[0], "old", &messages.old_set_message)
        .pop()
        .unwrap();
    let signatures = ValidatorSetTransitionSignatures {
        old_set_signatures: vec![one.clone(), one],
        new_set_signatures: sign(&fixture.new_keys, &[0, 1], "new", &messages.new_set_message),
    };
    assert_eq!(
        create_validator_set_transition_certificate(
            fixture.source(),
            "duplicates",
            &new_manifest,
            240,
            signatures
        )
        .unwrap_err(),
        ValidatorSetTransitionError::DuplicateSignature,
    );

    let certificate = String::from_utf8(fixture.certificate(&new_manifest)).unwrap();
    let tampered = certificate
        .replacen("transition-1-to-2", "transition-replayed", 1)
        .into_bytes();
    assert_eq!(
        verify_validator_set_transition(&tampered, fixture.source(), &fixture.time).unwrap_err(),
        ValidatorSetTransitionError::InvalidSignature,
    );
    let noncanonical = format!(" {}", certificate).into_bytes();
    assert_eq!(
        verify_validator_set_transition(&noncanonical, fixture.source(), &fixture.time)
            .unwrap_err(),
        ValidatorSetTransitionError::InvalidCertificate,
    );
}

fn certificate(
    source: ValidatorSetTransitionSource<'_>,
    transition_id: &str,
    new_manifest: &ValidatorSetManifest,
    expires: u64,
    old: SignedSet<'_>,
    new: SignedSet<'_>,
) -> Result<Vec<u8>, ValidatorSetTransitionError> {
    let messages =
        validator_set_transition_signing_messages(source, transition_id, new_manifest, expires)?;
    let signatures = ValidatorSetTransitionSignatures {
        old_set_signatures: sign(old.keys, old.indexes, old.prefix, &messages.old_set_message),
        new_set_signatures: sign(new.keys, new.indexes, new.prefix, &messages.new_set_message),
    };
    create_validator_set_transition_certificate(
        source,
        transition_id,
        new_manifest,
        expires,
        signatures,
    )
}

struct SignedSet<'a> {
    keys: &'a [SigningKey],
    prefix: &'a str,
    indexes: &'static [usize],
}

impl<'a> SignedSet<'a> {
    fn quorum(keys: &'a [SigningKey], prefix: &'a str) -> Self {
        Self {
            keys,
            prefix,
            indexes: &[0, 1],
        }
    }

    fn one(keys: &'a [SigningKey], prefix: &'a str) -> Self {
        Self {
            keys,
            prefix,
            indexes: &[0],
        }
    }
}

fn sign(
    keys: &[SigningKey],
    indexes: &[usize],
    prefix: &str,
    message: &[u8],
) -> Vec<ValidatorSignature> {
    indexes
        .iter()
        .map(|index| ValidatorSignature {
            validator_id: format!("{prefix}-{}", index + 1),
            signature: hex_signature(&keys[*index], message),
        })
        .collect()
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
fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
}
fn hex_signature(key: &SigningKey, message: &[u8]) -> String {
    format!("0x{}", hex::encode(key.sign(message).to_bytes()))
}
fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
