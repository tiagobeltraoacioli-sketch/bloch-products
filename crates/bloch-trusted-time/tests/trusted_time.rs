use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimeError, TrustedTimePolicy,
    TrustedTimeSignature, create_trusted_time_token, parse_trusted_time_boundary,
    parse_trusted_time_policy, trusted_time_policy_bytes, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

const NONCE: &str = "trusted_time_nonce_0123456789abcdef0123456789abcdef";

struct Fixture {
    policy: TrustedTimePolicy,
    keys: Vec<SigningKey>,
    pin: String,
}

impl Fixture {
    fn new() -> Self {
        let keys = vec![
            SigningKey::from_bytes(&[91; 32]),
            SigningKey::from_bytes(&[92; 32]),
            SigningKey::from_bytes(&[93; 32]),
        ];
        let policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "trusted-time-production-a".into(),
            signature_domain: "bloch-products-trusted-time".into(),
            state_identity: "data:tenant-a:lifecycle".into(),
            remote_cursor_policy_sha256: format!("0x{}", "42".repeat(32)),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            max_token_lifetime_seconds: 30,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| TrustedTimeAuthority {
                    authority_id: format!("time-authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let pin = trusted_time_policy_sha256(&policy).unwrap();
        Self { policy, keys, pin }
    }

    fn token_with(&self, nonce: &str, at: u64, until: u64, signers: &[usize]) -> Vec<u8> {
        let message =
            trusted_time_signature_message(&self.policy, &self.pin, nonce, at, until).unwrap();
        let signatures = signers
            .iter()
            .map(|index| TrustedTimeSignature {
                authority_id: format!("time-authority-{}", index + 1),
                signature: format!(
                    "0x{}",
                    hex::encode(self.keys[*index].sign(&message).to_bytes())
                ),
            })
            .collect::<Vec<_>>();
        create_trusted_time_token(&self.policy, &self.pin, nonce, at, until, &signatures).unwrap()
    }
}

#[test]
fn verifies_threshold_token_and_produces_canonical_boundary() {
    let fixture = Fixture::new();
    let token = fixture.token_with(NONCE, 2_000, 2_030, &[0, 1]);
    let verified =
        verify_trusted_time_token(&token, &fixture.policy, &fixture.pin, NONCE, None).unwrap();
    assert_eq!(verified.unix_seconds().unwrap(), 2_000);
    assert_eq!(verified.valid_until_unix_seconds(), 2_030);
    assert_eq!(verified.state_identity(), "data:tenant-a:lifecycle");
    assert_eq!(
        verified.remote_cursor_policy_sha256(),
        fixture.policy.remote_cursor_policy_sha256
    );
    assert_eq!(
        verified.authority_ids(),
        &["time-authority-1", "time-authority-2"]
    );
    assert!(!verified.authority_independence_proven());

    let bytes = verified
        .rollback_boundary()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let parsed = parse_trusted_time_boundary(&bytes, &fixture.pin).unwrap();
    assert_eq!(parsed.not_before_unix_seconds(), 2_030);
}

#[test]
fn capability_expires_at_the_exact_monotonic_deadline() {
    let fixture = Fixture::new();
    let token = fixture.token_with(NONCE, 2_000, 2_001, &[0, 1]);
    let verified =
        verify_trusted_time_token(&token, &fixture.policy, &fixture.pin, NONCE, None).unwrap();
    assert_eq!(verified.unix_seconds().unwrap(), 2_000);
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    assert_eq!(
        verified.unix_seconds(),
        Err(TrustedTimeError::ExpiredCapability)
    );
}

#[test]
fn canonical_policy_requires_exact_independent_pin() {
    let fixture = Fixture::new();
    let bytes = trusted_time_policy_bytes(&fixture.policy).unwrap();
    assert_eq!(
        parse_trusted_time_policy(&bytes, &fixture.pin).unwrap(),
        fixture.policy
    );
    let wrong = format!("0x{}", "00".repeat(32));
    assert_eq!(
        parse_trusted_time_policy(&bytes, &wrong),
        Err(TrustedTimeError::PolicyPinMismatch)
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert_eq!(
        parse_trusted_time_policy(&noncanonical, &fixture.pin),
        Err(TrustedTimeError::InvalidPolicy)
    );
}

#[test]
fn rejects_nonce_replay_and_insufficient_threshold() {
    let fixture = Fixture::new();
    let token = fixture.token_with(NONCE, 2_000, 2_030, &[0, 1]);
    assert!(matches!(
        verify_trusted_time_token(
            &token,
            &fixture.policy,
            &fixture.pin,
            "different_nonce_0123456789abcdef0123456789abcdef",
            None
        ),
        Err(TrustedTimeError::NonceMismatch)
    ));

    let message =
        trusted_time_signature_message(&fixture.policy, &fixture.pin, NONCE, 2_000, 2_030).unwrap();
    let one = [TrustedTimeSignature {
        authority_id: "time-authority-1".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.keys[0].sign(&message).to_bytes())
        ),
    }];
    assert_eq!(
        create_trusted_time_token(&fixture.policy, &fixture.pin, NONCE, 2_000, 2_030, &one),
        Err(TrustedTimeError::ThresholdNotMet)
    );
}

#[test]
fn rejects_old_token_across_persisted_rollback_boundary() {
    let fixture = Fixture::new();
    let newer = fixture.token_with(NONCE, 3_000, 3_030, &[0, 1]);
    let verified =
        verify_trusted_time_token(&newer, &fixture.policy, &fixture.pin, NONCE, None).unwrap();
    let boundary = verified.rollback_boundary().unwrap();

    let old = fixture.token_with(NONCE, 2_999, 3_029, &[0, 2]);
    assert!(matches!(
        verify_trusted_time_token(&old, &fixture.policy, &fixture.pin, NONCE, Some(&boundary)),
        Err(TrustedTimeError::RollbackDetected)
    ));
}

#[test]
fn rejects_cross_policy_boundary_and_tampering() {
    let fixture = Fixture::new();
    let token = fixture.token_with(NONCE, 2_000, 2_030, &[0, 1]);
    let verified =
        verify_trusted_time_token(&token, &fixture.policy, &fixture.pin, NONCE, None).unwrap();
    let mut boundary_bytes = verified
        .rollback_boundary()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    boundary_bytes.push(b'\n');
    assert!(parse_trusted_time_boundary(&boundary_bytes, &fixture.pin).is_err());

    let wrong_pin = format!("0x{}", "ab".repeat(32));
    assert!(
        parse_trusted_time_boundary(
            &verified
                .rollback_boundary()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            &wrong_pin
        )
        .is_err()
    );
}

#[test]
fn rejects_oversized_interval_duplicate_keys_and_modified_signature() {
    let fixture = Fixture::new();
    assert_eq!(
        trusted_time_signature_message(&fixture.policy, &fixture.pin, NONCE, 2_000, 2_031),
        Err(TrustedTimeError::InvalidEnvelope)
    );

    let mut duplicate = fixture.policy.clone();
    duplicate.authorities[1].ed25519_public_key =
        duplicate.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        trusted_time_policy_bytes(&duplicate),
        Err(TrustedTimeError::InvalidPolicy)
    );

    let mut token = fixture.token_with(NONCE, 2_000, 2_030, &[0, 1]);
    let index = token.iter().position(|byte| *byte == b'a').unwrap();
    token[index] = b'b';
    assert!(verify_trusted_time_token(&token, &fixture.policy, &fixture.pin, NONCE, None).is_err());
}
