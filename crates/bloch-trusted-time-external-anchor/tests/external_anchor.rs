use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimeBoundary, TrustedTimePolicy,
    TrustedTimeSignature, VerifiedTrustedTime, create_trusted_time_token,
    trusted_time_policy_sha256, trusted_time_signature_message, verify_trusted_time_token,
};
use bloch_trusted_time_external_anchor::{
    EXTERNAL_ANCHOR_POLICY_SCHEMA, ExternalAnchorAuthority, ExternalAnchorError,
    ExternalAnchorPolicy, ExternalAnchorSignature, create_external_anchor_document,
    external_anchor_policy_bytes, external_anchor_policy_sha256, external_anchor_signature_message,
    parse_external_anchor_expectation, parse_external_anchor_policy, verify_external_anchor,
};
use ed25519_dalek::{Signer, SigningKey};

const TIME_NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHALLENGE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER_CHALLENGE: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Fixture {
    time_policy: TrustedTimePolicy,
    time_key: SigningKey,
    time_pin: String,
    anchor_policy: ExternalAnchorPolicy,
    anchor_keys: Vec<SigningKey>,
    anchor_pin: String,
}

impl Fixture {
    fn new() -> Self {
        let time_key = SigningKey::from_bytes(&[41; 32]);
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "time-a".into(),
            signature_domain: "bloch-time-a".into(),
            state_identity: "data:tenant-a:lifecycle".into(),
            remote_cursor_policy_sha256: format!("0x{}", "21".repeat(32)),
            threshold: 1,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 20_000,
            max_token_lifetime_seconds: 1_000,
            authorities: vec![TrustedTimeAuthority {
                authority_id: "time-1".into(),
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(time_key.verifying_key().as_bytes())
                ),
            }],
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let anchor_keys = vec![
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
            SigningKey::from_bytes(&[53; 32]),
        ];
        let anchor_policy = ExternalAnchorPolicy {
            schema: EXTERNAL_ANCHOR_POLICY_SCHEMA.into(),
            policy_id: "external-anchor-a".into(),
            signature_domain: "bloch-anchor-a".into(),
            state_identity: time_policy.state_identity.clone(),
            trusted_time_policy_sha256: time_pin.clone(),
            remote_cursor_policy_sha256: time_policy.remote_cursor_policy_sha256.clone(),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            max_anchor_lifetime_seconds: 500,
            authorities: anchor_keys
                .iter()
                .enumerate()
                .map(|(index, key)| ExternalAnchorAuthority {
                    authority_id: format!("anchor-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let anchor_pin = external_anchor_policy_sha256(&anchor_policy).unwrap();
        Self {
            time_policy,
            time_key,
            time_pin,
            anchor_policy,
            anchor_keys,
            anchor_pin,
        }
    }

    fn trusted_time(&self) -> VerifiedTrustedTime {
        self.time_at(2_000, 2_100)
    }

    fn time_at(&self, at: u64, until: u64) -> VerifiedTrustedTime {
        let message = trusted_time_signature_message(
            &self.time_policy,
            &self.time_pin,
            TIME_NONCE,
            at,
            until,
        )
        .unwrap();
        let signature = TrustedTimeSignature {
            authority_id: "time-1".into(),
            signature: format!("0x{}", hex::encode(self.time_key.sign(&message).to_bytes())),
        };
        let token = create_trusted_time_token(
            &self.time_policy,
            &self.time_pin,
            TIME_NONCE,
            at,
            until,
            &[signature],
        )
        .unwrap();
        verify_trusted_time_token(&token, &self.time_policy, &self.time_pin, TIME_NONCE, None)
            .unwrap()
    }

    fn boundary(&self, floor: u64) -> TrustedTimeBoundary {
        self.time_at(floor - 30, floor).rollback_boundary().unwrap()
    }

    fn document(
        &self,
        generation: u64,
        boundary: &TrustedTimeBoundary,
        nonce: &str,
        issued_at: u64,
        expires_at: u64,
        signers: &[usize],
    ) -> Vec<u8> {
        let message = external_anchor_signature_message(
            &self.anchor_policy,
            &self.anchor_pin,
            generation,
            boundary,
            issued_at,
            expires_at,
            nonce,
        )
        .unwrap();
        let signatures = signers
            .iter()
            .map(|index| ExternalAnchorSignature {
                authority_id: format!("anchor-{}", index + 1),
                signature: format!(
                    "0x{}",
                    hex::encode(self.anchor_keys[*index].sign(&message).to_bytes())
                ),
            })
            .collect::<Vec<_>>();
        create_external_anchor_document(
            &self.anchor_policy,
            &self.anchor_pin,
            generation,
            boundary,
            issued_at,
            expires_at,
            nonce,
            &signatures,
        )
        .unwrap()
    }
}

#[test]
fn verifies_canonical_threshold_anchor_with_trusted_time() {
    let fixture = Fixture::new();
    let boundary = fixture.boundary(1_950);
    let document = fixture.document(7, &boundary, CHALLENGE, 1_990, 2_200, &[0, 1]);
    let verified = verify_external_anchor(
        &document,
        &fixture.anchor_policy,
        &fixture.anchor_pin,
        CHALLENGE,
        &fixture.trusted_time(),
        None,
    )
    .unwrap();
    assert_eq!(verified.generation(), 7);
    assert_eq!(verified.boundary_not_before_unix_seconds(), 1_950);
    assert_eq!(verified.authority_ids(), &["anchor-1", "anchor-2"]);
    assert_eq!(verified.retention_expectation().generation(), 7);

    let expectation_bytes = verified.retention_expectation().canonical_bytes().unwrap();
    let restored = parse_external_anchor_expectation(
        &expectation_bytes,
        &fixture.anchor_pin,
        &fixture.anchor_policy.state_identity,
        &fixture.time_pin,
        &fixture.anchor_policy.remote_cursor_policy_sha256,
    )
    .unwrap();
    assert_eq!(restored, verified.retention_expectation());

    let bytes = external_anchor_policy_bytes(&fixture.anchor_policy).unwrap();
    assert_eq!(
        parse_external_anchor_policy(&bytes, &fixture.anchor_pin).unwrap(),
        fixture.anchor_policy
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert_eq!(
        parse_external_anchor_policy(&noncanonical, &fixture.anchor_pin),
        Err(ExternalAnchorError::InvalidPolicy)
    );
}

#[test]
fn rejects_tampered_noncanonical_and_cross_audience_expectations() {
    let fixture = Fixture::new();
    let document = fixture.document(
        7,
        &fixture.boundary(1_950),
        CHALLENGE,
        1_990,
        2_200,
        &[0, 1],
    );
    let verified = verify_external_anchor(
        &document,
        &fixture.anchor_policy,
        &fixture.anchor_pin,
        CHALLENGE,
        &fixture.trusted_time(),
        None,
    )
    .unwrap();
    let bytes = verified.retention_expectation().canonical_bytes().unwrap();

    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    assert_eq!(
        parse_external_anchor_expectation(
            &noncanonical,
            &fixture.anchor_pin,
            &fixture.anchor_policy.state_identity,
            &fixture.time_pin,
            &fixture.anchor_policy.remote_cursor_policy_sha256,
        ),
        Err(ExternalAnchorError::InvalidExpectation)
    );

    let tampered = String::from_utf8(bytes.clone())
        .unwrap()
        .replace(
            "trusted-time-external-anchor-expectation.v1",
            "trusted-time-external-anchor-expectation.v2",
        )
        .into_bytes();
    assert_eq!(
        parse_external_anchor_expectation(
            &tampered,
            &fixture.anchor_pin,
            &fixture.anchor_policy.state_identity,
            &fixture.time_pin,
            &fixture.anchor_policy.remote_cursor_policy_sha256,
        ),
        Err(ExternalAnchorError::InvalidExpectation)
    );

    assert_eq!(
        parse_external_anchor_expectation(
            &bytes,
            &fixture.anchor_pin,
            "data:tenant-b:lifecycle",
            &fixture.time_pin,
            &fixture.anchor_policy.remote_cursor_policy_sha256,
        ),
        Err(ExternalAnchorError::AudienceMismatch)
    );
    assert_eq!(
        parse_external_anchor_expectation(
            &bytes,
            &format!("0x{}", "99".repeat(32)),
            &fixture.anchor_policy.state_identity,
            &fixture.time_pin,
            &fixture.anchor_policy.remote_cursor_policy_sha256,
        ),
        Err(ExternalAnchorError::AudienceMismatch)
    );
}

#[test]
fn rejects_replayed_document_for_a_different_challenge() {
    let fixture = Fixture::new();
    let document = fixture.document(
        1,
        &fixture.boundary(1_930),
        CHALLENGE,
        1_990,
        2_200,
        &[0, 1],
    );
    assert_eq!(
        verify_external_anchor(
            &document,
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            OTHER_CHALLENGE,
            &fixture.trusted_time(),
            None,
        ),
        Err(ExternalAnchorError::NonceMismatch)
    );
}

#[test]
fn rejects_generation_and_boundary_rollback_against_retained_expectation() {
    let fixture = Fixture::new();
    let retained_document = fixture.document(
        8,
        &fixture.boundary(1_960),
        CHALLENGE,
        1_990,
        2_200,
        &[0, 1],
    );
    let trusted_time = fixture.trusted_time();
    let retained = verify_external_anchor(
        &retained_document,
        &fixture.anchor_policy,
        &fixture.anchor_pin,
        CHALLENGE,
        &trusted_time,
        None,
    )
    .unwrap()
    .retention_expectation();

    for document in [
        fixture.document(
            7,
            &fixture.boundary(1_960),
            CHALLENGE,
            1_990,
            2_200,
            &[0, 2],
        ),
        fixture.document(
            9,
            &fixture.boundary(1_959),
            CHALLENGE,
            1_990,
            2_200,
            &[0, 2],
        ),
        fixture.document(
            8,
            &fixture.boundary(1_961),
            CHALLENGE,
            1_990,
            2_200,
            &[0, 2],
        ),
    ] {
        assert_eq!(
            verify_external_anchor(
                &document,
                &fixture.anchor_policy,
                &fixture.anchor_pin,
                CHALLENGE,
                &trusted_time,
                Some(&retained),
            ),
            Err(ExternalAnchorError::RollbackDetected)
        );
    }
}

#[test]
fn rejects_trusted_time_attested_before_the_external_boundary() {
    let fixture = Fixture::new();
    let document = fixture.document(
        1,
        &fixture.boundary(1_950),
        CHALLENGE,
        1_700,
        1_900,
        &[0, 1],
    );
    let old_trusted_time = fixture.time_at(1_800, 1_900);
    assert_eq!(
        verify_external_anchor(
            &document,
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            CHALLENGE,
            &old_trusted_time,
            None,
        ),
        Err(ExternalAnchorError::RollbackDetected)
    );
}

#[test]
fn rejects_cross_audience_and_cross_policy() {
    let fixture = Fixture::new();
    let document = fixture.document(
        1,
        &fixture.boundary(1_930),
        CHALLENGE,
        1_990,
        2_200,
        &[0, 1],
    );
    let mut wrong_time_policy = fixture.time_policy.clone();
    wrong_time_policy.state_identity = "data:tenant-b:lifecycle".into();
    let wrong_time_pin = trusted_time_policy_sha256(&wrong_time_policy).unwrap();
    let message = trusted_time_signature_message(
        &wrong_time_policy,
        &wrong_time_pin,
        TIME_NONCE,
        2_000,
        2_100,
    )
    .unwrap();
    let signature = TrustedTimeSignature {
        authority_id: "time-1".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.time_key.sign(&message).to_bytes())
        ),
    };
    let token = create_trusted_time_token(
        &wrong_time_policy,
        &wrong_time_pin,
        TIME_NONCE,
        2_000,
        2_100,
        &[signature],
    )
    .unwrap();
    let wrong_time = verify_trusted_time_token(
        &token,
        &wrong_time_policy,
        &wrong_time_pin,
        TIME_NONCE,
        None,
    )
    .unwrap();
    assert_eq!(
        verify_external_anchor(
            &document,
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            CHALLENGE,
            &wrong_time,
            None,
        ),
        Err(ExternalAnchorError::AudienceMismatch)
    );
    assert_eq!(
        verify_external_anchor(
            &document,
            &fixture.anchor_policy,
            &format!("0x{}", "00".repeat(32)),
            CHALLENGE,
            &fixture.trusted_time(),
            None,
        ),
        Err(ExternalAnchorError::PolicyPinMismatch)
    );
}

#[test]
fn rejects_duplicate_keys_and_duplicate_signers() {
    let fixture = Fixture::new();
    let mut duplicate_key = fixture.anchor_policy.clone();
    duplicate_key.authorities[1].ed25519_public_key =
        duplicate_key.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        external_anchor_policy_bytes(&duplicate_key),
        Err(ExternalAnchorError::InvalidPolicy)
    );

    let mut weak_key = fixture.anchor_policy.clone();
    weak_key.authorities[1].ed25519_public_key = format!("0x01{}", "00".repeat(31));
    assert_eq!(
        external_anchor_policy_bytes(&weak_key),
        Err(ExternalAnchorError::InvalidPolicy)
    );

    let boundary = fixture.boundary(1_930);
    let message = external_anchor_signature_message(
        &fixture.anchor_policy,
        &fixture.anchor_pin,
        1,
        &boundary,
        1_990,
        2_200,
        CHALLENGE,
    )
    .unwrap();
    let signature = ExternalAnchorSignature {
        authority_id: "anchor-1".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.anchor_keys[0].sign(&message).to_bytes())
        ),
    };
    assert_eq!(
        create_external_anchor_document(
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            1,
            &boundary,
            1_990,
            2_200,
            CHALLENGE,
            &[signature.clone(), signature],
        ),
        Err(ExternalAnchorError::InvalidDocument)
    );
}

#[test]
fn rejects_expiry_using_verified_trusted_time_and_noncanonical_document() {
    let fixture = Fixture::new();
    let document = fixture.document(
        1,
        &fixture.boundary(1_930),
        CHALLENGE,
        1_500,
        1_900,
        &[0, 1],
    );
    assert_eq!(
        verify_external_anchor(
            &document,
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            CHALLENGE,
            &fixture.trusted_time(),
            None,
        ),
        Err(ExternalAnchorError::OutsideValidityWindow)
    );

    let mut noncanonical = fixture.document(
        1,
        &fixture.boundary(1_930),
        CHALLENGE,
        1_990,
        2_200,
        &[0, 1],
    );
    noncanonical.push(b'\n');
    assert_eq!(
        verify_external_anchor(
            &noncanonical,
            &fixture.anchor_policy,
            &fixture.anchor_pin,
            CHALLENGE,
            &fixture.trusted_time(),
            None,
        ),
        Err(ExternalAnchorError::InvalidDocument)
    );
}
