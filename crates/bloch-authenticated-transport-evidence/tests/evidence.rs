use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TRANSPORT_POLICY_SCHEMA, TransportAuthority,
    TransportEvidenceError, TransportEvidenceExpectation, TransportEvidenceParameters,
    TransportEvidenceSignature, TransportExchangeExpectation, TransportExchangeParameters,
    TransportPurpose, authenticated_transport_policy_sha256,
    create_authenticated_transport_evidence, create_authenticated_transport_evidence_for_exchange,
    transport_evidence_signature_message, transport_evidence_signature_message_for_exchange,
    verify_authenticated_transport_evidence, verify_authenticated_transport_exchange_evidence,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NONCE: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const REQUEST: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const RESPONSE: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";
const SERVER_PIN: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
const CLIENT_PIN: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";
const TIME_NONCE: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";

struct Fixture {
    policy: AuthenticatedTransportPolicy,
    pin: String,
    transport_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
}

impl Fixture {
    fn new(identity: &str) -> Self {
        let time_keys = vec![
            SigningKey::from_bytes(&[61; 32]),
            SigningKey::from_bytes(&[62; 32]),
            SigningKey::from_bytes(&[63; 32]),
        ];
        let time_policy = time_policy(identity, &time_keys);
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let transport_keys = vec![
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
            SigningKey::from_bytes(&[53; 32]),
        ];
        let policy = AuthenticatedTransportPolicy {
            schema: TRANSPORT_POLICY_SCHEMA.into(),
            policy_id: "transport-policy-1".into(),
            signature_domain: "bloch-products-transport-v1".into(),
            service_id: "remote-cursor-primary".into(),
            purpose: TransportPurpose::RemoteCursor,
            state_identity: identity.into(),
            trusted_time_policy_sha256: time_pin.clone(),
            remote_cursor_policy_sha256: REMOTE_PIN.into(),
            endpoint_dns_name: "cursor.internal.example".into(),
            endpoint_port: 443,
            tls_version: "TLSv1.3".into(),
            alpn: "h2".into(),
            allowed_cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_AES_256_GCM_SHA384".into(),
            ],
            server_spki_sha256: vec![SERVER_PIN.into()],
            client_spki_sha256: CLIENT_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 2_000,
            max_evidence_age_seconds: 10,
            max_round_trip_millis: 2_000,
            max_response_bytes: 65_536,
            authorities: transport_keys
                .iter()
                .enumerate()
                .map(|(index, key)| TransportAuthority {
                    authority_id: format!("transport-{}", index + 1),
                    ed25519_public_key: hex_key(key),
                })
                .collect(),
        };
        let pin = authenticated_transport_policy_sha256(&policy).unwrap();
        Self {
            policy,
            pin,
            transport_keys,
            time_policy,
            time_pin,
            time_keys,
        }
    }

    fn parameters(&self, observed_at: u64) -> TransportEvidenceParameters<'static> {
        TransportEvidenceParameters {
            request_nonce: NONCE,
            request_sha256: REQUEST,
            response_sha256: RESPONSE,
            response_bytes: 4_096,
            round_trip_millis: 125,
            observed_at_unix_seconds: observed_at,
            cipher_suite: "TLS_AES_128_GCM_SHA256",
            server_spki_sha256: SERVER_PIN,
        }
    }

    fn evidence(
        &self,
        observed_at: u64,
        signer_count: usize,
    ) -> Result<Vec<u8>, TransportEvidenceError> {
        let parameters = self.parameters(observed_at);
        let message = transport_evidence_signature_message(&self.policy, &self.pin, parameters)?;
        let signatures = self
            .transport_keys
            .iter()
            .take(signer_count)
            .enumerate()
            .map(|(index, key)| TransportEvidenceSignature {
                authority_id: format!("transport-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_authenticated_transport_evidence(&self.policy, &self.pin, parameters, &signatures)
    }

    fn trusted_time(&self, now: u64) -> VerifiedTrustedTime {
        verified_time(&self.time_policy, &self.time_pin, &self.time_keys, now)
    }
}

#[test]
fn threshold_evidence_authenticates_exact_tls_exchange() {
    let fixture = Fixture::new(IDENTITY);
    let evidence = fixture.evidence(1_120, 2).unwrap();
    let trusted = fixture.trusted_time(1_120);
    let verified = verify_authenticated_transport_evidence(
        &evidence,
        &fixture.policy,
        &fixture.pin,
        expectation(),
        &trusted,
    )
    .unwrap();
    assert_eq!(verified.service_id(), "remote-cursor-primary");
    assert_eq!(verified.purpose(), TransportPurpose::RemoteCursor);
    assert_eq!(verified.request_sha256(), REQUEST);
    assert_eq!(verified.response_sha256(), RESPONSE);
    assert_eq!(verified.authority_ids(), &["transport-1", "transport-2"]);
    verified.ensure_monotonic_freshness().unwrap();
}

#[test]
fn request_nonce_digest_and_size_substitution_fail_closed() {
    let fixture = Fixture::new(IDENTITY);
    let evidence = fixture.evidence(1_120, 2).unwrap();
    let trusted = fixture.trusted_time(1_120);
    for changed in [
        TransportEvidenceExpectation {
            request_nonce: SERVER_PIN,
            ..expectation()
        },
        TransportEvidenceExpectation {
            request_sha256: SERVER_PIN,
            ..expectation()
        },
        TransportEvidenceExpectation {
            response_sha256: SERVER_PIN,
            ..expectation()
        },
        TransportEvidenceExpectation {
            response_bytes: 4_095,
            ..expectation()
        },
    ] {
        assert_eq!(
            verify_authenticated_transport_evidence(
                &evidence,
                &fixture.policy,
                &fixture.pin,
                changed,
                &trusted,
            )
            .unwrap_err(),
            TransportEvidenceError::ExchangeMismatch
        );
    }
}

#[test]
fn byte_derived_api_binds_the_exact_request_and_response() {
    let fixture = Fixture::new(IDENTITY);
    let request = br#"{"operation":"cursor"}"#;
    let response = br#"{"generation":7}"#;
    let exchange = TransportExchangeParameters {
        request_nonce: NONCE,
        request_bytes: request,
        response_bytes: response,
        round_trip_millis: 125,
        observed_at_unix_seconds: 1_120,
        cipher_suite: "TLS_AES_128_GCM_SHA256",
        server_spki_sha256: SERVER_PIN,
    };
    let message =
        transport_evidence_signature_message_for_exchange(&fixture.policy, &fixture.pin, exchange)
            .unwrap();
    let signatures = fixture
        .transport_keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| TransportEvidenceSignature {
            authority_id: format!("transport-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let evidence = create_authenticated_transport_evidence_for_exchange(
        &fixture.policy,
        &fixture.pin,
        exchange,
        &signatures,
    )
    .unwrap();
    let trusted = fixture.trusted_time(1_120);
    verify_authenticated_transport_exchange_evidence(
        &evidence,
        &fixture.policy,
        &fixture.pin,
        TransportExchangeExpectation {
            purpose: TransportPurpose::RemoteCursor,
            request_nonce: NONCE,
            request_bytes: request,
            response_bytes: response,
        },
        &trusted,
    )
    .unwrap();

    for (changed_request, changed_response) in [
        (&b"other-request"[..], &response[..]),
        (&request[..], &b"other-response"[..]),
    ] {
        assert_eq!(
            verify_authenticated_transport_exchange_evidence(
                &evidence,
                &fixture.policy,
                &fixture.pin,
                TransportExchangeExpectation {
                    purpose: TransportPurpose::RemoteCursor,
                    request_nonce: NONCE,
                    request_bytes: changed_request,
                    response_bytes: changed_response,
                },
                &trusted,
            )
            .unwrap_err(),
            TransportEvidenceError::ExchangeMismatch
        );
    }
}

#[test]
fn cross_audience_and_stale_evidence_are_rejected() {
    let fixture = Fixture::new(IDENTITY);
    let evidence = fixture.evidence(1_120, 2).unwrap();
    let cross = Fixture::new("pay:tenant-a:lifecycle").trusted_time(1_120);
    assert_eq!(
        verify_authenticated_transport_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            expectation(),
            &cross,
        )
        .unwrap_err(),
        TransportEvidenceError::AudienceMismatch
    );
    let stale = fixture.trusted_time(1_130);
    assert_eq!(
        verify_authenticated_transport_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            expectation(),
            &stale,
        )
        .unwrap_err(),
        TransportEvidenceError::OutsideValidityWindow
    );
}

#[test]
fn policy_rejects_duplicate_or_weak_authorities_and_transport_pins() {
    let fixture = Fixture::new(IDENTITY);
    let mut duplicate_key = fixture.policy.clone();
    duplicate_key.authorities[1].ed25519_public_key =
        duplicate_key.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        authenticated_transport_policy_sha256(&duplicate_key),
        Err(TransportEvidenceError::InvalidPolicy)
    );
    let mut weak = fixture.policy.clone();
    weak.authorities[0].ed25519_public_key = format!("0x01{}", "00".repeat(31));
    assert_eq!(
        authenticated_transport_policy_sha256(&weak),
        Err(TransportEvidenceError::InvalidPolicy)
    );
    let mut duplicate_pin = fixture.policy.clone();
    duplicate_pin.server_spki_sha256.push(SERVER_PIN.into());
    assert_eq!(
        authenticated_transport_policy_sha256(&duplicate_pin),
        Err(TransportEvidenceError::InvalidPolicy)
    );
    assert_eq!(
        fixture.evidence(1_120, 1),
        Err(TransportEvidenceError::ThresholdNotMet)
    );
}

#[test]
fn noncanonical_or_wrong_pinned_policy_is_rejected() {
    let fixture = Fixture::new(IDENTITY);
    let mut evidence = fixture.evidence(1_120, 2).unwrap();
    evidence.push(b'\n');
    let trusted = fixture.trusted_time(1_120);
    assert_eq!(
        verify_authenticated_transport_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            expectation(),
            &trusted,
        )
        .unwrap_err(),
        TransportEvidenceError::InvalidEvidence
    );
    let wrong_pin = format!("0x{}", "9".repeat(64));
    assert_eq!(
        verify_authenticated_transport_evidence(
            &fixture.evidence(1_120, 2).unwrap(),
            &fixture.policy,
            &wrong_pin,
            expectation(),
            &trusted,
        )
        .unwrap_err(),
        TransportEvidenceError::PolicyPinMismatch
    );
}

fn expectation() -> TransportEvidenceExpectation<'static> {
    TransportEvidenceExpectation {
        purpose: TransportPurpose::RemoteCursor,
        request_nonce: NONCE,
        request_sha256: REQUEST,
        response_sha256: RESPONSE,
        response_bytes: 4_096,
    }
}

fn time_policy(identity: &str, keys: &[SigningKey]) -> TrustedTimePolicy {
    TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: format!("transport-time-{}", identity.replace(':', "-")),
        signature_domain: "bloch-products-trusted-time-v1".into(),
        state_identity: identity.into(),
        remote_cursor_policy_sha256: REMOTE_PIN.into(),
        threshold: 2,
        effective_at_unix_seconds: 1_000,
        expires_at_unix_seconds: 2_000,
        max_token_lifetime_seconds: 30,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeAuthority {
                authority_id: format!("time-{}", index + 1),
                ed25519_public_key: hex_key(key),
            })
            .collect(),
    }
}

fn verified_time(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey],
    now: u64,
) -> VerifiedTrustedTime {
    let message = trusted_time_signature_message(policy, pin, TIME_NONCE, now, now + 20).unwrap();
    let signatures = keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let token =
        create_trusted_time_token(policy, pin, TIME_NONCE, now, now + 20, &signatures).unwrap();
    verify_trusted_time_token(&token, policy, pin, TIME_NONCE, None).unwrap()
}

fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().as_bytes()))
}
