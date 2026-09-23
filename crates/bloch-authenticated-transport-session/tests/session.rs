use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TRANSPORT_POLICY_SCHEMA, TransportAuthority,
    TransportEvidenceError, TransportEvidenceSignature, TransportExchangeParameters,
    TransportPurpose, authenticated_transport_policy_sha256,
    create_authenticated_transport_evidence_for_exchange,
    transport_evidence_signature_message_for_exchange,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportRequest, AuthenticatedTransportSessionError, MonotonicDeadlineRead,
    TransportCallbackError, TransportIngressError, execute_authenticated_transport_session,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::RefCell;
use std::convert::Infallible;
use std::time::{Duration, Instant};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const SERVER_PIN: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
const CLIENT_PIN: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";
const TIME_NONCE: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
const RESPONSE: &[u8] = b"pong";

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
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            server_spki_sha256: vec![SERVER_PIN.into()],
            client_spki_sha256: CLIENT_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 2_000,
            max_evidence_age_seconds: 10,
            max_round_trip_millis: 2_000,
            max_response_bytes: 8,
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

    fn trusted_time(&self) -> VerifiedTrustedTime {
        verified_time(&self.time_policy, &self.time_pin, &self.time_keys, 1_120)
    }

    fn evidence(&self, request: &AuthenticatedTransportRequest<'_>, response: &[u8]) -> Vec<u8> {
        self.evidence_for_request_bytes(request, request.request_bytes(), response)
    }

    fn evidence_for_request_bytes(
        &self,
        request: &AuthenticatedTransportRequest<'_>,
        signed_request_bytes: &[u8],
        response: &[u8],
    ) -> Vec<u8> {
        let parameters = TransportExchangeParameters {
            request_nonce: request.request_nonce(),
            request_bytes: signed_request_bytes,
            response_bytes: response,
            round_trip_millis: 10,
            observed_at_unix_seconds: 1_120,
            cipher_suite: "TLS_AES_128_GCM_SHA256",
            server_spki_sha256: SERVER_PIN,
        };
        let message =
            transport_evidence_signature_message_for_exchange(&self.policy, &self.pin, parameters)
                .unwrap();
        let signatures = self
            .transport_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TransportEvidenceSignature {
                authority_id: format!("transport-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_authenticated_transport_evidence_for_exchange(
            &self.policy,
            &self.pin,
            parameters,
            &signatures,
        )
        .unwrap()
    }

    fn execute<F>(
        &self,
        trusted_time: &VerifiedTrustedTime,
        callback: F,
    ) -> Result<
        bloch_authenticated_transport_session::VerifiedAuthenticatedTransportResponse,
        AuthenticatedTransportSessionError<Infallible>,
    >
    where
        F: for<'a> FnOnce(
            AuthenticatedTransportRequest<'a>,
        ) -> Result<
            bloch_authenticated_transport_session::AuthenticatedTransportInput,
            TransportCallbackError<Infallible>,
        >,
    {
        execute_authenticated_transport_session(
            &self.policy,
            &self.pin,
            TransportPurpose::RemoteCursor,
            b"GET /cursor",
            Duration::from_secs(1),
            trusted_time,
            callback,
        )
    }
}

#[test]
fn exact_response_is_released_only_after_valid_evidence() {
    let fixture = Fixture::new(IDENTITY);
    let trusted = fixture.trusted_time();
    let verified = fixture
        .execute(&trusted, |request| {
            assert_eq!(request.request_bytes(), b"GET /cursor");
            assert!(request.request_nonce().starts_with("0x"));
            let evidence = fixture.evidence(&request, RESPONSE);
            collect(&request, RESPONSE, &evidence)
        })
        .unwrap();
    assert_eq!(verified.response_bytes(), RESPONSE);
    assert_eq!(
        verified.evidence().purpose(),
        TransportPurpose::RemoteCursor
    );
}

#[test]
fn response_or_request_substitution_fails_closed() {
    let fixture = Fixture::new(IDENTITY);
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence(&request, b"pung");
        collect(&request, RESPONSE, &evidence)
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Evidence(
            TransportEvidenceError::ExchangeMismatch
        ))
    ));

    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence_for_request_bytes(&request, b"GET /other", RESPONSE);
        collect(&request, RESPONSE, &evidence)
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Evidence(
            TransportEvidenceError::ExchangeMismatch
        ))
    ));
}

#[test]
fn evidence_replay_fails_against_fresh_nonce() {
    let fixture = Fixture::new(IDENTITY);
    let saved = RefCell::new(None);
    let trusted = fixture.trusted_time();
    fixture
        .execute(&trusted, |request| {
            let evidence = fixture.evidence(&request, RESPONSE);
            *saved.borrow_mut() = Some(evidence.clone());
            collect(&request, RESPONSE, &evidence)
        })
        .unwrap();
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        collect(&request, RESPONSE, saved.borrow().as_ref().unwrap())
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Evidence(
            TransportEvidenceError::ExchangeMismatch
        ))
    ));
}

#[test]
fn oversized_response_is_stopped_incrementally() {
    let fixture = Fixture::new(IDENTITY);
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence(&request, RESPONSE);
        collect(&request, b"ninebytes", &evidence)
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Callback(
            TransportCallbackError::Ingress(TransportIngressError::ResponseTooLarge)
        ))
    ));
}

#[test]
fn deadline_is_checked_around_every_read() {
    let fixture = Fixture::new(IDENTITY);
    let trusted = fixture.trusted_time();
    let result = execute_authenticated_transport_session(
        &fixture.policy,
        &fixture.pin,
        TransportPurpose::RemoteCursor,
        b"GET /cursor",
        Duration::from_millis(1),
        &trusted,
        |request| {
            let evidence = fixture.evidence(&request, RESPONSE);
            let mut slow = SlowReader;
            let mut evidence = SliceReader::new(&evidence);
            request
                .collect_exchange(&mut slow, &mut evidence)
                .map_err(TransportCallbackError::Ingress)
        },
    );
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Callback(
            TransportCallbackError::Ingress(TransportIngressError::DeadlineExceeded)
        ))
    ));
}

#[test]
fn cross_audience_and_wrong_purpose_fail_before_callback() {
    let fixture = Fixture::new(IDENTITY);
    let cross = Fixture::new("pay:tenant-a:lifecycle").trusted_time();
    let called = RefCell::new(false);
    let result = fixture.execute(&cross, |_| {
        *called.borrow_mut() = true;
        unreachable!()
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::Evidence(
            TransportEvidenceError::AudienceMismatch
        ))
    ));
    assert!(!*called.borrow());

    let trusted = fixture.trusted_time();
    let wrong = execute_authenticated_transport_session::<Infallible, _>(
        &fixture.policy,
        &fixture.pin,
        TransportPurpose::TrustedTime,
        b"GET /cursor",
        Duration::from_secs(1),
        &trusted,
        |_| unreachable!(),
    );
    assert!(matches!(
        wrong,
        Err(AuthenticatedTransportSessionError::InvalidConfiguration)
    ));
}

#[test]
fn expired_trusted_time_fails_before_callback() {
    let fixture = Fixture::new(IDENTITY);
    let expired = verified_time_with_lifetime(
        &fixture.time_policy,
        &fixture.time_pin,
        &fixture.time_keys,
        1_120,
        1,
    );
    std::thread::sleep(Duration::from_millis(1_100));
    let called = RefCell::new(false);
    let result = fixture.execute(&expired, |_| {
        *called.borrow_mut() = true;
        unreachable!()
    });
    assert!(matches!(
        result,
        Err(AuthenticatedTransportSessionError::TrustedTime(
            bloch_trusted_time::TrustedTimeError::ExpiredCapability
        ))
    ));
    assert!(!*called.borrow());
}

fn collect(
    request: &AuthenticatedTransportRequest<'_>,
    response: &[u8],
    evidence: &[u8],
) -> Result<
    bloch_authenticated_transport_session::AuthenticatedTransportInput,
    TransportCallbackError<Infallible>,
> {
    let mut response = SliceReader::new(response);
    let mut evidence = SliceReader::new(evidence);
    request
        .collect_exchange(&mut response, &mut evidence)
        .map_err(TransportCallbackError::Ingress)
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl MonotonicDeadlineRead for SliceReader<'_> {
    type Error = Infallible;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, Self::Error> {
        let count = buffer.len().min(self.bytes.len() - self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

struct SlowReader;

impl MonotonicDeadlineRead for SlowReader {
    type Error = Infallible;

    fn read_with_deadline(
        &mut self,
        _buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, Self::Error> {
        std::thread::sleep(Duration::from_millis(3));
        Ok(0)
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
    verified_time_with_lifetime(policy, pin, keys, now, 20)
}

fn verified_time_with_lifetime(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey],
    now: u64,
    lifetime: u64,
) -> VerifiedTrustedTime {
    let valid_until = now + lifetime;
    let message =
        trusted_time_signature_message(policy, pin, TIME_NONCE, now, valid_until).unwrap();
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
        create_trusted_time_token(policy, pin, TIME_NONCE, now, valid_until, &signatures).unwrap();
    verify_trusted_time_token(&token, policy, pin, TIME_NONCE, None).unwrap()
}

fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().as_bytes()))
}
