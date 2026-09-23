use bloch_authenticated_fetch_adapter::{
    AdapterHandshakeObservation, AuthenticatedFetchAdapter, AuthenticatedFetchAdapterError,
    AuthenticatedFetchError, AuthenticatedFetchParameters, AuthenticatedFetchRequest,
    ExternalMtlsKeyHandle, FetchCacheMode, FetchContractError, execute_authenticated_fetch,
};
use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TRANSPORT_POLICY_SCHEMA, TransportAuthority,
    TransportEvidenceSignature, TransportExchangeParameters, TransportPurpose,
    authenticated_transport_policy_sha256, create_authenticated_transport_evidence_for_exchange,
    transport_evidence_signature_message_for_exchange,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportInput, AuthenticatedTransportSessionError, MonotonicDeadlineRead,
    TransportCallbackError,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::convert::Infallible;
use std::time::{Duration, Instant};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const SERVER_PIN: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
const CLIENT_PIN: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";
const TIME_NONCE: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
const RESPONSE: &[u8] = b"fresh-response";

struct Fixture {
    policy: AuthenticatedTransportPolicy,
    pin: String,
    transport_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
}

impl Fixture {
    fn new() -> Self {
        let time_keys = signing_keys(61);
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "fetch-time-policy".into(),
            signature_domain: "bloch-products-trusted-time-v1".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: REMOTE_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 2_000,
            max_token_lifetime_seconds: 30,
            authorities: authorities("time", &time_keys),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let transport_keys = signing_keys(51);
        let policy = AuthenticatedTransportPolicy {
            schema: TRANSPORT_POLICY_SCHEMA.into(),
            policy_id: "fetch-transport-policy".into(),
            signature_domain: "bloch-products-transport-v1".into(),
            service_id: "bloch-data-fetch-primary".into(),
            purpose: TransportPurpose::RemoteCursor,
            state_identity: IDENTITY.into(),
            trusted_time_policy_sha256: time_pin.clone(),
            remote_cursor_policy_sha256: REMOTE_PIN.into(),
            endpoint_dns_name: "data.internal.example".into(),
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
            max_response_bytes: 32,
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
        let now = 1_120;
        let valid_until = 1_140;
        let message = trusted_time_signature_message(
            &self.time_policy,
            &self.time_pin,
            TIME_NONCE,
            now,
            valid_until,
        )
        .unwrap();
        let signatures = self
            .time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let token = create_trusted_time_token(
            &self.time_policy,
            &self.time_pin,
            TIME_NONCE,
            now,
            valid_until,
            &signatures,
        )
        .unwrap();
        verify_trusted_time_token(&token, &self.time_policy, &self.time_pin, TIME_NONCE, None)
            .unwrap()
    }

    fn evidence(&self, request: &AuthenticatedFetchRequest<'_>, response: &[u8]) -> Vec<u8> {
        let parameters = TransportExchangeParameters {
            request_nonce: request.request_nonce(),
            request_bytes: request.request_bytes(),
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
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    Endpoint,
    ServerPin,
    ClientPin,
    Cipher,
    KeyHandle,
    PeerUnverified,
    ClientCertificateMissing,
    ResponseFromCache,
    CacheRead,
    CacheWrite,
    ResponseEvidenceMismatch,
    OversizedResponse,
}

struct TestAdapter<'a> {
    fixture: &'a Fixture,
    mutation: Mutation,
    other_handle: ExternalMtlsKeyHandle,
    called: bool,
}

impl AuthenticatedFetchAdapter for TestAdapter<'_> {
    type Error = Infallible;

    fn fetch(
        &mut self,
        request: AuthenticatedFetchRequest<'_>,
    ) -> Result<AuthenticatedTransportInput, AuthenticatedFetchAdapterError<Self::Error>> {
        self.called = true;
        assert_eq!(request.endpoint_dns_name(), "data.internal.example");
        assert_eq!(request.endpoint_port(), 443);
        assert_eq!(request.tls_version(), "TLSv1.3");
        assert_eq!(request.alpn(), "h2");
        assert_eq!(request.allowed_cipher_suites(), ["TLS_AES_128_GCM_SHA256"]);
        assert_eq!(request.server_spki_sha256(), [SERVER_PIN]);
        assert_eq!(request.client_spki_sha256(), CLIENT_PIN);
        assert_eq!(request.purpose(), TransportPurpose::RemoteCursor);
        assert_eq!(request.cache_mode(), FetchCacheMode::Disabled);
        assert!(!request.request_bytes().is_empty());
        assert!(request.deadline() > Instant::now());
        assert_eq!(request.maximum_response_bytes(), 32);
        let response: &[u8] = if matches!(self.mutation, Mutation::OversizedResponse) {
            b"response-that-is-deliberately-over-32-bytes"
        } else {
            RESPONSE
        };
        let evidenced_response: &[u8] = if matches!(
            self.mutation,
            Mutation::ResponseEvidenceMismatch | Mutation::OversizedResponse
        ) {
            if matches!(self.mutation, Mutation::ResponseEvidenceMismatch) {
                b"substituted-response"
            } else {
                RESPONSE
            }
        } else {
            response
        };
        let evidence = self.fixture.evidence(&request, evidenced_response);
        let mut response_reader = SliceReader::new(response);
        let mut evidence_reader = SliceReader::new(&evidence);
        let endpoint = if matches!(self.mutation, Mutation::Endpoint) {
            "attacker.example"
        } else {
            "data.internal.example"
        };
        let server_pin = if matches!(self.mutation, Mutation::ServerPin) {
            REMOTE_PIN
        } else {
            SERVER_PIN
        };
        let client_pin = if matches!(self.mutation, Mutation::ClientPin) {
            REMOTE_PIN
        } else {
            CLIENT_PIN
        };
        let cipher = if matches!(self.mutation, Mutation::Cipher) {
            "TLS_AES_256_GCM_SHA384"
        } else {
            "TLS_AES_128_GCM_SHA256"
        };
        let key_handle = if matches!(self.mutation, Mutation::KeyHandle) {
            &self.other_handle
        } else {
            request.mtls_key_handle()
        };
        let observation = AdapterHandshakeObservation {
            endpoint_dns_name: endpoint,
            endpoint_port: 443,
            tls_version: "TLSv1.3",
            alpn: "h2",
            cipher_suite: cipher,
            server_spki_sha256: server_pin,
            client_spki_sha256: client_pin,
            mtls_key_handle: key_handle,
            peer_certificate_verified: !matches!(self.mutation, Mutation::PeerUnverified),
            client_certificate_used: !matches!(self.mutation, Mutation::ClientCertificateMissing),
            response_from_cache: matches!(self.mutation, Mutation::ResponseFromCache),
            cache_read_attempted: matches!(self.mutation, Mutation::CacheRead),
            cache_write_attempted: matches!(self.mutation, Mutation::CacheWrite),
        };
        request.complete_exchange(observation, &mut response_reader, &mut evidence_reader)
    }
}

#[test]
fn valid_exact_non_cached_exchange_is_released() {
    let fixture = Fixture::new();
    let handle = ExternalMtlsKeyHandle::parse("hsm://cluster-a/client-data-1").unwrap();
    let mut adapter = new_adapter(&fixture, Mutation::None);
    let trusted = fixture.trusted_time();
    let verified = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            &fixture.pin,
            TransportPurpose::RemoteCursor,
        ),
    )
    .unwrap();
    assert!(adapter.called);
    assert_eq!(verified.response_bytes(), RESPONSE);
}

#[test]
fn endpoint_tls_identity_and_key_handle_substitution_fail_closed() {
    for mutation in [
        Mutation::Endpoint,
        Mutation::ServerPin,
        Mutation::ClientPin,
        Mutation::Cipher,
        Mutation::KeyHandle,
    ] {
        assert_contract_failure(mutation, FetchContractError::HandshakeMismatch);
    }
}

#[test]
fn peer_mtls_and_every_cache_path_fail_closed() {
    assert_contract_failure(
        Mutation::PeerUnverified,
        FetchContractError::PeerNotVerified,
    );
    assert_contract_failure(
        Mutation::ClientCertificateMissing,
        FetchContractError::ClientCertificateNotUsed,
    );
    for mutation in [
        Mutation::ResponseFromCache,
        Mutation::CacheRead,
        Mutation::CacheWrite,
    ] {
        assert_contract_failure(mutation, FetchContractError::CacheUseForbidden);
    }
}

#[test]
fn response_substitution_and_oversized_ingress_fail_closed() {
    let fixture = Fixture::new();
    let handle = ExternalMtlsKeyHandle::parse("hsm://cluster-a/client-data-1").unwrap();
    let trusted = fixture.trusted_time();
    let mut adapter = new_adapter(&fixture, Mutation::ResponseEvidenceMismatch);
    let result = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            &fixture.pin,
            TransportPurpose::RemoteCursor,
        ),
    );
    assert!(matches!(
        result,
        Err(AuthenticatedFetchError::Session(
            AuthenticatedTransportSessionError::Evidence(
                bloch_authenticated_transport_evidence::TransportEvidenceError::ExchangeMismatch
            )
        ))
    ));

    let trusted = fixture.trusted_time();
    let mut adapter = new_adapter(&fixture, Mutation::OversizedResponse);
    let result = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            &fixture.pin,
            TransportPurpose::RemoteCursor,
        ),
    );
    assert!(matches!(
        result,
        Err(AuthenticatedFetchError::Session(
            AuthenticatedTransportSessionError::Callback(TransportCallbackError::Transport(
                AuthenticatedFetchAdapterError::Ingress(
                    bloch_authenticated_transport_session::TransportIngressError::ResponseTooLarge
                )
            ))
        ))
    ));
}

#[test]
fn wrong_policy_pin_and_purpose_fail_before_adapter() {
    let fixture = Fixture::new();
    let handle = ExternalMtlsKeyHandle::parse("hsm://cluster-a/client-data-1").unwrap();
    let trusted = fixture.trusted_time();
    let mut adapter = new_adapter(&fixture, Mutation::None);
    let result = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            REMOTE_PIN,
            TransportPurpose::RemoteCursor,
        ),
    );
    assert!(matches!(
        result,
        Err(AuthenticatedFetchError::InvalidConfiguration)
    ));
    assert!(!adapter.called);

    let trusted = fixture.trusted_time();
    let mut adapter = new_adapter(&fixture, Mutation::None);
    let result = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            &fixture.pin,
            TransportPurpose::TrustedTime,
        ),
    );
    assert!(matches!(
        result,
        Err(AuthenticatedFetchError::InvalidConfiguration)
    ));
    assert!(!adapter.called);
}

#[test]
fn key_handle_parser_rejects_secret_bearing_or_ambiguous_values() {
    for value in [
        "",
        "file:///tmp/key.pem",
        "pkcs11:object=x?pin-value=1234",
        "hsm://cluster/key?secret=x",
        "hsm://UPPERCASE",
        "hsm://cluster/../key",
        "hsm://cluster//key",
        "kms://",
    ] {
        assert_eq!(
            ExternalMtlsKeyHandle::parse(value),
            Err(FetchContractError::InvalidKeyHandle)
        );
    }
    assert!(ExternalMtlsKeyHandle::parse("kms://tenant-a/client-key-1").is_ok());
    assert!(ExternalMtlsKeyHandle::parse("pkcs11-object://slot-3/object-7").is_ok());
}

fn assert_contract_failure(mutation: Mutation, expected: FetchContractError) {
    let fixture = Fixture::new();
    let handle = ExternalMtlsKeyHandle::parse("hsm://cluster-a/client-data-1").unwrap();
    let trusted = fixture.trusted_time();
    let mut adapter = new_adapter(&fixture, mutation);
    let result = execute_authenticated_fetch(
        &mut adapter,
        parameters(
            &fixture,
            &handle,
            &trusted,
            &fixture.pin,
            TransportPurpose::RemoteCursor,
        ),
    );
    assert!(matches!(
        result,
        Err(AuthenticatedFetchError::Session(
            AuthenticatedTransportSessionError::Callback(TransportCallbackError::Transport(
                AuthenticatedFetchAdapterError::Contract(error)
            ))
        )) if error == expected
    ));
}

fn new_adapter(fixture: &Fixture, mutation: Mutation) -> TestAdapter<'_> {
    TestAdapter {
        fixture,
        mutation,
        other_handle: ExternalMtlsKeyHandle::parse("hsm://cluster-b/client-data-2").unwrap(),
        called: false,
    }
}

fn parameters<'a>(
    fixture: &'a Fixture,
    handle: &'a ExternalMtlsKeyHandle,
    trusted_time: &'a VerifiedTrustedTime,
    expected_policy_sha256: &'a str,
    expected_purpose: TransportPurpose,
) -> AuthenticatedFetchParameters<'a> {
    AuthenticatedFetchParameters {
        policy: &fixture.policy,
        expected_policy_sha256,
        expected_purpose,
        key_handle: handle,
        request_bytes: b"GET /snapshot",
        timeout: Duration::from_secs(1),
        trusted_time,
    }
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

fn signing_keys(first: u8) -> Vec<SigningKey> {
    (first..=first + 2)
        .map(|value| SigningKey::from_bytes(&[value; 32]))
        .collect()
}

fn authorities(prefix: &str, keys: &[SigningKey]) -> Vec<TrustedTimeAuthority> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeAuthority {
            authority_id: format!("{prefix}-{}", index + 1),
            ed25519_public_key: hex_key(key),
        })
        .collect()
}

fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().as_bytes()))
}
