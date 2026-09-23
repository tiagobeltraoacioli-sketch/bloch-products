use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TRANSPORT_POLICY_SCHEMA, TransportAuthority,
    TransportEvidenceSignature, TransportExchangeParameters, TransportPurpose,
    authenticated_transport_policy_sha256, create_authenticated_transport_evidence_for_exchange,
    transport_evidence_signature_message_for_exchange,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportRequest, MonotonicDeadlineRead, TransportCallbackError,
};
use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasDecision,
    RemoteCursorCasRequestParameters, RemoteCursorPolicy, RemoteCursorSignature,
    create_remote_cursor_cas_receipt, create_remote_cursor_cas_request,
    parse_remote_cursor_cas_request, remote_cursor_cas_receipt_signature_message,
    remote_cursor_policy_sha256,
};
use bloch_local_state_remote_cursor_caller_auth::{
    CALLER_AUTH_POLICY_SCHEMA, CallerAuthority, CallerAuthorizationPolicy, CallerSignature,
    VerifiedRemoteCursorCasCallerAuthorization, caller_authorization_policy_sha256,
    caller_authorization_signature_message, create_caller_authorization,
    verify_caller_authorization_with_trusted_time,
};
use bloch_local_state_remote_cursor_cas_session::{
    CasCallerAuthorization, RemoteCursorCasSessionConfiguration, RemoteCursorCasSessionError,
    canonical_cas_transport_request, execute_remote_cursor_cas_session,
};
use bloch_local_state_store::{StateRoot, write_state};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const REQUEST_NONCE: &str = "cas_nonce_0123456789abcdef0123456789abcdef";
const TIME_NONCE: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
const SERVER_PIN: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
const CLIENT_PIN: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Roots {
    path: std::path::PathBuf,
    current: CheckpointCursor,
    successor: CheckpointCursor,
    successor_root: StateRoot,
}

impl Roots {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bloch-cas-session-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root0 = write_state(&path, IDENTITY, 0, b"zero", None).unwrap();
        let root1 = write_state(&path, IDENTITY, 1, b"one", Some(&root0)).unwrap();
        Self {
            path,
            current: cursor_for(&root0, 11),
            successor: cursor_for(&root1, 21),
            successor_root: root1,
        }
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

struct Fixture {
    _roots: Roots,
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
    transport_policy: AuthenticatedTransportPolicy,
    transport_pin: String,
    transport_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
    request: bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest,
}

impl Fixture {
    fn new() -> Self {
        let roots = Roots::new();
        let remote_keys = vec![
            SigningKey::from_bytes(&[71; 32]),
            SigningKey::from_bytes(&[72; 32]),
        ];
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-cas-policy".into(),
            signature_domain: "bloch-control-plane-cas".into(),
            state_identity: IDENTITY.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_observation_age_seconds: 100,
            authorities: authorities("remote", &remote_keys),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let request_bytes = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&roots.current),
                successor_cursor: &roots.successor,
                successor_root: &roots.successor_root,
                request_id: "request-1",
                request_nonce: REQUEST_NONCE,
                requested_at_unix_seconds: 200,
            },
            &remote_policy,
            &remote_pin,
        )
        .unwrap();
        let request =
            parse_remote_cursor_cas_request(&request_bytes, &remote_policy, &remote_pin).unwrap();

        let time_keys = vec![
            SigningKey::from_bytes(&[61; 32]),
            SigningKey::from_bytes(&[62; 32]),
        ];
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "cas-session-time".into(),
            signature_domain: "bloch-products-trusted-time-v1".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_token_lifetime_seconds: 30,
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
        let transport_keys = vec![
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
        ];
        let transport_policy = AuthenticatedTransportPolicy {
            schema: TRANSPORT_POLICY_SCHEMA.into(),
            policy_id: "cas-session-transport".into(),
            signature_domain: "bloch-products-transport-v1".into(),
            service_id: "remote-cursor-cas-primary".into(),
            purpose: TransportPurpose::RemoteCursorCas,
            state_identity: IDENTITY.into(),
            trusted_time_policy_sha256: time_pin.clone(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            endpoint_dns_name: "cas.internal.example".into(),
            endpoint_port: 443,
            tls_version: "TLSv1.3".into(),
            alpn: "h2".into(),
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            server_spki_sha256: vec![SERVER_PIN.into()],
            client_spki_sha256: CLIENT_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_evidence_age_seconds: 20,
            max_round_trip_millis: 2_000,
            max_response_bytes: 128 * 1024,
            authorities: transport_keys
                .iter()
                .enumerate()
                .map(|(index, key)| TransportAuthority {
                    authority_id: format!("transport-{}", index + 1),
                    ed25519_public_key: hex_key(key),
                })
                .collect(),
        };
        let transport_pin = authenticated_transport_policy_sha256(&transport_policy).unwrap();
        Self {
            _roots: roots,
            remote_policy,
            remote_pin,
            remote_keys,
            transport_policy,
            transport_pin,
            transport_keys,
            time_policy,
            time_pin,
            time_keys,
            request,
        }
    }

    fn trusted_time(&self) -> VerifiedTrustedTime {
        let message =
            trusted_time_signature_message(&self.time_policy, &self.time_pin, TIME_NONCE, 250, 280)
                .unwrap();
        let signatures = self
            .time_keys
            .iter()
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
            250,
            280,
            &signatures,
        )
        .unwrap();
        verify_trusted_time_token(&token, &self.time_policy, &self.time_pin, TIME_NONCE, None)
            .unwrap()
    }

    fn receipt(&self, decision: RemoteCursorCasDecision) -> Vec<u8> {
        let message = remote_cursor_cas_receipt_signature_message(
            self.request.canonical_bytes(),
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            240,
        )
        .unwrap();
        let signatures = self
            .remote_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorSignature {
                authority_id: format!("remote-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_remote_cursor_cas_receipt(
            self.request.canonical_bytes(),
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            240,
            &signatures,
        )
        .unwrap()
    }

    fn evidence(
        &self,
        request: &AuthenticatedTransportRequest<'_>,
        signed_request: &[u8],
        response: &[u8],
    ) -> Vec<u8> {
        let parameters = TransportExchangeParameters {
            request_nonce: request.request_nonce(),
            request_bytes: signed_request,
            response_bytes: response,
            round_trip_millis: 10,
            observed_at_unix_seconds: 250,
            cipher_suite: "TLS_AES_128_GCM_SHA256",
            server_spki_sha256: SERVER_PIN,
        };
        let message = transport_evidence_signature_message_for_exchange(
            &self.transport_policy,
            &self.transport_pin,
            parameters,
        )
        .unwrap();
        let signatures = self
            .transport_keys
            .iter()
            .enumerate()
            .map(|(index, key)| TransportEvidenceSignature {
                authority_id: format!("transport-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_authenticated_transport_evidence_for_exchange(
            &self.transport_policy,
            &self.transport_pin,
            parameters,
            &signatures,
        )
        .unwrap()
    }

    fn authorization(
        &self,
        trusted: &VerifiedTrustedTime,
    ) -> (Vec<u8>, VerifiedRemoteCursorCasCallerAuthorization) {
        let keys = [
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
        ];
        let policy = CallerAuthorizationPolicy {
            schema: CALLER_AUTH_POLICY_SCHEMA.into(),
            policy_id: "cas-caller-policy".into(),
            signature_domain: "bloch-products-cas-caller-v1".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: self.remote_pin.clone(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_authorization_age_seconds: 100,
            max_authorization_lifetime_seconds: 100,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CallerAuthority {
                    authority_id: format!("caller-{}", index + 1),
                    ed25519_public_key: hex_key(key),
                })
                .collect(),
        };
        let pin = caller_authorization_policy_sha256(&policy).unwrap();
        let nonce = "0x9999999999999999999999999999999999999999999999999999999999999999";
        let message =
            caller_authorization_signature_message(&self.request, &policy, &pin, nonce, 240, 275)
                .unwrap();
        let signatures = keys
            .iter()
            .enumerate()
            .map(|(index, key)| CallerSignature {
                authority_id: format!("caller-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let bytes =
            create_caller_authorization(&self.request, &policy, &pin, nonce, 240, 275, &signatures)
                .unwrap();
        let authorization = verify_caller_authorization_with_trusted_time(
            &bytes,
            &self.request,
            &policy,
            &pin,
            nonce,
            trusted,
        )
        .unwrap();
        (bytes, authorization)
    }

    fn execute<F>(
        &self,
        trusted_time: &VerifiedTrustedTime,
        callback: F,
    ) -> Result<
        bloch_local_state_remote_cursor_cas_session::VerifiedRemoteCursorCasSession,
        RemoteCursorCasSessionError<Infallible>,
    >
    where
        F: for<'a> FnOnce(
            AuthenticatedTransportRequest<'a>,
        ) -> Result<
            bloch_authenticated_transport_session::AuthenticatedTransportInput,
            TransportCallbackError<Infallible>,
        >,
    {
        let (authorization_bytes, authorization) = self.authorization(trusted_time);
        execute_remote_cursor_cas_session(
            &self.request,
            CasCallerAuthorization::Verified {
                canonical_authorization_bytes: &authorization_bytes,
                authorization: &authorization,
            },
            RemoteCursorCasSessionConfiguration {
                remote_cursor_policy: &self.remote_policy,
                expected_remote_cursor_policy_sha256: &self.remote_pin,
                transport_policy: &self.transport_policy,
                expected_transport_policy_sha256: &self.transport_pin,
                timeout: Duration::from_secs(1),
            },
            trusted_time,
            callback,
        )
    }
}

#[test]
fn exact_exchange_releases_only_verified_opaque_receipt() {
    let fixture = Fixture::new();
    let trusted = fixture.trusted_time();
    let receipt = fixture.receipt(RemoteCursorCasDecision::Accepted);
    let verified = fixture
        .execute(&trusted, |request| {
            let wire: serde_json::Value = serde_json::from_slice(request.request_bytes()).unwrap();
            assert_eq!(wire["requestSha256"], fixture.request.request_sha256());
            assert!(wire.get("callerAuthorization").is_some());
            let evidence = fixture.evidence(&request, request.request_bytes(), &receipt);
            collect(&request, &receipt, &evidence)
        })
        .unwrap();
    assert_eq!(verified.request_sha256(), fixture.request.request_sha256());
    assert_eq!(
        verified.receipt_sha256(),
        verified.receipt().receipt_sha256()
    );
    assert!(!verified.linearizability_proven());
}

#[test]
fn request_response_and_decision_substitution_fail_closed() {
    let fixture = Fixture::new();
    let receipt = fixture.receipt(RemoteCursorCasDecision::Accepted);
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence(&request, b"substituted request", &receipt);
        collect(&request, &receipt, &evidence)
    });
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Transport(_))
    ));

    let mut tampered: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    tampered["envelope"]["decision"] =
        serde_json::json!({"result":"refused","reasonCode":"conflict"});
    let tampered = serde_json::to_vec(&tampered).unwrap();
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence(&request, request.request_bytes(), &tampered);
        collect(&request, &tampered, &evidence)
    });
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Receipt(_))
    ));

    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let evidence = fixture.evidence(&request, request.request_bytes(), &receipt);
        collect(&request, b"{}", &evidence)
    });
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Transport(_))
    ));
}

#[test]
fn transport_evidence_replay_under_fresh_nonce_fails() {
    let fixture = Fixture::new();
    let receipt = fixture.receipt(RemoteCursorCasDecision::Accepted);
    let saved = RefCell::new(None);
    let trusted = fixture.trusted_time();
    fixture
        .execute(&trusted, |request| {
            let evidence = fixture.evidence(&request, request.request_bytes(), &receipt);
            *saved.borrow_mut() = Some(evidence.clone());
            collect(&request, &receipt, &evidence)
        })
        .unwrap();
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        collect(&request, &receipt, saved.borrow().as_ref().unwrap())
    });
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Transport(_))
    ));
}

#[test]
fn caller_authorization_bytes_require_exact_bound_capability() {
    let fixture = Fixture::new();
    let trusted = fixture.trusted_time();
    let keys = [
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    ];
    let policy = CallerAuthorizationPolicy {
        schema: CALLER_AUTH_POLICY_SCHEMA.into(),
        policy_id: "cas-caller-policy".into(),
        signature_domain: "bloch-products-cas-caller-v1".into(),
        state_identity: IDENTITY.into(),
        remote_cursor_policy_sha256: fixture.remote_pin.clone(),
        threshold: 2,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        max_authorization_age_seconds: 100,
        max_authorization_lifetime_seconds: 100,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| CallerAuthority {
                authority_id: format!("caller-{}", index + 1),
                ed25519_public_key: hex_key(key),
            })
            .collect(),
    };
    let pin = caller_authorization_policy_sha256(&policy).unwrap();
    let nonce = "0x9999999999999999999999999999999999999999999999999999999999999999";
    let message =
        caller_authorization_signature_message(&fixture.request, &policy, &pin, nonce, 240, 275)
            .unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| CallerSignature {
            authority_id: format!("caller-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let bytes = create_caller_authorization(
        &fixture.request,
        &policy,
        &pin,
        nonce,
        240,
        275,
        &signatures,
    )
    .unwrap();
    let authorization = verify_caller_authorization_with_trusted_time(
        &bytes,
        &fixture.request,
        &policy,
        &pin,
        nonce,
        &trusted,
    )
    .unwrap();

    let wire = canonical_cas_transport_request(
        &fixture.request,
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes: &bytes,
            authorization: &authorization,
        },
    )
    .unwrap();
    let wire: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        wire["callerAuthorization"]["authorizationSha256"],
        authorization.authorization_sha256()
    );

    let mut substituted = bytes;
    substituted.push(b'\n');
    let result = canonical_cas_transport_request(
        &fixture.request,
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes: &substituted,
            authorization: &authorization,
        },
    );
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::CallerAuthorizationMismatch)
    ));
}

#[test]
fn oversize_timeout_and_cross_policy_fail_closed() {
    let fixture = Fixture::new();
    let trusted = fixture.trusted_time();
    let result = fixture.execute(&trusted, |request| {
        let oversized = vec![b'x'; 128 * 1024 + 1];
        let evidence = fixture.evidence(&request, request.request_bytes(), b"unused");
        collect(&request, &oversized, &evidence)
    });
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Transport(_))
    ));

    let trusted = fixture.trusted_time();
    let (authorization_bytes, authorization) = fixture.authorization(&trusted);
    let result = execute_remote_cursor_cas_session(
        &fixture.request,
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes: &authorization_bytes,
            authorization: &authorization,
        },
        RemoteCursorCasSessionConfiguration {
            remote_cursor_policy: &fixture.remote_policy,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            transport_policy: &fixture.transport_policy,
            expected_transport_policy_sha256: &fixture.transport_pin,
            timeout: Duration::from_millis(1),
        },
        &trusted,
        |request| {
            let receipt = fixture.receipt(RemoteCursorCasDecision::Accepted);
            let evidence = fixture.evidence(&request, request.request_bytes(), &receipt);
            let mut slow = SlowReader;
            let mut evidence = SliceReader::new(&evidence);
            request
                .collect_exchange(&mut slow, &mut evidence)
                .map_err(TransportCallbackError::Ingress)
        },
    );
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::Transport(_))
    ));

    let trusted = fixture.trusted_time();
    let mut wrong = fixture.transport_policy.clone();
    wrong.remote_cursor_policy_sha256 =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let wrong_pin = authenticated_transport_policy_sha256(&wrong).unwrap();
    let called = RefCell::new(false);
    let (authorization_bytes, authorization) = fixture.authorization(&trusted);
    let result = execute_remote_cursor_cas_session::<Infallible, _>(
        &fixture.request,
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes: &authorization_bytes,
            authorization: &authorization,
        },
        RemoteCursorCasSessionConfiguration {
            remote_cursor_policy: &fixture.remote_policy,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            transport_policy: &wrong,
            expected_transport_policy_sha256: &wrong_pin,
            timeout: Duration::from_secs(1),
        },
        &trusted,
        |_| {
            *called.borrow_mut() = true;
            unreachable!()
        },
    );
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::AudienceMismatch)
    ));
    assert!(!*called.borrow());

    let mut wrong_remote = fixture.remote_policy.clone();
    wrong_remote.policy_id = "substituted-remote-policy".into();
    let called = RefCell::new(false);
    let result = execute_remote_cursor_cas_session::<Infallible, _>(
        &fixture.request,
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes: &authorization_bytes,
            authorization: &authorization,
        },
        RemoteCursorCasSessionConfiguration {
            remote_cursor_policy: &wrong_remote,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            transport_policy: &fixture.transport_policy,
            expected_transport_policy_sha256: &fixture.transport_pin,
            timeout: Duration::from_secs(1),
        },
        &trusted,
        |_| {
            *called.borrow_mut() = true;
            unreachable!()
        },
    );
    assert!(matches!(
        result,
        Err(RemoteCursorCasSessionError::AudienceMismatch)
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

fn authorities(prefix: &str, keys: &[SigningKey]) -> Vec<RemoteCursorAuthority> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorAuthority {
            authority_id: format!("{prefix}-{}", index + 1),
            ed25519_public_key: hex_key(key),
        })
        .collect()
}

fn cursor_for(root: &StateRoot, marker: u8) -> CheckpointCursor {
    let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
    let root_digest = hash(&root.canonical_bytes().unwrap());
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        root.state_identity(),
        root.generation(),
        digest(marker),
        digest(marker + 1),
        digest(marker + 2),
        root_digest,
        root.state_sha256()
    );
    parse_cursor(bytes.as_bytes()).unwrap()
}

fn hex_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().as_bytes()))
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
