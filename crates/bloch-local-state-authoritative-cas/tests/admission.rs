use bloch_local_state_authoritative_cas::{
    AuthoritativeCasConfiguration, AuthoritativeCasError, AuthoritativeCasInput,
    ExecuteAuthoritativeCasError, execute_authoritative_cas,
};
use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasRequestParameters,
    RemoteCursorPolicy, ValidatedRemoteCursorCasRequest, create_remote_cursor_cas_request,
    parse_remote_cursor_cas_request, remote_cursor_policy_sha256,
};
use bloch_local_state_remote_cursor_caller_auth::{
    CALLER_AUTH_POLICY_SCHEMA, CallerAuthority, CallerAuthorizationPolicy, CallerSignature,
    ReplayProtectedRemoteCursorCasCallerAuthorization, bind_consumed_challenge,
    caller_authorization_policy_sha256, caller_authorization_signature_message,
    create_caller_authorization, verify_caller_authorization_with_trusted_time,
};
use bloch_local_state_remote_cursor_challenge_store::{
    ChallengeAudience, consume_challenge, issue_challenge, provision_challenge_store,
};
use bloch_local_state_store::{StateRoot, write_state};
use bloch_local_state_writer_epoch_floor_store::{
    WriterEpochFloor, WriterEpochFloorAudience, provision_writer_epoch_floor_store,
};
use bloch_local_state_writer_fencing::{
    FencingAuthority, FencingSignature, WRITER_FENCING_POLICY_SCHEMA, WriterFencingPolicy,
    WriterLeaseParameters, create_writer_fencing_certificate, verify_successor_writer_lease,
    writer_fencing_policy_sha256, writer_fencing_signature_message,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STATE: &str = "data:tenant-a:lifecycle";
const CAS_SERVICE: &str = "remote-cursor-cas-primary";
const CAS_POLICY: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const TIME_NONCE: &str = "time_nonce_0123456789abcdef0123456789abcdef";
const REQUEST_NONCE: &str = "cas_nonce_0123456789abcdef0123456789abcdef";
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    path: std::path::PathBuf,
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    caller_pin: String,
    writer_pin: String,
    request: ValidatedRemoteCursorCasRequest,
    authorization: RefCell<Option<ReplayProtectedRemoteCursorCasCallerAuthorization>>,
    lease: bloch_local_state_writer_fencing::VerifiedWriterLease,
    floor: WriterEpochFloor,
    successor_root: StateRoot,
    successor_cursor: CheckpointCursor,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).expect("remove fixture");
    }
}

impl Fixture {
    fn new() -> Self {
        Self::with_epochs(7, 8)
    }

    fn with_epochs(floor_epoch: u64, writer_epoch: u64) -> Self {
        let path = fixture_path();
        let current_root = write_state(&path, STATE, 0, b"zero", None).expect("current root");
        let successor_root =
            write_state(&path, STATE, 1, b"one", Some(&current_root)).expect("successor root");
        let current_cursor = cursor_for(&current_root, 10);
        let successor_cursor = cursor_for(&successor_root, 20);

        let remote_keys = keys(&[11, 12, 13]);
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-policy".into(),
            signature_domain: "remote-cursor-production".into(),
            state_identity: STATE.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_observation_age_seconds: 60,
            authorities: remote_keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("remote-{}", index + 1),
                    ed25519_public_key: public_key(key),
                })
                .collect(),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).expect("remote pin");
        let trusted_time = trusted_time(&remote_pin);

        let request_bytes = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(&current_cursor),
                successor_cursor: &successor_cursor,
                successor_root: &successor_root,
                request_id: "request-1",
                request_nonce: REQUEST_NONCE,
                requested_at_unix_seconds: 200,
            },
            &remote_policy,
            &remote_pin,
        )
        .expect("request");
        let request = parse_remote_cursor_cas_request(&request_bytes, &remote_policy, &remote_pin)
            .expect("validated request");

        let caller_keys = keys(&[21, 22, 23]);
        let caller_policy = CallerAuthorizationPolicy {
            schema: CALLER_AUTH_POLICY_SCHEMA.into(),
            policy_id: "caller-policy".into(),
            signature_domain: "cas-callers-production".into(),
            state_identity: STATE.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_authorization_age_seconds: 60,
            max_authorization_lifetime_seconds: 60,
            authorities: caller_keys
                .iter()
                .enumerate()
                .map(|(index, key)| CallerAuthority {
                    authority_id: format!("caller-{}", index + 1),
                    ed25519_public_key: public_key(key),
                })
                .collect(),
        };
        let caller_pin = caller_authorization_policy_sha256(&caller_policy).expect("caller pin");
        let challenge_path = path.join("caller-challenges");
        provision_challenge_store(&challenge_path).expect("challenge store");
        let challenge_audience = ChallengeAudience {
            caller_policy_sha256: &caller_pin,
            remote_cursor_policy_sha256: &remote_pin,
            state_identity: STATE,
        };
        let issued = issue_challenge(&challenge_path, challenge_audience, Duration::from_secs(30))
            .expect("issued challenge");
        let authorization_nonce = issued.nonce().to_owned();
        let auth_message = caller_authorization_signature_message(
            &request,
            &caller_policy,
            &caller_pin,
            &authorization_nonce,
            195,
            240,
        )
        .expect("authorization message");
        let auth_signatures = caller_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| CallerSignature {
                authority_id: format!("caller-{}", index + 1),
                signature: signature(key, &auth_message),
            })
            .collect::<Vec<_>>();
        let authorization_bytes = create_caller_authorization(
            &request,
            &caller_policy,
            &caller_pin,
            &authorization_nonce,
            195,
            240,
            &auth_signatures,
        )
        .expect("authorization");
        let authorization = verify_caller_authorization_with_trusted_time(
            &authorization_bytes,
            &request,
            &caller_policy,
            &caller_pin,
            &authorization_nonce,
            &trusted_time,
        )
        .expect("verified authorization");
        let consumed = consume_challenge(
            &challenge_path,
            challenge_audience,
            issued,
            &authorization_nonce,
        )
        .expect("consumed challenge");
        let authorization =
            bind_consumed_challenge(authorization, consumed).expect("replay-protected auth");

        let writer_keys = keys(&[31, 32, 33]);
        let writer_policy = WriterFencingPolicy {
            schema: WRITER_FENCING_POLICY_SCHEMA.into(),
            policy_id: "writer-policy".into(),
            signature_domain: "cas-writers-production".into(),
            state_identity: STATE.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            cas_service_id: CAS_SERVICE.into(),
            cas_policy_sha256: CAS_POLICY.into(),
            trusted_time_policy_sha256: trusted_time.trusted_time_policy_sha256().into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_lease_lifetime_seconds: 60,
            authorities: writer_keys
                .iter()
                .enumerate()
                .map(|(index, key)| FencingAuthority {
                    authority_id: format!("writer-{}", index + 1),
                    ed25519_public_key: public_key(key),
                })
                .collect(),
        };
        let writer_pin = writer_fencing_policy_sha256(&writer_policy).expect("writer pin");
        let make_certificate = |epoch| {
            let parameters = WriterLeaseParameters {
                writer_id: "writer-primary",
                epoch,
                effective_at_unix_seconds: 190,
                expires_at_unix_seconds: 240,
            };
            let message = writer_fencing_signature_message(&writer_policy, &writer_pin, parameters)
                .expect("lease message");
            let signatures = writer_keys
                .iter()
                .take(2)
                .enumerate()
                .map(|(index, key)| FencingSignature {
                    authority_id: format!("writer-{}", index + 1),
                    signature: signature(key, &message),
                })
                .collect();
            create_writer_fencing_certificate(&writer_policy, &writer_pin, parameters, signatures)
                .expect("certificate")
        };
        let floor_certificate = make_certificate(floor_epoch);
        let floor_lease = verify_successor_writer_lease(
            &floor_certificate,
            &writer_policy,
            &writer_pin,
            floor_epoch - 1,
            &trusted_time,
        )
        .expect("verified floor lease");
        let floor_audience = WriterEpochFloorAudience {
            writer_fencing_policy_sha256: &writer_pin,
            state_identity: STATE,
            remote_cursor_policy_sha256: &remote_pin,
            cas_service_id: CAS_SERVICE,
            cas_policy_sha256: CAS_POLICY,
        };
        let floor = provision_writer_epoch_floor_store(
            &path.join("writer-epoch-floor"),
            floor_audience,
            &floor_lease,
        )
        .expect("writer epoch floor");
        let certificate = make_certificate(writer_epoch);
        let lease = verify_successor_writer_lease(
            &certificate,
            &writer_policy,
            &writer_pin,
            writer_epoch - 1,
            &trusted_time,
        )
        .expect("verified lease");
        Self {
            path,
            remote_policy,
            remote_pin,
            caller_pin,
            writer_pin,
            request,
            authorization: RefCell::new(Some(authorization)),
            lease,
            floor,
            successor_root,
            successor_cursor,
        }
    }

    fn configuration(&self) -> AuthoritativeCasConfiguration<'_> {
        AuthoritativeCasConfiguration {
            state_identity: STATE,
            remote_cursor_policy_sha256: &self.remote_pin,
            caller_policy_sha256: &self.caller_pin,
            writer_fencing_policy_sha256: &self.writer_pin,
            cas_service_id: CAS_SERVICE,
            cas_policy_sha256: CAS_POLICY,
            expected_writer_id: "writer-primary",
        }
    }

    fn input(&self) -> AuthoritativeCasInput<'_> {
        AuthoritativeCasInput {
            request: &self.request,
            caller_authorization: self
                .authorization
                .borrow_mut()
                .take()
                .expect("unused authorization"),
            writer_lease: &self.lease,
            external_epoch_floor: &self.floor,
        }
    }
}

#[test]
fn admits_exact_request_authorization_lease_and_floor_once() {
    let fixture = Fixture::new();
    let calls = AtomicU64::new(0);
    let operation_digest = execute_authoritative_cas(
        fixture.configuration(),
        fixture.input(),
        |operation| -> Result<String, ()> {
            calls.fetch_add(1, Ordering::SeqCst);
            operation
                .ensure_freshness()
                .expect("fresh at commit boundary");
            assert_eq!(operation.request_sha256(), fixture.request.request_sha256());
            assert_eq!(operation.writer_id(), "writer-primary");
            assert_eq!(operation.writer_epoch(), 8);
            assert_eq!(operation.external_epoch_floor(), fixture.floor.epoch());
            assert_eq!(
                operation.external_epoch_floor_source_id(),
                fixture.floor.store_id()
            );
            assert_eq!(
                operation.external_epoch_floor_evidence_sha256(),
                fixture.floor.evidence_sha256()
            );
            assert!(!operation.consensus_proven());
            assert!(!operation.linearizability_proven());
            assert!(!operation.floor_persistence_proven());
            Ok(operation.operation_sha256().into())
        },
    )
    .expect("admitted callback");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(operation_digest.starts_with("0x"));
    assert_eq!(operation_digest.len(), 66);
}

#[test]
fn wrong_audience_pins_writer_and_service_never_reach_callback() {
    let bad_digest = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for variant in 0..7 {
        let fixture = Fixture::new();
        let mut configuration = fixture.configuration();
        match variant {
            0 => configuration.state_identity = "pay:merchant-a:adjustment",
            1 => configuration.remote_cursor_policy_sha256 = bad_digest,
            2 => configuration.caller_policy_sha256 = bad_digest,
            3 => configuration.writer_fencing_policy_sha256 = bad_digest,
            4 => configuration.cas_service_id = "other-cas",
            5 => configuration.cas_policy_sha256 = bad_digest,
            6 => configuration.expected_writer_id = "writer-secondary",
            _ => unreachable!(),
        }
        assert_refused_without_callback(
            configuration,
            fixture.input(),
            AuthoritativeCasError::AudienceMismatch,
        );
    }
}

#[test]
fn equal_or_higher_epoch_floor_never_reaches_callback() {
    for floor in [8, 9, u64::MAX] {
        let fixture = Fixture::with_epochs(floor, 8);
        assert_refused_without_callback(
            fixture.configuration(),
            fixture.input(),
            AuthoritativeCasError::EpochRollback,
        );
    }
}

#[test]
fn substituted_caller_authorization_never_reaches_callback() {
    let fixture = Fixture::new();
    let second_request_bytes = create_remote_cursor_cas_request(
        RemoteCursorCasRequestParameters {
            expected_current: Some(fixture.request.expected_current().expect("current")),
            successor_cursor: &fixture.successor_cursor,
            successor_root: &fixture.successor_root,
            request_id: "request-2",
            request_nonce: REQUEST_NONCE,
            requested_at_unix_seconds: 200,
        },
        &fixture.remote_policy,
        &fixture.remote_pin,
    )
    .expect("second request");
    let second_request = parse_remote_cursor_cas_request(
        &second_request_bytes,
        &fixture.remote_policy,
        &fixture.remote_pin,
    )
    .expect("second parsed request");
    let substituted_input = AuthoritativeCasInput {
        request: &second_request,
        ..fixture.input()
    };
    assert_refused_without_callback(
        fixture.configuration(),
        substituted_input,
        AuthoritativeCasError::CallerAuthorizationMismatch,
    );
}

#[test]
fn invalid_configuration_fails_before_callback() {
    let fixture = Fixture::new();
    assert_refused_without_callback(
        AuthoritativeCasConfiguration {
            cas_policy_sha256: "not-a-digest",
            ..fixture.configuration()
        },
        fixture.input(),
        AuthoritativeCasError::InvalidConfiguration,
    );
}

#[test]
fn callback_failure_is_distinct_and_not_retried() {
    let fixture = Fixture::new();
    let calls = AtomicU64::new(0);
    let result = execute_authoritative_cas(fixture.configuration(), fixture.input(), |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>("adapter-failed")
    });
    assert_eq!(
        result,
        Err(ExecuteAuthoritativeCasError::Callback("adapter-failed"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn assert_refused_without_callback(
    configuration: AuthoritativeCasConfiguration<'_>,
    input: AuthoritativeCasInput<'_>,
    expected: AuthoritativeCasError,
) {
    let called = AtomicBool::new(false);
    let result = execute_authoritative_cas(configuration, input, |_| {
        called.store(true, Ordering::SeqCst);
        Ok::<(), ()>(())
    });
    assert_eq!(
        result,
        Err(ExecuteAuthoritativeCasError::Admission(expected))
    );
    assert!(!called.load(Ordering::SeqCst));
}

fn trusted_time(remote_pin: &str) -> VerifiedTrustedTime {
    let time_keys = keys(&[41, 42, 43]);
    let policy = TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: "time-policy".into(),
        signature_domain: "trusted-time-production".into(),
        state_identity: STATE.into(),
        remote_cursor_policy_sha256: remote_pin.into(),
        threshold: 2,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        max_token_lifetime_seconds: 60,
        authorities: time_keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeAuthority {
                authority_id: format!("time-{}", index + 1),
                ed25519_public_key: public_key(key),
            })
            .collect(),
    };
    let pin = trusted_time_policy_sha256(&policy).expect("time pin");
    let message =
        trusted_time_signature_message(&policy, &pin, TIME_NONCE, 200, 240).expect("time message");
    let signatures = time_keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-{}", index + 1),
            signature: signature(key, &message),
        })
        .collect::<Vec<_>>();
    let token = create_trusted_time_token(&policy, &pin, TIME_NONCE, 200, 240, &signatures)
        .expect("time token");
    verify_trusted_time_token(&token, &policy, &pin, TIME_NONCE, None).expect("verified time")
}

fn fixture_path() -> std::path::PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-authoritative-cas-{}-{now}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn cursor_for(root: &StateRoot, marker: u8) -> CheckpointCursor {
    let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
    let root_sha = sha256(&root.canonical_bytes().expect("root bytes"));
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        root.state_identity(),
        root.generation(),
        digest(marker),
        digest(marker + 1),
        digest(marker + 2),
        root_sha,
        root.state_sha256()
    );
    parse_cursor(bytes.as_bytes()).expect("cursor")
}

fn keys(seeds: &[u8]) -> Vec<SigningKey> {
    seeds
        .iter()
        .map(|seed| SigningKey::from_bytes(&[*seed; 32]))
        .collect()
}

fn public_key(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
}

fn signature(key: &SigningKey, message: &[u8]) -> String {
    format!("0x{}", hex::encode(key.sign(message).to_bytes()))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
