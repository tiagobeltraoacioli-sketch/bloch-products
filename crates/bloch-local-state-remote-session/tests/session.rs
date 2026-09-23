use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorError, RemoteCursorPolicy,
    RemoteCursorSignature, create_remote_cursor_observation, remote_cursor_policy_bytes,
    remote_cursor_policy_sha256, remote_cursor_signature_message,
};
use bloch_local_state_remote_session::{
    BoundedIngressError, FetchSessionError, MAX_INGRESS_READ_CHUNK_BYTES, RemoteCursorFetchRequest,
    fetch_verified_remote_cursor, fetch_verified_remote_cursor_with_trusted_time,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    create_trusted_time_token, trusted_time_policy_sha256, trusted_time_signature_message,
    verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::Cell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Fixture {
    cursor: CheckpointCursor,
    policy: RemoteCursorPolicy,
    policy_bytes: Vec<u8>,
    policy_pin: String,
    keys: Vec<SigningKey>,
    now: u64,
}

impl Fixture {
    fn new(max_age: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let digest = |byte: &str| byte.repeat(64);
        let cursor = parse_cursor(
            format!(
                "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"data:tenant-a:lifecycle\",\"generation\":0,\"checkpointSha256\":\"0x{}\",\"checkpointPolicySha256\":\"0x{}\",\"semanticManifestSha256\":\"0x{}\",\"stateRootSha256\":\"0x{}\",\"stateSha256\":\"0x{}\"}}",
                digest("1"), digest("2"), digest("3"), digest("4"), digest("5")
            )
            .as_bytes(),
        )
        .unwrap();
        let keys = vec![
            SigningKey::from_bytes(&[81; 32]),
            SigningKey::from_bytes(&[82; 32]),
        ];
        let policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "fetch-session-policy".into(),
            signature_domain: "bloch-products-fetch-session".into(),
            state_identity: cursor.state_identity().into(),
            threshold: 2,
            effective_at_unix_seconds: now - 1_000,
            expires_at_unix_seconds: now + 1_000,
            max_observation_age_seconds: max_age,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let policy_pin = remote_cursor_policy_sha256(&policy).unwrap();
        let policy_bytes = remote_cursor_policy_bytes(&policy).unwrap();
        Self {
            cursor,
            policy,
            policy_bytes,
            policy_pin,
            keys,
            now,
        }
    }

    fn observation(&self, nonce: &str, observed_at: u64) -> Vec<u8> {
        let message = remote_cursor_signature_message(
            &self.cursor,
            &self.policy,
            &self.policy_pin,
            nonce,
            observed_at,
        )
        .unwrap();
        let signatures = self
            .keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_remote_cursor_observation(
            &self.cursor,
            &self.policy,
            &self.policy_pin,
            nonce,
            observed_at,
            &signatures,
        )
        .unwrap()
    }

    fn fetch<F>(
        &self,
        transport: F,
    ) -> Result<
        bloch_local_state_remote_cursor::VerifiedRemoteCursor,
        FetchSessionError<std::io::Error>,
    >
    where
        F: for<'session> FnOnce(
            RemoteCursorFetchRequest<'session>,
        ) -> Result<Vec<u8>, std::io::Error>,
    {
        fetch_verified_remote_cursor(
            &self.policy_bytes,
            &self.policy_pin,
            self.cursor.state_identity(),
            Duration::from_secs(1),
            transport,
        )
    }
}

#[test]
fn returns_only_a_current_verified_cursor() {
    let fixture = Fixture::new(30);
    let verified = fixture
        .fetch(|request| {
            assert_eq!(
                request.expected_state_identity(),
                fixture.cursor.state_identity()
            );
            assert_eq!(request.request_nonce().len(), 64);
            assert!(request.deadline() > std::time::Instant::now());
            Ok(fixture.observation(request.request_nonce(), fixture.now))
        })
        .unwrap();
    assert_eq!(verified.cursor(), &fixture.cursor);
    assert!(!verified.remote_monotonicity_proven());
}

#[test]
fn trusted_time_capability_drives_freshness_without_an_operator_time_argument() {
    let fixture = Fixture::new(30);
    let keys = [
        SigningKey::from_bytes(&[101; 32]),
        SigningKey::from_bytes(&[102; 32]),
    ];
    let policy = TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: "session-trusted-time".into(),
        signature_domain: "bloch-products-session-trusted-time".into(),
        state_identity: fixture.cursor.state_identity().into(),
        remote_cursor_policy_sha256: fixture.policy_pin.clone(),
        threshold: 2,
        effective_at_unix_seconds: fixture.now - 60,
        expires_at_unix_seconds: fixture.now + 60,
        max_token_lifetime_seconds: 30,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeAuthority {
                authority_id: format!("time-authority-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let pin = trusted_time_policy_sha256(&policy).unwrap();
    let time_nonce = "trusted_time_session_nonce_0123456789abcdef0123456789abcdef";
    let message =
        trusted_time_signature_message(&policy, &pin, time_nonce, fixture.now, fixture.now + 30)
            .unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let token = create_trusted_time_token(
        &policy,
        &pin,
        time_nonce,
        fixture.now,
        fixture.now + 30,
        &signatures,
    )
    .unwrap();
    let trusted_time = verify_trusted_time_token(&token, &policy, &pin, time_nonce, None).unwrap();

    let verified = fetch_verified_remote_cursor_with_trusted_time(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        &trusted_time,
        &pin,
        |request| {
            Ok::<_, std::io::Error>(fixture.observation(request.request_nonce(), fixture.now))
        },
    )
    .unwrap();
    assert_eq!(verified.cursor(), &fixture.cursor);

    let called = Cell::new(false);
    let wrong_pin = format!("0x{}", "00".repeat(32));
    let cross_policy = fetch_verified_remote_cursor_with_trusted_time(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        &trusted_time,
        &wrong_pin,
        |_request| {
            called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        cross_policy,
        Err(FetchSessionError::TrustedTimeContextMismatch)
    ));
    assert!(!called.get());

    let mut other_policy = policy.clone();
    other_policy.state_identity = "pay:merchant-a:adjustment-1".into();
    let other_pin = trusted_time_policy_sha256(&other_policy).unwrap();
    let other_message = trusted_time_signature_message(
        &other_policy,
        &other_pin,
        time_nonce,
        fixture.now,
        fixture.now + 30,
    )
    .unwrap();
    let other_signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&other_message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let other_token = create_trusted_time_token(
        &other_policy,
        &other_pin,
        time_nonce,
        fixture.now,
        fixture.now + 30,
        &other_signatures,
    )
    .unwrap();
    let other_time =
        verify_trusted_time_token(&other_token, &other_policy, &other_pin, time_nonce, None)
            .unwrap();
    let cross_audience = fetch_verified_remote_cursor_with_trusted_time(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        &other_time,
        &other_pin,
        |_request| {
            called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        cross_audience,
        Err(FetchSessionError::TrustedTimeContextMismatch)
    ));
    assert!(!called.get());
}

#[test]
fn timeout_is_rejected_using_monotonic_deadline() {
    let fixture = Fixture::new(30);
    let result = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_millis(5),
        |request| {
            let response = fixture.observation(request.request_nonce(), fixture.now);
            std::thread::sleep(Duration::from_millis(20));
            Ok::<_, std::io::Error>(response)
        },
    );
    assert!(matches!(result, Err(FetchSessionError::DeadlineExceeded)));
}

#[test]
fn replayed_response_fails_against_the_new_in_memory_nonce() {
    let fixture = Fixture::new(30);
    let mut retained = Vec::new();
    fixture
        .fetch(|request| {
            retained = fixture.observation(request.request_nonce(), fixture.now);
            Ok(retained.clone())
        })
        .unwrap();
    let result = fixture.fetch(|_request| Ok(retained));
    assert!(matches!(
        result,
        Err(FetchSessionError::Authentication(
            RemoteCursorError::NonceMismatch
        ))
    ));
}

#[test]
fn stale_and_future_observations_fail_against_current_system_time() {
    let fixture = Fixture::new(10);
    let stale =
        fixture.fetch(|request| Ok(fixture.observation(request.request_nonce(), fixture.now - 20)));
    assert!(matches!(
        stale,
        Err(FetchSessionError::Authentication(
            RemoteCursorError::OutsideFreshnessWindow
        ))
    ));
    let future =
        fixture.fetch(|request| Ok(fixture.observation(request.request_nonce(), fixture.now + 20)));
    assert!(matches!(
        future,
        Err(FetchSessionError::Authentication(
            RemoteCursorError::OutsideFreshnessWindow
        ))
    ));
}

#[test]
fn cross_identity_is_rejected_before_transport() {
    let fixture = Fixture::new(30);
    let called = Cell::new(false);
    let result = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        "pay:merchant-a:adjustment-1",
        Duration::from_secs(1),
        |_request| {
            called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        result,
        Err(FetchSessionError::InvalidConfiguration)
    ));
    assert!(!called.get());
}

#[test]
fn oversized_response_and_zero_timeout_fail_before_authentication() {
    let fixture = Fixture::new(30);
    let oversized = fixture.fetch(|request| Ok(vec![0_u8; request.maximum_response_bytes() + 1]));
    assert!(matches!(
        oversized,
        Err(FetchSessionError::ResponseTooLarge)
    ));

    let called = Cell::new(false);
    let invalid = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::ZERO,
        |_request| {
            called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        invalid,
        Err(FetchSessionError::InvalidConfiguration)
    ));
    assert!(!called.get());
}

#[test]
fn bounded_ingress_incrementally_reads_a_valid_authenticated_response() {
    let fixture = Fixture::new(30);
    let largest_requested = Cell::new(0_usize);
    let result = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        |request| {
            let response = fixture.observation(request.request_nonce(), fixture.now);
            let mut offset = 0_usize;
            let expected_deadline = request.deadline();
            let mut ingress = |buffer: &mut [u8], deadline| {
                assert_eq!(deadline, expected_deadline);
                largest_requested.set(largest_requested.get().max(buffer.len()));
                let available = response.len() - offset;
                let copied = available.min(buffer.len()).min(17);
                buffer[..copied].copy_from_slice(&response[offset..offset + copied]);
                offset += copied;
                Ok::<_, std::io::Error>(copied)
            };
            request.read_bounded_response(&mut ingress)
        },
    )
    .unwrap();

    assert_eq!(result.cursor(), &fixture.cursor);
    assert!(largest_requested.get() <= MAX_INGRESS_READ_CHUNK_BYTES);
}

#[test]
fn bounded_ingress_detects_an_unbounded_virtual_stream_without_growing_past_limit() {
    let fixture = Fixture::new(30);
    let bytes_returned = Cell::new(0_usize);
    let largest_requested = Cell::new(0_usize);
    let result = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        |request| {
            let limit = request.maximum_response_bytes();
            let mut ingress = |buffer: &mut [u8], _deadline| {
                largest_requested.set(largest_requested.get().max(buffer.len()));
                buffer.fill(0x5a);
                bytes_returned.set(bytes_returned.get() + buffer.len());
                Ok::<_, std::io::Error>(buffer.len())
            };
            let result = request.read_bounded_response(&mut ingress);
            assert_eq!(bytes_returned.get(), limit + 1);
            result
        },
    );

    assert!(matches!(
        result,
        Err(FetchSessionError::Transport(
            BoundedIngressError::ResponseTooLarge
        ))
    ));
    assert_eq!(largest_requested.get(), MAX_INGRESS_READ_CHUNK_BYTES);

    let exact_limit = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        |request| {
            let limit = request.maximum_response_bytes();
            let mut emitted = 0_usize;
            let mut ingress = |buffer: &mut [u8], _deadline| {
                let copied = (limit - emitted).min(buffer.len());
                buffer[..copied].fill(0x5a);
                emitted += copied;
                Ok::<_, std::io::Error>(copied)
            };
            request.read_bounded_response(&mut ingress)
        },
    );
    assert!(matches!(
        exact_limit,
        Err(FetchSessionError::Authentication(_))
    ));
}

#[test]
fn bounded_ingress_rejects_a_reader_that_returns_after_the_deadline() {
    let fixture = Fixture::new(30);
    let result = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_millis(5),
        |request| {
            let mut ingress = |buffer: &mut [u8], _deadline| {
                std::thread::sleep(Duration::from_millis(20));
                buffer[0] = b'{';
                Ok::<_, std::io::Error>(1)
            };
            request.read_bounded_response(&mut ingress)
        },
    );

    assert!(matches!(
        result,
        Err(FetchSessionError::Transport(
            BoundedIngressError::DeadlineExceeded
        ))
    ));

    let late_error = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_millis(5),
        |request| {
            let mut ingress = |_buffer: &mut [u8], _deadline| {
                std::thread::sleep(Duration::from_millis(20));
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "late transport timeout",
                ))
            };
            request.read_bounded_response(&mut ingress)
        },
    );
    assert!(matches!(
        late_error,
        Err(FetchSessionError::Transport(
            BoundedIngressError::DeadlineExceeded
        ))
    ));
}

#[test]
fn bounded_ingress_rejects_empty_and_contract_violating_readers() {
    let fixture = Fixture::new(30);
    let empty = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        |request| {
            let mut ingress = |_buffer: &mut [u8], _deadline| Ok::<_, std::io::Error>(0);
            request.read_bounded_response(&mut ingress)
        },
    );
    assert!(matches!(
        empty,
        Err(FetchSessionError::Transport(
            BoundedIngressError::EmptyResponse
        ))
    ));

    let invalid_count = fetch_verified_remote_cursor(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        fixture.cursor.state_identity(),
        Duration::from_secs(1),
        |request| {
            let mut ingress =
                |buffer: &mut [u8], _deadline| Ok::<_, std::io::Error>(buffer.len() + 1);
            request.read_bounded_response(&mut ingress)
        },
    );
    assert!(matches!(
        invalid_count,
        Err(FetchSessionError::Transport(
            BoundedIngressError::InvalidReadCount
        ))
    ));
}
