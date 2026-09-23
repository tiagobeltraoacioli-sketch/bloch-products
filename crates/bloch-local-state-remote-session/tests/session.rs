use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorError, RemoteCursorPolicy,
    RemoteCursorSignature, create_remote_cursor_observation, remote_cursor_policy_bytes,
    remote_cursor_policy_sha256, remote_cursor_signature_message,
};
use bloch_local_state_remote_session::{
    FetchSessionError, RemoteCursorFetchRequest, fetch_verified_remote_cursor,
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
