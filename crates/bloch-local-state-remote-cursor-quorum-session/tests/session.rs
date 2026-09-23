use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    create_remote_cursor_observation, remote_cursor_policy_bytes, remote_cursor_policy_sha256,
    remote_cursor_signature_message,
};
use bloch_local_state_remote_cursor_quorum_session::{
    QuorumCollectionError, QuorumCollectionLimits, QuorumCollectionMaterials,
    ReplicaSessionFailure, collect_verified_replica_quorum,
};
use bloch_local_state_remote_cursor_replica_quorum::{
    REPLICA_QUORUM_POLICY_SCHEMA, ReplicaDescriptor, ReplicaQuorumPolicy,
    replica_quorum_policy_bytes, replica_quorum_policy_sha256,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::time::Duration;

struct Fixture {
    cursor: CheckpointCursor,
    remote_policy: RemoteCursorPolicy,
    remote_policy_bytes: Vec<u8>,
    remote_pin: String,
    replica_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
    quorum_policy: ReplicaQuorumPolicy,
    quorum_policy_bytes: Vec<u8>,
    quorum_pin: String,
}

fn digest(marker: u8) -> String {
    format!("0x{}", format!("{marker:02x}").repeat(32))
}

impl Fixture {
    fn new() -> Self {
        let state_identity = "data:tenant-a:lifecycle";
        let cursor = parse_cursor(
            format!(
                "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{state_identity}\",\"generation\":7,\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                digest(5),
            )
            .as_bytes(),
        )
        .unwrap();
        let replica_keys = vec![
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[32; 32]),
            SigningKey::from_bytes(&[33; 32]),
        ];
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "quorum-collection-remote".into(),
            signature_domain: "quorum-collection-remote-domain".into(),
            state_identity: state_identity.into(),
            threshold: 1,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_observation_age_seconds: 60,
            authorities: replica_keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("replica-{}-signer", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let remote_policy_bytes = remote_cursor_policy_bytes(&remote_policy).unwrap();
        let time_keys = vec![
            SigningKey::from_bytes(&[61; 32]),
            SigningKey::from_bytes(&[62; 32]),
        ];
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "quorum-collection-time".into(),
            signature_domain: "quorum-collection-time-domain".into(),
            state_identity: state_identity.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_token_lifetime_seconds: 60,
            authorities: time_keys
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
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let quorum_policy = ReplicaQuorumPolicy {
            schema: REPLICA_QUORUM_POLICY_SCHEMA.into(),
            policy_id: "quorum-collection".into(),
            state_identity: state_identity.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            trusted_time_policy_sha256: time_pin.clone(),
            quorum: 2,
            max_observation_age_seconds: 30,
            max_observation_skew_seconds: 5,
            replicas: (1..=3)
                .map(|index| ReplicaDescriptor {
                    replica_id: format!("replica-{index}"),
                    provenance_id: format!("failure-domain-{index}"),
                    signer_authority_ids: vec![format!("replica-{index}-signer")],
                })
                .collect(),
        };
        let quorum_pin = replica_quorum_policy_sha256(&quorum_policy).unwrap();
        let quorum_policy_bytes = replica_quorum_policy_bytes(&quorum_policy).unwrap();
        Self {
            cursor,
            remote_policy,
            remote_policy_bytes,
            remote_pin,
            replica_keys,
            time_policy,
            time_pin,
            time_keys,
            quorum_policy,
            quorum_policy_bytes,
            quorum_pin,
        }
    }

    fn trusted_time(&self) -> VerifiedTrustedTime {
        let nonce = "quorum_collection_time_nonce_0123456789abcdef0123456789abcdef";
        let message =
            trusted_time_signature_message(&self.time_policy, &self.time_pin, nonce, 200, 230)
                .unwrap();
        let signatures = self
            .time_keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let token = create_trusted_time_token(
            &self.time_policy,
            &self.time_pin,
            nonce,
            200,
            230,
            &signatures,
        )
        .unwrap();
        verify_trusted_time_token(&token, &self.time_policy, &self.time_pin, nonce, None).unwrap()
    }

    fn observation(&self, signer: usize, nonce: &str) -> Vec<u8> {
        let message = remote_cursor_signature_message(
            &self.cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            200,
        )
        .unwrap();
        let signature = RemoteCursorSignature {
            authority_id: format!("replica-{}-signer", signer + 1),
            signature: format!(
                "0x{}",
                hex::encode(self.replica_keys[signer].sign(&message).to_bytes())
            ),
        };
        create_remote_cursor_observation(
            &self.cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            200,
            &[signature],
        )
        .unwrap()
    }

    fn collect<E, F>(
        &self,
        trusted_time: &VerifiedTrustedTime,
        transport: F,
    ) -> Result<
        bloch_local_state_remote_cursor_replica_quorum::VerifiedReplicaQuorum,
        QuorumCollectionError<E>,
    >
    where
        E: std::fmt::Debug,
        F: for<'a> FnMut(
            bloch_local_state_remote_cursor_quorum_session::ReplicaFetchRequest<'a>,
        ) -> Result<Vec<u8>, E>,
    {
        collect_verified_replica_quorum(
            QuorumCollectionMaterials {
                remote_cursor_policy_bytes: &self.remote_policy_bytes,
                expected_remote_cursor_policy_sha256: &self.remote_pin,
                replica_quorum_policy_bytes: &self.quorum_policy_bytes,
                expected_replica_quorum_policy_sha256: &self.quorum_pin,
                expected_previous: None,
                trusted_time,
            },
            QuorumCollectionLimits {
                collection_timeout: Duration::from_secs(2),
                per_replica_timeout: Duration::from_millis(500),
            },
            transport,
        )
    }
}

#[test]
fn collects_every_replica_with_distinct_nonce_and_returns_only_quorum() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut requested = Vec::new();
    let mut nonces = BTreeSet::new();
    let report = fixture
        .collect(&time, |request| {
            assert_eq!(
                request.expected_state_identity(),
                fixture.cursor.state_identity()
            );
            assert!(request.deadline() > std::time::Instant::now());
            assert!(request.maximum_response_bytes() > 0);
            requested.push(request.replica_id().to_owned());
            assert!(nonces.insert(request.request_nonce().to_owned()));
            let signer = request
                .replica_id()
                .strip_prefix("replica-")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                - 1;
            Ok::<_, Infallible>(fixture.observation(signer, request.request_nonce()))
        })
        .unwrap();
    assert_eq!(requested, ["replica-1", "replica-2", "replica-3"]);
    assert_eq!(nonces.len(), 3);
    assert_eq!(report.cursor(), &fixture.cursor);
    assert_eq!(report.replica_ids().len(), 3);
    assert!(!report.consensus_proven());
    assert!(!report.linearizability_proven());
    assert!(!report.replica_independence_proven());
}

#[test]
fn refuses_response_signed_by_a_different_requested_replica() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let result = fixture.collect(&time, |request| {
        let requested = request
            .replica_id()
            .strip_prefix("replica-")
            .unwrap()
            .parse::<usize>()
            .unwrap()
            - 1;
        let substituted = if requested == 0 { 1 } else { requested };
        Ok::<_, Infallible>(fixture.observation(substituted, request.request_nonce()))
    });
    assert!(matches!(
        result,
        Err(QuorumCollectionError::ReplicaIdentityMismatch { replica_id })
            if replica_id == "replica-1"
    ));
}

#[test]
fn refuses_raw_response_replay_under_another_replica_nonce() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut first_response: Option<Vec<u8>> = None;
    let result = fixture.collect(&time, |request| {
        if let Some(response) = &first_response {
            return Ok::<_, Infallible>(response.clone());
        }
        let response = fixture.observation(0, request.request_nonce());
        first_response = Some(response.clone());
        Ok(response)
    });
    assert!(matches!(
        result,
        Err(QuorumCollectionError::ReplicaSession {
            replica_id,
            failure: ReplicaSessionFailure::Authentication,
        }) if replica_id == "replica-2"
    ));
}

#[test]
fn rejects_invalid_limits_before_any_transport_call() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut called = false;
    let result = collect_verified_replica_quorum(
        QuorumCollectionMaterials {
            remote_cursor_policy_bytes: &fixture.remote_policy_bytes,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            replica_quorum_policy_bytes: &fixture.quorum_policy_bytes,
            expected_replica_quorum_policy_sha256: &fixture.quorum_pin,
            expected_previous: None,
            trusted_time: &time,
        },
        QuorumCollectionLimits {
            collection_timeout: Duration::ZERO,
            per_replica_timeout: Duration::from_secs(1),
        },
        |_request| {
            called = true;
            Ok::<_, Infallible>(Vec::new())
        },
    );
    assert!(matches!(
        result,
        Err(QuorumCollectionError::InvalidConfiguration)
    ));
    assert!(!called);
}

#[test]
fn rejects_cross_pinned_remote_policy_before_collection() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut called = false;
    let result = collect_verified_replica_quorum(
        QuorumCollectionMaterials {
            remote_cursor_policy_bytes: &fixture.remote_policy_bytes,
            expected_remote_cursor_policy_sha256: &format!("0x{}", "00".repeat(32)),
            replica_quorum_policy_bytes: &fixture.quorum_policy_bytes,
            expected_replica_quorum_policy_sha256: &fixture.quorum_pin,
            expected_previous: None,
            trusted_time: &time,
        },
        QuorumCollectionLimits {
            collection_timeout: Duration::from_secs(1),
            per_replica_timeout: Duration::from_secs(1),
        },
        |_request| {
            called = true;
            Ok::<_, Infallible>(Vec::new())
        },
    );
    assert!(matches!(
        result,
        Err(QuorumCollectionError::InvalidConfiguration)
    ));
    assert!(!called);
    assert_eq!(fixture.quorum_policy.replicas.len(), 3);
}

#[test]
fn rejects_cross_pinned_trusted_time_before_any_transport_call() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut cross_policy = fixture.quorum_policy.clone();
    cross_policy.trusted_time_policy_sha256 = format!("0x{}", "aa".repeat(32));
    let cross_bytes = replica_quorum_policy_bytes(&cross_policy).unwrap();
    let cross_pin = replica_quorum_policy_sha256(&cross_policy).unwrap();
    let mut called = false;
    let result = collect_verified_replica_quorum(
        QuorumCollectionMaterials {
            remote_cursor_policy_bytes: &fixture.remote_policy_bytes,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            replica_quorum_policy_bytes: &cross_bytes,
            expected_replica_quorum_policy_sha256: &cross_pin,
            expected_previous: None,
            trusted_time: &time,
        },
        QuorumCollectionLimits {
            collection_timeout: Duration::from_secs(1),
            per_replica_timeout: Duration::from_secs(1),
        },
        |_request| {
            called = true;
            Ok::<_, Infallible>(Vec::new())
        },
    );
    assert!(matches!(
        result,
        Err(QuorumCollectionError::ReplicaSession {
            replica_id,
            failure: ReplicaSessionFailure::TrustedTimeContextMismatch,
        }) if replica_id == "replica-1"
    ));
    assert!(!called);
}

#[test]
fn global_deadline_aborts_without_returning_partial_quorum() {
    let fixture = Fixture::new();
    let time = fixture.trusted_time();
    let mut calls = 0;
    let result = collect_verified_replica_quorum(
        QuorumCollectionMaterials {
            remote_cursor_policy_bytes: &fixture.remote_policy_bytes,
            expected_remote_cursor_policy_sha256: &fixture.remote_pin,
            replica_quorum_policy_bytes: &fixture.quorum_policy_bytes,
            expected_replica_quorum_policy_sha256: &fixture.quorum_pin,
            expected_previous: None,
            trusted_time: &time,
        },
        QuorumCollectionLimits {
            collection_timeout: Duration::from_millis(5),
            per_replica_timeout: Duration::from_secs(1),
        },
        |request| {
            calls += 1;
            std::thread::sleep(Duration::from_millis(15));
            Ok::<_, Infallible>(fixture.observation(0, request.request_nonce()))
        },
    );
    assert!(matches!(
        result,
        Err(QuorumCollectionError::ReplicaSession {
            replica_id,
            failure: ReplicaSessionFailure::DeadlineExceeded,
        }) if replica_id == "replica-1"
    ));
    assert_eq!(calls, 1);
}
