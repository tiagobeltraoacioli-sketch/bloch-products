use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    VerifiedRemoteCursor, create_remote_cursor_observation, remote_cursor_policy_sha256,
    remote_cursor_signature_message, verify_remote_cursor_observation,
};
use bloch_local_state_remote_cursor_replica_quorum::{
    REPLICA_QUORUM_POLICY_SCHEMA, ReplicaDescriptor, ReplicaEvidence, ReplicaQuorumError,
    ReplicaQuorumPolicy, parse_replica_quorum_policy, replica_quorum_policy_bytes,
    replica_quorum_policy_sha256, verify_replica_quorum,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_keys: Vec<SigningKey>,
    time_pin: String,
    quorum_policy: ReplicaQuorumPolicy,
    quorum_pin: String,
}

fn digest(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(32))
}

fn cursor(identity: &str, generation: u64, marker: u8) -> CheckpointCursor {
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{identity}\",\"generation\":{generation},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        digest(marker),
        digest(20),
        digest(21),
        digest(marker.wrapping_add(1)),
        digest(marker.wrapping_add(2)),
    );
    parse_cursor(bytes.as_bytes()).unwrap()
}

fn fixture() -> Fixture {
    let keys = vec![
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
        SigningKey::from_bytes(&[43; 32]),
    ];
    let authorities = keys
        .iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorAuthority {
            authority_id: format!("replica-{}-signer", index + 1),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
        })
        .collect();
    let remote_policy = RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "remote-prod".into(),
        signature_domain: "remote-prod-domain".into(),
        state_identity: "data:tenant-a:lifecycle".into(),
        threshold: 1,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        max_observation_age_seconds: 100,
        authorities,
    };
    let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
    let time_keys = vec![
        SigningKey::from_bytes(&[71; 32]),
        SigningKey::from_bytes(&[72; 32]),
    ];
    let time_policy = TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: "replica-quorum-time".into(),
        signature_domain: "replica-quorum-time-domain".into(),
        state_identity: remote_policy.state_identity.clone(),
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
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
    let quorum_policy = ReplicaQuorumPolicy {
        schema: REPLICA_QUORUM_POLICY_SCHEMA.into(),
        policy_id: "replica-quorum-prod".into(),
        state_identity: remote_policy.state_identity.clone(),
        remote_cursor_policy_sha256: remote_pin.clone(),
        trusted_time_policy_sha256: time_pin.clone(),
        quorum: 2,
        max_observation_age_seconds: 60,
        max_observation_skew_seconds: 20,
        replicas: (1..=3)
            .map(|index| ReplicaDescriptor {
                replica_id: format!("replica-{index}"),
                provenance_id: format!("failure-domain-{index}"),
                signer_authority_ids: vec![format!("replica-{index}-signer")],
            })
            .collect(),
    };
    let quorum_pin = replica_quorum_policy_sha256(&quorum_policy).unwrap();
    Fixture {
        remote_policy,
        remote_pin,
        keys,
        time_policy,
        time_keys,
        time_pin,
        quorum_policy,
        quorum_pin,
    }
}

fn trusted_time(fixture: &Fixture, now: u64) -> VerifiedTrustedTime {
    make_trusted_time(
        &fixture.time_policy,
        &fixture.time_pin,
        &fixture.time_keys,
        now,
    )
}

fn make_trusted_time(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey],
    now: u64,
) -> VerifiedTrustedTime {
    let nonce = "quorum_time_nonce_0123456789abcdef0123456789abcdef";
    let message = trusted_time_signature_message(policy, pin, nonce, now, now + 30).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let token = create_trusted_time_token(policy, pin, nonce, now, now + 30, &signatures).unwrap();
    verify_trusted_time_token(&token, policy, pin, nonce, None).unwrap()
}

fn verify<'a>(
    fixture: &Fixture,
    evidence: &[ReplicaEvidence<'a>],
    previous: Option<&CheckpointCursor>,
    now: u64,
) -> Result<bloch_local_state_remote_cursor_replica_quorum::VerifiedReplicaQuorum, ReplicaQuorumError>
{
    verify_replica_quorum(
        evidence,
        &fixture.quorum_policy,
        &fixture.quorum_pin,
        previous,
        &trusted_time(fixture, now),
    )
}

fn observation(
    fixture: &Fixture,
    replica: usize,
    cursor: &CheckpointCursor,
    observed_at: u64,
) -> VerifiedRemoteCursor {
    let nonce = format!("replica_{replica}_nonce_0123456789abcdef0123456789abcdef");
    let message = remote_cursor_signature_message(
        cursor,
        &fixture.remote_policy,
        &fixture.remote_pin,
        &nonce,
        observed_at,
    )
    .unwrap();
    let signature = RemoteCursorSignature {
        authority_id: format!("replica-{}-signer", replica + 1),
        signature: format!(
            "0x{}",
            hex::encode(fixture.keys[replica].sign(&message).to_bytes())
        ),
    };
    let bytes = create_remote_cursor_observation(
        cursor,
        &fixture.remote_policy,
        &fixture.remote_pin,
        &nonce,
        observed_at,
        &[signature],
    )
    .unwrap();
    verify_remote_cursor_observation(
        &bytes,
        &fixture.remote_policy,
        &fixture.remote_pin,
        &nonce,
        observed_at + 1,
    )
    .unwrap()
}

#[test]
fn returns_canonical_report_only_for_freshest_complete_cursor_quorum() {
    let fixture = fixture();
    let old = cursor(&fixture.remote_policy.state_identity, 6, 8);
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 201);
    let c = observation(&fixture, 2, &old, 199);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-3",
            observation: &c,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
    ];
    let report = verify(&fixture, &evidence, Some(&old), 210).unwrap();
    assert_eq!(report.cursor(), &current);
    assert_eq!(report.replica_ids(), &["replica-1", "replica-2"]);
    assert_eq!(report.observation_sha256s().len(), 2);
    assert_eq!(report.oldest_counted_observation_unix_seconds(), 200);
    assert_eq!(report.freshest_observation_unix_seconds(), 201);
    assert_eq!(report.trusted_time_policy_sha256(), fixture.time_pin);
    assert_eq!(report.evaluated_at_unix_seconds(), 210);
    assert!(!report.trusted_time_token_sha256().is_empty());
    assert!(!report.consensus_proven());
    assert!(!report.linearizability_proven());
    assert!(!report.replica_independence_proven());
    let parsed: serde_json::Value = serde_json::from_slice(report.canonical_bytes()).unwrap();
    assert_eq!(parsed["cursor"]["generation"], 7);

    let reordered = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-3",
            observation: &c,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
    ];
    let reordered_report = verify(&fixture, &reordered, Some(&old), 210).unwrap();
    assert_eq!(report.canonical_bytes(), reordered_report.canonical_bytes());
}

#[test]
fn rejects_duplicate_replica_and_duplicate_authenticated_evidence() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 200);
    let duplicate_replica = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &b,
        },
    ];
    assert_eq!(
        verify(&fixture, &duplicate_replica, None, 201),
        Err(ReplicaQuorumError::DuplicateEvidence)
    );
    let duplicate_artifact = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &a,
        },
    ];
    assert_eq!(
        verify(&fixture, &duplicate_artifact, None, 201),
        Err(ReplicaQuorumError::DuplicateEvidence)
    );
}

#[test]
fn rejects_duplicate_declared_provenance_and_noncanonical_manifest() {
    let mut invalid = fixture();
    invalid.quorum_policy.replicas[1].provenance_id =
        invalid.quorum_policy.replicas[0].provenance_id.clone();
    assert_eq!(
        replica_quorum_policy_bytes(&invalid.quorum_policy),
        Err(ReplicaQuorumError::DuplicateProvenance)
    );

    let fixture = fixture();
    let mut bytes = replica_quorum_policy_bytes(&fixture.quorum_policy).unwrap();
    bytes.push(b'\n');
    assert_eq!(
        parse_replica_quorum_policy(&bytes, &fixture.quorum_pin),
        Err(ReplicaQuorumError::InvalidPolicy)
    );
}

#[test]
fn rejects_wrong_signer_assignment_and_policy_pin() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 200);
    let swapped = [
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &b,
        },
    ];
    assert_eq!(
        verify(&fixture, &swapped, None, 201),
        Err(ReplicaQuorumError::SignerMismatch)
    );
    assert_eq!(
        verify_replica_quorum(
            &swapped,
            &fixture.quorum_policy,
            &digest(99),
            None,
            &trusted_time(&fixture, 201),
        ),
        Err(ReplicaQuorumError::PolicyPinMismatch)
    );
}

#[test]
fn rejects_split_brain_at_same_generation_even_with_other_quorum() {
    let fixture = fixture();
    let left = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let right = cursor(&fixture.remote_policy.state_identity, 7, 10);
    let a = observation(&fixture, 0, &left, 200);
    let b = observation(&fixture, 1, &left, 200);
    let c = observation(&fixture, 2, &right, 200);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
        ReplicaEvidence {
            replica_id: "replica-3",
            observation: &c,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 201),
        Err(ReplicaQuorumError::SplitBrain)
    );
}

#[test]
fn rejects_stale_quorum_when_a_newer_generation_is_seen() {
    let fixture = fixture();
    let old = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let new = cursor(&fixture.remote_policy.state_identity, 8, 10);
    let a = observation(&fixture, 0, &old, 200);
    let b = observation(&fixture, 1, &old, 200);
    let c = observation(&fixture, 2, &new, 201);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
        ReplicaEvidence {
            replica_id: "replica-3",
            observation: &c,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 202),
        Err(ReplicaQuorumError::StaleQuorum)
    );
}

#[test]
fn rejects_timestamp_stale_votes_and_prior_rollback() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let future = cursor(&fixture.remote_policy.state_identity, 8, 10);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 230);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 231),
        Err(ReplicaQuorumError::StaleQuorum)
    );

    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 201);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, Some(&future), 202),
        Err(ReplicaQuorumError::Rollback)
    );
}

#[test]
fn rejects_cross_identity_before_counting_votes() {
    let fixture = fixture();
    let wrong = cursor("data:tenant-b:lifecycle", 7, 9);
    let mut other_policy = fixture.remote_policy.clone();
    other_policy.state_identity = "data:tenant-b:lifecycle".into();
    let other_pin = remote_cursor_policy_sha256(&other_policy).unwrap();
    let nonce = "cross_identity_nonce_0123456789abcdef0123456789abcdef";
    let message =
        remote_cursor_signature_message(&wrong, &other_policy, &other_pin, nonce, 200).unwrap();
    let signature = RemoteCursorSignature {
        authority_id: "replica-1-signer".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.keys[0].sign(&message).to_bytes())
        ),
    };
    let bytes = create_remote_cursor_observation(
        &wrong,
        &other_policy,
        &other_pin,
        nonce,
        200,
        &[signature],
    )
    .unwrap();
    let cross =
        verify_remote_cursor_observation(&bytes, &other_policy, &other_pin, nonce, 201).unwrap();
    let right_cursor = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let right = observation(&fixture, 1, &right_cursor, 200);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &cross,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &right,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 201),
        Err(ReplicaQuorumError::IdentityMismatch)
    );
}

#[test]
fn rejects_same_state_observation_from_another_remote_policy() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let mut other_policy = fixture.remote_policy.clone();
    other_policy.policy_id = "other-remote-prod".into();
    let other_pin = remote_cursor_policy_sha256(&other_policy).unwrap();
    let nonce = "cross_policy_nonce_0123456789abcdef0123456789abcdef";
    let message =
        remote_cursor_signature_message(&current, &other_policy, &other_pin, nonce, 200).unwrap();
    let signature = RemoteCursorSignature {
        authority_id: "replica-1-signer".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.keys[0].sign(&message).to_bytes())
        ),
    };
    let bytes = create_remote_cursor_observation(
        &current,
        &other_policy,
        &other_pin,
        nonce,
        200,
        &[signature],
    )
    .unwrap();
    let cross =
        verify_remote_cursor_observation(&bytes, &other_policy, &other_pin, nonce, 201).unwrap();
    let right = observation(&fixture, 1, &current, 200);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &cross,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &right,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 201),
        Err(ReplicaQuorumError::IdentityMismatch)
    );
}

#[test]
fn policy_requires_two_to_sixteen_replicas_and_quorum_of_two() {
    let mut invalid_quorum = fixture();
    invalid_quorum.quorum_policy.quorum = 1;
    assert_eq!(
        replica_quorum_policy_bytes(&invalid_quorum.quorum_policy),
        Err(ReplicaQuorumError::InvalidPolicy)
    );

    let mut invalid_replicas = fixture();
    invalid_replicas.quorum_policy.replicas.truncate(1);
    invalid_replicas.quorum_policy.quorum = 2;
    assert_eq!(
        replica_quorum_policy_bytes(&invalid_replicas.quorum_policy),
        Err(ReplicaQuorumError::InvalidPolicy)
    );
}

#[test]
fn rejects_absolute_staleness_at_exclusive_boundary_and_future_evidence() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 200);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
    ];
    assert_eq!(
        verify(&fixture, &evidence, None, 260),
        Err(ReplicaQuorumError::OutsideFreshnessWindow)
    );
    assert_eq!(
        verify(&fixture, &evidence, None, 199),
        Err(ReplicaQuorumError::OutsideFreshnessWindow)
    );
}

#[test]
fn rejects_cross_trusted_time_policy_and_audience() {
    let fixture = fixture();
    let current = cursor(&fixture.remote_policy.state_identity, 7, 9);
    let a = observation(&fixture, 0, &current, 200);
    let b = observation(&fixture, 1, &current, 200);
    let evidence = [
        ReplicaEvidence {
            replica_id: "replica-1",
            observation: &a,
        },
        ReplicaEvidence {
            replica_id: "replica-2",
            observation: &b,
        },
    ];

    let mut other_policy = fixture.time_policy.clone();
    other_policy.policy_id = "other-replica-quorum-time".into();
    let other_pin = trusted_time_policy_sha256(&other_policy).unwrap();
    let other_time = make_trusted_time(&other_policy, &other_pin, &fixture.time_keys, 201);
    assert_eq!(
        verify_replica_quorum(
            &evidence,
            &fixture.quorum_policy,
            &fixture.quorum_pin,
            None,
            &other_time,
        ),
        Err(ReplicaQuorumError::TrustedTimeAudienceMismatch)
    );

    let mut other_audience = fixture.time_policy.clone();
    other_audience.state_identity = "data:tenant-b:lifecycle".into();
    let audience_pin = trusted_time_policy_sha256(&other_audience).unwrap();
    let audience_time = make_trusted_time(&other_audience, &audience_pin, &fixture.time_keys, 201);
    assert_eq!(
        verify_replica_quorum(
            &evidence,
            &fixture.quorum_policy,
            &fixture.quorum_pin,
            None,
            &audience_time,
        ),
        Err(ReplicaQuorumError::TrustedTimeAudienceMismatch)
    );
}
