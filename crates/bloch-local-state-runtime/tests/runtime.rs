#![cfg(unix)]

use bloch_data_governance::{
    LIFECYCLE_POLICY_SCHEMA, LIFECYCLE_STATE_SCHEMA, LifecycleActor, LifecycleActorRole,
    LifecyclePhase, LifecyclePolicy, RetentionDisposition, canonical_lifecycle_policy_bytes,
    lifecycle_policy_sha256,
};
use bloch_local_state_admission::{
    DATA_SEMANTIC_MANIFEST_SCHEMA, DataLifecycleSemanticManifest, PAY_SEMANTIC_MANIFEST_SCHEMA,
    PayAdjustmentSemanticManifest, data_semantic_manifest_bytes, data_semantic_manifest_sha256,
    pay_semantic_manifest_bytes, pay_semantic_manifest_sha256,
};
use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    authenticate_root_checkpoint, checkpoint_policy_bytes, checkpoint_policy_sha256,
    checkpoint_signature_message, create_root_checkpoint,
};
use bloch_local_state_coordination::{
    CoordinationError, provision_local_state_coordination_directory,
    with_coordinated_state_transition,
};
use bloch_local_state_cursor::admit_checkpoint;
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    create_remote_cursor_observation, remote_cursor_policy_bytes, remote_cursor_policy_sha256,
    remote_cursor_signature_message,
};
use bloch_local_state_remote_session::FetchSessionError;
use bloch_local_state_runtime::*;
use bloch_local_state_store::write_state;
use bloch_pay_adjustments::{ADJUSTMENT_STATE_SCHEMA, AdjustmentStatus};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-runtime-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    identity: String,
    state_store: Temp,
    cursor_store: Temp,
    coordination: Temp,
    artifact: Vec<u8>,
    checkpoint_policy: Vec<u8>,
    semantic: Vec<u8>,
    remote_policy: RemoteCursorPolicy,
    remote_policy_bytes: Vec<u8>,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
    cursor: bloch_local_state_cursor::CheckpointCursor,
}

impl Fixture {
    fn new(identity: &str, state: &[u8], semantic: Vec<u8>, semantic_pin: &str) -> Self {
        let now = now();
        let state_store = Temp::new("state");
        let cursor_store = Temp::new("cursor");
        let coordination = Temp::new("coordination");
        provision_local_state_coordination_directory(&coordination.0).unwrap();
        let root = write_state(&state_store.0, identity, 0, state, None).unwrap();
        let keys = [
            SigningKey::from_bytes(&[91; 32]),
            SigningKey::from_bytes(&[92; 32]),
        ];
        let checkpoint_policy = CheckpointPolicy {
            schema: POLICY_SCHEMA.into(),
            policy_id: "runtime-checkpoint".into(),
            checkpoint_domain: "bloch-products-runtime".into(),
            state_identity: identity.into(),
            threshold: 2,
            effective_at_unix_seconds: now - 100,
            expires_at_unix_seconds: now + 1_000,
            max_checkpoint_age_seconds: 100,
            authorities: authorities(&keys, "checkpoint"),
        };
        let checkpoint_pin = checkpoint_policy_sha256(&checkpoint_policy).unwrap();
        let message = checkpoint_signature_message(
            &root,
            &checkpoint_policy,
            &checkpoint_pin,
            semantic_pin,
            now - 10,
        )
        .unwrap();
        let signatures = signatures(&keys, "checkpoint", &message);
        let artifact = create_root_checkpoint(
            &root,
            &checkpoint_policy,
            &checkpoint_pin,
            semantic_pin,
            now - 10,
            &signatures,
        )
        .unwrap();
        let verified =
            authenticate_root_checkpoint(&artifact, &checkpoint_policy, &checkpoint_pin, now)
                .unwrap();
        let cursor = admit_checkpoint(&cursor_store.0, &verified, None).unwrap();

        let remote_keys = vec![
            SigningKey::from_bytes(&[93; 32]),
            SigningKey::from_bytes(&[94; 32]),
        ];
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "runtime-remote".into(),
            signature_domain: "bloch-products-runtime-remote".into(),
            state_identity: identity.into(),
            threshold: 2,
            effective_at_unix_seconds: now - 100,
            expires_at_unix_seconds: now + 1_000,
            max_observation_age_seconds: 30,
            authorities: remote_keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("remote-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let remote_policy_bytes = remote_cursor_policy_bytes(&remote_policy).unwrap();
        Self {
            identity: identity.into(),
            state_store,
            cursor_store,
            coordination,
            artifact,
            checkpoint_policy: checkpoint_policy_bytes(&checkpoint_policy).unwrap(),
            semantic,
            remote_policy,
            remote_policy_bytes,
            remote_pin,
            remote_keys,
            cursor,
        }
    }

    fn response(&self, nonce: &str) -> Vec<u8> {
        self.response_at(nonce, now())
    }

    fn response_at(&self, nonce: &str, observed: u64) -> Vec<u8> {
        let message = remote_cursor_signature_message(
            &self.cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            observed,
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
        create_remote_cursor_observation(
            &self.cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            observed,
            &signatures,
        )
        .unwrap()
    }

    fn remote(&self, timeout: Duration) -> RemoteFetchMaterials<'_> {
        RemoteFetchMaterials {
            policy_bytes: &self.remote_policy_bytes,
            expected_policy_sha256: &self.remote_pin,
            expected_state_identity: &self.identity,
            timeout,
        }
    }

    fn local(&self) -> LocalAdmissionMaterials<'_> {
        LocalAdmissionMaterials {
            checkpoint_artifact_bytes: &self.artifact,
            checkpoint_policy_bytes: &self.checkpoint_policy,
            semantic_manifest_bytes: &self.semantic,
            coordination_directory: &self.coordination.0,
            cursor_store: &self.cursor_store.0,
            state_store: &self.state_store.0,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PayState<'a> {
    schema: &'static str,
    adjustment_policy_sha256: &'a str,
    reconciliation_policy_sha256: &'a str,
    adjustment_id: &'a str,
    payment_observation_id: &'a str,
    payment_observation_sha256: &'a str,
    payment_amount_minor: u64,
    generation: u64,
    status: AdjustmentStatus,
    applied_events: Vec<serde_json::Value>,
    settlement_qualified: bool,
    credit_authorized: bool,
    funds_moved: bool,
}

fn pay_fixture() -> Fixture {
    let adjustment = digest(b"adjustment");
    let reconciliation = digest(b"reconciliation");
    let observation = digest(b"observation");
    let identity = "pay:merchant-a:adjustment-1";
    let state = serde_json::to_vec(&PayState {
        schema: ADJUSTMENT_STATE_SCHEMA,
        adjustment_policy_sha256: &adjustment,
        reconciliation_policy_sha256: &reconciliation,
        adjustment_id: "adjustment-1",
        payment_observation_id: "observation-1",
        payment_observation_sha256: &observation,
        payment_amount_minor: 10,
        generation: 0,
        status: AdjustmentStatus::Active,
        applied_events: vec![],
        settlement_qualified: false,
        credit_authorized: false,
        funds_moved: false,
    })
    .unwrap();
    let manifest = PayAdjustmentSemanticManifest {
        schema: PAY_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: identity.into(),
        adjustment_policy_sha256: adjustment,
        reconciliation_policy_sha256: reconciliation,
        adjustment_id: "adjustment-1".into(),
        payment_observation_id: "observation-1".into(),
        payment_observation_sha256: observation,
        payment_amount_minor: 10,
        generation: 0,
    };
    let semantic = pay_semantic_manifest_bytes(&manifest).unwrap();
    let pin = pay_semantic_manifest_sha256(&manifest).unwrap();
    Fixture::new(identity, &state, semantic, &pin)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataState<'a> {
    schema: &'static str,
    lifecycle_policy_sha256: &'a str,
    governance_policy_sha256: &'a str,
    dataset_schema_sha256: &'a str,
    record_sha256: &'a str,
    dispose_after_unix_seconds: u64,
    disposition: RetentionDisposition,
    sequence: u64,
    phase: LifecyclePhase,
    active_legal_hold_id: Option<&'a str>,
    disposal_order_id: Option<&'a str>,
    evidence_id: Option<&'a str>,
    evidence_sha256: Option<&'a str>,
    events: Vec<serde_json::Value>,
}

fn data_fixture() -> (Fixture, Vec<u8>) {
    let governance = digest(b"governance");
    let dataset = digest(b"dataset");
    let record = digest(b"record");
    let roles = [
        LifecycleActorRole::LegalHoldAuthority,
        LifecycleActorRole::DisposalAuthority,
        LifecycleActorRole::EvidenceRecorder,
    ];
    let policy = LifecyclePolicy {
        schema: LIFECYCLE_POLICY_SCHEMA.into(),
        policy_id: "runtime-lifecycle".into(),
        signature_domain: "bloch-data-runtime".into(),
        governance_policy_sha256: governance.clone(),
        dataset_schema_sha256: dataset.clone(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: u64::MAX - 1,
        dispose_after_unix_seconds: 800,
        disposition: RetentionDisposition::Delete,
        initial_legal_hold_id: None,
        actors: roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                let key = SigningKey::from_bytes(&[(index + 101) as u8; 32]);
                LifecycleActor {
                    actor_id: format!("actor-{}", index + 1),
                    role: *role,
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                }
            })
            .collect(),
    };
    let lifecycle_pin = lifecycle_policy_sha256(&policy).unwrap();
    let state = serde_json::to_vec(&DataState {
        schema: LIFECYCLE_STATE_SCHEMA,
        lifecycle_policy_sha256: &lifecycle_pin,
        governance_policy_sha256: &governance,
        dataset_schema_sha256: &dataset,
        record_sha256: &record,
        dispose_after_unix_seconds: 800,
        disposition: RetentionDisposition::Delete,
        sequence: 0,
        phase: LifecyclePhase::Retained,
        active_legal_hold_id: None,
        disposal_order_id: None,
        evidence_id: None,
        evidence_sha256: None,
        events: vec![],
    })
    .unwrap();
    let identity = "data:tenant-a:lifecycle";
    let manifest = DataLifecycleSemanticManifest {
        schema: DATA_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: identity.into(),
        lifecycle_policy_sha256: lifecycle_pin,
        governance_policy_sha256: governance,
        dataset_schema_sha256: dataset,
        record_sha256: record,
        sequence: 0,
    };
    let semantic = data_semantic_manifest_bytes(&manifest).unwrap();
    let pin = data_semantic_manifest_sha256(&manifest).unwrap();
    (
        Fixture::new(identity, &state, semantic, &pin),
        canonical_lifecycle_policy_bytes(&policy).unwrap(),
    )
}

#[test]
fn happy_paths_return_only_admitted_data_and_pay_state() {
    let pay = pay_fixture();
    let admitted = start_pay(
        PayStartupMaterials {
            remote: pay.remote(Duration::from_secs(1)),
            local: pay.local(),
        },
        |request| Ok::<_, std::io::Error>(pay.response(request.request_nonce())),
    )
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");

    let (data, lifecycle_policy) = data_fixture();
    let admitted = start_data(
        DataStartupMaterials {
            remote: data.remote(Duration::from_secs(1)),
            local: data.local(),
            lifecycle_policy_bytes: &lifecycle_policy,
        },
        |request| Ok::<_, std::io::Error>(data.response(request.request_nonce())),
    )
    .unwrap();
    assert_eq!(admitted.state().sequence(), 0);
}

#[test]
fn trusted_time_paths_admit_data_and_pay_without_operator_time() {
    let pay = pay_fixture();
    let (pay_time, pay_time_pin) = trusted_time(&pay.identity, &pay.remote_pin);
    let admitted = start_pay_with_trusted_time(
        PayStartupMaterials {
            remote: pay.remote(Duration::from_secs(1)),
            local: pay.local(),
        },
        &pay_time,
        &pay_time_pin,
        |request| {
            Ok::<_, std::io::Error>(
                pay.response_at(request.request_nonce(), pay_time.unix_seconds().unwrap()),
            )
        },
    )
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");

    let (data, lifecycle_policy) = data_fixture();
    let (data_time, data_time_pin) = trusted_time(&data.identity, &data.remote_pin);
    let admitted = start_data_with_trusted_time(
        DataStartupMaterials {
            remote: data.remote(Duration::from_secs(1)),
            local: data.local(),
            lifecycle_policy_bytes: &lifecycle_policy,
        },
        &data_time,
        &data_time_pin,
        |request| {
            Ok::<_, std::io::Error>(
                data.response_at(request.request_nonce(), data_time.unix_seconds().unwrap()),
            )
        },
    )
    .unwrap();
    assert_eq!(admitted.state().sequence(), 0);
}

#[test]
fn timeout_replay_and_cross_identity_fail_closed() {
    let fixture = pay_fixture();
    let timeout = start_pay(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_millis(5)),
            local: fixture.local(),
        },
        |request| {
            let response = fixture.response(request.request_nonce());
            std::thread::sleep(Duration::from_millis(20));
            Ok::<_, std::io::Error>(response)
        },
    );
    assert!(matches!(
        timeout,
        Err(StartupRuntimeError::Remote(
            FetchSessionError::DeadlineExceeded
        ))
    ));

    let mut retained = Vec::new();
    start_pay(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        |request| {
            retained = fixture.response(request.request_nonce());
            Ok::<_, std::io::Error>(retained.clone())
        },
    )
    .unwrap();
    let replay = start_pay(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        |_request| Ok::<_, std::io::Error>(retained),
    );
    assert!(matches!(
        replay,
        Err(StartupRuntimeError::Remote(
            FetchSessionError::Authentication(_)
        ))
    ));

    let called = Cell::new(false);
    let cross = start_pay(
        PayStartupMaterials {
            remote: RemoteFetchMaterials {
                expected_state_identity: "data:tenant-a:lifecycle",
                ..fixture.remote(Duration::from_secs(1))
            },
            local: fixture.local(),
        },
        |_request| {
            called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        cross,
        Err(StartupRuntimeError::Remote(
            FetchSessionError::InvalidConfiguration
        ))
    ));
    assert!(!called.get());
}

#[test]
fn local_lock_is_acquired_before_remote_fetch() {
    let fixture = pay_fixture();
    let transported = Cell::new(false);
    with_coordinated_state_transition(&fixture.coordination.0, |_scope| {
        let started = Instant::now();
        let result = start_pay(
            PayStartupMaterials {
                remote: fixture.remote(Duration::from_secs(1)),
                local: fixture.local(),
            },
            |request| {
                transported.set(true);
                Ok::<_, std::io::Error>(fixture.response(request.request_nonce()))
            },
        );
        assert!(!transported.get());
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            result,
            Err(StartupRuntimeError::Coordination(CoordinationError::Busy))
        ));
        Ok::<_, std::io::Error>(())
    })
    .unwrap();
}

#[test]
fn trusted_time_path_acquires_local_lock_before_remote_fetch() {
    let fixture = pay_fixture();
    let (trusted_time, trusted_time_pin) = trusted_time(&fixture.identity, &fixture.remote_pin);
    let transported = Cell::new(false);
    with_coordinated_state_transition(&fixture.coordination.0, |_scope| {
        let result = start_pay_with_trusted_time(
            PayStartupMaterials {
                remote: fixture.remote(Duration::from_secs(1)),
                local: fixture.local(),
            },
            &trusted_time,
            &trusted_time_pin,
            |request| {
                transported.set(true);
                Ok::<_, std::io::Error>(fixture.response(request.request_nonce()))
            },
        );
        assert!(!transported.get());
        assert!(matches!(
            result,
            Err(StartupRuntimeError::Coordination(CoordinationError::Busy))
        ));
        Ok::<_, std::io::Error>(())
    })
    .unwrap();
}

fn authorities(keys: &[SigningKey], prefix: &str) -> Vec<CheckpointAuthority> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| CheckpointAuthority {
            authority_id: format!("{prefix}-{}", index + 1),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
        })
        .collect()
}

fn signatures(
    keys: &[SigningKey],
    prefix: &str,
    message: &[u8],
) -> Vec<DetachedCheckpointSignature> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| DetachedCheckpointSignature {
            authority_id: format!("{prefix}-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(message).to_bytes())),
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn trusted_time(
    state_identity: &str,
    remote_cursor_policy_sha256: &str,
) -> (VerifiedTrustedTime, String) {
    let now = now();
    let nonce = "runtime_trusted_time_nonce_0123456789abcdef0123456789abcdef";
    let keys = [
        SigningKey::from_bytes(&[111; 32]),
        SigningKey::from_bytes(&[112; 32]),
    ];
    let policy = TrustedTimePolicy {
        schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
        policy_id: "runtime-trusted-time".into(),
        signature_domain: "bloch-products-runtime-time".into(),
        state_identity: state_identity.into(),
        remote_cursor_policy_sha256: remote_cursor_policy_sha256.into(),
        threshold: 2,
        effective_at_unix_seconds: now - 60,
        expires_at_unix_seconds: now + 60,
        max_token_lifetime_seconds: 30,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeAuthority {
                authority_id: format!("time-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    };
    let pin = trusted_time_policy_sha256(&policy).unwrap();
    let message = trusted_time_signature_message(&policy, &pin, nonce, now, now + 30).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let token =
        create_trusted_time_token(&policy, &pin, nonce, now, now + 30, &signatures).unwrap();
    (
        verify_trusted_time_token(&token, &policy, &pin, nonce, None).unwrap(),
        pin,
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
