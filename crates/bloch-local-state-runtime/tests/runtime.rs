#![cfg(unix)]

use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TRANSPORT_POLICY_SCHEMA, TransportAuthority,
    TransportEvidenceSignature, TransportExchangeParameters, TransportPurpose,
    authenticated_transport_policy_sha256, create_authenticated_transport_evidence_for_exchange,
    transport_evidence_signature_message_for_exchange,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportRequest, MonotonicDeadlineRead as TransportDeadlineRead,
};
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
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimeBoundary, TrustedTimePolicy,
    TrustedTimeSignature, VerifiedTrustedTime, create_trusted_time_token,
    trusted_time_policy_bytes, trusted_time_policy_sha256, trusted_time_signature_message,
    verify_trusted_time_token,
};
use bloch_trusted_time_boundary_store::{
    TrustedTimeBoundaryAudience, load_trusted_time_boundary, provision_trusted_time_boundary_store,
};
use bloch_trusted_time_external_anchor::{
    EXTERNAL_ANCHOR_POLICY_SCHEMA, ExternalAnchorAuthority, ExternalAnchorPolicy,
    ExternalAnchorSignature, create_external_anchor_document, external_anchor_policy_bytes,
    external_anchor_policy_sha256, external_anchor_signature_message, verify_external_anchor,
};
use bloch_trusted_time_session::MonotonicDeadlineRead;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

struct TokenReader {
    bytes: Vec<u8>,
    offset: usize,
}

struct AnchorFixture {
    policy: ExternalAnchorPolicy,
    policy_bytes: Vec<u8>,
    pin: String,
    keys: [SigningKey; 2],
    expectation: Vec<u8>,
}

impl AnchorFixture {
    fn new(
        state_identity: &str,
        time_policy: &TrustedTimePolicy,
        time_pin: &str,
        time_keys: &[SigningKey; 2],
        remote_pin: &str,
        at: u64,
    ) -> Self {
        let keys = [
            SigningKey::from_bytes(&[121; 32]),
            SigningKey::from_bytes(&[122; 32]),
        ];
        let policy = ExternalAnchorPolicy {
            schema: EXTERNAL_ANCHOR_POLICY_SCHEMA.into(),
            policy_id: "runtime-external-anchor".into(),
            signature_domain: "bloch-products-runtime-external-anchor".into(),
            state_identity: state_identity.into(),
            trusted_time_policy_sha256: time_pin.into(),
            remote_cursor_policy_sha256: remote_pin.into(),
            threshold: 2,
            effective_at_unix_seconds: at - 60,
            expires_at_unix_seconds: at + 60,
            max_anchor_lifetime_seconds: 30,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| ExternalAnchorAuthority {
                    authority_id: format!("anchor-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let pin = external_anchor_policy_sha256(&policy).unwrap();
        let retained_boundary = boundary_at(time_policy, time_pin, time_keys, at - 2);
        let retained_time = verified_time_at(time_policy, time_pin, time_keys, at);
        let document = anchor_document(
            &policy,
            &pin,
            &keys,
            1,
            &retained_boundary,
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            at - 1,
            at + 20,
        );
        let expectation = verify_external_anchor(
            &document,
            &policy,
            &pin,
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            &retained_time,
            None,
        )
        .unwrap()
        .retention_expectation()
        .canonical_bytes()
        .unwrap();
        let policy_bytes = external_anchor_policy_bytes(&policy).unwrap();
        Self {
            policy,
            policy_bytes,
            pin,
            keys,
            expectation,
        }
    }

    fn response(
        &self,
        nonce: &str,
        boundary: &TrustedTimeBoundary,
        at: u64,
    ) -> ExternalAnchorFetchResponse {
        ExternalAnchorFetchResponse {
            document_bytes: anchor_document(
                &self.policy,
                &self.pin,
                &self.keys,
                2,
                boundary,
                nonce,
                at,
                at + 20,
            ),
            authenticated_expectation_bytes: self.expectation.clone(),
        }
    }
}

impl MonotonicDeadlineRead for TokenReader {
    type Error = std::io::Error;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, Self::Error> {
        let available = self.bytes.len().saturating_sub(self.offset);
        let read = available.min(buffer.len());
        buffer[..read].copy_from_slice(&self.bytes[self.offset..self.offset + read]);
        self.offset += read;
        Ok(read)
    }
}

impl TransportDeadlineRead for TokenReader {
    type Error = std::io::Error;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, Self::Error> {
        let available = self.bytes.len().saturating_sub(self.offset);
        let read = available.min(buffer.len());
        buffer[..read].copy_from_slice(&self.bytes[self.offset..self.offset + read]);
        self.offset += read;
        Ok(read)
    }
}

struct TransportFixture {
    policy: AuthenticatedTransportPolicy,
    pin: String,
    keys: [SigningKey; 2],
}

impl TransportFixture {
    fn new(
        purpose: TransportPurpose,
        identity: &str,
        time_pin: &str,
        remote_pin: &str,
        at: u64,
    ) -> Self {
        let key_byte = match purpose {
            TransportPurpose::ExternalTimeAnchor => 123,
            TransportPurpose::RemoteCursor => 124,
            _ => unreachable!(),
        };
        let keys = [
            SigningKey::from_bytes(&[key_byte; 32]),
            SigningKey::from_bytes(&[key_byte + 1; 32]),
        ];
        let policy = AuthenticatedTransportPolicy {
            schema: TRANSPORT_POLICY_SCHEMA.into(),
            policy_id: format!("runtime-{purpose:?}"),
            signature_domain: "bloch-products-runtime-transport".into(),
            service_id: format!("runtime-{purpose:?}"),
            purpose,
            state_identity: identity.into(),
            trusted_time_policy_sha256: time_pin.into(),
            remote_cursor_policy_sha256: remote_pin.into(),
            endpoint_dns_name: "runtime.internal.example".into(),
            endpoint_port: 443,
            tls_version: "TLSv1.3".into(),
            alpn: "h2".into(),
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            server_spki_sha256: vec![
                "0x5555555555555555555555555555555555555555555555555555555555555555".into(),
            ],
            client_spki_sha256:
                "0x6666666666666666666666666666666666666666666666666666666666666666".into(),
            threshold: 2,
            effective_at_unix_seconds: at - 60,
            expires_at_unix_seconds: at + 60,
            max_evidence_age_seconds: 20,
            max_round_trip_millis: 1_000,
            max_response_bytes: 256 * 1024,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| TransportAuthority {
                    authority_id: format!("transport-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let pin = authenticated_transport_policy_sha256(&policy).unwrap();
        Self { policy, pin, keys }
    }

    fn collect(
        &self,
        request: &AuthenticatedTransportRequest<'_>,
        response: &[u8],
        signed_response: &[u8],
        at: u64,
    ) -> Result<
        bloch_authenticated_transport_session::AuthenticatedTransportInput,
        bloch_authenticated_transport_session::TransportCallbackError<std::io::Error>,
    > {
        let exchange = TransportExchangeParameters {
            request_nonce: request.request_nonce(),
            request_bytes: request.request_bytes(),
            response_bytes: signed_response,
            round_trip_millis: 1,
            observed_at_unix_seconds: at,
            cipher_suite: "TLS_AES_128_GCM_SHA256",
            server_spki_sha256: "0x5555555555555555555555555555555555555555555555555555555555555555",
        };
        let message =
            transport_evidence_signature_message_for_exchange(&self.policy, &self.pin, exchange)
                .unwrap();
        let signatures = self
            .keys
            .iter()
            .enumerate()
            .map(|(index, key)| TransportEvidenceSignature {
                authority_id: format!("transport-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let evidence = create_authenticated_transport_evidence_for_exchange(
            &self.policy,
            &self.pin,
            exchange,
            &signatures,
        )
        .unwrap();
        let mut response = TokenReader {
            bytes: response.to_vec(),
            offset: 0,
        };
        let mut evidence = TokenReader {
            bytes: evidence,
            offset: 0,
        };
        request
            .collect_exchange(&mut response, &mut evidence)
            .map_err(bloch_authenticated_transport_session::TransportCallbackError::Ingress)
    }
}

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
fn fresh_time_acquisition_advances_boundary_before_pay_admission() {
    let fixture = pay_fixture();
    let boundary_store = Temp::new("trusted-time-boundary");
    let (policy, pin, keys) = trusted_time_policy(&fixture.identity, &fixture.remote_pin);
    let initial_nonce = "runtime_initial_time_nonce_0123456789abcdef0123456789abcdef";
    let initial_at = now() - 31;
    let initial_token = trusted_time_token(&policy, &pin, &keys, initial_nonce, initial_at);
    let initial_time =
        verify_trusted_time_token(&initial_token, &policy, &pin, initial_nonce, None).unwrap();
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: &pin,
        state_identity: &fixture.identity,
        remote_cursor_policy_sha256: &fixture.remote_pin,
    };
    provision_trusted_time_boundary_store(
        &boundary_store.0,
        audience,
        &initial_time.rollback_boundary().unwrap(),
    )
    .unwrap();
    let policy_bytes = trusted_time_policy_bytes(&policy).unwrap();
    let issued_at = now();

    let admitted = start_pay_with_fresh_trusted_time(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        TrustedTimeStartupMaterials {
            policy_bytes: &policy_bytes,
            expected_policy_sha256: &pin,
            boundary_store: &boundary_store.0,
            timeout: Duration::from_secs(1),
        },
        |request| {
            Ok::<_, std::io::Error>(TokenReader {
                bytes: trusted_time_token(&policy, &pin, &keys, request.request_nonce(), issued_at),
                offset: 0,
            })
        },
        |request| {
            assert_eq!(
                load_trusted_time_boundary(&boundary_store.0, audience)
                    .unwrap()
                    .not_before_unix_seconds(),
                issued_at + 30
            );
            Ok::<_, std::io::Error>(fixture.response_at(request.request_nonce(), issued_at))
        },
    )
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");
    assert_eq!(
        load_trusted_time_boundary(&boundary_store.0, audience)
            .unwrap()
            .not_before_unix_seconds(),
        issued_at + 30
    );
}

#[test]
fn external_anchor_is_verified_before_local_advance_and_cursor_fetch() {
    let fixture = pay_fixture();
    let boundary_store = Temp::new("anchored-time-boundary");
    let (time_policy, time_pin, time_keys) =
        trusted_time_policy(&fixture.identity, &fixture.remote_pin);
    let at = now();
    let initial = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: &time_pin,
        state_identity: &fixture.identity,
        remote_cursor_policy_sha256: &fixture.remote_pin,
    };
    provision_trusted_time_boundary_store(&boundary_store.0, audience, &initial).unwrap();
    let time_policy_bytes = trusted_time_policy_bytes(&time_policy).unwrap();
    let anchor = AnchorFixture::new(
        &fixture.identity,
        &time_policy,
        &time_pin,
        &time_keys,
        &fixture.remote_pin,
        at,
    );
    let anchor_boundary = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let stage = Cell::new(0);

    let admitted = start_pay_with_fresh_trusted_time_and_external_anchor(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        TrustedTimeStartupMaterials {
            policy_bytes: &time_policy_bytes,
            expected_policy_sha256: &time_pin,
            boundary_store: &boundary_store.0,
            timeout: Duration::from_secs(1),
        },
        ExternalAnchorStartupMaterials {
            policy_bytes: &anchor.policy_bytes,
            expected_policy_sha256: &anchor.pin,
            timeout: Duration::from_secs(1),
        },
        |request| {
            Ok::<_, std::io::Error>(TokenReader {
                bytes: trusted_time_token(
                    &time_policy,
                    &time_pin,
                    &time_keys,
                    request.request_nonce(),
                    at,
                ),
                offset: 0,
            })
        },
        |request| {
            assert_eq!(stage.get(), 0);
            assert_eq!(
                load_trusted_time_boundary(&boundary_store.0, audience)
                    .unwrap()
                    .not_before_unix_seconds(),
                at - 1
            );
            stage.set(1);
            Ok::<_, std::io::Error>(anchor.response(request.request_nonce(), &anchor_boundary, at))
        },
        |request| {
            assert_eq!(stage.get(), 1);
            assert_eq!(
                load_trusted_time_boundary(&boundary_store.0, audience)
                    .unwrap()
                    .not_before_unix_seconds(),
                at + 30
            );
            stage.set(2);
            Ok::<_, std::io::Error>(fixture.response_at(request.request_nonce(), at))
        },
    )
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");
    assert_eq!(stage.get(), 2);
}

#[test]
fn authenticated_transport_gates_anchor_and_cursor_before_protocol_use() {
    let fixture = pay_fixture();
    let boundary_store = Temp::new("authenticated-transport-boundary");
    let (time_policy, time_pin, time_keys) =
        trusted_time_policy(&fixture.identity, &fixture.remote_pin);
    let at = now();
    let initial = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: &time_pin,
        state_identity: &fixture.identity,
        remote_cursor_policy_sha256: &fixture.remote_pin,
    };
    provision_trusted_time_boundary_store(&boundary_store.0, audience, &initial).unwrap();
    let time_policy_bytes = trusted_time_policy_bytes(&time_policy).unwrap();
    let anchor = AnchorFixture::new(
        &fixture.identity,
        &time_policy,
        &time_pin,
        &time_keys,
        &fixture.remote_pin,
        at,
    );
    let anchor_boundary = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let anchor_transport = TransportFixture::new(
        TransportPurpose::ExternalTimeAnchor,
        &fixture.identity,
        &time_pin,
        &fixture.remote_pin,
        at,
    );
    let cursor_transport = TransportFixture::new(
        TransportPurpose::RemoteCursor,
        &fixture.identity,
        &time_pin,
        &fixture.remote_pin,
        at,
    );
    let stage = Cell::new(0);

    let admitted = start_pay_with_authenticated_transport(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        TrustedTimeStartupMaterials {
            policy_bytes: &time_policy_bytes,
            expected_policy_sha256: &time_pin,
            boundary_store: &boundary_store.0,
            timeout: Duration::from_secs(1),
        },
        ExternalAnchorStartupMaterials {
            policy_bytes: &anchor.policy_bytes,
            expected_policy_sha256: &anchor.pin,
            timeout: Duration::from_secs(1),
        },
        AnchoredAuthenticatedTransportStartupMaterials {
            external_anchor: AuthenticatedTransportStartupMaterials {
                policy: &anchor_transport.policy,
                expected_policy_sha256: &anchor_transport.pin,
                timeout: Duration::from_secs(1),
            },
            remote_cursor: AuthenticatedTransportStartupMaterials {
                policy: &cursor_transport.policy,
                expected_policy_sha256: &cursor_transport.pin,
                timeout: Duration::from_secs(1),
            },
        },
        |request| {
            Ok::<_, std::io::Error>(TokenReader {
                bytes: trusted_time_token(
                    &time_policy,
                    &time_pin,
                    &time_keys,
                    request.request_nonce(),
                    at,
                ),
                offset: 0,
            })
        },
        |request| {
            assert_eq!(stage.get(), 0);
            assert_eq!(
                load_trusted_time_boundary(&boundary_store.0, audience)
                    .unwrap()
                    .not_before_unix_seconds(),
                at - 1
            );
            let nonce = authenticated_request_first_field(request.request_bytes());
            let response = anchor.response(nonce, &anchor_boundary, at);
            let payload = encode_authenticated_external_anchor_payload(
                &response.document_bytes,
                &response.authenticated_expectation_bytes,
            )
            .unwrap();
            stage.set(1);
            anchor_transport.collect(&request, &payload, &payload, at)
        },
        |request| {
            assert_eq!(stage.get(), 1);
            assert_eq!(
                load_trusted_time_boundary(&boundary_store.0, audience)
                    .unwrap()
                    .not_before_unix_seconds(),
                at + 30
            );
            let nonce = authenticated_request_first_field(request.request_bytes());
            let response = fixture.response_at(nonce, at);
            stage.set(2);
            cursor_transport.collect(&request, &response, &response, at)
        },
    )
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");
    assert_eq!(stage.get(), 2);
}

#[test]
fn authenticated_anchor_response_substitution_fails_before_boundary_mutation() {
    let fixture = pay_fixture();
    let boundary_store = Temp::new("authenticated-substitution-boundary");
    let (time_policy, time_pin, time_keys) =
        trusted_time_policy(&fixture.identity, &fixture.remote_pin);
    let at = now();
    let initial = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: &time_pin,
        state_identity: &fixture.identity,
        remote_cursor_policy_sha256: &fixture.remote_pin,
    };
    provision_trusted_time_boundary_store(&boundary_store.0, audience, &initial).unwrap();
    let time_policy_bytes = trusted_time_policy_bytes(&time_policy).unwrap();
    let anchor = AnchorFixture::new(
        &fixture.identity,
        &time_policy,
        &time_pin,
        &time_keys,
        &fixture.remote_pin,
        at,
    );
    let anchor_boundary = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let anchor_transport = TransportFixture::new(
        TransportPurpose::ExternalTimeAnchor,
        &fixture.identity,
        &time_pin,
        &fixture.remote_pin,
        at,
    );
    let cursor_transport = TransportFixture::new(
        TransportPurpose::RemoteCursor,
        &fixture.identity,
        &time_pin,
        &fixture.remote_pin,
        at,
    );
    let cursor_called = Cell::new(false);

    let result = start_pay_with_authenticated_transport(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        TrustedTimeStartupMaterials {
            policy_bytes: &time_policy_bytes,
            expected_policy_sha256: &time_pin,
            boundary_store: &boundary_store.0,
            timeout: Duration::from_secs(1),
        },
        ExternalAnchorStartupMaterials {
            policy_bytes: &anchor.policy_bytes,
            expected_policy_sha256: &anchor.pin,
            timeout: Duration::from_secs(1),
        },
        AnchoredAuthenticatedTransportStartupMaterials {
            external_anchor: AuthenticatedTransportStartupMaterials {
                policy: &anchor_transport.policy,
                expected_policy_sha256: &anchor_transport.pin,
                timeout: Duration::from_secs(1),
            },
            remote_cursor: AuthenticatedTransportStartupMaterials {
                policy: &cursor_transport.policy,
                expected_policy_sha256: &cursor_transport.pin,
                timeout: Duration::from_secs(1),
            },
        },
        |request| {
            Ok::<_, std::io::Error>(TokenReader {
                bytes: trusted_time_token(
                    &time_policy,
                    &time_pin,
                    &time_keys,
                    request.request_nonce(),
                    at,
                ),
                offset: 0,
            })
        },
        |request| {
            let nonce = authenticated_request_first_field(request.request_bytes());
            let response = anchor.response(nonce, &anchor_boundary, at);
            let signed = encode_authenticated_external_anchor_payload(
                &response.document_bytes,
                &response.authenticated_expectation_bytes,
            )
            .unwrap();
            let mut substituted = signed.clone();
            *substituted.last_mut().unwrap() ^= 1;
            anchor_transport.collect(&request, &substituted, &signed, at)
        },
        |_request| -> Result<
            bloch_authenticated_transport_session::AuthenticatedTransportInput,
            bloch_authenticated_transport_session::TransportCallbackError<std::io::Error>,
        > {
            cursor_called.set(true);
            unreachable!()
        },
    );
    assert!(matches!(
        result,
        Err(AnchoredFreshStartupRuntimeError::ExternalAnchorTransport(_))
    ));
    assert!(!cursor_called.get());
    assert_eq!(
        load_trusted_time_boundary(&boundary_store.0, audience)
            .unwrap()
            .not_before_unix_seconds(),
        at - 1
    );
}

#[test]
fn external_anchor_rollback_does_not_advance_local_boundary_or_fetch_cursor() {
    let fixture = pay_fixture();
    let boundary_store = Temp::new("rollback-anchor-boundary");
    let (time_policy, time_pin, time_keys) =
        trusted_time_policy(&fixture.identity, &fixture.remote_pin);
    let at = now();
    let initial = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: &time_pin,
        state_identity: &fixture.identity,
        remote_cursor_policy_sha256: &fixture.remote_pin,
    };
    provision_trusted_time_boundary_store(&boundary_store.0, audience, &initial).unwrap();
    let time_policy_bytes = trusted_time_policy_bytes(&time_policy).unwrap();
    let anchor = AnchorFixture::new(
        &fixture.identity,
        &time_policy,
        &time_pin,
        &time_keys,
        &fixture.remote_pin,
        at,
    );
    let future_boundary = boundary_at(&time_policy, &time_pin, &time_keys, at + 1);
    let cursor_called = Cell::new(false);

    let result = start_pay_with_fresh_trusted_time_and_external_anchor(
        PayStartupMaterials {
            remote: fixture.remote(Duration::from_secs(1)),
            local: fixture.local(),
        },
        TrustedTimeStartupMaterials {
            policy_bytes: &time_policy_bytes,
            expected_policy_sha256: &time_pin,
            boundary_store: &boundary_store.0,
            timeout: Duration::from_secs(1),
        },
        ExternalAnchorStartupMaterials {
            policy_bytes: &anchor.policy_bytes,
            expected_policy_sha256: &anchor.pin,
            timeout: Duration::from_secs(1),
        },
        |request| {
            Ok::<_, std::io::Error>(TokenReader {
                bytes: trusted_time_token(
                    &time_policy,
                    &time_pin,
                    &time_keys,
                    request.request_nonce(),
                    at,
                ),
                offset: 0,
            })
        },
        |request| {
            Ok::<_, std::io::Error>(anchor.response(request.request_nonce(), &future_boundary, at))
        },
        |_request| {
            cursor_called.set(true);
            Ok::<_, std::io::Error>(Vec::new())
        },
    );
    assert!(matches!(
        result,
        Err(AnchoredFreshStartupRuntimeError::ExternalAnchorVerification(_))
    ));
    assert!(!cursor_called.get());
    assert_eq!(
        load_trusted_time_boundary(&boundary_store.0, audience)
            .unwrap()
            .not_before_unix_seconds(),
        at - 1
    );
}

#[test]
fn external_anchor_transport_and_cross_audience_fail_before_local_mutation() {
    for mode in ["transport", "cross-audience", "cross-policy"] {
        let cross_audience = mode == "cross-audience";
        let fixture = pay_fixture();
        let boundary_store = Temp::new("failed-anchor-boundary");
        let (time_policy, time_pin, time_keys) =
            trusted_time_policy(&fixture.identity, &fixture.remote_pin);
        let at = now();
        let initial = boundary_at(&time_policy, &time_pin, &time_keys, at - 1);
        let audience = TrustedTimeBoundaryAudience {
            trusted_time_policy_sha256: &time_pin,
            state_identity: &fixture.identity,
            remote_cursor_policy_sha256: &fixture.remote_pin,
        };
        provision_trusted_time_boundary_store(&boundary_store.0, audience, &initial).unwrap();
        let time_policy_bytes = trusted_time_policy_bytes(&time_policy).unwrap();
        let other_identity = "pay:other-merchant:adjustment-1";
        let (other_time_policy, other_time_pin, other_time_keys) =
            trusted_time_policy(other_identity, &fixture.remote_pin);
        let (anchor_time_policy, anchor_time_pin, anchor_time_keys) = if cross_audience {
            (&other_time_policy, &other_time_pin, &other_time_keys)
        } else {
            (&time_policy, &time_pin, &time_keys)
        };
        let anchor = AnchorFixture::new(
            if cross_audience {
                other_identity
            } else {
                &fixture.identity
            },
            anchor_time_policy,
            anchor_time_pin,
            anchor_time_keys,
            &fixture.remote_pin,
            at,
        );
        let anchor_boundary = boundary_at(
            anchor_time_policy,
            anchor_time_pin,
            anchor_time_keys,
            at - 1,
        );
        let cursor_called = Cell::new(false);
        let result = start_pay_with_fresh_trusted_time_and_external_anchor(
            PayStartupMaterials {
                remote: fixture.remote(Duration::from_secs(1)),
                local: fixture.local(),
            },
            TrustedTimeStartupMaterials {
                policy_bytes: &time_policy_bytes,
                expected_policy_sha256: &time_pin,
                boundary_store: &boundary_store.0,
                timeout: Duration::from_secs(1),
            },
            ExternalAnchorStartupMaterials {
                policy_bytes: &anchor.policy_bytes,
                expected_policy_sha256: if mode == "cross-policy" {
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                } else {
                    &anchor.pin
                },
                timeout: Duration::from_secs(1),
            },
            |request| {
                Ok::<_, std::io::Error>(TokenReader {
                    bytes: trusted_time_token(
                        &time_policy,
                        &time_pin,
                        &time_keys,
                        request.request_nonce(),
                        at,
                    ),
                    offset: 0,
                })
            },
            |request| {
                if cross_audience {
                    Ok(anchor.response(request.request_nonce(), &anchor_boundary, at))
                } else {
                    Err(std::io::Error::other("anchor unavailable"))
                }
            },
            |_request| {
                cursor_called.set(true);
                Ok::<_, std::io::Error>(Vec::new())
            },
        );
        if mode == "transport" {
            assert!(matches!(
                result,
                Err(AnchoredFreshStartupRuntimeError::ExternalAnchorTransport(_))
            ));
        } else {
            assert!(matches!(
                result,
                Err(AnchoredFreshStartupRuntimeError::ExternalAnchorVerification(_))
            ));
        }
        assert!(!cursor_called.get());
        assert_eq!(
            load_trusted_time_boundary(&boundary_store.0, audience)
                .unwrap()
                .not_before_unix_seconds(),
            at - 1
        );
    }
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

fn authenticated_request_first_field(request: &[u8]) -> &str {
    let marker = request.iter().position(|byte| *byte == 0).unwrap() + 1;
    let length = u32::from_be_bytes(request[marker..marker + 4].try_into().unwrap()) as usize;
    std::str::from_utf8(&request[marker + 4..marker + 4 + length]).unwrap()
}

fn trusted_time_policy(
    state_identity: &str,
    remote_cursor_policy_sha256: &str,
) -> (TrustedTimePolicy, String, [SigningKey; 2]) {
    let current = now();
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
        effective_at_unix_seconds: current - 60,
        expires_at_unix_seconds: current + 60,
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
    (policy, pin, keys)
}

fn trusted_time_token(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey; 2],
    nonce: &str,
    at: u64,
) -> Vec<u8> {
    let message = trusted_time_signature_message(policy, pin, nonce, at, at + 30).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| TrustedTimeSignature {
            authority_id: format!("time-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    create_trusted_time_token(policy, pin, nonce, at, at + 30, &signatures).unwrap()
}

fn trusted_time(
    state_identity: &str,
    remote_cursor_policy_sha256: &str,
) -> (VerifiedTrustedTime, String) {
    let now = now();
    let nonce = "runtime_trusted_time_nonce_0123456789abcdef0123456789abcdef";
    let (policy, pin, keys) = trusted_time_policy(state_identity, remote_cursor_policy_sha256);
    let token = trusted_time_token(&policy, &pin, &keys, nonce, now);
    (
        verify_trusted_time_token(&token, &policy, &pin, nonce, None).unwrap(),
        pin,
    )
}

fn verified_time_at(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey; 2],
    at: u64,
) -> VerifiedTrustedTime {
    let nonce = "runtime_anchor_time_nonce_0123456789abcdef0123456789abcdef";
    verify_trusted_time_token(
        &trusted_time_token(policy, pin, keys, nonce, at),
        policy,
        pin,
        nonce,
        None,
    )
    .unwrap()
}

fn boundary_at(
    policy: &TrustedTimePolicy,
    pin: &str,
    keys: &[SigningKey; 2],
    floor: u64,
) -> TrustedTimeBoundary {
    verified_time_at(policy, pin, keys, floor - 30)
        .rollback_boundary()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn anchor_document(
    policy: &ExternalAnchorPolicy,
    pin: &str,
    keys: &[SigningKey; 2],
    generation: u64,
    boundary: &TrustedTimeBoundary,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let message = external_anchor_signature_message(
        policy, pin, generation, boundary, issued_at, expires_at, nonce,
    )
    .unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| ExternalAnchorSignature {
            authority_id: format!("anchor-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    create_external_anchor_document(
        policy,
        pin,
        generation,
        boundary,
        issued_at,
        expires_at,
        nonce,
        &signatures,
    )
    .unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
