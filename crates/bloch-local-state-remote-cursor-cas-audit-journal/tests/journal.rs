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
    caller_authorization_policy_sha256, caller_authorization_signature_message,
    create_caller_authorization, verify_caller_authorization_with_trusted_time,
};
use bloch_local_state_remote_cursor_cas_audit_journal::{
    AppendOutcome, CAS_AUDIT_JOURNAL_POLICY_SCHEMA, CasAuditJournalError, CasAuditJournalPolicy,
    append_verified_cas_event, journal_policy_sha256, provision_cas_audit_journal,
    read_cas_audit_entries,
};
use bloch_local_state_remote_cursor_cas_session::{
    CasCallerAuthorization, RemoteCursorCasSessionConfiguration, VerifiedRemoteCursorCasSession,
    execute_remote_cursor_cas_session,
};
use bloch_local_state_store::{StateRoot, write_state};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const CAS_NONCE: &str = "cas_nonce_0123456789abcdef0123456789abcdef";
const AUTH_NONCE: &str = "0x9999999999999999999999999999999999999999999999999999999999999999";
const TIME_NONCE: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
const SERVER_PIN: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
const CLIENT_PIN: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: std::path::PathBuf,
    journal: std::path::PathBuf,
    journal_policy: CasAuditJournalPolicy,
    journal_pin: String,
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
    transport_policy: AuthenticatedTransportPolicy,
    transport_pin: String,
    transport_keys: Vec<SigningKey>,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
    caller_policy: CallerAuthorizationPolicy,
    caller_pin: String,
    caller_key: SigningKey,
    initial: CheckpointCursor,
    initial_root: StateRoot,
    current: CheckpointCursor,
    successor: CheckpointCursor,
    successor_root: StateRoot,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bloch-cas-audit-{}-{unique}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let state_store = root.join("states");
        let root0 = write_state(&state_store, IDENTITY, 0, b"zero", None).unwrap();
        let root1 = write_state(&state_store, IDENTITY, 1, b"one", Some(&root0)).unwrap();
        let current = cursor_for(&root0, 11);
        let successor = cursor_for(&root1, 21);

        let remote_keys = keys(71, 2);
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-cas-policy".into(),
            signature_domain: "bloch-control-plane-cas".into(),
            state_identity: IDENTITY.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_observation_age_seconds: 100,
            authorities: remote_keys
                .iter()
                .enumerate()
                .map(|(i, k)| RemoteCursorAuthority {
                    authority_id: format!("remote-{}", i + 1),
                    ed25519_public_key: key_hex(k),
                })
                .collect(),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let time_keys = keys(61, 2);
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "audit-time".into(),
            signature_domain: "bloch-audit-time".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_token_lifetime_seconds: 30,
            authorities: time_keys
                .iter()
                .enumerate()
                .map(|(i, k)| TrustedTimeAuthority {
                    authority_id: format!("time-{}", i + 1),
                    ed25519_public_key: key_hex(k),
                })
                .collect(),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let transport_keys = keys(51, 2);
        let transport_policy = AuthenticatedTransportPolicy {
            schema: TRANSPORT_POLICY_SCHEMA.into(),
            policy_id: "audit-transport".into(),
            signature_domain: "bloch-audit-transport".into(),
            service_id: "cas-primary".into(),
            purpose: TransportPurpose::RemoteCursorCas,
            state_identity: IDENTITY.into(),
            trusted_time_policy_sha256: time_pin.clone(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            endpoint_dns_name: "cas.internal.example".into(),
            endpoint_port: 443,
            tls_version: "TLSv1.3".into(),
            alpn: "h2".into(),
            allowed_cipher_suites: vec!["TLS_AES_256_GCM_SHA384".into()],
            server_spki_sha256: vec![SERVER_PIN.into()],
            client_spki_sha256: CLIENT_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_evidence_age_seconds: 30,
            max_round_trip_millis: 2_000,
            max_response_bytes: 131_072,
            authorities: transport_keys
                .iter()
                .enumerate()
                .map(|(i, k)| TransportAuthority {
                    authority_id: format!("transport-{}", i + 1),
                    ed25519_public_key: key_hex(k),
                })
                .collect(),
        };
        let transport_pin = authenticated_transport_policy_sha256(&transport_policy).unwrap();
        let caller_key = SigningKey::from_bytes(&[41; 32]);
        let caller_policy = CallerAuthorizationPolicy {
            schema: CALLER_AUTH_POLICY_SCHEMA.into(),
            policy_id: "audit-caller".into(),
            signature_domain: "bloch-audit-caller".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            threshold: 1,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_authorization_age_seconds: 100,
            max_authorization_lifetime_seconds: 100,
            authorities: vec![CallerAuthority {
                authority_id: "caller-1".into(),
                ed25519_public_key: key_hex(&caller_key),
            }],
        };
        let caller_pin = caller_authorization_policy_sha256(&caller_policy).unwrap();
        let journal_policy = CasAuditJournalPolicy {
            schema: CAS_AUDIT_JOURNAL_POLICY_SCHEMA.into(),
            policy_id: "cas-audit".into(),
            state_identity: IDENTITY.into(),
            remote_cursor_policy_sha256: remote_pin.clone(),
            cas_policy_sha256: remote_pin.clone(),
            cas_signature_domain: remote_policy.signature_domain.clone(),
            authenticated_transport_policy_sha256: transport_pin.clone(),
        };
        let journal_pin = journal_policy_sha256(&journal_policy).unwrap();
        let journal = root.join("journal");
        provision_cas_audit_journal(&journal, &journal_policy, &journal_pin).unwrap();
        Self {
            root,
            journal,
            journal_policy,
            journal_pin,
            remote_policy,
            remote_pin,
            remote_keys,
            transport_policy,
            transport_pin,
            transport_keys,
            time_policy,
            time_pin,
            time_keys,
            caller_policy,
            caller_pin,
            caller_key,
            initial: current.clone(),
            initial_root: root0,
            current,
            successor,
            successor_root: root1,
        }
    }

    fn session(
        &self,
        request_id: &str,
        decision: RemoteCursorCasDecision,
    ) -> VerifiedRemoteCursorCasSession {
        self.session_for(
            request_id,
            decision,
            Some(&self.current),
            &self.successor,
            &self.successor_root,
        )
    }

    fn bootstrap_session(
        &self,
        request_id: &str,
        decision: RemoteCursorCasDecision,
    ) -> VerifiedRemoteCursorCasSession {
        self.session_for(
            request_id,
            decision,
            None,
            &self.initial,
            &self.initial_root,
        )
    }

    fn session_for(
        &self,
        request_id: &str,
        decision: RemoteCursorCasDecision,
        expected_current: Option<&CheckpointCursor>,
        successor: &CheckpointCursor,
        successor_root: &StateRoot,
    ) -> VerifiedRemoteCursorCasSession {
        let request_bytes = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current,
                successor_cursor: successor,
                successor_root,
                request_id,
                request_nonce: CAS_NONCE,
                requested_at_unix_seconds: 200,
            },
            &self.remote_policy,
            &self.remote_pin,
        )
        .unwrap();
        let request =
            parse_remote_cursor_cas_request(&request_bytes, &self.remote_policy, &self.remote_pin)
                .unwrap();
        let receipt_message = remote_cursor_cas_receipt_signature_message(
            &request_bytes,
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            240,
        )
        .unwrap();
        let receipt_signatures = self
            .remote_keys
            .iter()
            .enumerate()
            .map(|(i, k)| RemoteCursorSignature {
                authority_id: format!("remote-{}", i + 1),
                signature: signature_hex(k, &receipt_message),
            })
            .collect::<Vec<_>>();
        let receipt = create_remote_cursor_cas_receipt(
            &request_bytes,
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            240,
            &receipt_signatures,
        )
        .unwrap();
        let time = self.trusted_time();
        let auth_message = caller_authorization_signature_message(
            &request,
            &self.caller_policy,
            &self.caller_pin,
            AUTH_NONCE,
            240,
            275,
        )
        .unwrap();
        let auth_bytes = create_caller_authorization(
            &request,
            &self.caller_policy,
            &self.caller_pin,
            AUTH_NONCE,
            240,
            275,
            &[CallerSignature {
                authority_id: "caller-1".into(),
                signature: signature_hex(&self.caller_key, &auth_message),
            }],
        )
        .unwrap();
        let auth = verify_caller_authorization_with_trusted_time(
            &auth_bytes,
            &request,
            &self.caller_policy,
            &self.caller_pin,
            AUTH_NONCE,
            &time,
        )
        .unwrap();
        execute_remote_cursor_cas_session(
            &request,
            CasCallerAuthorization::Verified {
                canonical_authorization_bytes: &auth_bytes,
                authorization: &auth,
            },
            RemoteCursorCasSessionConfiguration {
                remote_cursor_policy: &self.remote_policy,
                expected_remote_cursor_policy_sha256: &self.remote_pin,
                transport_policy: &self.transport_policy,
                expected_transport_policy_sha256: &self.transport_pin,
                timeout: Duration::from_secs(1),
            },
            &time,
            |wire| {
                let parameters = TransportExchangeParameters {
                    request_nonce: wire.request_nonce(),
                    request_bytes: wire.request_bytes(),
                    response_bytes: &receipt,
                    round_trip_millis: 10,
                    observed_at_unix_seconds: 250,
                    cipher_suite: "TLS_AES_256_GCM_SHA384",
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
                    .map(|(i, k)| TransportEvidenceSignature {
                        authority_id: format!("transport-{}", i + 1),
                        signature: signature_hex(k, &message),
                    })
                    .collect::<Vec<_>>();
                let evidence = create_authenticated_transport_evidence_for_exchange(
                    &self.transport_policy,
                    &self.transport_pin,
                    parameters,
                    &signatures,
                )
                .unwrap();
                collect(&wire, &receipt, &evidence)
            },
        )
        .unwrap()
    }

    fn trusted_time(&self) -> VerifiedTrustedTime {
        let message =
            trusted_time_signature_message(&self.time_policy, &self.time_pin, TIME_NONCE, 250, 280)
                .unwrap();
        let signatures = self
            .time_keys
            .iter()
            .enumerate()
            .map(|(i, k)| TrustedTimeSignature {
                authority_id: format!("time-{}", i + 1),
                signature: signature_hex(k, &message),
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn exact_session_append_and_replay_are_idempotent() {
    let f = Fixture::new();
    let session = f.session("request-1", RemoteCursorCasDecision::Accepted);
    assert_eq!(append(&f, &session).unwrap(), AppendOutcome::Appended);
    assert_eq!(append(&f, &session).unwrap(), AppendOutcome::ExactReplay);
    let entries = read_cas_audit_entries(&f.journal, &f.journal_policy, &f.journal_pin).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!((entries[0].sequence, entries[0].generation), (0, 1));
}

#[test]
fn same_request_changed_decision_and_second_acceptance_are_equivocation() {
    let f = Fixture::new();
    let refusal = f.session(
        "request-1",
        RemoteCursorCasDecision::Refused {
            reason_code: "conflict".into(),
        },
    );
    append(&f, &refusal).unwrap();
    let changed = f.session("request-1", RemoteCursorCasDecision::Accepted);
    assert!(matches!(
        append(&f, &changed),
        Err(CasAuditJournalError::Equivocation)
    ));

    let accepted = f.session("request-2", RemoteCursorCasDecision::Accepted);
    append(&f, &accepted).unwrap();
    let second = f.session("request-3", RemoteCursorCasDecision::Accepted);
    assert!(matches!(
        append(&f, &second),
        Err(CasAuditJournalError::Equivocation)
    ));
}

#[test]
fn crash_temp_is_removed_and_unsafe_mode_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let stale = f
        .journal
        .join(".journal.json.tmp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    std::fs::write(&stale, b"partial").unwrap();
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600)).unwrap();
    append(
        &f,
        &f.session("request-1", RemoteCursorCasDecision::Accepted),
    )
    .unwrap();
    assert!(!stale.exists());
    std::fs::set_permissions(
        f.journal.join("journal.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        read_cas_audit_entries(&f.journal, &f.journal_policy, &f.journal_pin),
        Err(CasAuditJournalError::UnsafeStore(_))
    ));
}

#[test]
fn hard_link_and_generation_rollback_fail_closed() {
    let f = Fixture::new();
    append(
        &f,
        &f.session("request-1", RemoteCursorCasDecision::Accepted),
    )
    .unwrap();
    let rollback = f.bootstrap_session(
        "request-bootstrap",
        RemoteCursorCasDecision::Refused {
            reason_code: "conflict".into(),
        },
    );
    assert!(matches!(
        append(&f, &rollback),
        Err(CasAuditJournalError::Rollback)
    ));

    std::fs::hard_link(
        f.journal.join("journal.json"),
        f.root.join("journal-hard-link"),
    )
    .unwrap();
    assert!(matches!(
        read_cas_audit_entries(&f.journal, &f.journal_policy, &f.journal_pin),
        Err(CasAuditJournalError::UnsafeStore(_))
    ));
}

#[test]
fn concurrent_distinct_refusals_preserve_all_entries() {
    let f = Arc::new(Fixture::new());
    let threads = (0..8)
        .map(|i| {
            let f = Arc::clone(&f);
            std::thread::spawn(move || {
                let session = f.session(
                    &format!("request-{i}"),
                    RemoteCursorCasDecision::Refused {
                        reason_code: "conflict".into(),
                    },
                );
                loop {
                    match append(&f, &session) {
                        Err(CasAuditJournalError::StoreBusy) => continue,
                        value => return value.unwrap(),
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    assert!(
        threads
            .into_iter()
            .all(|t| t.join().unwrap() == AppendOutcome::Appended)
    );
    assert_eq!(
        read_cas_audit_entries(&f.journal, &f.journal_policy, &f.journal_pin)
            .unwrap()
            .len(),
        8
    );
}

fn append(
    f: &Fixture,
    session: &VerifiedRemoteCursorCasSession,
) -> Result<AppendOutcome, CasAuditJournalError> {
    append_verified_cas_event(&f.journal, &f.journal_policy, &f.journal_pin, session)
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
fn keys(first: u8, count: u8) -> Vec<SigningKey> {
    (first..first + count)
        .map(|value| SigningKey::from_bytes(&[value; 32]))
        .collect()
}
fn key_hex(key: &SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().as_bytes()))
}
fn signature_hex(key: &SigningKey, message: &[u8]) -> String {
    format!("0x{}", hex::encode(key.sign(message).to_bytes()))
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
fn cursor_for(root: &StateRoot, marker: u8) -> CheckpointCursor {
    let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
    let bytes = format!(
        "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
        root.state_identity(),
        root.generation(),
        digest(marker),
        digest(marker + 1),
        digest(marker + 2),
        hash(&root.canonical_bytes().unwrap()),
        root.state_sha256()
    );
    parse_cursor(bytes.as_bytes()).unwrap()
}
