#![cfg(unix)]

use bloch_pay_allocation_store::*;
use bloch_pay_reconciliation::*;
use ed25519_dalek::{Signer, SigningKey};
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn authenticated_exact_replay_is_idempotent_and_recovers_after_orphan_temp() {
    let fixture = Fixture::new();
    let first = fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();
    let before = fs::read(fixture.store.join("allocations.json")).unwrap();
    fs::write(
        fixture.store.join(".allocations.json.tmp-crash"),
        b"partial",
    )
    .unwrap();
    let second = fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        before,
        fs::read(fixture.store.join("allocations.json")).unwrap()
    );
    assert_eq!(second.observer_id(), "signer-a");
    assert_eq!(second.observer_policy_sha256(), fixture.observer_policy_pin);
    assert!(!second.settlement_qualified());
    assert!(!second.credit_authorized());
    assert!(!second.funds_released());
}

#[test]
fn duplicate_observation_and_network_event_fail_closed() {
    let fixture = Fixture::new();
    fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();
    assert!(matches!(
        fixture.allocate("allocation-b", &fixture.authenticated),
        Err(AllocationError::DuplicateObservation)
    ));

    let mut same_event = observation("observation-b", "reference-bbbbbbbb", 10, 2);
    same_event.transaction_id = fixture.observation.transaction_id.clone();
    same_event.event_index = fixture.observation.event_index;
    let authenticated = fixture.authenticate(&same_event);
    let report = reconcile_authenticated(
        &fixture.policy,
        &fixture.policy_pin,
        &[invoice("invoice-b", "reference-bbbbbbbb")],
        std::slice::from_ref(&authenticated),
        500,
    )
    .unwrap();
    let request = AllocationRequest {
        allocation_id: "allocation-b".into(),
        kind: AllocationKind::Matched,
        invoice_id: Some("invoice-b".into()),
    };
    assert!(matches!(
        allocate(&fixture.store, &request, &report, &authenticated),
        Err(AllocationError::DuplicateNetworkEvent)
    ));
}

#[test]
fn report_and_exact_authenticated_observation_evidence_are_bound() {
    let fixture = Fixture::new();
    let wrong = AllocationRequest {
        allocation_id: "allocation-a".into(),
        kind: AllocationKind::Late,
        invoice_id: Some("invoice-a".into()),
    };
    assert!(matches!(
        allocate(
            &fixture.store,
            &wrong,
            &fixture.report,
            &fixture.authenticated
        ),
        Err(AllocationError::ReportMismatch)
    ));
    fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();

    let changed_report = reconcile_authenticated(
        &fixture.policy,
        &fixture.policy_pin,
        &[invoice("invoice-a", "reference-aaaaaaaa")],
        std::slice::from_ref(&fixture.authenticated),
        501,
    )
    .unwrap();
    let request = AllocationRequest {
        allocation_id: "allocation-a".into(),
        kind: AllocationKind::Matched,
        invoice_id: Some("invoice-a".into()),
    };
    assert!(matches!(
        allocate(
            &fixture.store,
            &request,
            &changed_report,
            &fixture.authenticated
        ),
        Err(AllocationError::AllocationConflict)
    ));

    // A separately valid signature cannot substitute different bytes under
    // the same observation ID for the evidence retained by this report.
    let mut changed = fixture.observation.clone();
    changed.amount_minor += 1;
    let changed = fixture.authenticate(&changed);
    assert!(matches!(
        allocate(&fixture.store, &request, &fixture.report, &changed),
        Err(AllocationError::InvalidReportEvidence)
    ));
}

#[test]
fn raw_report_has_no_allocation_bypass() {
    let fixture = Fixture::new();
    let raw = reconcile(
        &fixture.policy,
        &[invoice("invoice-a", "reference-aaaaaaaa")],
        std::slice::from_ref(&fixture.observation),
        500,
    )
    .unwrap();
    let request = AllocationRequest {
        allocation_id: "raw-refused".into(),
        kind: AllocationKind::Matched,
        invoice_id: Some("invoice-a".into()),
    };
    assert!(matches!(
        allocate(&fixture.store, &request, &raw, &fixture.authenticated),
        Err(AllocationError::InvalidReportEvidence)
    ));
}

#[test]
fn corruption_hardlinks_permissions_and_symlinks_are_rejected() {
    let fixture = Fixture::new();
    fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();
    assert_eq!(
        fs::metadata(&fixture.store).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let state = fixture.store.join("allocations.json");
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut bytes = fs::read(&state).unwrap();
    bytes.push(b'\n');
    fs::write(&state, bytes).unwrap();
    assert!(matches!(
        fixture.allocate("allocation-a", &fixture.authenticated),
        Err(AllocationError::InvalidState)
    ));

    let other = Fixture::new();
    other
        .allocate("allocation-a", &other.authenticated)
        .unwrap();
    fs::hard_link(
        other.store.join("allocations.json"),
        other.store.join("alias"),
    )
    .unwrap();
    assert!(matches!(
        other.allocate("allocation-a", &other.authenticated),
        Err(AllocationError::UnsafeStore(_))
    ));

    let third = Fixture::new();
    third
        .allocate("allocation-a", &third.authenticated)
        .unwrap();
    let link = third.root.join("store-link");
    symlink(&third.store, &link).unwrap();
    let request = AllocationRequest {
        allocation_id: "allocation-b".into(),
        kind: AllocationKind::Matched,
        invoice_id: Some("invoice-a".into()),
    };
    assert!(matches!(
        allocate(&link, &request, &third.report, &third.authenticated),
        Err(AllocationError::UnsafeStore(_))
    ));
}

#[test]
fn live_writer_lock_has_a_bounded_failure() {
    let fixture = Fixture::new();
    fixture
        .allocate("allocation-a", &fixture.authenticated)
        .unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.store.join(".allocation.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let started = std::time::Instant::now();
    assert!(matches!(
        fixture.allocate("allocation-a", &fixture.authenticated),
        Err(AllocationError::StoreBusy)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

struct Fixture {
    root: PathBuf,
    store: PathBuf,
    key: SigningKey,
    policy: ReconciliationPolicy,
    policy_pin: String,
    observer_policy: ObserverTrustPolicy,
    observer_policy_pin: String,
    observation: PaymentObservation,
    authenticated: AuthenticatedPaymentObservation,
    report: ReconciliationReport,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "bloch-pay-allocation-auth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let key = SigningKey::from_bytes(&[17; 32]);
        let policy = policy();
        let policy_pin = policy_sha256(&policy).unwrap();
        let observer_policy = observer_policy(&key, &policy_pin);
        let observer_policy_pin = observer_policy_sha256(&observer_policy).unwrap();
        let observation = observation("observation-a", "reference-aaaaaaaa", 10, 1);
        let authenticated = authenticate(
            &key,
            &policy,
            &policy_pin,
            &observer_policy,
            &observer_policy_pin,
            &observation,
        );
        let report = reconcile_authenticated(
            &policy,
            &policy_pin,
            &[invoice("invoice-a", "reference-aaaaaaaa")],
            std::slice::from_ref(&authenticated),
            500,
        )
        .unwrap();
        Self {
            store: root.join("store"),
            root,
            key,
            policy,
            policy_pin,
            observer_policy,
            observer_policy_pin,
            observation,
            authenticated,
            report,
        }
    }

    fn authenticate(&self, observation: &PaymentObservation) -> AuthenticatedPaymentObservation {
        authenticate(
            &self.key,
            &self.policy,
            &self.policy_pin,
            &self.observer_policy,
            &self.observer_policy_pin,
            observation,
        )
    }

    fn allocate(
        &self,
        id: &str,
        observation: &AuthenticatedPaymentObservation,
    ) -> Result<AllocationReceipt, AllocationError> {
        allocate(
            &self.store,
            &AllocationRequest {
                allocation_id: id.into(),
                kind: AllocationKind::Matched,
                invoice_id: Some("invoice-a".into()),
            },
            &self.report,
            observation,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn authenticate(
    key: &SigningKey,
    policy: &ReconciliationPolicy,
    policy_pin: &str,
    observers: &ObserverTrustPolicy,
    observer_pin: &str,
    observation: &PaymentObservation,
) -> AuthenticatedPaymentObservation {
    let message = observation_signing_bytes(
        policy,
        policy_pin,
        observers,
        observer_pin,
        "signer-a",
        observation,
        500,
    )
    .unwrap();
    let envelope = encode_observation_signature_envelope(
        policy,
        policy_pin,
        observers,
        observer_pin,
        "signer-a",
        observation,
        500,
        &key.sign(&message).to_bytes(),
    )
    .unwrap();
    verify_authenticated_observation(
        &envelope,
        policy,
        policy_pin,
        observers,
        observer_pin,
        observation,
        500,
    )
    .unwrap()
}

fn observer_policy(key: &SigningKey, reconciliation_policy_sha256: &str) -> ObserverTrustPolicy {
    ObserverTrustPolicy {
        schema: OBSERVER_POLICY_SCHEMA.into(),
        policy_id: "observer-policy-a".into(),
        signature_domain: "bloch-pay-production".into(),
        reconciliation_policy_sha256: reconciliation_policy_sha256.into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        observers: vec![TrustedObserver {
            observer_id: "signer-a".into(),
            source_id: "observer-a".into(),
            network: "bloch-l2".into(),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
        }],
    }
}

fn policy() -> ReconciliationPolicy {
    ReconciliationPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "policy-a".into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        max_invoice_lifetime_seconds: 1_000,
        allowed_source_ids: vec!["observer-a".into()],
        routes: vec![PaymentRoute {
            route_id: "route-a".into(),
            network: "bloch-l2".into(),
            asset_id: "blch".into(),
            minor_unit_exponent: 18,
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
    }
}
fn invoice(id: &str, reference: &str) -> Invoice {
    Invoice {
        schema: INVOICE_SCHEMA.into(),
        invoice_id: id.into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        route_id: "route-a".into(),
        reference: reference.into(),
        amount_minor: 10,
        issued_at_unix_seconds: 200,
        expires_at_unix_seconds: 800,
    }
}
fn observation(id: &str, reference: &str, amount: u64, index: u32) -> PaymentObservation {
    PaymentObservation {
        schema: OBSERVATION_SCHEMA.into(),
        observation_id: id.into(),
        source_id: "observer-a".into(),
        network: "bloch-l2".into(),
        transaction_id: format!("0x{:064x}", u64::from(index) + 1),
        event_index: index,
        asset_id: "blch".into(),
        destination: "0x1111111111111111111111111111111111111111".into(),
        reference: reference.into(),
        amount_minor: amount,
        observed_at_unix_seconds: 300,
        block_height: 1_000,
        block_hash: format!("0x{:064x}", u64::from(index) + 1),
    }
}
