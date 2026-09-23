use bloch_pay_reconciliation::*;

fn policy() -> ReconciliationPolicy {
    ReconciliationPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "merchant-a-reconciliation-v1".into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        max_invoice_lifetime_seconds: 1_000,
        allowed_source_ids: vec!["observer-a".into(), "observer-b".into()],
        routes: vec![PaymentRoute {
            route_id: "blch-l2".into(),
            network: "bloch-l2".into(),
            asset_id: "blch".into(),
            minor_unit_exponent: 18,
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
    }
}

fn invoice(id: &str, reference: &str, amount: u64) -> Invoice {
    Invoice {
        schema: INVOICE_SCHEMA.into(),
        invoice_id: id.into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        route_id: "blch-l2".into(),
        reference: reference.into(),
        amount_minor: amount,
        issued_at_unix_seconds: 200,
        expires_at_unix_seconds: 800,
    }
}

fn observation(id: &str, reference: &str, amount: u64, at: u64, index: u32) -> PaymentObservation {
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
        observed_at_unix_seconds: at,
        block_height: 1_000 + u64::from(index),
        block_hash: format!("0x{:064x}", u64::from(index) + 1),
    }
}

#[test]
fn canonical_policy_requires_independent_pin_and_exact_bytes() {
    let policy = policy();
    let bytes = canonical_policy_bytes(&policy).unwrap();
    let digest = policy_sha256(&policy).unwrap();
    assert_eq!(parse_policy(&bytes, &digest).unwrap(), policy);
    assert_eq!(
        parse_policy(&bytes, &format!("0x{}", "ab".repeat(32))),
        Err(ReconciliationError::PolicyDigestMismatch)
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert_eq!(
        parse_policy(&noncanonical, &digest),
        Err(ReconciliationError::NonCanonicalPolicy)
    );

    let text = String::from_utf8(canonical_policy_bytes(&policy).unwrap()).unwrap();
    let unknown = text.replacen('{', "{\"allow\":true,", 1);
    assert!(matches!(
        parse_policy(unknown.as_bytes(), &digest),
        Err(ReconciliationError::InvalidJson(_))
    ));
    let duplicate = text.replacen(
        "\"policyId\":",
        "\"policyId\":\"attacker\",\"policyId\":",
        1,
    );
    assert!(matches!(
        parse_policy(duplicate.as_bytes(), &digest),
        Err(ReconciliationError::InvalidJson(_))
    ));
    let oversized = vec![b' '; MAX_POLICY_BYTES + 1];
    assert!(matches!(
        parse_policy(&oversized, &digest),
        Err(ReconciliationError::TooLarge { .. })
    ));
}

#[test]
fn canonical_invoice_and_observation_bytes_are_validated_before_release() {
    let invoice = invoice("invoice-a", "reference-aaaaaaaa", 10);
    let observation = observation("obs-a", "reference-aaaaaaaa", 10, 300, 1);
    let invoice_value: serde_json::Value =
        serde_json::from_slice(&canonical_invoice_bytes(&policy(), &invoice).unwrap()).unwrap();
    let observation_value: serde_json::Value =
        serde_json::from_slice(&canonical_observation_bytes(&policy(), &observation, 500).unwrap())
            .unwrap();
    assert_eq!(invoice_value["invoiceId"], "invoice-a");
    assert_eq!(observation_value["observationId"], "obs-a");

    let mut invalid = observation;
    invalid.source_id = "untrusted".into();
    assert!(canonical_observation_bytes(&policy(), &invalid, 500).is_err());
}

#[test]
fn exact_partial_excess_and_no_observation_are_deterministic() {
    let invoices = vec![
        invoice("invoice-d", "reference-dddddd", 10),
        invoice("invoice-b", "reference-bbbbbbbb", 10),
        invoice("invoice-a", "reference-aaaaaaaa", 10),
        invoice("invoice-c", "reference-cccccccc", 10),
    ];
    let observations = vec![
        observation("obs-c1", "reference-cccccccc", 7, 300, 3),
        observation("obs-a1", "reference-aaaaaaaa", 10, 300, 1),
        observation("obs-b1", "reference-bbbbbbbb", 4, 300, 2),
        observation("obs-c2", "reference-cccccccc", 7, 301, 4),
    ];
    let report = reconcile(&policy(), &invoices, &observations, 500).unwrap();
    let states = report
        .invoices()
        .iter()
        .map(|item| (item.invoice_id(), item.state()))
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec![
            ("invoice-a", ReconciliationState::ExactObserved),
            ("invoice-b", ReconciliationState::PartialObserved),
            ("invoice-c", ReconciliationState::ExcessObserved),
            ("invoice-d", ReconciliationState::NoObservation),
        ]
    );
    assert!(!report.settlement_qualified());
    assert!(!report.credit_authorized());
    assert!(
        report
            .invoices()
            .iter()
            .all(|item| !item.settlement_qualified() && !item.credit_authorized())
    );
}

#[test]
fn late_and_unknown_observations_are_not_counted() {
    let invoices = vec![invoice("invoice-a", "reference-aaaaaaaa", 10)];
    let observations = vec![
        observation("obs-late", "reference-aaaaaaaa", 10, 800, 1),
        observation("obs-unknown", "reference-zzzzzzzz", 10, 300, 2),
    ];
    let report = reconcile(&policy(), &invoices, &observations, 900).unwrap();
    assert_eq!(
        report.invoices()[0].state(),
        ReconciliationState::NoObservation
    );
    assert_eq!(report.invoices()[0].late_observation_ids(), &["obs-late"]);
    assert_eq!(report.unmatched_observation_ids(), &["obs-unknown"]);
}

#[test]
fn route_source_tenant_and_future_substitution_fail_closed() {
    let invoices = vec![invoice("invoice-a", "reference-aaaaaaaa", 10)];
    let mut wrong_route = observation("obs-a", "reference-aaaaaaaa", 10, 300, 1);
    wrong_route.destination = "0x2222222222222222222222222222222222222222".into();
    assert_eq!(
        reconcile(&policy(), &invoices, &[wrong_route], 500),
        Err(ReconciliationError::RouteMismatch)
    );
    let mut wrong_source = observation("obs-a", "reference-aaaaaaaa", 10, 300, 1);
    wrong_source.source_id = "attacker".into();
    assert!(reconcile(&policy(), &invoices, &[wrong_source], 500).is_err());
    let mut cross_tenant = invoices[0].clone();
    cross_tenant.tenant_id = "tenant-b".into();
    assert!(reconcile(&policy(), &[cross_tenant], &[], 500).is_err());
    let future = observation("obs-a", "reference-aaaaaaaa", 10, 501, 1);
    assert!(reconcile(&policy(), &invoices, &[future], 500).is_err());
}

#[test]
fn duplicate_invoice_reference_and_chain_event_cannot_be_reused() {
    let first = invoice("invoice-a", "reference-aaaaaaaa", 10);
    let second = invoice("invoice-b", "reference-aaaaaaaa", 10);
    assert!(reconcile(&policy(), &[first.clone(), second], &[], 500).is_err());

    let first_observation = observation("obs-a", "reference-aaaaaaaa", 5, 300, 1);
    let mut duplicate_event = first_observation.clone();
    duplicate_event.observation_id = "obs-b".into();
    assert!(
        reconcile(
            &policy(),
            &[first],
            &[first_observation, duplicate_event],
            500
        )
        .is_err()
    );
}

#[test]
fn malformed_policy_invoice_and_observation_are_rejected() {
    let mut invalid_policy = policy();
    invalid_policy.allowed_source_ids.reverse();
    assert!(canonical_policy_bytes(&invalid_policy).is_err());
    let mut invalid_invoice = invoice("invoice-a", "short", 10);
    assert!(reconcile(&policy(), &[invalid_invoice.clone()], &[], 500).is_err());
    invalid_invoice.reference = "reference-aaaaaaaa".into();
    invalid_invoice.amount_minor = 0;
    assert!(reconcile(&policy(), &[invalid_invoice], &[], 500).is_err());
    let mut invalid_observation = observation("obs-a", "reference-aaaaaaaa", 10, 300, 1);
    invalid_observation.block_hash = format!("0x{}", "00".repeat(32));
    assert!(
        reconcile(
            &policy(),
            &[invoice("invoice-a", "reference-aaaaaaaa", 10)],
            &[invalid_observation],
            500
        )
        .is_err()
    );
}

#[test]
fn amount_overflow_fails_instead_of_wrapping() {
    let invoices = vec![invoice("invoice-a", "reference-aaaaaaaa", u64::MAX)];
    let observations = vec![
        observation("obs-a", "reference-aaaaaaaa", u64::MAX, 300, 1),
        observation("obs-b", "reference-aaaaaaaa", 1, 301, 2),
    ];
    assert_eq!(
        reconcile(&policy(), &invoices, &observations, 500),
        Err(ReconciliationError::AmountOverflow)
    );
}

#[test]
fn report_serialization_never_upgrades_observation_to_settlement() {
    let report = reconcile(
        &policy(),
        &[invoice("invoice-a", "reference-aaaaaaaa", 10)],
        &[observation("obs-a", "reference-aaaaaaaa", 10, 300, 1)],
        500,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&report_bytes(&report).unwrap()).unwrap();
    assert_eq!(value["settlementQualified"], false);
    assert_eq!(value["creditAuthorized"], false);
    assert_eq!(value["invoices"][0]["state"], "exact_observed");
    assert_eq!(value["invoices"][0]["settlementQualified"], false);
    assert_eq!(value["invoices"][0]["creditAuthorized"], false);
}
