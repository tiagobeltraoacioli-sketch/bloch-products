use bloch_pay_adjustments::*;
use bloch_pay_reconciliation::*;
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn dispute_refund_lifecycle_is_deterministic_replay_safe_and_non_custodial() {
    let fixture = Fixture::new();
    let state = initialize_adjustment(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        &fixture.reconciliation,
        &fixture.reconciliation_pin,
        "adjust-a",
        &fixture.payment,
    )
    .unwrap();
    let opened = fixture.authenticate(event(
        1,
        AdjustmentEventKind::DisputeOpenedObserved,
        "case-open",
        None,
    ));
    let disputed = apply_adjustment_event(&state, &opened).unwrap();
    assert_eq!(disputed.status(), AdjustmentStatus::Disputed);
    assert_eq!(
        apply_adjustment_event(&disputed, &opened).unwrap(),
        disputed
    );

    let resolved = fixture.authenticate(event(
        2,
        AdjustmentEventKind::DisputeResolvedRefundExpectedObserved,
        "case-resolved",
        None,
    ));
    let expected = apply_adjustment_event(&disputed, &resolved).unwrap();
    assert_eq!(expected.status(), AdjustmentStatus::RefundExpected);
    let refunded = fixture.authenticate(event(
        3,
        AdjustmentEventKind::RefundObserved,
        "refund-a",
        Some(("0xrefund1", 0, 10)),
    ));
    let final_state = apply_adjustment_event(&expected, &refunded).unwrap();
    assert_eq!(final_state.status(), AdjustmentStatus::RefundObserved);
    assert_eq!(final_state.generation(), 3);
    assert!(!final_state.settlement_qualified());
    assert!(!final_state.credit_authorized());
    assert!(!final_state.funds_moved());
    assert!(!refunded.settlement_qualified());
    assert!(!refunded.credit_authorized());
    assert!(!refunded.funds_moved());
    let state_bytes = final_state.canonical_bytes();
    let state_digest = final_state.state_sha256();
    let restored = restore_adjustment_state(
        &state_bytes,
        AdjustmentStateExpectation {
            adjustment_policy_sha256: &fixture.adjustments_pin,
            reconciliation_policy_sha256: &fixture.reconciliation_pin,
            adjustment_id: "adjust-a",
            payment_observation_id: fixture.payment.observation().observation_id.as_str(),
            payment_observation_sha256: fixture.payment.canonical_observation_sha256(),
            payment_amount_minor: fixture.payment.observation().amount_minor,
            generation: 3,
            state_sha256: &state_digest,
        },
    )
    .unwrap();
    assert_eq!(restored.canonical_bytes(), state_bytes);
    assert_eq!(restored.status(), AdjustmentStatus::RefundObserved);

    let mut tampered = state_bytes;
    tampered.push(b'\n');
    assert_eq!(
        restore_adjustment_state(
            &tampered,
            AdjustmentStateExpectation {
                adjustment_policy_sha256: &fixture.adjustments_pin,
                reconciliation_policy_sha256: &fixture.reconciliation_pin,
                adjustment_id: "adjust-a",
                payment_observation_id: fixture.payment.observation().observation_id.as_str(),
                payment_observation_sha256: fixture.payment.canonical_observation_sha256(),
                payment_amount_minor: fixture.payment.observation().amount_minor,
                generation: 3,
                state_sha256: &state_digest,
            },
        ),
        Err(AdjustmentError::StateExpectationMismatch)
    );
}

#[test]
fn cancellation_and_invalid_transitions_fail_closed() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let request = fixture.authenticate(event(
        1,
        AdjustmentEventKind::CancellationRequestedObserved,
        "cancel-request",
        None,
    ));
    let pending = apply_adjustment_event(&state, &request).unwrap();
    assert_eq!(pending.status(), AdjustmentStatus::CancellationPending);
    let disputed_while_pending = fixture.authenticate(event(
        2,
        AdjustmentEventKind::DisputeOpenedObserved,
        "case-while-pending",
        None,
    ));
    assert_eq!(
        apply_adjustment_event(&pending, &disputed_while_pending),
        Err(AdjustmentError::InvalidTransition)
    );
    let confirmed = fixture.authenticate(event(
        2,
        AdjustmentEventKind::CancellationConfirmedObserved,
        "cancel-confirmed",
        None,
    ));
    let cancelled = apply_adjustment_event(&pending, &confirmed).unwrap();
    assert_eq!(cancelled.status(), AdjustmentStatus::Cancelled);
    let impossible = fixture.authenticate(event(
        3,
        AdjustmentEventKind::DisputeResolvedNoRefundObserved,
        "resolution",
        None,
    ));
    assert_eq!(
        apply_adjustment_event(&cancelled, &impossible),
        Err(AdjustmentError::InvalidTransition)
    );
    let skipped = fixture.authenticate(event(
        4,
        AdjustmentEventKind::DisputeOpenedObserved,
        "case",
        None,
    ));
    assert_eq!(
        apply_adjustment_event(&cancelled, &skipped),
        Err(AdjustmentError::InvalidSequence)
    );
}

#[test]
fn signature_policy_authority_and_context_substitution_are_rejected() {
    let fixture = Fixture::new();
    let event = event(1, AdjustmentEventKind::DisputeOpenedObserved, "case", None);
    let message = adjustment_event_signing_bytes(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        "authority-a",
        &event,
    )
    .unwrap();
    let wrong = SigningKey::from_bytes(&[55; 32]);
    assert_eq!(
        verify_adjustment_event(
            &fixture.adjustments,
            &fixture.adjustments_pin,
            "authority-a",
            &event,
            &wrong.sign(&message).to_bytes(),
            550
        ),
        Err(AdjustmentError::InvalidSignature)
    );
    assert!(matches!(
        adjustment_event_signing_bytes(
            &fixture.adjustments,
            &format!("0x{}", "1".repeat(64)),
            "authority-a",
            &event
        ),
        Err(AdjustmentError::PolicyPinMismatch)
    ));
    let mut wrong_source = event.clone();
    wrong_source.source_id = "other-source".into();
    assert!(matches!(
        adjustment_event_signing_bytes(
            &fixture.adjustments,
            &fixture.adjustments_pin,
            "authority-a",
            &wrong_source
        ),
        Err(AdjustmentError::UnauthorizedAuthority)
    ));
    let mut wrong_context = event;
    wrong_context.adjustment_id = "adjust-b".into();
    let authenticated = fixture.authenticate(wrong_context);
    assert_eq!(
        apply_adjustment_event(&fixture.state(), &authenticated),
        Err(AdjustmentError::ContextMismatch)
    );
}

#[test]
fn conflicting_identity_network_event_stale_and_malformed_refund_are_rejected() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let first = fixture.authenticate(event(
        1,
        AdjustmentEventKind::DisputeOpenedObserved,
        "same-reference",
        Some(("0xtx1", 1, 0)),
    ));
    let state = apply_adjustment_event(&state, &first).unwrap();
    let duplicate_reference = fixture.authenticate(event(
        2,
        AdjustmentEventKind::DisputeResolvedNoRefundObserved,
        "same-reference",
        None,
    ));
    assert_eq!(
        apply_adjustment_event(&state, &duplicate_reference),
        Err(AdjustmentError::EventConflict)
    );

    let malformed = event(2, AdjustmentEventKind::RefundObserved, "refund", None);
    assert_eq!(
        adjustment_event_bytes(&malformed),
        Err(AdjustmentError::InvalidEvent)
    );
    let stale = event(
        2,
        AdjustmentEventKind::DisputeResolvedNoRefundObserved,
        "resolved",
        None,
    );
    let message = adjustment_event_signing_bytes(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        "authority-a",
        &stale,
    )
    .unwrap();
    assert_eq!(
        verify_adjustment_event(
            &fixture.adjustments,
            &fixture.adjustments_pin,
            "authority-a",
            &stale,
            &fixture.adjustment_key.sign(&message).to_bytes(),
            701
        ),
        Err(AdjustmentError::OutsideValidityWindow)
    );

    let over_refund = fixture.authenticate(event(
        2,
        AdjustmentEventKind::RefundObserved,
        "over-refund",
        Some(("0xtx2", 2, 11)),
    ));
    assert_eq!(
        apply_adjustment_event(&state, &over_refund),
        Err(AdjustmentError::RefundAmountExceeded)
    );
}

#[test]
fn canonical_policy_parser_and_payment_digest_binding_fail_closed() {
    let fixture = Fixture::new();
    let bytes = adjustment_policy_bytes(&fixture.adjustments).unwrap();
    assert_eq!(
        parse_adjustment_policy(&bytes, &fixture.adjustments_pin).unwrap(),
        fixture.adjustments
    );
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        parse_adjustment_policy(&trailing, &fixture.adjustments_pin),
        Err(AdjustmentError::InvalidPolicy)
    );
    let unknown = String::from_utf8(bytes)
        .unwrap()
        .replacen('{', "{\"unknown\":true,", 1);
    assert_eq!(
        parse_adjustment_policy(unknown.as_bytes(), &fixture.adjustments_pin),
        Err(AdjustmentError::InvalidPolicy)
    );

    let mut substituted = event(
        1,
        AdjustmentEventKind::DisputeOpenedObserved,
        "substitution",
        None,
    );
    substituted.payment_observation_sha256 = format!("0x{}", "4".repeat(64));
    let message = adjustment_event_signing_bytes(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        "authority-a",
        &substituted,
    )
    .unwrap();
    let authenticated = verify_adjustment_event(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        "authority-a",
        &substituted,
        &fixture.adjustment_key.sign(&message).to_bytes(),
        550,
    )
    .unwrap();
    assert_eq!(
        apply_adjustment_event(&fixture.state(), &authenticated),
        Err(AdjustmentError::ContextMismatch)
    );
}

#[test]
fn reconciliation_context_authority_order_keys_and_exclusive_expiry_fail_closed() {
    let fixture = Fixture::new();
    let mut wrong_tenant = fixture.adjustments.clone();
    wrong_tenant.tenant_id = "tenant-b".into();
    let wrong_tenant_pin = adjustment_policy_sha256(&wrong_tenant).unwrap();
    assert_eq!(
        initialize_adjustment(
            &wrong_tenant,
            &wrong_tenant_pin,
            &fixture.reconciliation,
            &fixture.reconciliation_pin,
            "adjust-a",
            &fixture.payment,
        ),
        Err(AdjustmentError::ContextMismatch)
    );

    let mut wrong_source = fixture.adjustments.clone();
    wrong_source.authorities[0].source_id = "unapproved-source".into();
    let wrong_source_pin = adjustment_policy_sha256(&wrong_source).unwrap();
    assert_eq!(
        initialize_adjustment(
            &wrong_source,
            &wrong_source_pin,
            &fixture.reconciliation,
            &fixture.reconciliation_pin,
            "adjust-a",
            &fixture.payment,
        ),
        Err(AdjustmentError::ContextMismatch)
    );

    let mut duplicate_key = fixture.adjustments.clone();
    let mut second = duplicate_key.authorities[0].clone();
    second.authority_id = "authority-b".into();
    duplicate_key.authorities.push(second);
    assert_eq!(
        adjustment_policy_sha256(&duplicate_key),
        Err(AdjustmentError::InvalidPolicy)
    );
    duplicate_key.authorities.swap(0, 1);
    duplicate_key.authorities[0].ed25519_public_key = format!(
        "0x{}",
        hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes())
    );
    assert_eq!(
        adjustment_policy_sha256(&duplicate_key),
        Err(AdjustmentError::InvalidPolicy)
    );

    let mut expired = event(
        1,
        AdjustmentEventKind::DisputeOpenedObserved,
        "at-expiry",
        None,
    );
    expired.payment_observation_sha256 = fixture.payment.canonical_observation_sha256().into();
    expired.occurred_at_unix_seconds = fixture.adjustments.expires_at_unix_seconds;
    let message = adjustment_event_signing_bytes(
        &fixture.adjustments,
        &fixture.adjustments_pin,
        "authority-a",
        &expired,
    )
    .unwrap();
    assert_eq!(
        verify_adjustment_event(
            &fixture.adjustments,
            &fixture.adjustments_pin,
            "authority-a",
            &expired,
            &fixture.adjustment_key.sign(&message).to_bytes(),
            fixture.adjustments.expires_at_unix_seconds,
        ),
        Err(AdjustmentError::OutsideValidityWindow)
    );
}

struct Fixture {
    adjustment_key: SigningKey,
    reconciliation: ReconciliationPolicy,
    reconciliation_pin: String,
    adjustments: AdjustmentPolicy,
    adjustments_pin: String,
    payment: AuthenticatedPaymentObservation,
}

impl Fixture {
    fn new() -> Self {
        let payment_key = SigningKey::from_bytes(&[17; 32]);
        let reconciliation = reconciliation_policy();
        let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
        let observer = ObserverTrustPolicy {
            schema: OBSERVER_POLICY_SCHEMA.into(),
            policy_id: "observer-policy".into(),
            signature_domain: "payment-production".into(),
            reconciliation_policy_sha256: reconciliation_pin.clone(),
            tenant_id: "tenant-a".into(),
            merchant_id: "merchant-a".into(),
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 10_000,
            observers: vec![TrustedObserver {
                observer_id: "payment-observer".into(),
                source_id: "source-a".into(),
                network: "bloch-l2".into(),
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(payment_key.verifying_key().to_bytes())
                ),
            }],
        };
        let observer_pin = observer_policy_sha256(&observer).unwrap();
        let observation = PaymentObservation {
            schema: OBSERVATION_SCHEMA.into(),
            observation_id: "payment-a".into(),
            source_id: "source-a".into(),
            network: "bloch-l2".into(),
            transaction_id: format!("0x{}", "1".repeat(64)),
            event_index: 0,
            asset_id: "blch".into(),
            destination: "0x1111111111111111111111111111111111111111".into(),
            reference: "invoice-reference".into(),
            amount_minor: 10,
            observed_at_unix_seconds: 400,
            block_height: 10,
            block_hash: format!("0x{}", "2".repeat(64)),
        };
        let payment_message = observation_signing_bytes(
            &reconciliation,
            &reconciliation_pin,
            &observer,
            &observer_pin,
            "payment-observer",
            &observation,
            500,
        )
        .unwrap();
        let envelope = encode_observation_signature_envelope(
            &reconciliation,
            &reconciliation_pin,
            &observer,
            &observer_pin,
            "payment-observer",
            &observation,
            500,
            &payment_key.sign(&payment_message).to_bytes(),
        )
        .unwrap();
        let payment = verify_authenticated_observation(
            &envelope,
            &reconciliation,
            &reconciliation_pin,
            &observer,
            &observer_pin,
            &observation,
            500,
        )
        .unwrap();
        let adjustment_key = SigningKey::from_bytes(&[29; 32]);
        let adjustments = AdjustmentPolicy {
            schema: ADJUSTMENT_POLICY_SCHEMA.into(),
            policy_id: "adjustment-policy".into(),
            signature_domain: "adjustment-production".into(),
            reconciliation_policy_sha256: reconciliation_pin.clone(),
            tenant_id: "tenant-a".into(),
            merchant_id: "merchant-a".into(),
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 10_000,
            max_event_age_seconds: 100,
            authorities: vec![AdjustmentAuthority {
                authority_id: "authority-a".into(),
                source_id: "adjustment-source".into(),
                network: "bloch-l2".into(),
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(adjustment_key.verifying_key().to_bytes())
                ),
                allowed_event_kinds: vec![
                    AdjustmentEventKind::CancellationRequestedObserved,
                    AdjustmentEventKind::CancellationConfirmedObserved,
                    AdjustmentEventKind::DisputeOpenedObserved,
                    AdjustmentEventKind::DisputeResolvedNoRefundObserved,
                    AdjustmentEventKind::DisputeResolvedRefundExpectedObserved,
                    AdjustmentEventKind::RefundObserved,
                ],
            }],
        };
        let adjustments_pin = adjustment_policy_sha256(&adjustments).unwrap();
        Self {
            adjustment_key,
            reconciliation,
            reconciliation_pin,
            adjustments,
            adjustments_pin,
            payment,
        }
    }
    fn state(&self) -> AdjustmentState {
        initialize_adjustment(
            &self.adjustments,
            &self.adjustments_pin,
            &self.reconciliation,
            &self.reconciliation_pin,
            "adjust-a",
            &self.payment,
        )
        .unwrap()
    }
    fn authenticate(&self, mut event: AdjustmentEvent) -> AuthenticatedAdjustmentEvent {
        event.payment_observation_sha256 = self.payment.canonical_observation_sha256().into();
        let message = adjustment_event_signing_bytes(
            &self.adjustments,
            &self.adjustments_pin,
            "authority-a",
            &event,
        )
        .unwrap();
        verify_adjustment_event(
            &self.adjustments,
            &self.adjustments_pin,
            "authority-a",
            &event,
            &self.adjustment_key.sign(&message).to_bytes(),
            550,
        )
        .unwrap()
    }
}

fn reconciliation_policy() -> ReconciliationPolicy {
    ReconciliationPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "reconciliation-policy".into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        max_invoice_lifetime_seconds: 1_000,
        allowed_source_ids: vec!["adjustment-source".into(), "source-a".into()],
        routes: vec![PaymentRoute {
            route_id: "route-a".into(),
            network: "bloch-l2".into(),
            asset_id: "blch".into(),
            minor_unit_exponent: 18,
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
    }
}

fn event(
    sequence: u64,
    kind: AdjustmentEventKind,
    reference: &str,
    network: Option<(&str, u32, u64)>,
) -> AdjustmentEvent {
    AdjustmentEvent {
        schema: ADJUSTMENT_EVENT_SCHEMA.into(),
        adjustment_id: "adjust-a".into(),
        payment_observation_id: "payment-a".into(),
        payment_observation_sha256: format!("0x{}", "3".repeat(64)),
        event_id: format!("event-{sequence}"),
        sequence,
        kind,
        source_id: "adjustment-source".into(),
        network: "bloch-l2".into(),
        external_reference: reference.into(),
        transaction_id: network.map(|item| item.0.into()),
        event_index: network.map(|item| item.1),
        amount_minor: network.and_then(|item| (item.2 > 0).then_some(item.2)),
        occurred_at_unix_seconds: 500,
    }
}
