use bloch_pay_reconciliation::*;
use ed25519_dalek::{Signer, SigningKey};

fn reconciliation_policy() -> ReconciliationPolicy {
    ReconciliationPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "reconciliation-1".into(),
        tenant_id: "tenant-1".into(),
        merchant_id: "merchant-1".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        max_invoice_lifetime_seconds: 800,
        allowed_source_ids: vec!["observer-source".into()],
        routes: vec![
            PaymentRoute {
                route_id: "route-a".into(),
                network: "bloch-l2".into(),
                asset_id: "usdc".into(),
                minor_unit_exponent: 6,
                destination: "0x1111111111111111111111111111111111111111".into(),
            },
            PaymentRoute {
                route_id: "route-b".into(),
                network: "bloch-l2".into(),
                asset_id: "usdt".into(),
                minor_unit_exponent: 6,
                destination: "0x2222222222222222222222222222222222222222".into(),
            },
        ],
    }
}

fn invoice(route_id: &str, amount_minor: u64) -> Invoice {
    Invoice {
        schema: INVOICE_SCHEMA.into(),
        invoice_id: "invoice-00000001".into(),
        tenant_id: "tenant-1".into(),
        merchant_id: "merchant-1".into(),
        route_id: route_id.into(),
        reference: "reference-00000001".into(),
        amount_minor,
        issued_at_unix_seconds: 110,
        expires_at_unix_seconds: 500,
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[19; 32])
}

fn authorization_policy(reconciliation_sha256: &str) -> InvoiceAuthorizationPolicy {
    InvoiceAuthorizationPolicy {
        schema: INVOICE_AUTHORIZATION_POLICY_SCHEMA.into(),
        policy_id: "invoice-auth-1".into(),
        signature_domain: "merchant-prod-1".into(),
        reconciliation_policy_sha256: reconciliation_sha256.into(),
        tenant_id: "tenant-1".into(),
        merchant_id: "merchant-1".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 900,
        issuers: vec![TrustedInvoiceIssuer {
            issuer_id: "billing-service-1".into(),
            route_ids: vec!["route-a".into()],
            ed25519_public_key: format!(
                "0x{}",
                hex::encode(signing_key().verifying_key().as_bytes())
            ),
        }],
    }
}

fn authorize(invoice: &Invoice) -> AuthorizedInvoice {
    authorize_at(invoice, 120)
}

fn authorize_at(invoice: &Invoice, authorized_at_unix_seconds: u64) -> AuthorizedInvoice {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization = authorization_policy(&reconciliation_pin);
    let authorization_pin = invoice_authorization_policy_sha256(&authorization).unwrap();
    let message = invoice_authorization_signing_bytes(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        invoice,
        authorized_at_unix_seconds,
    )
    .unwrap();
    let signature = signing_key().sign(&message).to_bytes();
    let envelope = encode_invoice_authorization_envelope(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        invoice,
        authorized_at_unix_seconds,
        &signature,
    )
    .unwrap();
    verify_authorized_invoice(
        &envelope,
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        invoice,
    )
    .unwrap()
}

#[test]
fn protected_reconciliation_rejects_future_dated_authorization() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization_pin =
        invoice_authorization_policy_sha256(&authorization_policy(&reconciliation_pin)).unwrap();
    let authorized = authorize_at(&invoice("route-a", 1), 300);
    assert_eq!(
        reconcile_authorized_invoices(
            &reconciliation,
            &reconciliation_pin,
            &authorization_pin,
            &[authorized],
            &[],
            200,
        ),
        Err(InvoiceAuthorizationError::InvalidField("authorizationTime"))
    );
}

#[test]
fn exact_invoice_is_authorized_and_enters_only_the_protected_path() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let invoice = invoice("route-a", 125_000);
    let authorized = authorize(&invoice);
    let authorization_pin =
        invoice_authorization_policy_sha256(&authorization_policy(&reconciliation_pin)).unwrap();

    assert_eq!(authorized.invoice(), &invoice);
    assert_eq!(authorized.issuer_id(), "billing-service-1");
    assert_eq!(
        authorized.reconciliation_policy_sha256(),
        reconciliation_pin
    );
    assert_eq!(authorized.authorized_at_unix_seconds(), 120);
    assert!(!authorized.settlement_qualified());
    assert!(!authorized.credit_authorized());

    let report = reconcile_authorized_invoices(
        &reconciliation,
        &reconciliation_pin,
        &authorization_pin,
        &[authorized],
        &[],
        200,
    )
    .unwrap();
    assert!(report.invoices_authorized());
    assert_eq!(report.invoice_authorization_evidence().len(), 1);
    assert_eq!(
        report.invoice_authorization_evidence()[0].invoice_id(),
        "invoice-00000001"
    );
    assert_eq!(
        report.invoice_authorization_evidence()[0].issuer_id(),
        Some("billing-service-1")
    );
    assert!(report.invoice_authorization_evidence()[0].authorized());
    assert_eq!(
        report.invoice_authorization_evidence()[0].authorization_policy_sha256(),
        Some(authorization_pin.as_str())
    );
    assert_eq!(
        report.invoice_authorization_evidence()[0].reconciliation_policy_sha256(),
        Some(reconciliation_pin.as_str())
    );
    assert_eq!(
        report.invoice_authorization_evidence()[0].authorized_at_unix_seconds(),
        Some(120)
    );
    let expected_invoice_digest = authorized_digest(&invoice, &reconciliation);
    assert_eq!(
        report.invoice_authorization_evidence()[0].canonical_invoice_sha256(),
        Some(expected_invoice_digest.as_str())
    );
    assert_eq!(report.invoices().len(), 1);
    assert!(report.observations_authenticated());
    assert!(!report.settlement_qualified());
    assert!(!report.credit_authorized());
}

#[test]
fn raw_and_observation_only_reconciliation_never_claim_invoice_authorization() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let invoice = invoice("route-a", 1);
    let raw = reconcile(&reconciliation, std::slice::from_ref(&invoice), &[], 200).unwrap();
    assert!(!raw.invoices_authorized());
    assert_eq!(raw.invoice_authorization_evidence().len(), 1);
    assert!(!raw.invoice_authorization_evidence()[0].authorized());
    assert_eq!(
        raw.invoice_authorization_evidence()[0].canonical_invoice_sha256(),
        None
    );
    assert_eq!(raw.invoice_authorization_evidence()[0].issuer_id(), None);

    let observation_only =
        reconcile_authenticated(&reconciliation, &reconciliation_pin, &[invoice], &[], 200)
            .unwrap();
    assert!(!observation_only.invoices_authorized());
    assert_eq!(observation_only.invoice_authorization_evidence().len(), 1);
    assert!(!observation_only.invoice_authorization_evidence()[0].authorized());
}

#[test]
fn protected_reconciliation_rechecks_the_independent_authorization_pin() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorized = authorize(&invoice("route-a", 1));
    assert_eq!(
        reconcile_authorized_invoices(
            &reconciliation,
            &reconciliation_pin,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[authorized],
            &[],
            200,
        ),
        Err(InvoiceAuthorizationError::AuthorizationPolicyDigestMismatch)
    );
}

#[test]
fn policy_and_invoice_parsers_require_exact_canonical_bytes_and_independent_pin() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization = authorization_policy(&reconciliation_pin);
    let policy_bytes = canonical_invoice_authorization_policy_bytes(&authorization).unwrap();
    let authorization_pin = invoice_authorization_policy_sha256(&authorization).unwrap();
    assert_eq!(
        parse_invoice_authorization_policy(&policy_bytes, &authorization_pin).unwrap(),
        authorization
    );
    assert_eq!(
        parse_invoice_authorization_policy(
            &policy_bytes,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        Err(InvoiceAuthorizationError::AuthorizationPolicyDigestMismatch)
    );
    let mut trailing = policy_bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        parse_invoice_authorization_policy(&trailing, &authorization_pin),
        Err(InvoiceAuthorizationError::NonCanonicalJson)
    );

    let invoice = invoice("route-a", 125_000);
    let invoice_bytes = canonical_invoice_bytes(&reconciliation, &invoice).unwrap();
    assert_eq!(
        parse_invoice_for_authorization(&invoice_bytes, &reconciliation).unwrap(),
        invoice
    );
    let mut noncanonical = invoice_bytes;
    noncanonical.push(b' ');
    assert_eq!(
        parse_invoice_for_authorization(&noncanonical, &reconciliation),
        Err(InvoiceAuthorizationError::NonCanonicalJson)
    );
}

#[test]
fn signature_is_bound_to_exact_invoice_and_envelope_digest() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization = authorization_policy(&reconciliation_pin);
    let authorization_pin = invoice_authorization_policy_sha256(&authorization).unwrap();
    let original = invoice("route-a", 125_000);
    let message = invoice_authorization_signing_bytes(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        &original,
        120,
    )
    .unwrap();
    let signature = signing_key().sign(&message).to_bytes();
    let envelope = encode_invoice_authorization_envelope(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        &original,
        120,
        &signature,
    )
    .unwrap();

    let substituted = invoice("route-a", 125_001);
    assert_eq!(
        verify_authorized_invoice(
            &envelope,
            &reconciliation,
            &reconciliation_pin,
            &authorization,
            &authorization_pin,
            &substituted,
        ),
        Err(InvoiceAuthorizationError::InvoiceDigestMismatch)
    );

    let original_digest = authorized_digest(&original, &reconciliation);
    let replacement = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let tampered = String::from_utf8(envelope)
        .unwrap()
        .replace(&original_digest, replacement)
        .into_bytes();
    assert_eq!(
        verify_authorized_invoice(
            &tampered,
            &reconciliation,
            &reconciliation_pin,
            &authorization,
            &authorization_pin,
            &original,
        ),
        Err(InvoiceAuthorizationError::InvoiceDigestMismatch)
    );
}

#[test]
fn route_policy_time_and_signature_substitution_fail_closed() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization = authorization_policy(&reconciliation_pin);
    let authorization_pin = invoice_authorization_policy_sha256(&authorization).unwrap();

    assert_eq!(
        invoice_authorization_signing_bytes(
            &reconciliation,
            &reconciliation_pin,
            &authorization,
            &authorization_pin,
            "billing-service-1",
            &invoice("route-b", 1),
            120,
        ),
        Err(InvoiceAuthorizationError::UntrustedIssuer)
    );
    assert_eq!(
        invoice_authorization_signing_bytes(
            &reconciliation,
            &reconciliation_pin,
            &authorization,
            &authorization_pin,
            "billing-service-1",
            &invoice("route-a", 1),
            99,
        ),
        Err(InvoiceAuthorizationError::InvalidField("authorizationTime"))
    );
    assert_eq!(
        encode_invoice_authorization_envelope(
            &reconciliation,
            &reconciliation_pin,
            &authorization,
            &authorization_pin,
            "billing-service-1",
            &invoice("route-a", 1),
            120,
            &[0; 64],
        ),
        Err(InvoiceAuthorizationError::InvalidSignature)
    );
}

#[test]
fn reconciliation_policy_and_context_are_cryptographically_bound() {
    let reconciliation = reconciliation_policy();
    let reconciliation_pin = policy_sha256(&reconciliation).unwrap();
    let authorization = authorization_policy(&reconciliation_pin);
    let authorization_pin = invoice_authorization_policy_sha256(&authorization).unwrap();
    let invoice = invoice("route-a", 10);
    let message = invoice_authorization_signing_bytes(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        &invoice,
        120,
    )
    .unwrap();
    let signature = signing_key().sign(&message).to_bytes();
    let envelope = encode_invoice_authorization_envelope(
        &reconciliation,
        &reconciliation_pin,
        &authorization,
        &authorization_pin,
        "billing-service-1",
        &invoice,
        120,
        &signature,
    )
    .unwrap();

    let mut changed_reconciliation = reconciliation;
    changed_reconciliation.routes[0].destination =
        "0x3333333333333333333333333333333333333333".into();
    let changed_pin = policy_sha256(&changed_reconciliation).unwrap();
    assert_eq!(
        verify_authorized_invoice(
            &envelope,
            &changed_reconciliation,
            &changed_pin,
            &authorization,
            &authorization_pin,
            &invoice,
        ),
        Err(InvoiceAuthorizationError::TrustContextMismatch)
    );
}

fn authorized_digest(invoice: &Invoice, policy: &ReconciliationPolicy) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "0x{}",
        hex::encode(Sha256::digest(
            canonical_invoice_bytes(policy, invoice).unwrap()
        ))
    )
}
