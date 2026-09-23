use bloch_route_risk::{
    QUOTE_PROVENANCE_ENVELOPE_SCHEMA, QUOTE_PROVENANCE_POLICY_SCHEMA, QuoteAuthority,
    QuoteAuthoritySignature, QuoteProvenanceEnvelope, QuoteProvenanceError, QuoteProvenancePolicy,
    ROUTE_RISK_POLICY_SCHEMA, RoutePolicy, RouteQuote, RouteRiskPolicy,
    compare_authenticated_routes, policy_sha256, quote_provenance_policy_sha256, quote_set_sha256,
    quote_signing_message, verify_quote_provenance,
};
use ed25519_dalek::{Signer, SigningKey};

fn quotes() -> Vec<RouteQuote> {
    vec![RouteQuote {
        route_id: "route-a".into(),
        quote_id: "quote-1".into(),
        observed_at_unix_seconds: 490,
        expires_at_unix_seconds: 550,
        input_amount: 10_000,
        gross_output_amount: 10_000,
        protocol_fee_output_amount: 100,
        estimated_gas_output_amount: 100,
        minimum_output_amount: 9_700,
        estimated_settlement_seconds: 100,
    }]
}

fn route_policy() -> RouteRiskPolicy {
    RouteRiskPolicy {
        schema: ROUTE_RISK_POLICY_SCHEMA.into(),
        policy_id: "routes".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        maximum_quote_age_seconds: 60,
        maximum_future_skew_seconds: 2,
        maximum_acceptable_risk_bps: 500,
        routes: vec![RoutePolicy {
            route_id: "route-a".into(),
            source_network: "ethereum".into(),
            destination_network: "bloch-700771".into(),
            input_asset: "usdc".into(),
            output_asset: "usdc".into(),
            minimum_input_amount: 100,
            maximum_input_amount: 1_000_000,
            base_risk_bps: 100,
            maximum_total_fee_bps: 300,
            maximum_settlement_seconds: 600,
        }],
    }
}

fn fixtures() -> (
    QuoteProvenancePolicy,
    QuoteProvenanceEnvelope,
    Vec<SigningKey>,
    String,
) {
    let keys = vec![
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    ];
    let policy = QuoteProvenancePolicy {
        schema: QUOTE_PROVENANCE_POLICY_SCHEMA.into(),
        policy_id: "quote-sources".into(),
        signature_domain: "prod-quotes-v1".into(),
        audience: "bloch-router-prod".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        signature_threshold: 2,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| QuoteAuthority {
                authority_id: format!("source-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
            })
            .collect(),
    };
    let policy_hash = quote_provenance_policy_sha256(&policy).unwrap();
    let route_hash = policy_sha256(&route_policy()).unwrap();
    let mut envelope = QuoteProvenanceEnvelope {
        schema: QUOTE_PROVENANCE_ENVELOPE_SCHEMA.into(),
        provenance_policy_sha256: policy_hash,
        route_risk_policy_sha256: route_hash.clone(),
        signature_domain: "prod-quotes-v1".into(),
        audience: "bloch-router-prod".into(),
        quote_set_sha256: quote_set_sha256(&quotes()).unwrap(),
        issued_at_unix_seconds: 495,
        valid_until_unix_seconds: 540,
        signatures: vec![],
    };
    let message = quote_signing_message(&envelope).unwrap();
    envelope.signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| QuoteAuthoritySignature {
            authority_id: format!("source-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect();
    (policy, envelope, keys, route_hash)
}

#[test]
fn exact_signed_quotes_are_authenticated_but_never_authorize_execution() {
    let (policy, envelope, _, route_hash) = fixtures();
    let policy_hash = quote_provenance_policy_sha256(&policy).unwrap();
    let capability = verify_quote_provenance(
        &policy,
        &policy_hash,
        &route_hash,
        "bloch-router-prod",
        &quotes(),
        &envelope,
        500,
    )
    .unwrap();
    assert_eq!(capability.signer_ids(), &["source-1", "source-2"]);
    assert_eq!(capability.verified_at_unix_seconds(), 500);
    assert!(!capability.quote_quality_proven());
    assert!(!capability.settlement_or_finality_proven());
    assert!(!capability.execution_authorized());
    let report =
        compare_authenticated_routes(&route_policy(), &route_hash, &quotes(), 500, &capability)
            .unwrap();
    assert!(report.quote_input_authenticated);
    assert!(!report.execution_authorized);
    let mut substituted = quotes();
    substituted[0].minimum_output_amount -= 1;
    assert!(
        compare_authenticated_routes(&route_policy(), &route_hash, &substituted, 500, &capability)
            .is_err()
    );
    assert!(
        compare_authenticated_routes(&route_policy(), &route_hash, &quotes(), 501, &capability)
            .is_err()
    );
}

#[test]
fn quote_policy_and_audience_substitution_fail_closed() {
    let (policy, envelope, _, route_hash) = fixtures();
    let policy_hash = quote_provenance_policy_sha256(&policy).unwrap();
    let mut changed = quotes();
    changed[0].minimum_output_amount -= 1;
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &changed,
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::BindingMismatch
    );
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "other-audience",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::AudienceMismatch
    );
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &format!("0x{}", "11".repeat(32)),
            "bloch-router-prod",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::BindingMismatch
    );
}

#[test]
fn duplicate_tampered_and_insufficient_signatures_are_rejected() {
    let (policy, mut envelope, _, route_hash) = fixtures();
    let policy_hash = quote_provenance_policy_sha256(&policy).unwrap();
    envelope.signatures[1] = envelope.signatures[0].clone();
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::DuplicateSignature
    );
    let (_, mut envelope, _, _) = fixtures();
    envelope.signatures.reverse();
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::InvalidEnvelope
    );
    let (_, mut envelope, _, _) = fixtures();
    envelope.signatures[0].signature.replace_range(2..4, "ff");
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::InvalidSignature
    );
    let (_, mut envelope, _, _) = fixtures();
    envelope.signatures.pop();
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            500
        )
        .unwrap_err(),
        QuoteProvenanceError::InsufficientSignatures
    );
}

#[test]
fn expired_future_and_weak_key_evidence_is_rejected() {
    let (policy, envelope, _, route_hash) = fixtures();
    let policy_hash = quote_provenance_policy_sha256(&policy).unwrap();
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            540
        )
        .unwrap_err(),
        QuoteProvenanceError::NotEffective
    );
    assert_eq!(
        verify_quote_provenance(
            &policy,
            &policy_hash,
            &route_hash,
            "bloch-router-prod",
            &quotes(),
            &envelope,
            494
        )
        .unwrap_err(),
        QuoteProvenanceError::NotEffective
    );
    let mut weak = policy;
    weak.authorities[0].ed25519_public_key = format!("0x{}", "00".repeat(32));
    assert_eq!(
        quote_provenance_policy_sha256(&weak).unwrap_err(),
        QuoteProvenanceError::InvalidPolicy
    );
}
