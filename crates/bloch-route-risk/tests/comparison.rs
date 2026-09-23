use bloch_route_risk::{
    ROUTE_RISK_POLICY_SCHEMA, RoutePolicy, RouteQuote, RouteRiskError, RouteRiskPolicy,
    canonical_policy_bytes, compare_routes, parse_policy, policy_sha256,
};

fn policy() -> RouteRiskPolicy {
    RouteRiskPolicy {
        schema: ROUTE_RISK_POLICY_SCHEMA.into(),
        policy_id: "router-main".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        maximum_quote_age_seconds: 60,
        maximum_future_skew_seconds: 2,
        maximum_acceptable_risk_bps: 500,
        routes: vec![
            RoutePolicy {
                route_id: "bridge-a".into(),
                source_network: "ethereum".into(),
                destination_network: "bloch-700771".into(),
                input_asset: "usdc".into(),
                output_asset: "usdc".into(),
                minimum_input_amount: 100,
                maximum_input_amount: 1_000_000,
                base_risk_bps: 100,
                maximum_total_fee_bps: 300,
                maximum_settlement_seconds: 600,
            },
            RoutePolicy {
                route_id: "dex-b".into(),
                source_network: "ethereum".into(),
                destination_network: "bloch-700771".into(),
                input_asset: "usdc".into(),
                output_asset: "usdc".into(),
                minimum_input_amount: 100,
                maximum_input_amount: 1_000_000,
                base_risk_bps: 200,
                maximum_total_fee_bps: 300,
                maximum_settlement_seconds: 300,
            },
        ],
    }
}

fn quote(route: &str, id: &str, minimum: u128) -> RouteQuote {
    RouteQuote {
        route_id: route.into(),
        quote_id: id.into(),
        observed_at_unix_seconds: 490,
        expires_at_unix_seconds: 550,
        input_amount: 10_000,
        gross_output_amount: 10_000,
        protocol_fee_output_amount: 100,
        estimated_gas_output_amount: 100,
        minimum_output_amount: minimum,
        estimated_settlement_seconds: 100,
    }
}

#[test]
fn canonical_policy_is_pinned_and_round_trips() {
    let policy = policy();
    let digest = policy_sha256(&policy).unwrap();
    let bytes = canonical_policy_bytes(&policy).unwrap();
    assert_eq!(parse_policy(&bytes, &digest).unwrap(), policy);
    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    assert_eq!(
        parse_policy(&noncanonical, &digest).unwrap_err(),
        RouteRiskError::InvalidPolicy
    );
}

#[test]
fn ranks_by_risk_adjusted_minimum_and_never_authorizes_execution() {
    let policy = policy();
    let digest = policy_sha256(&policy).unwrap();
    let report = compare_routes(
        &policy,
        &digest,
        &[quote("bridge-a", "q1", 9_700), quote("dex-b", "q2", 9_750)],
        500,
    )
    .unwrap();
    assert!(!report.quote_input_authenticated);
    assert!(!report.execution_authorized);
    assert_eq!(report.assessments[0].rank, Some(1));
    assert_eq!(report.assessments[1].rank, Some(2));
}

#[test]
fn stale_expired_costly_and_slow_quotes_fail_closed() {
    let policy = policy();
    let digest = policy_sha256(&policy).unwrap();
    let mut item = quote("bridge-a", "q1", 1);
    item.observed_at_unix_seconds = 400;
    item.expires_at_unix_seconds = 450;
    item.protocol_fee_output_amount = 9_999;
    item.estimated_gas_output_amount = 2;
    item.estimated_settlement_seconds = 601;
    let report = compare_routes(&policy, &digest, &[item], 500).unwrap();
    let result = &report.assessments[0];
    assert!(!result.eligible);
    assert_eq!(result.rank, None);
    assert!(result.reasons.contains(&"quoteTooOld".into()));
    assert!(
        result
            .reasons
            .contains(&"quoteExpiredOrInvalidWindow".into())
    );
    assert!(result.reasons.contains(&"costExceedsGrossOutput".into()));
    assert!(
        result
            .reasons
            .contains(&"settlementEstimateExceedsPinnedLimit".into())
    );
}

#[test]
fn unknown_unsorted_duplicate_and_wrong_pin_are_rejected() {
    let policy = policy();
    let digest = policy_sha256(&policy).unwrap();
    let unknown = quote("unknown", "q1", 9_000);
    assert_eq!(
        compare_routes(&policy, &digest, &[unknown], 500).unwrap_err(),
        RouteRiskError::UnknownRoute
    );
    assert_eq!(
        compare_routes(
            &policy,
            &digest,
            &[quote("dex-b", "q2", 9_000), quote("bridge-a", "q1", 9_000)],
            500,
        )
        .unwrap_err(),
        RouteRiskError::InvalidQuotes
    );
    let mut different_amount = quote("dex-b", "q2", 9_000);
    different_amount.input_amount += 1;
    assert_eq!(
        compare_routes(
            &policy,
            &digest,
            &[quote("bridge-a", "q1", 9_000), different_amount],
            500,
        )
        .unwrap_err(),
        RouteRiskError::InvalidQuotes
    );
    assert_eq!(
        compare_routes(
            &policy,
            &"0x00".repeat(32),
            &[quote("bridge-a", "q1", 9_000)],
            500
        )
        .unwrap_err(),
        RouteRiskError::PolicyPinMismatch
    );
}

#[test]
fn policy_and_amount_limits_are_enforced() {
    let mut policy = policy();
    policy.routes[0].base_risk_bps = 501;
    let digest = policy_sha256(&policy).unwrap();
    let mut item = quote("bridge-a", "q1", 9_000);
    item.input_amount = 99;
    let report = compare_routes(&policy, &digest, &[item], 500).unwrap();
    assert_eq!(
        report.assessments[0].reasons,
        vec![
            "inputAmountOutsidePinnedRouteLimits",
            "riskExceedsPinnedLimit"
        ]
    );
}

#[test]
fn invalid_policy_time_and_overflow_are_rejected() {
    let mut invalid = policy();
    invalid.routes.swap(0, 1);
    assert_eq!(
        policy_sha256(&invalid).unwrap_err(),
        RouteRiskError::InvalidPolicy
    );
    let mut incomparable = policy();
    incomparable.routes[1].output_asset = "usdt".into();
    assert_eq!(
        policy_sha256(&incomparable).unwrap_err(),
        RouteRiskError::InvalidPolicy
    );
    let policy = policy();
    let digest = policy_sha256(&policy).unwrap();
    assert_eq!(
        compare_routes(&policy, &digest, &[quote("bridge-a", "q1", 9_000)], 10_000).unwrap_err(),
        RouteRiskError::PolicyNotEffective
    );
    let mut item = quote("bridge-a", "q1", 1);
    item.protocol_fee_output_amount = u128::MAX;
    assert_eq!(
        compare_routes(&policy, &digest, &[item], 500).unwrap_err(),
        RouteRiskError::ArithmeticOverflow
    );
}
