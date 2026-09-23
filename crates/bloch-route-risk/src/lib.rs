//! Deterministic, read-only comparison of policy-pinned swap and bridge routes.
//!
//! Quote fields are caller-supplied observations. This crate validates and
//! compares them; it does not authenticate their source, execute a route,
//! authorize asset movement, or claim settlement/finality.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const ROUTE_RISK_POLICY_SCHEMA: &str = "bloch.products.route-risk-policy.v1";
pub const ROUTE_RISK_REPORT_SCHEMA: &str = "bloch.products.route-risk-report.v1";
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_ROUTES: usize = 256;
pub const MAX_QUOTES: usize = 1_024;
const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RoutePolicy {
    pub route_id: String,
    pub source_network: String,
    pub destination_network: String,
    pub input_asset: String,
    pub output_asset: String,
    pub minimum_input_amount: u128,
    pub maximum_input_amount: u128,
    pub base_risk_bps: u16,
    pub maximum_total_fee_bps: u16,
    pub maximum_settlement_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteRiskPolicy {
    pub schema: String,
    pub policy_id: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub maximum_quote_age_seconds: u64,
    pub maximum_future_skew_seconds: u64,
    pub maximum_acceptable_risk_bps: u16,
    pub routes: Vec<RoutePolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteQuote {
    pub route_id: String,
    pub quote_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub input_amount: u128,
    pub gross_output_amount: u128,
    pub protocol_fee_output_amount: u128,
    pub estimated_gas_output_amount: u128,
    pub minimum_output_amount: u128,
    pub estimated_settlement_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteAssessment {
    pub route_id: String,
    pub quote_id: String,
    pub eligible: bool,
    pub reasons: Vec<String>,
    pub total_cost_output_amount: u128,
    pub net_output_amount: u128,
    pub total_fee_bps: u16,
    pub policy_risk_bps: u16,
    pub risk_adjusted_minimum_output_amount: u128,
    pub rank: Option<u16>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteRiskReport {
    pub schema: &'static str,
    pub policy_sha256: String,
    pub evaluated_at_unix_seconds: u64,
    pub quote_input_authenticated: bool,
    pub execution_authorized: bool,
    pub assessments: Vec<RouteAssessment>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteRiskError {
    #[error("route-risk policy is invalid or non-canonical")]
    InvalidPolicy,
    #[error("route-risk policy pin mismatch")]
    PolicyPinMismatch,
    #[error("route quote set is invalid, duplicated or unordered")]
    InvalidQuotes,
    #[error("route quote references a route absent from the pinned policy")]
    UnknownRoute,
    #[error("route-risk evaluation time is outside the policy window")]
    PolicyNotEffective,
    #[error("route-risk arithmetic overflow")]
    ArithmeticOverflow,
}

pub fn canonical_policy_bytes(policy: &RouteRiskPolicy) -> Result<Vec<u8>, RouteRiskError> {
    validate_policy(policy)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| RouteRiskError::InvalidPolicy)?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(RouteRiskError::InvalidPolicy);
    }
    Ok(bytes)
}

pub fn policy_sha256(policy: &RouteRiskPolicy) -> Result<String, RouteRiskError> {
    Ok(hash(&canonical_policy_bytes(policy)?))
}

pub fn parse_policy(
    bytes: &[u8],
    expected_policy_sha256: &str,
) -> Result<RouteRiskPolicy, RouteRiskError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(RouteRiskError::InvalidPolicy);
    }
    let policy: RouteRiskPolicy =
        serde_json::from_slice(bytes).map_err(|_| RouteRiskError::InvalidPolicy)?;
    if canonical_policy_bytes(&policy)? != bytes {
        return Err(RouteRiskError::InvalidPolicy);
    }
    verify_policy_pin(&policy, expected_policy_sha256)?;
    Ok(policy)
}

pub fn compare_routes(
    policy: &RouteRiskPolicy,
    expected_policy_sha256: &str,
    quotes: &[RouteQuote],
    evaluated_at_unix_seconds: u64,
) -> Result<RouteRiskReport, RouteRiskError> {
    verify_policy_pin(policy, expected_policy_sha256)?;
    if evaluated_at_unix_seconds < policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= policy.expires_at_unix_seconds
    {
        return Err(RouteRiskError::PolicyNotEffective);
    }
    validate_quotes(quotes)?;
    let routes: BTreeMap<&str, &RoutePolicy> = policy
        .routes
        .iter()
        .map(|route| (route.route_id.as_str(), route))
        .collect();
    let mut assessments = Vec::with_capacity(quotes.len());
    for quote in quotes {
        let route = routes
            .get(quote.route_id.as_str())
            .ok_or(RouteRiskError::UnknownRoute)?;
        assessments.push(assess_quote(
            policy,
            route,
            quote,
            evaluated_at_unix_seconds,
        )?);
    }
    let mut eligible: Vec<usize> = assessments
        .iter()
        .enumerate()
        .filter_map(|(index, item)| item.eligible.then_some(index))
        .collect();
    eligible.sort_by(|left, right| {
        let left = &assessments[*left];
        let right = &assessments[*right];
        right
            .risk_adjusted_minimum_output_amount
            .cmp(&left.risk_adjusted_minimum_output_amount)
            .then_with(|| right.net_output_amount.cmp(&left.net_output_amount))
            .then_with(|| left.route_id.cmp(&right.route_id))
            .then_with(|| left.quote_id.cmp(&right.quote_id))
    });
    for (rank, index) in eligible.into_iter().enumerate() {
        assessments[index].rank =
            Some(u16::try_from(rank + 1).map_err(|_| RouteRiskError::ArithmeticOverflow)?);
    }
    Ok(RouteRiskReport {
        schema: ROUTE_RISK_REPORT_SCHEMA,
        policy_sha256: expected_policy_sha256.into(),
        evaluated_at_unix_seconds,
        quote_input_authenticated: false,
        execution_authorized: false,
        assessments,
    })
}

fn assess_quote(
    policy: &RouteRiskPolicy,
    route: &RoutePolicy,
    quote: &RouteQuote,
    now: u64,
) -> Result<RouteAssessment, RouteRiskError> {
    let total_cost = quote
        .protocol_fee_output_amount
        .checked_add(quote.estimated_gas_output_amount)
        .ok_or(RouteRiskError::ArithmeticOverflow)?;
    let net = quote.gross_output_amount.checked_sub(total_cost);
    let fee_bps_u128 = if quote.gross_output_amount == 0 {
        BASIS_POINTS
    } else {
        total_cost
            .checked_mul(BASIS_POINTS)
            .and_then(|value| value.checked_add(quote.gross_output_amount - 1))
            .and_then(|value| value.checked_div(quote.gross_output_amount))
            .ok_or(RouteRiskError::ArithmeticOverflow)?
    };
    let fee_bps = u16::try_from(fee_bps_u128.min(u128::from(u16::MAX)))
        .map_err(|_| RouteRiskError::ArithmeticOverflow)?;
    let mut reasons = Vec::new();
    if quote.input_amount < route.minimum_input_amount
        || quote.input_amount > route.maximum_input_amount
    {
        reasons.push("inputAmountOutsidePinnedRouteLimits".into());
    }
    if quote.observed_at_unix_seconds > now.saturating_add(policy.maximum_future_skew_seconds) {
        reasons.push("quoteObservedInFuture".into());
    }
    if now.saturating_sub(quote.observed_at_unix_seconds) > policy.maximum_quote_age_seconds {
        reasons.push("quoteTooOld".into());
    }
    if now >= quote.expires_at_unix_seconds
        || quote.expires_at_unix_seconds <= quote.observed_at_unix_seconds
    {
        reasons.push("quoteExpiredOrInvalidWindow".into());
    }
    if net.is_none() || quote.gross_output_amount == 0 {
        reasons.push("costExceedsGrossOutput".into());
    }
    let net = net.unwrap_or(0);
    if quote.minimum_output_amount == 0 || quote.minimum_output_amount > net {
        reasons.push("minimumOutputInvalid".into());
    }
    if fee_bps > route.maximum_total_fee_bps {
        reasons.push("feeExceedsPinnedLimit".into());
    }
    if route.base_risk_bps > policy.maximum_acceptable_risk_bps {
        reasons.push("riskExceedsPinnedLimit".into());
    }
    if quote.estimated_settlement_seconds == 0
        || quote.estimated_settlement_seconds > route.maximum_settlement_seconds
    {
        reasons.push("settlementEstimateExceedsPinnedLimit".into());
    }
    let risk_adjusted = quote
        .minimum_output_amount
        .checked_mul(BASIS_POINTS - u128::from(route.base_risk_bps))
        .ok_or(RouteRiskError::ArithmeticOverflow)?
        / BASIS_POINTS;
    Ok(RouteAssessment {
        route_id: quote.route_id.clone(),
        quote_id: quote.quote_id.clone(),
        eligible: reasons.is_empty(),
        reasons,
        total_cost_output_amount: total_cost,
        net_output_amount: net,
        total_fee_bps: fee_bps,
        policy_risk_bps: route.base_risk_bps,
        risk_adjusted_minimum_output_amount: risk_adjusted,
        rank: None,
    })
}

fn verify_policy_pin(
    policy: &RouteRiskPolicy,
    expected_policy_sha256: &str,
) -> Result<(), RouteRiskError> {
    if !valid_hash(expected_policy_sha256) {
        return Err(RouteRiskError::PolicyPinMismatch);
    }
    if policy_sha256(policy)? != expected_policy_sha256 {
        return Err(RouteRiskError::PolicyPinMismatch);
    }
    Ok(())
}

fn validate_policy(policy: &RouteRiskPolicy) -> Result<(), RouteRiskError> {
    if policy.schema != ROUTE_RISK_POLICY_SCHEMA
        || !valid_id(&policy.policy_id)
        || policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.maximum_quote_age_seconds == 0
        || policy.maximum_quote_age_seconds
            > policy.expires_at_unix_seconds - policy.effective_at_unix_seconds
        || policy.maximum_future_skew_seconds > policy.maximum_quote_age_seconds
        || policy.maximum_acceptable_risk_bps > 10_000
        || policy.routes.is_empty()
        || policy.routes.len() > MAX_ROUTES
    {
        return Err(RouteRiskError::InvalidPolicy);
    }
    let mut previous: Option<&str> = None;
    let comparison_pair = policy.routes.first().map(|route| {
        (
            route.source_network.as_str(),
            route.destination_network.as_str(),
            route.input_asset.as_str(),
            route.output_asset.as_str(),
        )
    });
    for route in &policy.routes {
        if !valid_id(&route.route_id)
            || !valid_id(&route.source_network)
            || !valid_id(&route.destination_network)
            || !valid_id(&route.input_asset)
            || !valid_id(&route.output_asset)
            || previous.is_some_and(|value| value >= route.route_id.as_str())
            || route.minimum_input_amount == 0
            || route.minimum_input_amount > route.maximum_input_amount
            || route.base_risk_bps > 10_000
            || route.maximum_total_fee_bps > 10_000
            || route.maximum_settlement_seconds == 0
            || comparison_pair
                != Some((
                    route.source_network.as_str(),
                    route.destination_network.as_str(),
                    route.input_asset.as_str(),
                    route.output_asset.as_str(),
                ))
        {
            return Err(RouteRiskError::InvalidPolicy);
        }
        previous = Some(&route.route_id);
    }
    Ok(())
}

fn validate_quotes(quotes: &[RouteQuote]) -> Result<(), RouteRiskError> {
    if quotes.is_empty() || quotes.len() > MAX_QUOTES {
        return Err(RouteRiskError::InvalidQuotes);
    }
    let mut previous: Option<(&str, &str)> = None;
    let mut ids = BTreeSet::new();
    let comparison_amount = quotes.first().map(|quote| quote.input_amount);
    for quote in quotes {
        let current = (quote.route_id.as_str(), quote.quote_id.as_str());
        if !valid_id(&quote.route_id)
            || !valid_id(&quote.quote_id)
            || quote.observed_at_unix_seconds == 0
            || quote.expires_at_unix_seconds == 0
            || quote.input_amount == 0
            || Some(quote.input_amount) != comparison_amount
            || quote.estimated_settlement_seconds == 0
            || previous.is_some_and(|value| value >= current)
            || !ids.insert(quote.quote_id.as_str())
        {
            return Err(RouteRiskError::InvalidQuotes);
        }
        previous = Some(current);
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
