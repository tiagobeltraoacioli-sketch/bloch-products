//! Deterministic, non-custodial invoice/payment observation reconciliation.
//!
//! Matching is not settlement qualification or authorization to credit, move
//! funds, release goods, or perform any regulated payment activity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const POLICY_SCHEMA: &str = "bloch.pay.reconciliation-policy.v1";
pub const INVOICE_SCHEMA: &str = "bloch.pay.invoice.v1";
pub const OBSERVATION_SCHEMA: &str = "bloch.pay.payment-observation.v1";
pub const REPORT_SCHEMA: &str = "bloch.pay.reconciliation-report.v1";
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_INVOICES: usize = 10_000;
pub const MAX_OBSERVATIONS: usize = 100_000;
const MAX_LIST_ITEMS: usize = 1_024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_INVOICE_LIFETIME_SECONDS: u64 = 31 * 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PaymentRoute {
    pub route_id: String,
    pub network: String,
    pub asset_id: String,
    pub minor_unit_exponent: u8,
    pub destination: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReconciliationPolicy {
    pub schema: String,
    pub policy_id: String,
    pub tenant_id: String,
    pub merchant_id: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_invoice_lifetime_seconds: u64,
    pub allowed_source_ids: Vec<String>,
    pub routes: Vec<PaymentRoute>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Invoice {
    pub schema: String,
    pub invoice_id: String,
    pub tenant_id: String,
    pub merchant_id: String,
    pub route_id: String,
    pub reference: String,
    pub amount_minor: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PaymentObservation {
    pub schema: String,
    pub observation_id: String,
    pub source_id: String,
    pub network: String,
    pub transaction_id: String,
    pub event_index: u32,
    pub asset_id: String,
    pub destination: String,
    pub reference: String,
    pub amount_minor: u64,
    pub observed_at_unix_seconds: u64,
    pub block_height: u64,
    pub block_hash: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationState {
    NoObservation,
    PartialObserved,
    ExactObserved,
    ExcessObserved,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceReconciliation {
    invoice_id: String,
    state: ReconciliationState,
    expected_amount_minor: u64,
    observed_amount_minor: u64,
    matched_observation_ids: Vec<String>,
    late_observation_ids: Vec<String>,
    settlement_qualified: bool,
    credit_authorized: bool,
}

impl InvoiceReconciliation {
    pub fn invoice_id(&self) -> &str {
        &self.invoice_id
    }
    pub fn state(&self) -> ReconciliationState {
        self.state
    }
    pub fn observed_amount_minor(&self) -> u64 {
        self.observed_amount_minor
    }
    pub fn matched_observation_ids(&self) -> &[String] {
        &self.matched_observation_ids
    }
    pub fn late_observation_ids(&self) -> &[String] {
        &self.late_observation_ids
    }
    pub fn settlement_qualified(&self) -> bool {
        self.settlement_qualified
    }
    pub fn credit_authorized(&self) -> bool {
        self.credit_authorized
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationReport {
    schema: String,
    policy_sha256: String,
    evaluated_at_unix_seconds: u64,
    invoices: Vec<InvoiceReconciliation>,
    unmatched_observation_ids: Vec<String>,
    settlement_qualified: bool,
    credit_authorized: bool,
}

impl ReconciliationReport {
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn invoices(&self) -> &[InvoiceReconciliation] {
        &self.invoices
    }
    pub fn unmatched_observation_ids(&self) -> &[String] {
        &self.unmatched_observation_ids
    }
    pub fn settlement_qualified(&self) -> bool {
        self.settlement_qualified
    }
    pub fn credit_authorized(&self) -> bool {
        self.credit_authorized
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReconciliationError {
    #[error("reconciliation policy is empty")]
    Empty,
    #[error("reconciliation policy exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid reconciliation policy JSON: {0}")]
    InvalidJson(String),
    #[error("invalid reconciliation policy field: {0}")]
    InvalidPolicy(&'static str),
    #[error("reconciliation policy is not canonical JSON")]
    NonCanonicalPolicy,
    #[error("reconciliation policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("invalid invoice: {0}")]
    InvalidInvoice(&'static str),
    #[error("invalid payment observation: {0}")]
    InvalidObservation(&'static str),
    #[error("payment observation conflicts with the invoice route")]
    RouteMismatch,
    #[error("amount overflow during reconciliation")]
    AmountOverflow,
    #[error("cannot encode reconciliation output: {0}")]
    Encoding(String),
}

pub fn canonical_policy_bytes(
    policy: &ReconciliationPolicy,
) -> Result<Vec<u8>, ReconciliationError> {
    validate_policy(policy)?;
    serde_json::to_vec(policy).map_err(|error| ReconciliationError::Encoding(error.to_string()))
}

pub fn policy_sha256(policy: &ReconciliationPolicy) -> Result<String, ReconciliationError> {
    Ok(sha256(&canonical_policy_bytes(policy)?))
}

pub fn parse_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<ReconciliationPolicy, ReconciliationError> {
    if bytes.is_empty() {
        return Err(ReconciliationError::Empty);
    }
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(ReconciliationError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_POLICY_BYTES,
        });
    }
    require_sha256(expected_sha256)?;
    let policy: ReconciliationPolicy = serde_json::from_slice(bytes)
        .map_err(|error| ReconciliationError::InvalidJson(error.to_string()))?;
    validate_policy(&policy)?;
    if canonical_policy_bytes(&policy)? != bytes {
        return Err(ReconciliationError::NonCanonicalPolicy);
    }
    if sha256(bytes) != expected_sha256 {
        return Err(ReconciliationError::PolicyDigestMismatch);
    }
    Ok(policy)
}

pub fn canonical_invoice_bytes(
    policy: &ReconciliationPolicy,
    invoice: &Invoice,
) -> Result<Vec<u8>, ReconciliationError> {
    validate_policy(policy)?;
    let routes = policy
        .routes
        .iter()
        .map(|route| (route.route_id.as_str(), route))
        .collect::<BTreeMap<_, _>>();
    validate_invoice(policy, invoice, &routes)?;
    serde_json::to_vec(invoice).map_err(|error| ReconciliationError::Encoding(error.to_string()))
}

pub fn canonical_observation_bytes(
    policy: &ReconciliationPolicy,
    observation: &PaymentObservation,
    evaluated_at_unix_seconds: u64,
) -> Result<Vec<u8>, ReconciliationError> {
    validate_policy(policy)?;
    if evaluated_at_unix_seconds < policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= policy.expires_at_unix_seconds
    {
        return Err(ReconciliationError::InvalidPolicy("evaluationTime"));
    }
    validate_observation(policy, observation, evaluated_at_unix_seconds)?;
    serde_json::to_vec(observation)
        .map_err(|error| ReconciliationError::Encoding(error.to_string()))
}

pub fn reconcile(
    policy: &ReconciliationPolicy,
    invoices: &[Invoice],
    observations: &[PaymentObservation],
    evaluated_at_unix_seconds: u64,
) -> Result<ReconciliationReport, ReconciliationError> {
    validate_policy(policy)?;
    if evaluated_at_unix_seconds < policy.effective_at_unix_seconds
        || evaluated_at_unix_seconds >= policy.expires_at_unix_seconds
    {
        return Err(ReconciliationError::InvalidPolicy("evaluationTime"));
    }
    if invoices.len() > MAX_INVOICES {
        return Err(ReconciliationError::InvalidInvoice("count"));
    }
    if observations.len() > MAX_OBSERVATIONS {
        return Err(ReconciliationError::InvalidObservation("count"));
    }

    let routes = policy
        .routes
        .iter()
        .map(|route| (route.route_id.as_str(), route))
        .collect::<BTreeMap<_, _>>();
    let mut invoice_ids = BTreeSet::new();
    let mut references = BTreeMap::new();
    for invoice in invoices {
        validate_invoice(policy, invoice, &routes)?;
        if !invoice_ids.insert(invoice.invoice_id.as_str())
            || references
                .insert(invoice.reference.as_str(), invoice)
                .is_some()
        {
            return Err(ReconciliationError::InvalidInvoice("duplicateIdentity"));
        }
    }

    let mut observation_ids = BTreeSet::new();
    let mut chain_events = BTreeSet::new();
    let mut allocated: BTreeMap<&str, Vec<&PaymentObservation>> = BTreeMap::new();
    let mut late: BTreeMap<&str, Vec<&PaymentObservation>> = BTreeMap::new();
    let mut unmatched = Vec::new();
    for observation in observations {
        validate_observation(policy, observation, evaluated_at_unix_seconds)?;
        if !observation_ids.insert(observation.observation_id.as_str())
            || !chain_events.insert((
                observation.network.as_str(),
                observation.transaction_id.as_str(),
                observation.event_index,
            ))
        {
            return Err(ReconciliationError::InvalidObservation("duplicateIdentity"));
        }
        let Some(invoice) = references.get(observation.reference.as_str()).copied() else {
            unmatched.push(observation.observation_id.clone());
            continue;
        };
        let route = routes[invoice.route_id.as_str()];
        if observation.network != route.network
            || observation.asset_id != route.asset_id
            || observation.destination != route.destination
        {
            return Err(ReconciliationError::RouteMismatch);
        }
        if observation.observed_at_unix_seconds < invoice.issued_at_unix_seconds {
            return Err(ReconciliationError::InvalidObservation("beforeInvoice"));
        }
        if observation.observed_at_unix_seconds >= invoice.expires_at_unix_seconds {
            late.entry(invoice.invoice_id.as_str())
                .or_default()
                .push(observation);
        } else {
            allocated
                .entry(invoice.invoice_id.as_str())
                .or_default()
                .push(observation);
        }
    }

    let mut ordered_invoices = invoices.iter().collect::<Vec<_>>();
    ordered_invoices.sort_by(|left, right| left.invoice_id.cmp(&right.invoice_id));
    let mut results = Vec::with_capacity(ordered_invoices.len());
    for invoice in ordered_invoices {
        let mut matches = allocated
            .remove(invoice.invoice_id.as_str())
            .unwrap_or_default();
        matches.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        let observed_amount_minor = matches.iter().try_fold(0_u64, |total, observation| {
            total
                .checked_add(observation.amount_minor)
                .ok_or(ReconciliationError::AmountOverflow)
        })?;
        let state = match observed_amount_minor.cmp(&invoice.amount_minor) {
            std::cmp::Ordering::Less if observed_amount_minor == 0 => {
                ReconciliationState::NoObservation
            }
            std::cmp::Ordering::Less => ReconciliationState::PartialObserved,
            std::cmp::Ordering::Equal => ReconciliationState::ExactObserved,
            std::cmp::Ordering::Greater => ReconciliationState::ExcessObserved,
        };
        let mut late_matches = late.remove(invoice.invoice_id.as_str()).unwrap_or_default();
        late_matches.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        results.push(InvoiceReconciliation {
            invoice_id: invoice.invoice_id.clone(),
            state,
            expected_amount_minor: invoice.amount_minor,
            observed_amount_minor,
            matched_observation_ids: matches
                .into_iter()
                .map(|item| item.observation_id.clone())
                .collect(),
            late_observation_ids: late_matches
                .into_iter()
                .map(|item| item.observation_id.clone())
                .collect(),
            settlement_qualified: false,
            credit_authorized: false,
        });
    }
    unmatched.sort();
    Ok(ReconciliationReport {
        schema: REPORT_SCHEMA.into(),
        policy_sha256: policy_sha256(policy)?,
        evaluated_at_unix_seconds,
        invoices: results,
        unmatched_observation_ids: unmatched,
        settlement_qualified: false,
        credit_authorized: false,
    })
}

pub fn report_bytes(report: &ReconciliationReport) -> Result<Vec<u8>, ReconciliationError> {
    serde_json::to_vec(report).map_err(|error| ReconciliationError::Encoding(error.to_string()))
}

fn validate_policy(policy: &ReconciliationPolicy) -> Result<(), ReconciliationError> {
    if policy.schema != POLICY_SCHEMA {
        return invalid_policy("schema");
    }
    for value in [&policy.policy_id, &policy.tenant_id, &policy.merchant_id] {
        if !valid_identifier(value) {
            return invalid_policy("identifier");
        }
    }
    if policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.max_invoice_lifetime_seconds == 0
        || policy.max_invoice_lifetime_seconds > MAX_INVOICE_LIFETIME_SECONDS
        || policy.allowed_source_ids.is_empty()
        || policy.allowed_source_ids.len() > MAX_LIST_ITEMS
        || !sorted_unique(&policy.allowed_source_ids)
        || !policy
            .allowed_source_ids
            .iter()
            .all(|value| valid_identifier(value))
        || policy.routes.is_empty()
        || policy.routes.len() > MAX_LIST_ITEMS
    {
        return invalid_policy("bounds");
    }
    let mut previous = None;
    let mut route_tuples = BTreeSet::new();
    for route in &policy.routes {
        if !valid_identifier(&route.route_id)
            || !valid_identifier(&route.network)
            || !valid_identifier(&route.asset_id)
            || route.minor_unit_exponent > 38
            || !valid_destination(&route.destination)
            || previous.is_some_and(|value: &str| value >= route.route_id.as_str())
            || !route_tuples.insert((
                route.network.as_str(),
                route.asset_id.as_str(),
                route.destination.as_str(),
            ))
        {
            return invalid_policy("route");
        }
        previous = Some(route.route_id.as_str());
    }
    Ok(())
}

fn validate_invoice<'a>(
    policy: &ReconciliationPolicy,
    invoice: &Invoice,
    routes: &BTreeMap<&'a str, &'a PaymentRoute>,
) -> Result<(), ReconciliationError> {
    if invoice.schema != INVOICE_SCHEMA
        || !valid_identifier(&invoice.invoice_id)
        || invoice.tenant_id != policy.tenant_id
        || invoice.merchant_id != policy.merchant_id
        || !routes.contains_key(invoice.route_id.as_str())
        || !valid_reference(&invoice.reference)
        || invoice.amount_minor == 0
        || invoice.issued_at_unix_seconds < policy.effective_at_unix_seconds
        || invoice.expires_at_unix_seconds > policy.expires_at_unix_seconds
        || invoice.issued_at_unix_seconds >= invoice.expires_at_unix_seconds
        || invoice
            .expires_at_unix_seconds
            .saturating_sub(invoice.issued_at_unix_seconds)
            > policy.max_invoice_lifetime_seconds
    {
        return Err(ReconciliationError::InvalidInvoice("fields"));
    }
    Ok(())
}

fn validate_observation(
    policy: &ReconciliationPolicy,
    observation: &PaymentObservation,
    evaluated_at: u64,
) -> Result<(), ReconciliationError> {
    if observation.schema != OBSERVATION_SCHEMA
        || !valid_identifier(&observation.observation_id)
        || policy
            .allowed_source_ids
            .binary_search(&observation.source_id)
            .is_err()
        || !valid_identifier(&observation.network)
        || !valid_hash(&observation.transaction_id)
        || !valid_identifier(&observation.asset_id)
        || !valid_destination(&observation.destination)
        || !valid_reference(&observation.reference)
        || observation.amount_minor == 0
        || observation.observed_at_unix_seconds > evaluated_at
        || observation.block_height == 0
        || !valid_hash(&observation.block_hash)
    {
        return Err(ReconciliationError::InvalidObservation("fields"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn valid_reference(value: &str) -> bool {
    valid_identifier(value) && value.len() >= 16
}

fn valid_destination(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value[2..].bytes().any(|byte| byte != b'0')
}

fn require_sha256(value: &str) -> Result<(), ReconciliationError> {
    if valid_hash(value) {
        Ok(())
    } else {
        invalid_policy("expectedSha256")
    }
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{:x}", Sha256::digest(bytes))
}

fn invalid_policy<T>(field: &'static str) -> Result<T, ReconciliationError> {
    Err(ReconciliationError::InvalidPolicy(field))
}
