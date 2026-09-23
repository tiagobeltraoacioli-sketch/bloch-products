//! Offline authorization of exact canonical invoices.
//!
//! Only public-key verification is implemented here. Private keys remain with
//! external signers, and authorization is never settlement, credit approval,
//! or permission to move funds.

use super::{
    AuthenticatedPaymentObservation, Invoice, ReconciliationError, ReconciliationPolicy,
    ReconciliationReport, canonical_invoice_bytes, policy_sha256, reconcile_authenticated,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const INVOICE_AUTHORIZATION_POLICY_SCHEMA: &str = "bloch.pay.invoice-authorization-policy.v1";
pub const INVOICE_AUTHORIZATION_SIGNATURE_SCHEMA: &str =
    "bloch.pay.invoice-authorization-signature.v1";
pub const MAX_INVOICE_AUTHORIZATION_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_INVOICE_AUTHORIZATION_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_CANONICAL_AUTHORIZED_INVOICE_BYTES: usize = 16 * 1024;
pub const MAX_INVOICE_ISSUERS: usize = 256;

const INVOICE_SIGNATURE_PROTOCOL_DOMAIN: &[u8] = b"bloch.pay.invoice.authorization.v1";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ROUTES_PER_ISSUER: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedInvoiceIssuer {
    pub issuer_id: String,
    pub route_ids: Vec<String>,
    pub ed25519_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InvoiceAuthorizationPolicy {
    pub schema: String,
    pub policy_id: String,
    pub signature_domain: String,
    pub reconciliation_policy_sha256: String,
    pub tenant_id: String,
    pub merchant_id: String,
    pub effective_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub issuers: Vec<TrustedInvoiceIssuer>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InvoiceAuthorizationEnvelope {
    schema: String,
    signature_domain: String,
    authorization_policy_sha256: String,
    reconciliation_policy_sha256: String,
    tenant_id: String,
    merchant_id: String,
    route_id: String,
    issuer_id: String,
    invoice_sha256: String,
    authorized_at_unix_seconds: u64,
    signature: String,
}

/// Opaque proof that an exact canonical invoice was authorized by a key in
/// the independently pinned issuance policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedInvoice {
    invoice: Invoice,
    issuer_id: String,
    authorization_policy_sha256: String,
    reconciliation_policy_sha256: String,
    canonical_invoice_sha256: String,
    authorized_at_unix_seconds: u64,
}

impl AuthorizedInvoice {
    pub fn invoice(&self) -> &Invoice {
        &self.invoice
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn authorization_policy_sha256(&self) -> &str {
        &self.authorization_policy_sha256
    }

    pub fn reconciliation_policy_sha256(&self) -> &str {
        &self.reconciliation_policy_sha256
    }

    pub fn canonical_invoice_sha256(&self) -> &str {
        &self.canonical_invoice_sha256
    }

    pub fn authorized_at_unix_seconds(&self) -> u64 {
        self.authorized_at_unix_seconds
    }

    pub fn settlement_qualified(&self) -> bool {
        false
    }

    pub fn credit_authorized(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceAuthorizationEvidenceRef {
    invoice_id: String,
    authorized: bool,
    canonical_invoice_sha256: Option<String>,
    issuer_id: Option<String>,
    authorization_policy_sha256: Option<String>,
    reconciliation_policy_sha256: Option<String>,
    authorized_at_unix_seconds: Option<u64>,
}

impl InvoiceAuthorizationEvidenceRef {
    pub(crate) fn unauthenticated(invoice_id: String) -> Self {
        Self {
            invoice_id,
            authorized: false,
            canonical_invoice_sha256: None,
            issuer_id: None,
            authorization_policy_sha256: None,
            reconciliation_policy_sha256: None,
            authorized_at_unix_seconds: None,
        }
    }

    pub fn invoice_id(&self) -> &str {
        &self.invoice_id
    }

    pub fn authorized(&self) -> bool {
        self.authorized
    }

    pub fn canonical_invoice_sha256(&self) -> Option<&str> {
        self.canonical_invoice_sha256.as_deref()
    }

    pub fn issuer_id(&self) -> Option<&str> {
        self.issuer_id.as_deref()
    }

    pub fn authorization_policy_sha256(&self) -> Option<&str> {
        self.authorization_policy_sha256.as_deref()
    }

    pub fn reconciliation_policy_sha256(&self) -> Option<&str> {
        self.reconciliation_policy_sha256.as_deref()
    }

    pub fn authorized_at_unix_seconds(&self) -> Option<u64> {
        self.authorized_at_unix_seconds
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvoiceAuthorizationError {
    #[error("{kind} JSON is empty")]
    Empty { kind: &'static str },
    #[error("{kind} JSON exceeds the {maximum}-byte limit: {actual} bytes")]
    TooLarge {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid {kind} JSON: {message}")]
    InvalidJson { kind: &'static str, message: String },
    #[error("invalid invoice authorization field: {0}")]
    InvalidField(&'static str),
    #[error("input is not exact canonical JSON")]
    NonCanonicalJson,
    #[error("invoice authorization policy digest mismatch")]
    AuthorizationPolicyDigestMismatch,
    #[error("reconciliation policy digest mismatch")]
    ReconciliationPolicyDigestMismatch,
    #[error("invoice authorization context does not match the reconciliation policy")]
    TrustContextMismatch,
    #[error("invoice issuer is not authorized for this route")]
    UntrustedIssuer,
    #[error("invoice digest mismatch")]
    InvoiceDigestMismatch,
    #[error("invalid detached Ed25519 signature")]
    InvalidSignature,
    #[error("invalid invoice: {0}")]
    InvalidInvoice(String),
    #[error("reconciliation failed: {0}")]
    Reconciliation(String),
}

pub fn canonical_invoice_authorization_policy_bytes(
    policy: &InvoiceAuthorizationPolicy,
) -> Result<Vec<u8>, InvoiceAuthorizationError> {
    validate_authorization_policy(policy)?;
    serde_json::to_vec(policy).map_err(|error| invalid_json("invoice authorization policy", error))
}

pub fn invoice_authorization_policy_sha256(
    policy: &InvoiceAuthorizationPolicy,
) -> Result<String, InvoiceAuthorizationError> {
    Ok(sha256_hex(&canonical_invoice_authorization_policy_bytes(
        policy,
    )?))
}

/// Parses exact canonical policy bytes against a separately provisioned pin.
pub fn parse_invoice_authorization_policy(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<InvoiceAuthorizationPolicy, InvoiceAuthorizationError> {
    check_size(
        bytes,
        MAX_INVOICE_AUTHORIZATION_POLICY_BYTES,
        "invoice authorization policy",
    )?;
    require_hash(expected_sha256, "expectedAuthorizationPolicySha256")?;
    let policy: InvoiceAuthorizationPolicy = serde_json::from_slice(bytes)
        .map_err(|error| invalid_json("invoice authorization policy", error))?;
    validate_authorization_policy(&policy)?;
    if canonical_invoice_authorization_policy_bytes(&policy)? != bytes {
        return Err(InvoiceAuthorizationError::NonCanonicalJson);
    }
    if sha256_hex(bytes) != expected_sha256 {
        return Err(InvoiceAuthorizationError::AuthorizationPolicyDigestMismatch);
    }
    Ok(policy)
}

/// Parses an invoice only when its bytes are the canonical representation
/// admitted by the reconciliation policy.
pub fn parse_invoice_for_authorization(
    bytes: &[u8],
    reconciliation_policy: &ReconciliationPolicy,
) -> Result<Invoice, InvoiceAuthorizationError> {
    check_size(bytes, MAX_CANONICAL_AUTHORIZED_INVOICE_BYTES, "invoice")?;
    let invoice: Invoice =
        serde_json::from_slice(bytes).map_err(|error| invalid_json("invoice", error))?;
    let canonical = canonical_invoice_bytes(reconciliation_policy, &invoice)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    if canonical != bytes {
        return Err(InvoiceAuthorizationError::NonCanonicalJson);
    }
    Ok(invoice)
}

/// Returns domain-separated bytes for an external Ed25519 signer. The
/// invoice and every relevant trust/route context are length framed.
#[allow(clippy::too_many_arguments)]
pub fn invoice_authorization_signing_bytes(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    authorization_policy: &InvoiceAuthorizationPolicy,
    expected_authorization_policy_sha256: &str,
    issuer_id: &str,
    invoice: &Invoice,
    authorized_at_unix_seconds: u64,
) -> Result<Vec<u8>, InvoiceAuthorizationError> {
    let (_, canonical_invoice) = validate_signing_context(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        authorization_policy,
        expected_authorization_policy_sha256,
        issuer_id,
        invoice,
        authorized_at_unix_seconds,
    )?;
    let mut message = Vec::with_capacity(canonical_invoice.len() + 768);
    append(&mut message, INVOICE_SIGNATURE_PROTOCOL_DOMAIN)?;
    append(
        &mut message,
        authorization_policy.signature_domain.as_bytes(),
    )?;
    append(
        &mut message,
        expected_authorization_policy_sha256.as_bytes(),
    )?;
    append(
        &mut message,
        expected_reconciliation_policy_sha256.as_bytes(),
    )?;
    append(&mut message, authorization_policy.tenant_id.as_bytes())?;
    append(&mut message, authorization_policy.merchant_id.as_bytes())?;
    append(&mut message, invoice.route_id.as_bytes())?;
    append(&mut message, issuer_id.as_bytes())?;
    append(&mut message, &authorized_at_unix_seconds.to_be_bytes())?;
    append(&mut message, &canonical_invoice)?;
    Ok(message)
}

/// Encodes a strict detached-signature envelope after verifying the supplied
/// signature. The crate never receives or stores a private key.
#[allow(clippy::too_many_arguments)]
pub fn encode_invoice_authorization_envelope(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    authorization_policy: &InvoiceAuthorizationPolicy,
    expected_authorization_policy_sha256: &str,
    issuer_id: &str,
    invoice: &Invoice,
    authorized_at_unix_seconds: u64,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, InvoiceAuthorizationError> {
    let message = invoice_authorization_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        authorization_policy,
        expected_authorization_policy_sha256,
        issuer_id,
        invoice,
        authorized_at_unix_seconds,
    )?;
    let issuer = trusted_issuer(authorization_policy, issuer_id, &invoice.route_id)?;
    verify_signature(issuer, &message, signature_bytes)?;
    let canonical = canonical_invoice_bytes(reconciliation_policy, invoice)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    let envelope = InvoiceAuthorizationEnvelope {
        schema: INVOICE_AUTHORIZATION_SIGNATURE_SCHEMA.into(),
        signature_domain: authorization_policy.signature_domain.clone(),
        authorization_policy_sha256: expected_authorization_policy_sha256.into(),
        reconciliation_policy_sha256: expected_reconciliation_policy_sha256.into(),
        tenant_id: invoice.tenant_id.clone(),
        merchant_id: invoice.merchant_id.clone(),
        route_id: invoice.route_id.clone(),
        issuer_id: issuer_id.into(),
        invoice_sha256: sha256_hex(&canonical),
        authorized_at_unix_seconds,
        signature: format!("0x{}", hex::encode(signature_bytes)),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| invalid_json("invoice authorization envelope", error))?;
    check_size(
        &bytes,
        MAX_INVOICE_AUTHORIZATION_ENVELOPE_BYTES,
        "invoice authorization envelope",
    )?;
    Ok(bytes)
}

/// Verifies the exact detached invoice and both independent policy pins.
#[allow(clippy::too_many_arguments)]
pub fn verify_authorized_invoice(
    envelope_bytes: &[u8],
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    authorization_policy: &InvoiceAuthorizationPolicy,
    expected_authorization_policy_sha256: &str,
    invoice: &Invoice,
) -> Result<AuthorizedInvoice, InvoiceAuthorizationError> {
    check_size(
        envelope_bytes,
        MAX_INVOICE_AUTHORIZATION_ENVELOPE_BYTES,
        "invoice authorization envelope",
    )?;
    let envelope: InvoiceAuthorizationEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|error| invalid_json("invoice authorization envelope", error))?;
    if serde_json::to_vec(&envelope)
        .map_err(|error| invalid_json("invoice authorization envelope", error))?
        != envelope_bytes
    {
        return Err(InvoiceAuthorizationError::NonCanonicalJson);
    }
    if envelope.schema != INVOICE_AUTHORIZATION_SIGNATURE_SCHEMA {
        return Err(InvoiceAuthorizationError::InvalidField("envelope.schema"));
    }
    let message = invoice_authorization_signing_bytes(
        reconciliation_policy,
        expected_reconciliation_policy_sha256,
        authorization_policy,
        expected_authorization_policy_sha256,
        &envelope.issuer_id,
        invoice,
        envelope.authorized_at_unix_seconds,
    )?;
    if envelope.signature_domain != authorization_policy.signature_domain
        || envelope.authorization_policy_sha256 != expected_authorization_policy_sha256
        || envelope.reconciliation_policy_sha256 != expected_reconciliation_policy_sha256
        || envelope.tenant_id != invoice.tenant_id
        || envelope.merchant_id != invoice.merchant_id
        || envelope.route_id != invoice.route_id
    {
        return Err(InvoiceAuthorizationError::TrustContextMismatch);
    }
    let canonical = canonical_invoice_bytes(reconciliation_policy, invoice)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    let invoice_digest = sha256_hex(&canonical);
    if envelope.invoice_sha256 != invoice_digest {
        return Err(InvoiceAuthorizationError::InvoiceDigestMismatch);
    }
    let issuer = trusted_issuer(authorization_policy, &envelope.issuer_id, &invoice.route_id)?;
    let signature = decode_hex_exact(&envelope.signature, 64, "signature")?;
    verify_signature(issuer, &message, &signature)?;
    Ok(AuthorizedInvoice {
        invoice: invoice.clone(),
        issuer_id: envelope.issuer_id,
        authorization_policy_sha256: envelope.authorization_policy_sha256,
        reconciliation_policy_sha256: envelope.reconciliation_policy_sha256,
        canonical_invoice_sha256: invoice_digest,
        authorized_at_unix_seconds: envelope.authorized_at_unix_seconds,
    })
}

/// Protected reconciliation path: raw `Invoice` values cannot enter it.
pub fn reconcile_authorized_invoices(
    policy: &ReconciliationPolicy,
    expected_policy_sha256: &str,
    expected_authorization_policy_sha256: &str,
    authorized_invoices: &[AuthorizedInvoice],
    authenticated_observations: &[AuthenticatedPaymentObservation],
    evaluated_at_unix_seconds: u64,
) -> Result<ReconciliationReport, InvoiceAuthorizationError> {
    require_hash(
        expected_authorization_policy_sha256,
        "expectedAuthorizationPolicySha256",
    )?;
    let actual_policy_sha256 = policy_sha256(policy)
        .map_err(|error| InvoiceAuthorizationError::Reconciliation(error.to_string()))?;
    if actual_policy_sha256 != expected_policy_sha256 {
        return Err(InvoiceAuthorizationError::ReconciliationPolicyDigestMismatch);
    }
    let mut invoices = Vec::with_capacity(authorized_invoices.len());
    let mut evidence = Vec::with_capacity(authorized_invoices.len());
    for authorized in authorized_invoices {
        if authorized.authorized_at_unix_seconds > evaluated_at_unix_seconds {
            return Err(InvoiceAuthorizationError::InvalidField("authorizationTime"));
        }
        if authorized.reconciliation_policy_sha256 != expected_policy_sha256 {
            return Err(InvoiceAuthorizationError::ReconciliationPolicyDigestMismatch);
        }
        if authorized.authorization_policy_sha256 != expected_authorization_policy_sha256 {
            return Err(InvoiceAuthorizationError::AuthorizationPolicyDigestMismatch);
        }
        let canonical = canonical_invoice_bytes(policy, &authorized.invoice)
            .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
        if sha256_hex(&canonical) != authorized.canonical_invoice_sha256 {
            return Err(InvoiceAuthorizationError::InvoiceDigestMismatch);
        }
        evidence.push(InvoiceAuthorizationEvidenceRef {
            invoice_id: authorized.invoice.invoice_id.clone(),
            authorized: true,
            canonical_invoice_sha256: Some(authorized.canonical_invoice_sha256.clone()),
            issuer_id: Some(authorized.issuer_id.clone()),
            authorization_policy_sha256: Some(authorized.authorization_policy_sha256.clone()),
            reconciliation_policy_sha256: Some(authorized.reconciliation_policy_sha256.clone()),
            authorized_at_unix_seconds: Some(authorized.authorized_at_unix_seconds),
        });
        invoices.push(authorized.invoice.clone());
    }
    let mut report = reconcile_authenticated(
        policy,
        expected_policy_sha256,
        &invoices,
        authenticated_observations,
        evaluated_at_unix_seconds,
    )
    .map_err(|error| InvoiceAuthorizationError::Reconciliation(error.to_string()))?;
    evidence.sort_by(|left, right| left.invoice_id.cmp(&right.invoice_id));
    report.record_authorized_invoices(evidence);
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn validate_signing_context<'a>(
    reconciliation_policy: &ReconciliationPolicy,
    expected_reconciliation_policy_sha256: &str,
    authorization_policy: &'a InvoiceAuthorizationPolicy,
    expected_authorization_policy_sha256: &str,
    issuer_id: &str,
    invoice: &Invoice,
    authorized_at_unix_seconds: u64,
) -> Result<(&'a TrustedInvoiceIssuer, Vec<u8>), InvoiceAuthorizationError> {
    require_hash(
        expected_reconciliation_policy_sha256,
        "expectedReconciliationPolicySha256",
    )?;
    require_hash(
        expected_authorization_policy_sha256,
        "expectedAuthorizationPolicySha256",
    )?;
    let actual_reconciliation = policy_sha256(reconciliation_policy)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    if actual_reconciliation != expected_reconciliation_policy_sha256 {
        return Err(InvoiceAuthorizationError::ReconciliationPolicyDigestMismatch);
    }
    if invoice_authorization_policy_sha256(authorization_policy)?
        != expected_authorization_policy_sha256
    {
        return Err(InvoiceAuthorizationError::AuthorizationPolicyDigestMismatch);
    }
    validate_policy_context(reconciliation_policy, authorization_policy)?;
    if authorized_at_unix_seconds < authorization_policy.effective_at_unix_seconds
        || authorized_at_unix_seconds >= authorization_policy.expires_at_unix_seconds
        || authorized_at_unix_seconds < invoice.issued_at_unix_seconds
        || authorized_at_unix_seconds >= invoice.expires_at_unix_seconds
    {
        return Err(InvoiceAuthorizationError::InvalidField("authorizationTime"));
    }
    let canonical = canonical_invoice_bytes(reconciliation_policy, invoice)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    if canonical.len() > MAX_CANONICAL_AUTHORIZED_INVOICE_BYTES {
        return Err(InvoiceAuthorizationError::TooLarge {
            kind: "invoice",
            actual: canonical.len(),
            maximum: MAX_CANONICAL_AUTHORIZED_INVOICE_BYTES,
        });
    }
    let issuer = trusted_issuer(authorization_policy, issuer_id, &invoice.route_id)?;
    Ok((issuer, canonical))
}

fn validate_authorization_policy(
    policy: &InvoiceAuthorizationPolicy,
) -> Result<(), InvoiceAuthorizationError> {
    if policy.schema != INVOICE_AUTHORIZATION_POLICY_SCHEMA {
        return Err(InvoiceAuthorizationError::InvalidField("policy.schema"));
    }
    for (field, value) in [
        ("policyId", policy.policy_id.as_str()),
        ("signatureDomain", policy.signature_domain.as_str()),
        ("tenantId", policy.tenant_id.as_str()),
        ("merchantId", policy.merchant_id.as_str()),
    ] {
        if !valid_identifier(value) {
            return Err(InvoiceAuthorizationError::InvalidField(field));
        }
    }
    require_hash(
        &policy.reconciliation_policy_sha256,
        "reconciliationPolicySha256",
    )?;
    if policy.effective_at_unix_seconds >= policy.expires_at_unix_seconds
        || policy.issuers.is_empty()
        || policy.issuers.len() > MAX_INVOICE_ISSUERS
    {
        return Err(InvoiceAuthorizationError::InvalidField("policyBounds"));
    }
    let mut issuer_ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut previous_issuer: Option<&str> = None;
    for issuer in &policy.issuers {
        if !valid_identifier(&issuer.issuer_id)
            || issuer.route_ids.is_empty()
            || issuer.route_ids.len() > MAX_ROUTES_PER_ISSUER
            || !sorted_unique(&issuer.route_ids)
            || !issuer.route_ids.iter().all(|route| valid_identifier(route))
        {
            return Err(InvoiceAuthorizationError::InvalidField("issuer"));
        }
        parse_public_key(&issuer.ed25519_public_key)?;
        if previous_issuer.is_some_and(|previous| previous >= issuer.issuer_id.as_str())
            || !issuer_ids.insert(issuer.issuer_id.as_str())
            || !keys.insert(issuer.ed25519_public_key.as_str())
        {
            return Err(InvoiceAuthorizationError::InvalidField("duplicateIssuer"));
        }
        previous_issuer = Some(issuer.issuer_id.as_str());
    }
    Ok(())
}

fn validate_policy_context(
    reconciliation_policy: &ReconciliationPolicy,
    authorization_policy: &InvoiceAuthorizationPolicy,
) -> Result<(), InvoiceAuthorizationError> {
    let reconciliation_digest = policy_sha256(reconciliation_policy)
        .map_err(|error| InvoiceAuthorizationError::InvalidInvoice(error.to_string()))?;
    if authorization_policy.reconciliation_policy_sha256 != reconciliation_digest
        || authorization_policy.tenant_id != reconciliation_policy.tenant_id
        || authorization_policy.merchant_id != reconciliation_policy.merchant_id
        || authorization_policy.issuers.iter().any(|issuer| {
            issuer.route_ids.iter().any(|route_id| {
                reconciliation_policy
                    .routes
                    .iter()
                    .all(|route| route.route_id != *route_id)
            })
        })
    {
        return Err(InvoiceAuthorizationError::TrustContextMismatch);
    }
    Ok(())
}

fn trusted_issuer<'a>(
    policy: &'a InvoiceAuthorizationPolicy,
    issuer_id: &str,
    route_id: &str,
) -> Result<&'a TrustedInvoiceIssuer, InvoiceAuthorizationError> {
    policy
        .issuers
        .iter()
        .find(|issuer| {
            issuer.issuer_id == issuer_id
                && issuer
                    .route_ids
                    .binary_search_by(|candidate| candidate.as_str().cmp(route_id))
                    .is_ok()
        })
        .ok_or(InvoiceAuthorizationError::UntrustedIssuer)
}

fn verify_signature(
    issuer: &TrustedInvoiceIssuer,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), InvoiceAuthorizationError> {
    let key = parse_public_key(&issuer.ed25519_public_key)?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| InvoiceAuthorizationError::InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| InvoiceAuthorizationError::InvalidSignature)
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, InvoiceAuthorizationError> {
    let bytes: [u8; 32] = decode_hex_exact(value, 32, "ed25519PublicKey")?
        .try_into()
        .map_err(|_| InvoiceAuthorizationError::InvalidField("ed25519PublicKey"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| InvoiceAuthorizationError::InvalidField("ed25519PublicKey"))?;
    if key.is_weak() {
        return Err(InvoiceAuthorizationError::InvalidField("ed25519PublicKey"));
    }
    Ok(key)
}

fn require_hash(value: &str, field: &'static str) -> Result<(), InvoiceAuthorizationError> {
    decode_hex_exact(value, 32, field).map(|_| ())
}

fn decode_hex_exact(
    value: &str,
    expected_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, InvoiceAuthorizationError> {
    if value.len() != expected_bytes.saturating_mul(2).saturating_add(2)
        || !value.starts_with("0x")
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(InvoiceAuthorizationError::InvalidField(field));
    }
    hex::decode(&value[2..]).map_err(|_| InvoiceAuthorizationError::InvalidField(field))
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

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn append(target: &mut Vec<u8>, value: &[u8]) -> Result<(), InvoiceAuthorizationError> {
    let length = u64::try_from(value.len())
        .map_err(|_| InvoiceAuthorizationError::InvalidField("length"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn check_size(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<(), InvoiceAuthorizationError> {
    if bytes.is_empty() {
        return Err(InvoiceAuthorizationError::Empty { kind });
    }
    if bytes.len() > maximum {
        return Err(InvoiceAuthorizationError::TooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn invalid_json(kind: &'static str, error: serde_json::Error) -> InvoiceAuthorizationError {
    InvoiceAuthorizationError::InvalidJson {
        kind,
        message: error.to_string(),
    }
}

impl From<ReconciliationError> for InvoiceAuthorizationError {
    fn from(error: ReconciliationError) -> Self {
        Self::Reconciliation(error.to_string())
    }
}
