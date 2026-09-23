//! Exact-exchange authenticated client composition for remote-cursor CAS.
//!
//! No networking or mutation is implemented here, and a successful session is
//! not evidence of linearizability, durability or authority independence.

use bloch_authenticated_transport_evidence::{AuthenticatedTransportPolicy, TransportPurpose};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportInput, AuthenticatedTransportRequest, AuthenticatedTransportSessionError,
    TransportCallbackError, execute_authenticated_transport_session,
};
use bloch_local_state_remote_cursor::{
    RemoteCursorCasError, RemoteCursorError, RemoteCursorPolicy, ValidatedRemoteCursorCasRequest,
    VerifiedRemoteCursorCasReceipt, remote_cursor_policy_sha256, verify_remote_cursor_cas_exchange,
};
use bloch_local_state_remote_cursor_caller_auth::{
    CallerAuthorizationError, VerifiedRemoteCursorCasCallerAuthorization,
};
use bloch_trusted_time::{TrustedTimeError, VerifiedTrustedTime};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

pub const REMOTE_CURSOR_CAS_SESSION_REQUEST_SCHEMA: &str =
    "bloch.products.remote-cursor-cas-session-request.v1";

/// Canonical bytes alone are deliberately insufficient: callers must also
/// supply the opaque result of verifying those same bytes against the same
/// canonical CAS request.
pub enum CasCallerAuthorization<'a> {
    Verified {
        canonical_authorization_bytes: &'a [u8],
        authorization: &'a VerifiedRemoteCursorCasCallerAuthorization,
    },
}

pub struct RemoteCursorCasSessionConfiguration<'a> {
    pub remote_cursor_policy: &'a RemoteCursorPolicy,
    pub expected_remote_cursor_policy_sha256: &'a str,
    pub transport_policy: &'a AuthenticatedTransportPolicy,
    pub expected_transport_policy_sha256: &'a str,
    pub timeout: Duration,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireCallerAuthorization<'a> {
    caller_policy_sha256: &'a str,
    authorization_sha256: &'a str,
    canonical_authorization_hex: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireRequest<'a> {
    schema: &'static str,
    remote_cursor_policy_sha256: &'a str,
    state_identity: &'a str,
    request_sha256: &'a str,
    canonical_request_hex: String,
    caller_authorization: WireCallerAuthorization<'a>,
}

/// Non-clone proof that one exact CAS request received an authenticated,
/// threshold-signed response under the configured audiences.
#[derive(Debug)]
pub struct VerifiedRemoteCursorCasSession {
    receipt: VerifiedRemoteCursorCasReceipt,
    request_sha256: String,
    receipt_sha256: String,
    transport_policy_sha256: String,
    transport_evidence_sha256: String,
    transport_service_id: String,
    transport_authority_ids: Vec<String>,
}

impl VerifiedRemoteCursorCasSession {
    pub fn receipt(&self) -> &VerifiedRemoteCursorCasReceipt {
        &self.receipt
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn transport_policy_sha256(&self) -> &str {
        &self.transport_policy_sha256
    }
    pub fn transport_evidence_sha256(&self) -> &str {
        &self.transport_evidence_sha256
    }
    pub fn transport_service_id(&self) -> &str {
        &self.transport_service_id
    }
    pub fn transport_authority_ids(&self) -> &[String] {
        &self.transport_authority_ids
    }
    pub fn linearizability_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum RemoteCursorCasSessionError<E> {
    #[error("remote cursor CAS session audience is inconsistent")]
    AudienceMismatch,
    #[error("remote cursor policy is invalid or does not match its configured pin")]
    RemoteCursorPolicy(#[source] RemoteCursorError),
    #[error("caller authorization is not the verified authorization for this exact request")]
    CallerAuthorizationMismatch,
    #[error("caller authorization is no longer fresh")]
    CallerAuthorization(#[source] CallerAuthorizationError),
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTime(#[source] TrustedTimeError),
    #[error("canonical transport request cannot be encoded")]
    RequestEncoding,
    #[error("authenticated transport session failed")]
    Transport(#[source] AuthenticatedTransportSessionError<E>),
    #[error("remote cursor CAS receipt verification failed")]
    Receipt(#[source] RemoteCursorCasError),
}

/// Builds the only bytes sent to the transport callback.
///
/// This is public for adapters that must preflight request sizing or audit the
/// protocol. It never accepts detached authorization bytes without the opaque
/// verifier capability that binds them to `request`.
pub fn canonical_cas_transport_request(
    request: &ValidatedRemoteCursorCasRequest,
    caller_authorization: CasCallerAuthorization<'_>,
) -> Result<Vec<u8>, RemoteCursorCasSessionError<std::convert::Infallible>> {
    build_transport_request(request, &caller_authorization)
}

/// Executes one bounded, nonce-bound authenticated exchange and verifies the
/// returned signed receipt before releasing an opaque result.
pub fn execute_remote_cursor_cas_session<E, F>(
    request: &ValidatedRemoteCursorCasRequest,
    caller_authorization: CasCallerAuthorization<'_>,
    configuration: RemoteCursorCasSessionConfiguration<'_>,
    trusted_time: &VerifiedTrustedTime,
    callback: F,
) -> Result<VerifiedRemoteCursorCasSession, RemoteCursorCasSessionError<E>>
where
    F: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    ) -> Result<AuthenticatedTransportInput, TransportCallbackError<E>>,
{
    let computed_remote_pin = remote_cursor_policy_sha256(configuration.remote_cursor_policy)
        .map_err(RemoteCursorCasSessionError::RemoteCursorPolicy)?;
    if computed_remote_pin != configuration.expected_remote_cursor_policy_sha256
        || request.remote_cursor_policy_sha256()
            != configuration.expected_remote_cursor_policy_sha256
        || request.state_identity() != configuration.remote_cursor_policy.state_identity
        || configuration.transport_policy.purpose != TransportPurpose::RemoteCursorCas
        || configuration.transport_policy.remote_cursor_policy_sha256
            != configuration.expected_remote_cursor_policy_sha256
        || configuration.transport_policy.state_identity != request.state_identity()
        || trusted_time.remote_cursor_policy_sha256()
            != configuration.expected_remote_cursor_policy_sha256
        || trusted_time.state_identity() != request.state_identity()
    {
        return Err(RemoteCursorCasSessionError::AudienceMismatch);
    }

    let transport_request = build_transport_request::<E>(request, &caller_authorization)?;
    let response = execute_authenticated_transport_session(
        configuration.transport_policy,
        configuration.expected_transport_policy_sha256,
        TransportPurpose::RemoteCursorCas,
        &transport_request,
        configuration.timeout,
        trusted_time,
        callback,
    )
    .map_err(RemoteCursorCasSessionError::Transport)?;
    ensure_authorization_freshness(&caller_authorization)?;

    let evaluated_at = trusted_time
        .unix_seconds()
        .map_err(RemoteCursorCasSessionError::TrustedTime)?;
    let exchange = verify_remote_cursor_cas_exchange(
        response.response_bytes(),
        request.canonical_bytes(),
        configuration.remote_cursor_policy,
        configuration.expected_remote_cursor_policy_sha256,
        evaluated_at,
    )
    .map_err(RemoteCursorCasSessionError::Receipt)?;

    // Copy only authenticated provenance before consuming the transport
    // response. Raw response/evidence documents are intentionally not exposed.
    let evidence = response.evidence();
    let result = VerifiedRemoteCursorCasSession {
        receipt: exchange.receipt().clone(),
        request_sha256: request.request_sha256().into(),
        receipt_sha256: exchange.receipt().receipt_sha256().into(),
        transport_policy_sha256: evidence.policy_sha256().into(),
        transport_evidence_sha256: evidence.evidence_sha256().into(),
        transport_service_id: evidence.service_id().into(),
        transport_authority_ids: evidence.authority_ids().to_vec(),
    };
    response
        .evidence()
        .ensure_monotonic_freshness()
        .map_err(|error| {
            RemoteCursorCasSessionError::Transport(AuthenticatedTransportSessionError::Evidence(
                error,
            ))
        })?;
    Ok(result)
}

fn build_transport_request<E>(
    request: &ValidatedRemoteCursorCasRequest,
    caller_authorization: &CasCallerAuthorization<'_>,
) -> Result<Vec<u8>, RemoteCursorCasSessionError<E>> {
    let caller_authorization = match caller_authorization {
        CasCallerAuthorization::Verified {
            canonical_authorization_bytes,
            authorization,
        } => {
            authorization
                .ensure_monotonic_freshness()
                .map_err(RemoteCursorCasSessionError::CallerAuthorization)?;
            let authorization_sha256 = hash(canonical_authorization_bytes);
            if canonical_authorization_bytes.is_empty()
                || authorization_sha256 != authorization.authorization_sha256()
                || authorization.remote_cursor_policy_sha256()
                    != request.remote_cursor_policy_sha256()
                || authorization.state_identity() != request.state_identity()
                || authorization.request_sha256() != request.request_sha256()
                || authorization.canonical_request() != request.canonical_bytes()
            {
                return Err(RemoteCursorCasSessionError::CallerAuthorizationMismatch);
            }
            WireCallerAuthorization {
                caller_policy_sha256: authorization.caller_policy_sha256(),
                authorization_sha256: authorization.authorization_sha256(),
                canonical_authorization_hex: hex::encode(canonical_authorization_bytes),
            }
        }
    };
    serde_json::to_vec(&WireRequest {
        schema: REMOTE_CURSOR_CAS_SESSION_REQUEST_SCHEMA,
        remote_cursor_policy_sha256: request.remote_cursor_policy_sha256(),
        state_identity: request.state_identity(),
        request_sha256: request.request_sha256(),
        canonical_request_hex: hex::encode(request.canonical_bytes()),
        caller_authorization,
    })
    .map_err(|_| RemoteCursorCasSessionError::RequestEncoding)
}

fn ensure_authorization_freshness<E>(
    caller_authorization: &CasCallerAuthorization<'_>,
) -> Result<(), RemoteCursorCasSessionError<E>> {
    match caller_authorization {
        CasCallerAuthorization::Verified { authorization, .. } => authorization
            .ensure_monotonic_freshness()
            .map_err(RemoteCursorCasSessionError::CallerAuthorization),
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
