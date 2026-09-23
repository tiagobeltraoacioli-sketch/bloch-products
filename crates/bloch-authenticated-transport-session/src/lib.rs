//! One-shot, transport-neutral acquisition of an evidence-authenticated response.
//!
//! This crate performs no network or TLS operations. See the crate README for
//! the operational properties which remain the adapter's responsibility.

use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, MAX_TRANSPORT_EVIDENCE_BYTES, TransportEvidenceError,
    TransportExchangeExpectation, TransportPurpose, VerifiedAuthenticatedTransportEvidence,
    authenticated_transport_policy_sha256, verify_authenticated_transport_exchange_evidence,
};
use bloch_trusted_time::{TrustedTimeError, VerifiedTrustedTime};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_INGRESS_READ_CHUNK_BYTES: usize = 4 * 1024;
const NONCE_BYTES: usize = 32;

/// Read interface whose implementation must honor the supplied absolute
/// monotonic deadline for every potentially blocking operation.
pub trait MonotonicDeadlineRead {
    type Error;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, Self::Error>;
}

impl<E, F> MonotonicDeadlineRead for F
where
    F: FnMut(&mut [u8], Instant) -> Result<usize, E>,
{
    type Error = E;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, Self::Error> {
        self(buffer, deadline)
    }
}

#[derive(Debug, Error)]
pub enum TransportIngressError<E> {
    #[error("authenticated transport ingress read failed")]
    Read(#[source] E),
    #[error("authenticated transport ingress exceeded its monotonic deadline")]
    DeadlineExceeded,
    #[error("authenticated transport response exceeds the policy limit")]
    ResponseTooLarge,
    #[error("authenticated transport evidence exceeds the protocol limit")]
    EvidenceTooLarge,
    #[error("authenticated transport evidence is empty")]
    EmptyEvidence,
    #[error("authenticated transport ingress returned an invalid byte count")]
    InvalidReadCount,
}

#[derive(Debug, Error)]
pub enum TransportCallbackError<E> {
    #[error("authenticated transport callback failed")]
    Transport(#[source] E),
    #[error("authenticated transport bounded ingress failed")]
    Ingress(#[source] TransportIngressError<E>),
}

/// Borrowed values valid for exactly one callback invocation.
pub struct AuthenticatedTransportRequest<'session> {
    request_bytes: &'session [u8],
    request_nonce: &'session str,
    deadline: Instant,
    maximum_response_bytes: usize,
}

impl AuthenticatedTransportRequest<'_> {
    pub fn request_bytes(&self) -> &[u8] {
        self.request_bytes
    }

    pub fn request_nonce(&self) -> &str {
        self.request_nonce
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn maximum_response_bytes(&self) -> usize {
        self.maximum_response_bytes
    }

    /// Incrementally and exclusively constructs the callback result. The
    /// private fields prevent adapters from bypassing the bounded readers.
    pub fn collect_exchange<R, V, E>(
        &self,
        response: &mut R,
        evidence: &mut V,
    ) -> Result<AuthenticatedTransportInput, TransportIngressError<E>>
    where
        R: MonotonicDeadlineRead<Error = E>,
        V: MonotonicDeadlineRead<Error = E>,
    {
        let response_bytes = read_bounded(
            response,
            self.deadline,
            self.maximum_response_bytes,
            TransportIngressError::ResponseTooLarge,
        )?;
        let evidence_bytes = read_bounded(
            evidence,
            self.deadline,
            MAX_TRANSPORT_EVIDENCE_BYTES,
            TransportIngressError::EvidenceTooLarge,
        )?;
        if evidence_bytes.is_empty() {
            return Err(TransportIngressError::EmptyEvidence);
        }
        Ok(AuthenticatedTransportInput {
            response_bytes,
            evidence_bytes,
        })
    }
}

/// Bounded callback output. It can only be constructed through
/// [`AuthenticatedTransportRequest::collect_exchange`].
pub struct AuthenticatedTransportInput {
    response_bytes: Vec<u8>,
    evidence_bytes: Vec<u8>,
}

/// Opaque, non-clone result. Response access exists only after all evidence
/// and audience checks have completed successfully.
#[derive(Debug)]
pub struct VerifiedAuthenticatedTransportResponse {
    response_bytes: Vec<u8>,
    evidence: VerifiedAuthenticatedTransportEvidence,
}

impl VerifiedAuthenticatedTransportResponse {
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }

    pub fn evidence(&self) -> &VerifiedAuthenticatedTransportEvidence {
        &self.evidence
    }

    pub fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

#[derive(Debug, Error)]
pub enum AuthenticatedTransportSessionError<E> {
    #[error("authenticated transport session configuration is invalid")]
    InvalidConfiguration,
    #[error("operating-system nonce generation failed")]
    NonceGeneration,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTime(#[source] TrustedTimeError),
    #[error("authenticated transport callback failed")]
    Callback(#[source] TransportCallbackError<E>),
    #[error("authenticated transport session exceeded its monotonic deadline")]
    DeadlineExceeded,
    #[error("authenticated transport evidence verification failed")]
    Evidence(#[source] TransportEvidenceError),
}

/// Performs one fresh request and returns its response only after exact-exchange
/// evidence has been authenticated against `trusted_time`.
pub fn execute_authenticated_transport_session<E, F>(
    policy: &AuthenticatedTransportPolicy,
    expected_policy_sha256: &str,
    expected_purpose: TransportPurpose,
    request_bytes: &[u8],
    timeout: Duration,
    trusted_time: &VerifiedTrustedTime,
    callback: F,
) -> Result<VerifiedAuthenticatedTransportResponse, AuthenticatedTransportSessionError<E>>
where
    F: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    ) -> Result<AuthenticatedTransportInput, TransportCallbackError<E>>,
{
    let computed_pin = authenticated_transport_policy_sha256(policy)
        .map_err(AuthenticatedTransportSessionError::Evidence)?;
    let policy_response_limit = usize::try_from(policy.max_response_bytes)
        .map_err(|_| AuthenticatedTransportSessionError::InvalidConfiguration)?;
    if computed_pin != expected_policy_sha256
        || policy.purpose != expected_purpose
        || request_bytes.is_empty()
        || request_bytes.len() > MAX_REQUEST_BYTES
        || timeout.is_zero()
        || timeout > MAX_SESSION_TIMEOUT
        || timeout > Duration::from_millis(policy.max_round_trip_millis)
        || policy_response_limit == 0
    {
        return Err(AuthenticatedTransportSessionError::InvalidConfiguration);
    }

    // Fail before transport if trusted time is expired or targets another
    // policy/audience. The verifier repeats these checks after acquisition.
    trusted_time
        .unix_seconds()
        .map_err(AuthenticatedTransportSessionError::TrustedTime)?;
    if trusted_time.trusted_time_policy_sha256() != policy.trusted_time_policy_sha256
        || trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != policy.remote_cursor_policy_sha256
    {
        return Err(AuthenticatedTransportSessionError::Evidence(
            TransportEvidenceError::AudienceMismatch,
        ));
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(AuthenticatedTransportSessionError::InvalidConfiguration)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| AuthenticatedTransportSessionError::NonceGeneration)?;
    let request_nonce = format!("0x{}", hex::encode(nonce));
    let input = callback(AuthenticatedTransportRequest {
        request_bytes,
        request_nonce: &request_nonce,
        deadline,
        maximum_response_bytes: policy_response_limit,
    })
    .map_err(AuthenticatedTransportSessionError::Callback)?;
    if Instant::now() >= deadline {
        return Err(AuthenticatedTransportSessionError::DeadlineExceeded);
    }

    let evidence = verify_authenticated_transport_exchange_evidence(
        &input.evidence_bytes,
        policy,
        expected_policy_sha256,
        TransportExchangeExpectation {
            purpose: expected_purpose,
            request_nonce: &request_nonce,
            request_bytes,
            response_bytes: &input.response_bytes,
        },
        trusted_time,
    )
    .map_err(AuthenticatedTransportSessionError::Evidence)?;
    if Instant::now() >= deadline {
        return Err(AuthenticatedTransportSessionError::DeadlineExceeded);
    }
    evidence
        .ensure_monotonic_freshness()
        .map_err(AuthenticatedTransportSessionError::Evidence)?;

    Ok(VerifiedAuthenticatedTransportResponse {
        response_bytes: input.response_bytes,
        evidence,
    })
}

fn read_bounded<R, E>(
    reader: &mut R,
    deadline: Instant,
    limit: usize,
    overflow: TransportIngressError<E>,
) -> Result<Vec<u8>, TransportIngressError<E>>
where
    R: MonotonicDeadlineRead<Error = E>,
{
    let mut result = Vec::with_capacity(limit.min(MAX_INGRESS_READ_CHUNK_BYTES));
    let mut chunk = [0_u8; MAX_INGRESS_READ_CHUNK_BYTES];
    loop {
        if Instant::now() >= deadline {
            return Err(TransportIngressError::DeadlineExceeded);
        }
        let remaining = limit - result.len();
        let requested = if remaining == 0 {
            1
        } else {
            remaining.min(chunk.len())
        };
        let read_result = reader.read_with_deadline(&mut chunk[..requested], deadline);
        if Instant::now() >= deadline {
            return Err(TransportIngressError::DeadlineExceeded);
        }
        let read = read_result.map_err(TransportIngressError::Read)?;
        if read > requested {
            return Err(TransportIngressError::InvalidReadCount);
        }
        if read == 0 {
            return Ok(result);
        }
        if remaining == 0 {
            return Err(overflow);
        }
        result.extend_from_slice(&chunk[..read]);
    }
}
