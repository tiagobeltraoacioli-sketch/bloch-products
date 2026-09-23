//! One-shot, transport-neutral acquisition of threshold-authenticated time.
//!
//! The request nonce and unverified response exist only inside the acquisition
//! call. This crate performs no network or filesystem I/O and holds no private
//! keys. Callers must independently provision the policy pin and persist the
//! rollback boundary in rollback-resistant storage.

use bloch_trusted_time::{
    MAX_TRUSTED_TIME_TOKEN_BYTES, TrustedTimeBoundary, TrustedTimeError, VerifiedTrustedTime,
    parse_trusted_time_policy, verify_trusted_time_token,
};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_ACQUISITION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_INGRESS_READ_CHUNK_BYTES: usize = 4 * 1024;
const NONCE_BYTES: usize = 32;

/// Reader contract for transports capable of applying an absolute monotonic
/// deadline to every potentially blocking read.
///
/// Implementations must return no later than `deadline`. Checks around each
/// call reject late returns but cannot preempt a reader which ignores it.
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
pub enum TrustedTimeAcquisitionError<E> {
    #[error("trusted-time acquisition configuration is invalid")]
    InvalidConfiguration,
    #[error("trusted-time transport failed")]
    Transport(#[source] E),
    #[error("trusted-time acquisition exceeded its monotonic deadline")]
    DeadlineExceeded,
    #[error("trusted-time response exceeds the bounded protocol size")]
    ResponseTooLarge,
    #[error("trusted-time response is empty")]
    EmptyResponse,
    #[error("trusted-time ingress returned an invalid byte count")]
    InvalidReadCount,
    #[error("trusted-time authentication failed")]
    Authentication(#[source] TrustedTimeError),
    #[error("operating-system nonce generation failed")]
    NonceGeneration,
}

/// Borrowed request which is valid only during a single transport callback.
pub struct TrustedTimeFetchRequest<'session> {
    request_nonce: &'session str,
    expected_policy_sha256: &'session str,
    expected_state_identity: &'session str,
    expected_remote_cursor_policy_sha256: &'session str,
    deadline: Instant,
}

impl TrustedTimeFetchRequest<'_> {
    pub fn request_nonce(&self) -> &str {
        self.request_nonce
    }

    pub fn expected_policy_sha256(&self) -> &str {
        self.expected_policy_sha256
    }

    pub fn expected_state_identity(&self) -> &str {
        self.expected_state_identity
    }

    pub fn expected_remote_cursor_policy_sha256(&self) -> &str {
        self.expected_remote_cursor_policy_sha256
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn maximum_response_bytes(&self) -> usize {
        MAX_TRUSTED_TIME_TOKEN_BYTES
    }
}

/// Acquires exactly one fresh trusted-time token and returns only its opaque,
/// authenticated capability.
///
/// `transport` receives the nonce, independently pinned policy context,
/// expected audience, and absolute deadline. It returns a bounded reader; raw
/// token bytes are incrementally consumed and dropped before this function
/// returns. The transport and reader must enforce the supplied deadline on all
/// blocking work.
pub fn acquire_verified_trusted_time<E, R, F>(
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
    expected_state_identity: &str,
    expected_remote_cursor_policy_sha256: &str,
    rollback_boundary: Option<&TrustedTimeBoundary>,
    timeout: Duration,
    transport: F,
) -> Result<VerifiedTrustedTime, TrustedTimeAcquisitionError<E>>
where
    R: MonotonicDeadlineRead<Error = E>,
    F: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<R, E>,
{
    if timeout.is_zero()
        || timeout > MAX_ACQUISITION_TIMEOUT
        || expected_state_identity.is_empty()
        || expected_state_identity.len() > 128
    {
        return Err(TrustedTimeAcquisitionError::InvalidConfiguration);
    }

    let policy = parse_trusted_time_policy(policy_bytes, expected_policy_sha256)
        .map_err(TrustedTimeAcquisitionError::Authentication)?;
    if policy.state_identity != expected_state_identity
        || policy.remote_cursor_policy_sha256 != expected_remote_cursor_policy_sha256
    {
        return Err(TrustedTimeAcquisitionError::InvalidConfiguration);
    }
    if rollback_boundary
        .is_some_and(|boundary| boundary.trusted_time_policy_sha256() != expected_policy_sha256)
    {
        return Err(TrustedTimeAcquisitionError::Authentication(
            TrustedTimeError::InvalidBoundary,
        ));
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(TrustedTimeAcquisitionError::InvalidConfiguration)?;
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|_| TrustedTimeAcquisitionError::NonceGeneration)?;
    let nonce = hex::encode(nonce_bytes);

    let request = TrustedTimeFetchRequest {
        request_nonce: &nonce,
        expected_policy_sha256,
        expected_state_identity,
        expected_remote_cursor_policy_sha256,
        deadline,
    };
    let mut reader = transport(request).map_err(TrustedTimeAcquisitionError::Transport)?;
    if Instant::now() >= deadline {
        return Err(TrustedTimeAcquisitionError::DeadlineExceeded);
    }
    let token = read_bounded_response(&mut reader, deadline)?;
    let verified = verify_trusted_time_token(
        &token,
        &policy,
        expected_policy_sha256,
        &nonce,
        rollback_boundary,
    )
    .map_err(TrustedTimeAcquisitionError::Authentication)?;
    if Instant::now() >= deadline {
        return Err(TrustedTimeAcquisitionError::DeadlineExceeded);
    }
    Ok(verified)
}

fn read_bounded_response<E, R>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Vec<u8>, TrustedTimeAcquisitionError<E>>
where
    R: MonotonicDeadlineRead<Error = E>,
{
    let limit = MAX_TRUSTED_TIME_TOKEN_BYTES;
    let mut response = Vec::with_capacity(limit.min(MAX_INGRESS_READ_CHUNK_BYTES));
    let mut chunk = [0_u8; MAX_INGRESS_READ_CHUNK_BYTES];

    loop {
        if Instant::now() >= deadline {
            return Err(TrustedTimeAcquisitionError::DeadlineExceeded);
        }
        let remaining = limit - response.len();
        let requested = if remaining == 0 {
            1
        } else {
            remaining.min(chunk.len())
        };
        let read_result = reader.read_with_deadline(&mut chunk[..requested], deadline);
        if Instant::now() >= deadline {
            return Err(TrustedTimeAcquisitionError::DeadlineExceeded);
        }
        let read = read_result.map_err(TrustedTimeAcquisitionError::Transport)?;
        if read > requested {
            return Err(TrustedTimeAcquisitionError::InvalidReadCount);
        }
        if read == 0 {
            break;
        }
        if remaining == 0 {
            return Err(TrustedTimeAcquisitionError::ResponseTooLarge);
        }
        response.extend_from_slice(&chunk[..read]);
    }
    if response.is_empty() {
        return Err(TrustedTimeAcquisitionError::EmptyResponse);
    }
    Ok(response)
}
