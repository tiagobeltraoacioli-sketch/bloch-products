//! One-shot, transport-neutral authenticated remote cursor fetch sessions.

use bloch_local_state_remote_cursor::{
    MAX_REMOTE_CURSOR_OBSERVATION_BYTES, RemoteCursorError, VerifiedRemoteCursor,
    parse_remote_cursor_policy, verify_remote_cursor_observation,
};
use bloch_trusted_time::{TrustedTimeError, VerifiedTrustedTime};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_INGRESS_READ_CHUNK_BYTES: usize = 4 * 1024;
const NONCE_BYTES: usize = 32;

/// Minimal transport-neutral interface for reads which can apply an absolute
/// monotonic deadline to every potentially blocking operation.
///
/// Implementations must arrange for the operation to return no later than
/// `deadline`. The bounded reader also checks the deadline immediately before
/// and after every call, but cannot preempt an implementation which ignores
/// it.
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
pub enum BoundedIngressError<E> {
    #[error("remote cursor ingress read failed")]
    Read(#[source] E),
    #[error("remote cursor ingress exceeded its monotonic deadline")]
    DeadlineExceeded,
    #[error("remote cursor response exceeds the bounded protocol size")]
    ResponseTooLarge,
    #[error("remote cursor response is empty")]
    EmptyResponse,
    #[error("remote cursor ingress returned an invalid byte count")]
    InvalidReadCount,
}

/// Borrowed request valid only during one transport callback.
pub struct RemoteCursorFetchRequest<'session> {
    request_nonce: &'session str,
    expected_state_identity: &'session str,
    deadline: Instant,
}

impl RemoteCursorFetchRequest<'_> {
    pub fn request_nonce(&self) -> &str {
        self.request_nonce
    }

    pub fn expected_state_identity(&self) -> &str {
        self.expected_state_identity
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn maximum_response_bytes(&self) -> usize {
        MAX_REMOTE_CURSOR_OBSERVATION_BYTES
    }

    /// Incrementally consumes one response without allowing the ingress
    /// implementation to choose an unbounded allocation size.
    pub fn read_bounded_response<R>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<u8>, BoundedIngressError<R::Error>>
    where
        R: MonotonicDeadlineRead,
    {
        read_bounded_remote_cursor_response(self, reader)
    }
}

/// Reads a remote-cursor response incrementally, with a hard byte limit and an
/// absolute monotonic deadline supplied to every ingress operation.
///
/// At most [`MAX_INGRESS_READ_CHUNK_BYTES`] are requested per operation. Once
/// the protocol limit has been reached, a one-byte probe is used to distinguish
/// an exact-size response from an oversized response without growing the
/// result buffer beyond the limit.
pub fn read_bounded_remote_cursor_response<R>(
    request: &RemoteCursorFetchRequest<'_>,
    reader: &mut R,
) -> Result<Vec<u8>, BoundedIngressError<R::Error>>
where
    R: MonotonicDeadlineRead,
{
    let deadline = request.deadline();
    let limit = request.maximum_response_bytes();
    let mut response = Vec::with_capacity(limit.min(MAX_INGRESS_READ_CHUNK_BYTES));
    let mut chunk = [0_u8; MAX_INGRESS_READ_CHUNK_BYTES];

    loop {
        if Instant::now() >= deadline {
            return Err(BoundedIngressError::DeadlineExceeded);
        }

        let remaining = limit - response.len();
        let requested = if remaining == 0 {
            1
        } else {
            remaining.min(chunk.len())
        };
        let read_result = reader.read_with_deadline(&mut chunk[..requested], deadline);

        if Instant::now() >= deadline {
            return Err(BoundedIngressError::DeadlineExceeded);
        }
        let read = read_result.map_err(BoundedIngressError::Read)?;
        if read > requested {
            return Err(BoundedIngressError::InvalidReadCount);
        }
        if read == 0 {
            break;
        }
        if remaining == 0 {
            return Err(BoundedIngressError::ResponseTooLarge);
        }
        response.extend_from_slice(&chunk[..read]);
    }

    if response.is_empty() {
        return Err(BoundedIngressError::EmptyResponse);
    }
    Ok(response)
}

#[derive(Debug, Error)]
pub enum FetchSessionError<E> {
    #[error("remote cursor fetch configuration is invalid")]
    InvalidConfiguration,
    #[error("remote cursor transport failed")]
    Transport(#[source] E),
    #[error("remote cursor transport exceeded its monotonic deadline")]
    DeadlineExceeded,
    #[error("remote cursor response exceeds the bounded protocol size")]
    ResponseTooLarge,
    #[error("current system time is before the Unix epoch")]
    InvalidSystemTime,
    #[error("trusted-time capability is unavailable or expired")]
    TrustedTime(#[source] TrustedTimeError),
    #[error("trusted-time policy or audience does not match the remote cursor request")]
    TrustedTimeContextMismatch,
    #[error("remote cursor authentication failed")]
    Authentication(#[source] RemoteCursorError),
    #[error("operating-system nonce generation failed")]
    NonceGeneration,
}

/// Performs exactly one fresh fetch and returns only an authenticated cursor.
///
/// `transport` must apply the supplied monotonic deadline to all blocking I/O.
/// The session also rejects a response returned after that deadline. The nonce
/// is generated and dropped inside this function and is never returned.
///
/// This compatibility entry point relies on the host wall clock and is not the
/// qualified trusted-time path. Production callers requiring that gate should
/// use [`fetch_verified_remote_cursor_with_trusted_time`].
pub fn fetch_verified_remote_cursor<E, F>(
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
    expected_state_identity: &str,
    timeout: Duration,
    transport: F,
) -> Result<VerifiedRemoteCursor, FetchSessionError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    fetch_with_evaluated_at(
        policy_bytes,
        expected_policy_sha256,
        expected_state_identity,
        timeout,
        transport,
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| FetchSessionError::InvalidSystemTime)
                .map(|duration| duration.as_secs())
        },
    )
}

/// Performs one authenticated fetch using a threshold-verified time
/// capability instead of accepting or reading an operator-controlled time.
pub fn fetch_verified_remote_cursor_with_trusted_time<E, F>(
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
    expected_state_identity: &str,
    timeout: Duration,
    trusted_time: &VerifiedTrustedTime,
    expected_trusted_time_policy_sha256: &str,
    transport: F,
) -> Result<VerifiedRemoteCursor, FetchSessionError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    if trusted_time.trusted_time_policy_sha256() != expected_trusted_time_policy_sha256
        || trusted_time.state_identity() != expected_state_identity
        || trusted_time.remote_cursor_policy_sha256() != expected_policy_sha256
    {
        return Err(FetchSessionError::TrustedTimeContextMismatch);
    }
    trusted_time
        .unix_seconds()
        .map_err(FetchSessionError::TrustedTime)?;
    fetch_with_evaluated_at(
        policy_bytes,
        expected_policy_sha256,
        expected_state_identity,
        timeout,
        transport,
        || {
            trusted_time
                .unix_seconds()
                .map_err(FetchSessionError::TrustedTime)
        },
    )
}

fn fetch_with_evaluated_at<E, F, T>(
    policy_bytes: &[u8],
    expected_policy_sha256: &str,
    expected_state_identity: &str,
    timeout: Duration,
    transport: F,
    evaluated_at: T,
) -> Result<VerifiedRemoteCursor, FetchSessionError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
    T: FnOnce() -> Result<u64, FetchSessionError<E>>,
{
    if timeout.is_zero()
        || timeout > MAX_FETCH_TIMEOUT
        || expected_state_identity.is_empty()
        || expected_state_identity.len() > 128
    {
        return Err(FetchSessionError::InvalidConfiguration);
    }
    let policy = parse_remote_cursor_policy(policy_bytes, expected_policy_sha256)
        .map_err(FetchSessionError::Authentication)?;
    if policy.state_identity != expected_state_identity {
        return Err(FetchSessionError::InvalidConfiguration);
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(FetchSessionError::InvalidConfiguration)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| FetchSessionError::NonceGeneration)?;
    let nonce = hex::encode(nonce);
    let response = transport(RemoteCursorFetchRequest {
        request_nonce: &nonce,
        expected_state_identity,
        deadline,
    })
    .map_err(FetchSessionError::Transport)?;
    if Instant::now() >= deadline {
        return Err(FetchSessionError::DeadlineExceeded);
    }
    if response.is_empty() || response.len() > MAX_REMOTE_CURSOR_OBSERVATION_BYTES {
        return Err(FetchSessionError::ResponseTooLarge);
    }
    let evaluated_at = evaluated_at()?;
    let verified = verify_remote_cursor_observation(
        &response,
        &policy,
        expected_policy_sha256,
        &nonce,
        evaluated_at,
    )
    .map_err(FetchSessionError::Authentication)?;
    if Instant::now() >= deadline {
        return Err(FetchSessionError::DeadlineExceeded);
    }
    Ok(verified)
}
