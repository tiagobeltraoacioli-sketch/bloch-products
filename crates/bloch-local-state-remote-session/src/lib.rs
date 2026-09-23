//! One-shot, transport-neutral authenticated remote cursor fetch sessions.

use bloch_local_state_remote_cursor::{
    MAX_REMOTE_CURSOR_OBSERVATION_BYTES, RemoteCursorError, VerifiedRemoteCursor,
    parse_remote_cursor_policy, verify_remote_cursor_observation,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const NONCE_BYTES: usize = 32;

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
    let evaluated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FetchSessionError::InvalidSystemTime)?
        .as_secs();
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
