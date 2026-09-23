//! Fail-closed admission boundary for an authoritative remote-cursor CAS.
//!
//! This library performs no mutation. It gates an integration callback with
//! verified capabilities but does not prove the callback is linearizable,
//! durable, independent or production-qualified.

use bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest;
use bloch_local_state_remote_cursor_caller_auth::{
    CallerAuthorizationError, ReplayProtectedRemoteCursorCasCallerAuthorization,
};
use bloch_local_state_writer_epoch_floor_store::WriterEpochFloor;
use bloch_local_state_writer_fencing::{VerifiedWriterLease, WriterFencingError};
use sha2::{Digest, Sha256};
use thiserror::Error;

const OPERATION_PREFIX: &[u8] = b"BLOCH-PRODUCTS-AUTHORITATIVE-CAS-OPERATION-V1\0";

/// Independently configured pins for one authoritative CAS deployment.
#[derive(Clone, Copy, Debug)]
pub struct AuthoritativeCasConfiguration<'a> {
    pub state_identity: &'a str,
    pub remote_cursor_policy_sha256: &'a str,
    pub caller_policy_sha256: &'a str,
    pub writer_fencing_policy_sha256: &'a str,
    pub cas_service_id: &'a str,
    pub cas_policy_sha256: &'a str,
    pub expected_writer_id: &'a str,
}

/// Inputs whose exact relationship is checked before the callback can run.
pub struct AuthoritativeCasInput<'a> {
    pub request: &'a ValidatedRemoteCursorCasRequest,
    pub caller_authorization: ReplayProtectedRemoteCursorCasCallerAuthorization,
    pub writer_lease: &'a VerifiedWriterLease,
    pub external_epoch_floor: &'a WriterEpochFloor,
}

/// Non-constructible, callback-scoped proof of admission for one exact write.
pub struct AuthorizedCasOperation<'a> {
    request: &'a ValidatedRemoteCursorCasRequest,
    caller_authorization: ReplayProtectedRemoteCursorCasCallerAuthorization,
    writer_lease: &'a VerifiedWriterLease,
    floor: &'a WriterEpochFloor,
    operation_sha256: String,
}

impl AuthorizedCasOperation<'_> {
    pub fn request(&self) -> &ValidatedRemoteCursorCasRequest {
        self.request
    }
    pub fn request_sha256(&self) -> &str {
        self.request.request_sha256()
    }
    pub fn caller_authorization_sha256(&self) -> &str {
        self.caller_authorization.authorization_sha256()
    }
    pub fn challenge_consumption_sha256(&self) -> &str {
        self.caller_authorization.challenge_consumption_sha256()
    }
    pub fn writer_fencing_certificate_sha256(&self) -> &str {
        self.writer_lease.certificate_sha256()
    }
    pub fn writer_id(&self) -> &str {
        self.writer_lease.writer_id()
    }
    pub fn writer_epoch(&self) -> u64 {
        self.writer_lease.epoch()
    }
    pub fn external_epoch_floor(&self) -> u64 {
        self.floor.epoch()
    }
    pub fn external_epoch_floor_source_id(&self) -> &str {
        self.floor.store_id()
    }
    pub fn external_epoch_floor_evidence_sha256(&self) -> &str {
        self.floor.evidence_sha256()
    }
    pub fn external_epoch_floor_state_sha256(&self) -> &str {
        self.floor.state_sha256()
    }
    pub fn operation_sha256(&self) -> &str {
        &self.operation_sha256
    }

    /// Rechecks both monotonic capabilities. Adapters should call this at the
    /// atomic commit boundary; admission also calls it before callback entry.
    pub fn ensure_freshness(&self) -> Result<(), AuthoritativeCasError> {
        self.caller_authorization
            .ensure_monotonic_freshness()
            .map_err(AuthoritativeCasError::CallerAuthorizationExpired)?;
        self.writer_lease
            .ensure_monotonic_freshness()
            .map_err(AuthoritativeCasError::WriterLeaseExpired)
    }

    pub fn consensus_proven(&self) -> bool {
        false
    }
    pub fn linearizability_proven(&self) -> bool {
        false
    }
    pub fn floor_persistence_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthoritativeCasError {
    #[error("authoritative CAS configuration is invalid")]
    InvalidConfiguration,
    #[error("request, caller authorization or writer lease crosses its configured audience")]
    AudienceMismatch,
    #[error("caller authorization does not bind the exact canonical request")]
    CallerAuthorizationMismatch,
    #[error("caller authorization is no longer fresh")]
    CallerAuthorizationExpired(#[source] CallerAuthorizationError),
    #[error("writer lease is no longer fresh")]
    WriterLeaseExpired(#[source] WriterFencingError),
    #[error("writer epoch does not advance the explicit external floor")]
    EpochRollback,
}

/// Runs `callback` only after all admission checks succeed.
///
/// The callback error is kept distinct from an admission refusal. This
/// function intentionally performs no retry because a CAS outcome may be
/// ambiguous after an adapter failure.
pub fn execute_authoritative_cas<R, E, F>(
    configuration: AuthoritativeCasConfiguration<'_>,
    input: AuthoritativeCasInput<'_>,
    callback: F,
) -> Result<R, ExecuteAuthoritativeCasError<E>>
where
    F: FnOnce(&AuthorizedCasOperation<'_>) -> Result<R, E>,
{
    validate_configuration(&configuration).map_err(ExecuteAuthoritativeCasError::Admission)?;
    validate_audiences(&configuration, &input).map_err(ExecuteAuthoritativeCasError::Admission)?;
    validate_exact_authorization(&input).map_err(ExecuteAuthoritativeCasError::Admission)?;
    if input.writer_lease.epoch() <= input.external_epoch_floor.epoch() {
        return Err(ExecuteAuthoritativeCasError::Admission(
            AuthoritativeCasError::EpochRollback,
        ));
    }
    let operation_sha256 = operation_digest(&configuration, &input);
    let operation = AuthorizedCasOperation {
        request: input.request,
        caller_authorization: input.caller_authorization,
        writer_lease: input.writer_lease,
        floor: input.external_epoch_floor,
        operation_sha256,
    };
    operation
        .ensure_freshness()
        .map_err(ExecuteAuthoritativeCasError::Admission)?;
    callback(&operation).map_err(ExecuteAuthoritativeCasError::Callback)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecuteAuthoritativeCasError<E> {
    #[error("authoritative CAS admission refused")]
    Admission(#[source] AuthoritativeCasError),
    #[error("authoritative CAS adapter failed")]
    Callback(E),
}

fn validate_configuration(
    configuration: &AuthoritativeCasConfiguration<'_>,
) -> Result<(), AuthoritativeCasError> {
    if !valid_id(configuration.state_identity)
        || !valid_digest(configuration.remote_cursor_policy_sha256)
        || !valid_digest(configuration.caller_policy_sha256)
        || !valid_digest(configuration.writer_fencing_policy_sha256)
        || !valid_id(configuration.cas_service_id)
        || !valid_digest(configuration.cas_policy_sha256)
        || !valid_id(configuration.expected_writer_id)
    {
        return Err(AuthoritativeCasError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_audiences(
    configuration: &AuthoritativeCasConfiguration<'_>,
    input: &AuthoritativeCasInput<'_>,
) -> Result<(), AuthoritativeCasError> {
    if input.request.state_identity() != configuration.state_identity
        || input.request.remote_cursor_policy_sha256() != configuration.remote_cursor_policy_sha256
        || input.caller_authorization.state_identity() != configuration.state_identity
        || input.caller_authorization.remote_cursor_policy_sha256()
            != configuration.remote_cursor_policy_sha256
        || input.caller_authorization.caller_policy_sha256() != configuration.caller_policy_sha256
        || input.writer_lease.state_identity() != configuration.state_identity
        || input.writer_lease.remote_cursor_policy_sha256()
            != configuration.remote_cursor_policy_sha256
        || input.writer_lease.writer_fencing_policy_sha256()
            != configuration.writer_fencing_policy_sha256
        || input.writer_lease.cas_service_id() != configuration.cas_service_id
        || input.writer_lease.cas_policy_sha256() != configuration.cas_policy_sha256
        || input.writer_lease.writer_id() != configuration.expected_writer_id
        || input.external_epoch_floor.state_identity() != configuration.state_identity
        || input.external_epoch_floor.remote_cursor_policy_sha256()
            != configuration.remote_cursor_policy_sha256
        || input.external_epoch_floor.writer_fencing_policy_sha256()
            != configuration.writer_fencing_policy_sha256
        || input.external_epoch_floor.cas_service_id() != configuration.cas_service_id
        || input.external_epoch_floor.cas_policy_sha256() != configuration.cas_policy_sha256
    {
        return Err(AuthoritativeCasError::AudienceMismatch);
    }
    Ok(())
}

fn validate_exact_authorization(
    input: &AuthoritativeCasInput<'_>,
) -> Result<(), AuthoritativeCasError> {
    if input.caller_authorization.request_sha256() != input.request.request_sha256()
        || input.caller_authorization.canonical_request() != input.request.canonical_bytes()
    {
        return Err(AuthoritativeCasError::CallerAuthorizationMismatch);
    }
    Ok(())
}

fn operation_digest(
    configuration: &AuthoritativeCasConfiguration<'_>,
    input: &AuthoritativeCasInput<'_>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(OPERATION_PREFIX);
    for value in [
        input.request.request_sha256().as_bytes(),
        input.caller_authorization.authorization_sha256().as_bytes(),
        input
            .caller_authorization
            .challenge_consumption_sha256()
            .as_bytes(),
        input.writer_lease.certificate_sha256().as_bytes(),
        input.writer_lease.writer_id().as_bytes(),
        input.external_epoch_floor.store_id().as_bytes(),
        input.external_epoch_floor.state_sha256().as_bytes(),
        input.external_epoch_floor.evidence_sha256().as_bytes(),
        configuration.state_identity.as_bytes(),
        configuration.remote_cursor_policy_sha256.as_bytes(),
        configuration.caller_policy_sha256.as_bytes(),
        configuration.writer_fencing_policy_sha256.as_bytes(),
        configuration.cas_service_id.as_bytes(),
        configuration.cas_policy_sha256.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(input.writer_lease.epoch().to_be_bytes());
    digest.update(input.external_epoch_floor.epoch().to_be_bytes());
    format!("0x{}", hex_encode(digest.finalize().as_slice()))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}
