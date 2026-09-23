//! Fail-closed contract between authenticated transport verification and a
//! separately qualified live fetch adapter.
//!
//! No network, TLS, private-key, cache or HSM operation is implemented here.

use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TransportPurpose, authenticated_transport_policy_sha256,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportInput, AuthenticatedTransportRequest, AuthenticatedTransportSessionError,
    MonotonicDeadlineRead, TransportCallbackError, TransportIngressError,
    VerifiedAuthenticatedTransportResponse, execute_authenticated_transport_session,
};
use bloch_trusted_time::VerifiedTrustedTime;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_KEY_HANDLE_BYTES: usize = 256;

/// Non-secret reference to a non-exportable client private key.
///
/// The deliberately restricted syntax excludes URI query/user-info fields and
/// byte-bearing key material. It is an identifier, not proof that the backing
/// provider is non-exportable; that property requires deployment qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalMtlsKeyHandle(String);

impl ExternalMtlsKeyHandle {
    pub fn parse(value: &str) -> Result<Self, FetchContractError> {
        let parsed = value.split_once("://");
        let valid = parsed.is_some_and(|(scheme, suffix)| {
            matches!(scheme, "hsm" | "kms" | "pkcs11-object")
                && !suffix.is_empty()
                && suffix.split('/').all(|segment| {
                    !segment.is_empty()
                        && segment != "."
                        && segment != ".."
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
        });
        if !valid || value.len() > MAX_KEY_HANDLE_BYTES {
            return Err(FetchContractError::InvalidKeyHandle);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Adapter-reported facts about the connection that carried this exchange.
/// These claims are checked against policy and must also be supported by the
/// independently authenticated transport evidence.
#[derive(Clone, Copy, Debug)]
pub struct AdapterHandshakeObservation<'a> {
    pub endpoint_dns_name: &'a str,
    pub endpoint_port: u16,
    pub tls_version: &'a str,
    pub alpn: &'a str,
    pub cipher_suite: &'a str,
    pub server_spki_sha256: &'a str,
    pub client_spki_sha256: &'a str,
    pub mtls_key_handle: &'a ExternalMtlsKeyHandle,
    pub peer_certificate_verified: bool,
    pub client_certificate_used: bool,
    pub response_from_cache: bool,
    pub cache_read_attempted: bool,
    pub cache_write_attempted: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FetchContractError {
    #[error("external mTLS key handle is invalid")]
    InvalidKeyHandle,
    #[error("adapter handshake does not match the pinned endpoint or TLS policy")]
    HandshakeMismatch,
    #[error("adapter did not verify the peer certificate")]
    PeerNotVerified,
    #[error("adapter did not use the configured mTLS client certificate")]
    ClientCertificateNotUsed,
    #[error("adapter cache use is forbidden")]
    CacheUseForbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchCacheMode {
    Disabled,
}

#[derive(Debug, Error)]
pub enum AuthenticatedFetchAdapterError<E> {
    #[error("live fetch adapter failed")]
    Adapter(#[source] E),
    #[error("live fetch adapter violated the authenticated-fetch contract")]
    Contract(#[source] FetchContractError),
    #[error("live fetch adapter returned invalid bounded ingress")]
    Ingress(#[source] TransportIngressError<E>),
}

/// Adapter request scoped to one fresh authenticated transport session.
/// Its private fields prevent construction outside this crate.
pub struct AuthenticatedFetchRequest<'session> {
    transport: AuthenticatedTransportRequest<'session>,
    policy: &'session AuthenticatedTransportPolicy,
    expected_purpose: TransportPurpose,
    key_handle: &'session ExternalMtlsKeyHandle,
}

impl AuthenticatedFetchRequest<'_> {
    pub fn request_bytes(&self) -> &[u8] {
        self.transport.request_bytes()
    }

    pub fn request_nonce(&self) -> &str {
        self.transport.request_nonce()
    }

    pub fn deadline(&self) -> Instant {
        self.transport.deadline()
    }

    pub fn maximum_response_bytes(&self) -> usize {
        self.transport.maximum_response_bytes()
    }

    pub fn endpoint_dns_name(&self) -> &str {
        &self.policy.endpoint_dns_name
    }

    pub fn endpoint_port(&self) -> u16 {
        self.policy.endpoint_port
    }

    pub fn tls_version(&self) -> &str {
        &self.policy.tls_version
    }

    pub fn alpn(&self) -> &str {
        &self.policy.alpn
    }

    pub fn allowed_cipher_suites(&self) -> &[String] {
        &self.policy.allowed_cipher_suites
    }

    pub fn server_spki_sha256(&self) -> &[String] {
        &self.policy.server_spki_sha256
    }

    pub fn client_spki_sha256(&self) -> &str {
        &self.policy.client_spki_sha256
    }

    pub fn purpose(&self) -> TransportPurpose {
        self.expected_purpose
    }

    pub fn mtls_key_handle(&self) -> &ExternalMtlsKeyHandle {
        self.key_handle
    }

    pub fn cache_mode(&self) -> FetchCacheMode {
        FetchCacheMode::Disabled
    }

    /// Validates adapter-observed handshake/cache facts, then exclusively
    /// constructs bounded exact response/evidence input for verification.
    pub fn complete_exchange<R, V, E>(
        &self,
        observation: AdapterHandshakeObservation<'_>,
        response: &mut R,
        evidence: &mut V,
    ) -> Result<AuthenticatedTransportInput, AuthenticatedFetchAdapterError<E>>
    where
        R: MonotonicDeadlineRead<Error = E>,
        V: MonotonicDeadlineRead<Error = E>,
    {
        self.validate_observation(observation)
            .map_err(AuthenticatedFetchAdapterError::Contract)?;
        self.transport
            .collect_exchange(response, evidence)
            .map_err(AuthenticatedFetchAdapterError::Ingress)
    }

    fn validate_observation(
        &self,
        observation: AdapterHandshakeObservation<'_>,
    ) -> Result<(), FetchContractError> {
        if !observation.peer_certificate_verified {
            return Err(FetchContractError::PeerNotVerified);
        }
        if !observation.client_certificate_used {
            return Err(FetchContractError::ClientCertificateNotUsed);
        }
        if observation.response_from_cache
            || observation.cache_read_attempted
            || observation.cache_write_attempted
        {
            return Err(FetchContractError::CacheUseForbidden);
        }
        if self.policy.purpose != self.expected_purpose
            || observation.endpoint_dns_name != self.policy.endpoint_dns_name
            || observation.endpoint_port != self.policy.endpoint_port
            || observation.tls_version != self.policy.tls_version
            || observation.alpn != self.policy.alpn
            || !self
                .policy
                .allowed_cipher_suites
                .iter()
                .any(|allowed| allowed == observation.cipher_suite)
            || !self
                .policy
                .server_spki_sha256
                .iter()
                .any(|allowed| allowed == observation.server_spki_sha256)
            || observation.client_spki_sha256 != self.policy.client_spki_sha256
            || observation.mtls_key_handle != self.key_handle
        {
            return Err(FetchContractError::HandshakeMismatch);
        }
        Ok(())
    }
}

/// Live implementation boundary. Implementors must use `complete_exchange`;
/// `AuthenticatedTransportInput` has no public unchecked constructor.
pub trait AuthenticatedFetchAdapter {
    type Error;

    fn fetch(
        &mut self,
        request: AuthenticatedFetchRequest<'_>,
    ) -> Result<AuthenticatedTransportInput, AuthenticatedFetchAdapterError<Self::Error>>;
}

#[derive(Clone, Copy)]
pub struct AuthenticatedFetchParameters<'a> {
    pub policy: &'a AuthenticatedTransportPolicy,
    pub expected_policy_sha256: &'a str,
    pub expected_purpose: TransportPurpose,
    pub key_handle: &'a ExternalMtlsKeyHandle,
    pub request_bytes: &'a [u8],
    pub timeout: Duration,
    pub trusted_time: &'a VerifiedTrustedTime,
}

/// Executes one non-cacheable fetch and releases response bytes only after
/// contract validation and exact-exchange evidence verification.
pub fn execute_authenticated_fetch<A>(
    adapter: &mut A,
    parameters: AuthenticatedFetchParameters<'_>,
) -> Result<VerifiedAuthenticatedTransportResponse, AuthenticatedFetchError<A::Error>>
where
    A: AuthenticatedFetchAdapter,
{
    // Duplicate the cheap pin check before invoking any live adapter. The
    // transport session repeats it, preserving defense in depth.
    let computed_pin = authenticated_transport_policy_sha256(parameters.policy)
        .map_err(|_| AuthenticatedFetchError::InvalidConfiguration)?;
    if computed_pin != parameters.expected_policy_sha256
        || parameters.policy.purpose != parameters.expected_purpose
    {
        return Err(AuthenticatedFetchError::InvalidConfiguration);
    }

    execute_authenticated_transport_session(
        parameters.policy,
        parameters.expected_policy_sha256,
        parameters.expected_purpose,
        parameters.request_bytes,
        parameters.timeout,
        parameters.trusted_time,
        |transport| {
            adapter
                .fetch(AuthenticatedFetchRequest {
                    transport,
                    policy: parameters.policy,
                    expected_purpose: parameters.expected_purpose,
                    key_handle: parameters.key_handle,
                })
                .map_err(TransportCallbackError::Transport)
        },
    )
    .map_err(AuthenticatedFetchError::Session)
}

#[derive(Debug, Error)]
pub enum AuthenticatedFetchError<E> {
    #[error("authenticated fetch configuration is invalid")]
    InvalidConfiguration,
    #[error("authenticated fetch session failed")]
    Session(#[source] AuthenticatedTransportSessionError<AuthenticatedFetchAdapterError<E>>),
}
