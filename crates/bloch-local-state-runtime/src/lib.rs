//! In-process remote-fetch plus coordinated product startup admission.

use bloch_authenticated_transport_evidence::{
    AuthenticatedTransportPolicy, TransportPurpose, authenticated_transport_policy_sha256,
};
use bloch_authenticated_transport_session::{
    AuthenticatedTransportInput, AuthenticatedTransportRequest, AuthenticatedTransportSessionError,
    TransportCallbackError, execute_authenticated_transport_session,
};
use bloch_local_state_admission::{
    AdmissionError, AdmittedAdjustmentState, AdmittedLifecycleState, DataLifecycleAdmission,
    PayAdjustmentAdmission, StartupAdmission, admit_data_lifecycle, admit_pay_adjustment,
};
use bloch_local_state_coordination::{
    CoordinatedError, CoordinationError, with_coordinated_startup_admission,
};
use bloch_local_state_remote_session::{
    FetchSessionError, RemoteCursorFetchRequest, fetch_verified_remote_cursor,
    fetch_verified_remote_cursor_with_trusted_time,
};
use bloch_trusted_time::VerifiedTrustedTime;
use bloch_trusted_time_boundary_store::{
    BoundaryStoreError, TrustedTimeBoundaryAudience, advance_trusted_time_boundary,
    load_trusted_time_boundary,
};
use bloch_trusted_time_external_anchor::{
    ExternalAnchorError, MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES, MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES,
    parse_external_anchor_expectation, parse_external_anchor_policy, verify_external_anchor,
};
use bloch_trusted_time_session::{
    MonotonicDeadlineRead as TrustedTimeDeadlineRead, TrustedTimeAcquisitionError,
    TrustedTimeFetchRequest, acquire_verified_trusted_time,
};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

pub struct RemoteFetchMaterials<'a> {
    pub policy_bytes: &'a [u8],
    pub expected_policy_sha256: &'a str,
    pub expected_state_identity: &'a str,
    pub timeout: Duration,
}

pub struct LocalAdmissionMaterials<'a> {
    pub checkpoint_artifact_bytes: &'a [u8],
    pub checkpoint_policy_bytes: &'a [u8],
    pub semantic_manifest_bytes: &'a [u8],
    pub coordination_directory: &'a Path,
    pub cursor_store: &'a Path,
    pub state_store: &'a Path,
}

pub struct DataStartupMaterials<'a> {
    pub remote: RemoteFetchMaterials<'a>,
    pub local: LocalAdmissionMaterials<'a>,
    pub lifecycle_policy_bytes: &'a [u8],
}

pub struct PayStartupMaterials<'a> {
    pub remote: RemoteFetchMaterials<'a>,
    pub local: LocalAdmissionMaterials<'a>,
}

pub struct TrustedTimeStartupMaterials<'a> {
    pub policy_bytes: &'a [u8],
    pub expected_policy_sha256: &'a str,
    pub boundary_store: &'a Path,
    pub timeout: Duration,
}

/// Independently pinned external-anchor inputs. The expectation returned by
/// the callback must come from an already authenticated independent source;
/// this runtime deliberately does not persist it locally.
pub struct ExternalAnchorStartupMaterials<'a> {
    pub policy_bytes: &'a [u8],
    pub expected_policy_sha256: &'a str,
    pub timeout: Duration,
}

/// Independently pinned authenticated-transport policy for one startup
/// exchange. The policy itself fixes the endpoint, TLS profile, mTLS client,
/// attestors and Data/Pay audience; the caller cannot override those values in
/// the transport callback.
pub struct AuthenticatedTransportStartupMaterials<'a> {
    pub policy: &'a AuthenticatedTransportPolicy,
    pub expected_policy_sha256: &'a str,
    pub timeout: Duration,
}

/// Authenticated transport profiles for the two external exchanges in an
/// anchored startup. Distinct purpose-specific policies are mandatory.
pub struct AnchoredAuthenticatedTransportStartupMaterials<'a> {
    pub external_anchor: AuthenticatedTransportStartupMaterials<'a>,
    pub remote_cursor: AuthenticatedTransportStartupMaterials<'a>,
}

const AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX: &[u8] =
    b"BLOCH-AUTHENTICATED-EXTERNAL-ANCHOR-PAYLOAD-V1\0";

/// Constructs the exact response body expected from the authenticated anchor
/// exchange. Both the signed anchor and independently retained expectation are
/// covered by the transport evidence before either byte string is exposed to
/// an anchor parser.
pub fn encode_authenticated_external_anchor_payload(
    document_bytes: &[u8],
    expectation_bytes: &[u8],
) -> Result<Vec<u8>, AuthenticatedTransportPayloadError> {
    if document_bytes.is_empty()
        || document_bytes.len() > MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES
        || expectation_bytes.is_empty()
        || expectation_bytes.len() > MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES
    {
        return Err(AuthenticatedTransportPayloadError);
    }
    let document_len =
        u32::try_from(document_bytes.len()).map_err(|_| AuthenticatedTransportPayloadError)?;
    let mut payload = Vec::with_capacity(
        AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX.len()
            + 4
            + document_bytes.len()
            + expectation_bytes.len(),
    );
    payload.extend_from_slice(AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX);
    payload.extend_from_slice(&document_len.to_be_bytes());
    payload.extend_from_slice(document_bytes);
    payload.extend_from_slice(expectation_bytes);
    Ok(payload)
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("authenticated transport payload is invalid")]
pub struct AuthenticatedTransportPayloadError;

#[derive(Debug, Error)]
pub enum AuthenticatedAnchorTransportError<E> {
    #[error("authenticated external-anchor transport session failed")]
    Session(#[source] AuthenticatedTransportSessionError<E>),
    #[error("authenticated external-anchor response payload is invalid")]
    Payload(#[source] AuthenticatedTransportPayloadError),
}

/// Borrowed, one-shot challenge passed to the caller's external-anchor
/// transport while the product coordination lock is held.
pub struct ExternalAnchorFetchRequest<'session> {
    request_nonce: &'session str,
    expected_policy_sha256: &'session str,
    expected_state_identity: &'session str,
    expected_trusted_time_policy_sha256: &'session str,
    expected_remote_cursor_policy_sha256: &'session str,
    deadline: std::time::Instant,
}

impl ExternalAnchorFetchRequest<'_> {
    pub fn request_nonce(&self) -> &str {
        self.request_nonce
    }
    pub fn expected_policy_sha256(&self) -> &str {
        self.expected_policy_sha256
    }
    pub fn expected_state_identity(&self) -> &str {
        self.expected_state_identity
    }
    pub fn expected_trusted_time_policy_sha256(&self) -> &str {
        self.expected_trusted_time_policy_sha256
    }
    pub fn expected_remote_cursor_policy_sha256(&self) -> &str {
        self.expected_remote_cursor_policy_sha256
    }
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }
    pub fn maximum_document_bytes(&self) -> usize {
        MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES
    }
    pub fn maximum_expectation_bytes(&self) -> usize {
        MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES
    }
}

/// Untrusted anchor document plus the prior expectation delivered over the
/// caller's authenticated independent channel.
pub struct ExternalAnchorFetchResponse {
    pub document_bytes: Vec<u8>,
    pub authenticated_expectation_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum StartupRuntimeError<E> {
    #[error("local startup coordination failed")]
    Coordination(#[source] CoordinationError),
    #[error("remote cursor fetch session failed")]
    Remote(#[source] FetchSessionError<E>),
    #[error("local startup admission failed")]
    Admission(#[source] AdmissionError),
}

enum StartupOperationError<E> {
    Remote(FetchSessionError<E>),
    Admission(AdmissionError),
}

#[derive(Debug, Error)]
pub enum FreshStartupRuntimeError<TE, CE> {
    #[error("local startup coordination failed")]
    Coordination(#[source] CoordinationError),
    #[error("trusted-time boundary store failed")]
    TrustedTimeBoundary(#[source] BoundaryStoreError),
    #[error("fresh trusted-time acquisition failed")]
    TrustedTimeAcquisition(#[source] TrustedTimeAcquisitionError<TE>),
    #[error("remote cursor fetch session failed")]
    Remote(#[source] FetchSessionError<CE>),
    #[error("local startup admission failed")]
    Admission(#[source] AdmissionError),
}

enum FreshStartupOperationError<TE, CE> {
    TrustedTimeBoundary(BoundaryStoreError),
    TrustedTimeAcquisition(TrustedTimeAcquisitionError<TE>),
    Remote(FetchSessionError<CE>),
    Admission(AdmissionError),
}

#[derive(Debug, Error)]
pub enum AnchoredFreshStartupRuntimeError<TE, AE, CE> {
    #[error("local startup coordination failed")]
    Coordination(#[source] CoordinationError),
    #[error("trusted-time boundary store failed")]
    TrustedTimeBoundary(#[source] BoundaryStoreError),
    #[error("fresh trusted-time acquisition failed")]
    TrustedTimeAcquisition(#[source] TrustedTimeAcquisitionError<TE>),
    #[error("external-anchor request configuration or nonce generation failed")]
    ExternalAnchorConfiguration,
    #[error("external-anchor transport failed")]
    ExternalAnchorTransport(#[source] AE),
    #[error("external-anchor transport exceeded its monotonic deadline")]
    ExternalAnchorDeadlineExceeded,
    #[error("external-anchor verification failed")]
    ExternalAnchorVerification(#[source] ExternalAnchorError),
    #[error("authenticated transport startup configuration is invalid")]
    AuthenticatedTransportConfiguration,
    #[error("remote cursor fetch session failed")]
    Remote(#[source] FetchSessionError<CE>),
    #[error("local startup admission failed")]
    Admission(#[source] AdmissionError),
}

enum AnchoredFreshStartupOperationError<TE, AE, CE> {
    TrustedTimeBoundary(BoundaryStoreError),
    TrustedTimeAcquisition(TrustedTimeAcquisitionError<TE>),
    ExternalAnchorConfiguration,
    ExternalAnchorTransport(AE),
    ExternalAnchorDeadlineExceeded,
    ExternalAnchorVerification(ExternalAnchorError),
    AuthenticatedTransportConfiguration,
    Remote(FetchSessionError<CE>),
    Admission(AdmissionError),
}

enum BoundaryAdvanceError {
    Capability(bloch_trusted_time::TrustedTimeError),
    Store(BoundaryStoreError),
}

enum TrustedTimePreparationError<TE> {
    Boundary(BoundaryStoreError),
    Acquisition(TrustedTimeAcquisitionError<TE>),
}

/// Compatibility-only startup using the host wall clock for remote freshness.
/// Use [`start_data_with_trusted_time`] for the qualified trusted-time path.
pub fn start_data<E, F>(
    materials: DataStartupMaterials<'_>,
    transport: F,
) -> Result<AdmittedLifecycleState, StartupRuntimeError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let verified_remote =
            fetch(&materials.remote, transport).map_err(StartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_data_lifecycle(DataLifecycleAdmission {
            startup,
            lifecycle_policy_bytes: materials.lifecycle_policy_bytes,
        })
        .map_err(StartupOperationError::Admission)
    });
    map_coordinated(result)
}

/// Starts Bloch Data while holding the local lock and verifies remote
/// freshness with a threshold-authenticated, monotonic time capability.
pub fn start_data_with_trusted_time<E, F>(
    materials: DataStartupMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    expected_trusted_time_policy_sha256: &str,
    transport: F,
) -> Result<AdmittedLifecycleState, StartupRuntimeError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            trusted_time,
            expected_trusted_time_policy_sha256,
            transport,
        )
        .map_err(StartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_data_lifecycle(DataLifecycleAdmission {
            startup,
            lifecycle_policy_bytes: materials.lifecycle_policy_bytes,
        })
        .map_err(StartupOperationError::Admission)
    });
    map_coordinated(result)
}

/// Acquires fresh threshold-authenticated time, durably advances its rollback
/// floor, and starts Bloch Data under one local coordination capability.
/// Every cooperating boundary updater for this audience must use the same
/// coordination directory.
pub fn start_data_with_fresh_trusted_time<TE, TR, TF, CE, CF>(
    materials: DataStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    trusted_time_transport: TF,
    remote_cursor_transport: CF,
) -> Result<AdmittedLifecycleState, FreshStartupRuntimeError<TE, CE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    CF: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, CE>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let trusted_time = acquire_and_advance_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            remote_cursor_transport,
        )
        .map_err(FreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_data_lifecycle(DataLifecycleAdmission {
            startup,
            lifecycle_policy_bytes: materials.lifecycle_policy_bytes,
        })
        .map_err(FreshStartupOperationError::Admission)
    });
    map_fresh_coordinated(result)
}

/// Compatibility-only startup using the host wall clock for remote freshness.
/// Use [`start_pay_with_trusted_time`] for the qualified trusted-time path.
pub fn start_pay<E, F>(
    materials: PayStartupMaterials<'_>,
    transport: F,
) -> Result<AdmittedAdjustmentState, StartupRuntimeError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let verified_remote =
            fetch(&materials.remote, transport).map_err(StartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_pay_adjustment(PayAdjustmentAdmission { startup })
            .map_err(StartupOperationError::Admission)
    });
    map_coordinated(result)
}

/// Starts Bloch Pay while holding the local lock and verifies remote
/// freshness with a threshold-authenticated, monotonic time capability.
pub fn start_pay_with_trusted_time<E, F>(
    materials: PayStartupMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    expected_trusted_time_policy_sha256: &str,
    transport: F,
) -> Result<AdmittedAdjustmentState, StartupRuntimeError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            trusted_time,
            expected_trusted_time_policy_sha256,
            transport,
        )
        .map_err(StartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_pay_adjustment(PayAdjustmentAdmission { startup })
            .map_err(StartupOperationError::Admission)
    });
    map_coordinated(result)
}

/// Acquires fresh threshold-authenticated time, durably advances its rollback
/// floor, and starts Bloch Pay under one local coordination capability.
/// Every cooperating boundary updater for this audience must use the same
/// coordination directory.
pub fn start_pay_with_fresh_trusted_time<TE, TR, TF, CE, CF>(
    materials: PayStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    trusted_time_transport: TF,
    remote_cursor_transport: CF,
) -> Result<AdmittedAdjustmentState, FreshStartupRuntimeError<TE, CE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    CF: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, CE>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let trusted_time = acquire_and_advance_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            remote_cursor_transport,
        )
        .map_err(FreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_pay_adjustment(PayAdjustmentAdmission { startup })
            .map_err(FreshStartupOperationError::Admission)
    });
    map_fresh_coordinated(result)
}

/// Acquires fresh trusted time and an independently retained, nonce-bound
/// external anti-rollback anchor before advancing local time or fetching the
/// remote cursor. The complete sequence is serialized by the product's local
/// coordination lock.
pub fn start_pay_with_fresh_trusted_time_and_external_anchor<TE, TR, TF, AE, AF, CE, CF>(
    materials: PayStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    external_anchor_materials: ExternalAnchorStartupMaterials<'_>,
    trusted_time_transport: TF,
    external_anchor_transport: AF,
    remote_cursor_transport: CF,
) -> Result<AdmittedAdjustmentState, AnchoredFreshStartupRuntimeError<TE, AE, CE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    AF: for<'session> FnOnce(
        ExternalAnchorFetchRequest<'session>,
    ) -> Result<ExternalAnchorFetchResponse, AE>,
    CF: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, CE>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let trusted_time = acquire_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )
        .map_err(|error| match error {
            TrustedTimePreparationError::Boundary(error) => {
                AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
            }
            TrustedTimePreparationError::Acquisition(error) => {
                AnchoredFreshStartupOperationError::TrustedTimeAcquisition(error)
            }
        })?;
        verify_external_anchor_for_startup(
            &materials.remote,
            &trusted_time_materials,
            &external_anchor_materials,
            &trusted_time,
            external_anchor_transport,
        )?;
        advance_boundary(&materials.remote, &trusted_time_materials, &trusted_time).map_err(
            |error| match error {
                BoundaryAdvanceError::Capability(error) => {
                    AnchoredFreshStartupOperationError::TrustedTimeAcquisition(
                        TrustedTimeAcquisitionError::Authentication(error),
                    )
                }
                BoundaryAdvanceError::Store(error) => {
                    AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
                }
            },
        )?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            remote_cursor_transport,
        )
        .map_err(AnchoredFreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_pay_adjustment(PayAdjustmentAdmission { startup })
            .map_err(AnchoredFreshStartupOperationError::Admission)
    });
    map_anchored_fresh_coordinated(result)
}

/// Data counterpart of
/// [`start_pay_with_fresh_trusted_time_and_external_anchor`].
pub fn start_data_with_fresh_trusted_time_and_external_anchor<TE, TR, TF, AE, AF, CE, CF>(
    materials: DataStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    external_anchor_materials: ExternalAnchorStartupMaterials<'_>,
    trusted_time_transport: TF,
    external_anchor_transport: AF,
    remote_cursor_transport: CF,
) -> Result<AdmittedLifecycleState, AnchoredFreshStartupRuntimeError<TE, AE, CE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    AF: for<'session> FnOnce(
        ExternalAnchorFetchRequest<'session>,
    ) -> Result<ExternalAnchorFetchResponse, AE>,
    CF: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, CE>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        let trusted_time = acquire_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )
        .map_err(|error| match error {
            TrustedTimePreparationError::Boundary(error) => {
                AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
            }
            TrustedTimePreparationError::Acquisition(error) => {
                AnchoredFreshStartupOperationError::TrustedTimeAcquisition(error)
            }
        })?;
        verify_external_anchor_for_startup(
            &materials.remote,
            &trusted_time_materials,
            &external_anchor_materials,
            &trusted_time,
            external_anchor_transport,
        )?;
        advance_boundary(&materials.remote, &trusted_time_materials, &trusted_time).map_err(
            |error| match error {
                BoundaryAdvanceError::Capability(error) => {
                    AnchoredFreshStartupOperationError::TrustedTimeAcquisition(
                        TrustedTimeAcquisitionError::Authentication(error),
                    )
                }
                BoundaryAdvanceError::Store(error) => {
                    AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
                }
            },
        )?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            remote_cursor_transport,
        )
        .map_err(AnchoredFreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_data_lifecycle(DataLifecycleAdmission {
            startup,
            lifecycle_policy_bytes: materials.lifecycle_policy_bytes,
        })
        .map_err(AnchoredFreshStartupOperationError::Admission)
    });
    map_anchored_fresh_coordinated(result)
}

/// Fully evidence-gated anchored startup for Bloch Pay. The anchor payload and
/// remote cursor are unavailable to their protocol parsers until a fresh,
/// exact-exchange transport session has verified them. Policy pins and
/// purposes are validated before trusted-time acquisition or durable mutation.
pub fn start_pay_with_authenticated_transport<TE, TR, TF, AE, AF, CE, CF>(
    materials: PayStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    external_anchor_materials: ExternalAnchorStartupMaterials<'_>,
    authenticated_transport: AnchoredAuthenticatedTransportStartupMaterials<'_>,
    trusted_time_transport: TF,
    external_anchor_transport: AF,
    remote_cursor_transport: CF,
) -> Result<
    AdmittedAdjustmentState,
    AnchoredFreshStartupRuntimeError<
        TE,
        AuthenticatedAnchorTransportError<AE>,
        AuthenticatedTransportSessionError<CE>,
    >,
>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    AF: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    )
        -> Result<AuthenticatedTransportInput, TransportCallbackError<AE>>,
    CF: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    )
        -> Result<AuthenticatedTransportInput, TransportCallbackError<CE>>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        validate_authenticated_transport_materials(
            &materials.remote,
            &trusted_time_materials,
            &authenticated_transport,
        )?;
        let trusted_time = acquire_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )
        .map_err(map_authenticated_trusted_time_preparation)?;
        verify_external_anchor_for_startup(
            &materials.remote,
            &trusted_time_materials,
            &external_anchor_materials,
            &trusted_time,
            |request| {
                fetch_authenticated_anchor(
                    request,
                    &authenticated_transport.external_anchor,
                    &trusted_time,
                    external_anchor_transport,
                )
            },
        )?;
        advance_authenticated_boundary(&materials.remote, &trusted_time_materials, &trusted_time)?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            |request| {
                fetch_authenticated_remote_cursor(
                    request,
                    &authenticated_transport.remote_cursor,
                    &trusted_time,
                    remote_cursor_transport,
                )
            },
        )
        .map_err(AnchoredFreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_pay_adjustment(PayAdjustmentAdmission { startup })
            .map_err(AnchoredFreshStartupOperationError::Admission)
    });
    map_anchored_fresh_coordinated(result)
}

/// Bloch Data counterpart of [`start_pay_with_authenticated_transport`].
pub fn start_data_with_authenticated_transport<TE, TR, TF, AE, AF, CE, CF>(
    materials: DataStartupMaterials<'_>,
    trusted_time_materials: TrustedTimeStartupMaterials<'_>,
    external_anchor_materials: ExternalAnchorStartupMaterials<'_>,
    authenticated_transport: AnchoredAuthenticatedTransportStartupMaterials<'_>,
    trusted_time_transport: TF,
    external_anchor_transport: AF,
    remote_cursor_transport: CF,
) -> Result<
    AdmittedLifecycleState,
    AnchoredFreshStartupRuntimeError<
        TE,
        AuthenticatedAnchorTransportError<AE>,
        AuthenticatedTransportSessionError<CE>,
    >,
>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
    AF: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    )
        -> Result<AuthenticatedTransportInput, TransportCallbackError<AE>>,
    CF: for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    )
        -> Result<AuthenticatedTransportInput, TransportCallbackError<CE>>,
{
    let result = with_coordinated_startup_admission(materials.local.coordination_directory, |_| {
        validate_authenticated_transport_materials(
            &materials.remote,
            &trusted_time_materials,
            &authenticated_transport,
        )?;
        let trusted_time = acquire_trusted_time(
            &materials.remote,
            &trusted_time_materials,
            trusted_time_transport,
        )
        .map_err(map_authenticated_trusted_time_preparation)?;
        verify_external_anchor_for_startup(
            &materials.remote,
            &trusted_time_materials,
            &external_anchor_materials,
            &trusted_time,
            |request| {
                fetch_authenticated_anchor(
                    request,
                    &authenticated_transport.external_anchor,
                    &trusted_time,
                    external_anchor_transport,
                )
            },
        )?;
        advance_authenticated_boundary(&materials.remote, &trusted_time_materials, &trusted_time)?;
        let verified_remote = fetch_with_trusted_time(
            &materials.remote,
            &trusted_time,
            trusted_time_materials.expected_policy_sha256,
            |request| {
                fetch_authenticated_remote_cursor(
                    request,
                    &authenticated_transport.remote_cursor,
                    &trusted_time,
                    remote_cursor_transport,
                )
            },
        )
        .map_err(AnchoredFreshStartupOperationError::Remote)?;
        let startup = startup(&materials.local, &verified_remote);
        admit_data_lifecycle(DataLifecycleAdmission {
            startup,
            lifecycle_policy_bytes: materials.lifecycle_policy_bytes,
        })
        .map_err(AnchoredFreshStartupOperationError::Admission)
    });
    map_anchored_fresh_coordinated(result)
}

fn fetch<E, F>(
    materials: &RemoteFetchMaterials<'_>,
    transport: F,
) -> Result<bloch_local_state_remote_cursor::VerifiedRemoteCursor, FetchSessionError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    fetch_verified_remote_cursor(
        materials.policy_bytes,
        materials.expected_policy_sha256,
        materials.expected_state_identity,
        materials.timeout,
        transport,
    )
}

fn validate_authenticated_transport_materials<TE, AE, CE>(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    transports: &AnchoredAuthenticatedTransportStartupMaterials<'_>,
) -> Result<(), AnchoredFreshStartupOperationError<TE, AE, CE>> {
    let valid = [
        (
            &transports.external_anchor,
            TransportPurpose::ExternalTimeAnchor,
        ),
        (&transports.remote_cursor, TransportPurpose::RemoteCursor),
    ]
    .into_iter()
    .all(|(materials, purpose)| {
        authenticated_transport_policy_sha256(materials.policy)
            .is_ok_and(|pin| pin == materials.expected_policy_sha256)
            && materials.policy.purpose == purpose
            && materials.policy.state_identity == remote.expected_state_identity
            && materials.policy.trusted_time_policy_sha256 == trusted.expected_policy_sha256
            && materials.policy.remote_cursor_policy_sha256 == remote.expected_policy_sha256
            && !materials.timeout.is_zero()
            && materials.timeout <= Duration::from_secs(60)
            && materials.timeout <= Duration::from_millis(materials.policy.max_round_trip_millis)
            && usize::try_from(materials.policy.max_response_bytes).is_ok_and(|limit| limit > 0)
    });
    if valid {
        Ok(())
    } else {
        Err(AnchoredFreshStartupOperationError::AuthenticatedTransportConfiguration)
    }
}

fn map_authenticated_trusted_time_preparation<TE, AE, CE>(
    error: TrustedTimePreparationError<TE>,
) -> AnchoredFreshStartupOperationError<TE, AE, CE> {
    match error {
        TrustedTimePreparationError::Boundary(error) => {
            AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
        }
        TrustedTimePreparationError::Acquisition(error) => {
            AnchoredFreshStartupOperationError::TrustedTimeAcquisition(error)
        }
    }
}

fn advance_authenticated_boundary<TE, AE, CE>(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    verified: &VerifiedTrustedTime,
) -> Result<(), AnchoredFreshStartupOperationError<TE, AE, CE>> {
    advance_boundary(remote, trusted, verified).map_err(|error| match error {
        BoundaryAdvanceError::Capability(error) => {
            AnchoredFreshStartupOperationError::TrustedTimeAcquisition(
                TrustedTimeAcquisitionError::Authentication(error),
            )
        }
        BoundaryAdvanceError::Store(error) => {
            AnchoredFreshStartupOperationError::TrustedTimeBoundary(error)
        }
    })
}

fn fetch_authenticated_anchor<AE>(
    request: ExternalAnchorFetchRequest<'_>,
    transport: &AuthenticatedTransportStartupMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    callback: impl for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    ) -> Result<
        AuthenticatedTransportInput,
        TransportCallbackError<AE>,
    >,
) -> Result<ExternalAnchorFetchResponse, AuthenticatedAnchorTransportError<AE>> {
    let request_bytes = canonical_authenticated_request(
        b"BLOCH-EXTERNAL-ANCHOR-TRANSPORT-REQUEST-V1\0",
        &[
            request.request_nonce(),
            request.expected_policy_sha256(),
            request.expected_state_identity(),
            request.expected_trusted_time_policy_sha256(),
            request.expected_remote_cursor_policy_sha256(),
        ],
    )
    .map_err(AuthenticatedAnchorTransportError::Payload)?;
    let verified = execute_authenticated_transport_session(
        transport.policy,
        transport.expected_policy_sha256,
        TransportPurpose::ExternalTimeAnchor,
        &request_bytes,
        transport.timeout,
        trusted_time,
        callback,
    )
    .map_err(AuthenticatedAnchorTransportError::Session)?;
    decode_authenticated_external_anchor_payload(verified.response_bytes())
        .map_err(AuthenticatedAnchorTransportError::Payload)
}

fn fetch_authenticated_remote_cursor<CE>(
    request: RemoteCursorFetchRequest<'_>,
    transport: &AuthenticatedTransportStartupMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    callback: impl for<'session> FnOnce(
        AuthenticatedTransportRequest<'session>,
    ) -> Result<
        AuthenticatedTransportInput,
        TransportCallbackError<CE>,
    >,
) -> Result<Vec<u8>, AuthenticatedTransportSessionError<CE>> {
    let request_bytes = canonical_authenticated_request(
        b"BLOCH-REMOTE-CURSOR-TRANSPORT-REQUEST-V1\0",
        &[request.request_nonce(), request.expected_state_identity()],
    )
    .map_err(|_| AuthenticatedTransportSessionError::InvalidConfiguration)?;
    execute_authenticated_transport_session(
        transport.policy,
        transport.expected_policy_sha256,
        TransportPurpose::RemoteCursor,
        &request_bytes,
        transport.timeout,
        trusted_time,
        callback,
    )
    .map(|response| response.into_response_bytes())
}

fn canonical_authenticated_request(
    prefix: &[u8],
    fields: &[&str],
) -> Result<Vec<u8>, AuthenticatedTransportPayloadError> {
    let mut request = Vec::from(prefix);
    for field in fields {
        let bytes = field.as_bytes();
        let length = u32::try_from(bytes.len()).map_err(|_| AuthenticatedTransportPayloadError)?;
        request.extend_from_slice(&length.to_be_bytes());
        request.extend_from_slice(bytes);
    }
    Ok(request)
}

fn decode_authenticated_external_anchor_payload(
    payload: &[u8],
) -> Result<ExternalAnchorFetchResponse, AuthenticatedTransportPayloadError> {
    let header = AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX.len() + 4;
    if payload.len() <= header || !payload.starts_with(AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX) {
        return Err(AuthenticatedTransportPayloadError);
    }
    let length_offset = AUTHENTICATED_ANCHOR_PAYLOAD_PREFIX.len();
    let document_len = u32::from_be_bytes(
        payload[length_offset..header]
            .try_into()
            .map_err(|_| AuthenticatedTransportPayloadError)?,
    ) as usize;
    let document_end = header
        .checked_add(document_len)
        .ok_or(AuthenticatedTransportPayloadError)?;
    if document_len == 0
        || document_len > MAX_EXTERNAL_ANCHOR_DOCUMENT_BYTES
        || document_end >= payload.len()
        || payload.len() - document_end > MAX_EXTERNAL_ANCHOR_EXPECTATION_BYTES
    {
        return Err(AuthenticatedTransportPayloadError);
    }
    Ok(ExternalAnchorFetchResponse {
        document_bytes: payload[header..document_end].to_vec(),
        authenticated_expectation_bytes: payload[document_end..].to_vec(),
    })
}

fn acquire_and_advance_trusted_time<TE, TR, TF, CE>(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    transport: TF,
) -> Result<VerifiedTrustedTime, FreshStartupOperationError<TE, CE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
{
    let verified =
        acquire_trusted_time(remote, trusted, transport).map_err(|error| match error {
            TrustedTimePreparationError::Boundary(error) => {
                FreshStartupOperationError::TrustedTimeBoundary(error)
            }
            TrustedTimePreparationError::Acquisition(error) => {
                FreshStartupOperationError::TrustedTimeAcquisition(error)
            }
        })?;
    advance_boundary(remote, trusted, &verified).map_err(|error| match error {
        BoundaryAdvanceError::Capability(error) => {
            FreshStartupOperationError::TrustedTimeAcquisition(
                TrustedTimeAcquisitionError::Authentication(error),
            )
        }
        BoundaryAdvanceError::Store(error) => {
            FreshStartupOperationError::TrustedTimeBoundary(error)
        }
    })?;
    Ok(verified)
}

fn acquire_trusted_time<TE, TR, TF>(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    transport: TF,
) -> Result<VerifiedTrustedTime, TrustedTimePreparationError<TE>>
where
    TR: TrustedTimeDeadlineRead<Error = TE>,
    TF: for<'session> FnOnce(TrustedTimeFetchRequest<'session>) -> Result<TR, TE>,
{
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: trusted.expected_policy_sha256,
        state_identity: remote.expected_state_identity,
        remote_cursor_policy_sha256: remote.expected_policy_sha256,
    };
    let retained = load_trusted_time_boundary(trusted.boundary_store, audience)
        .map_err(TrustedTimePreparationError::Boundary)?;
    let verified = acquire_verified_trusted_time(
        trusted.policy_bytes,
        trusted.expected_policy_sha256,
        remote.expected_state_identity,
        remote.expected_policy_sha256,
        Some(&retained),
        trusted.timeout,
        transport,
    )
    .map_err(TrustedTimePreparationError::Acquisition)?;
    Ok(verified)
}

fn advance_boundary(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    verified: &VerifiedTrustedTime,
) -> Result<(), BoundaryAdvanceError> {
    let audience = TrustedTimeBoundaryAudience {
        trusted_time_policy_sha256: trusted.expected_policy_sha256,
        state_identity: remote.expected_state_identity,
        remote_cursor_policy_sha256: remote.expected_policy_sha256,
    };
    let next = verified
        .rollback_boundary()
        .map_err(BoundaryAdvanceError::Capability)?;
    advance_trusted_time_boundary(trusted.boundary_store, audience, &next)
        .map_err(BoundaryAdvanceError::Store)
        .map(|_| ())
}

fn verify_external_anchor_for_startup<AE, TE, CE, AF>(
    remote: &RemoteFetchMaterials<'_>,
    trusted_materials: &TrustedTimeStartupMaterials<'_>,
    anchor_materials: &ExternalAnchorStartupMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    transport: AF,
) -> Result<(), AnchoredFreshStartupOperationError<TE, AE, CE>>
where
    AF: for<'session> FnOnce(
        ExternalAnchorFetchRequest<'session>,
    ) -> Result<ExternalAnchorFetchResponse, AE>,
{
    if anchor_materials.timeout.is_zero() || anchor_materials.timeout > Duration::from_secs(60) {
        return Err(AnchoredFreshStartupOperationError::ExternalAnchorConfiguration);
    }
    let policy = parse_external_anchor_policy(
        anchor_materials.policy_bytes,
        anchor_materials.expected_policy_sha256,
    )
    .map_err(AnchoredFreshStartupOperationError::ExternalAnchorVerification)?;
    let deadline = std::time::Instant::now()
        .checked_add(anchor_materials.timeout)
        .ok_or(AnchoredFreshStartupOperationError::ExternalAnchorConfiguration)?;
    let mut nonce_bytes = [0_u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|_| AnchoredFreshStartupOperationError::ExternalAnchorConfiguration)?;
    let nonce = format!("0x{}", hex::encode(nonce_bytes));
    let response = transport(ExternalAnchorFetchRequest {
        request_nonce: &nonce,
        expected_policy_sha256: anchor_materials.expected_policy_sha256,
        expected_state_identity: remote.expected_state_identity,
        expected_trusted_time_policy_sha256: trusted_materials.expected_policy_sha256,
        expected_remote_cursor_policy_sha256: remote.expected_policy_sha256,
        deadline,
    })
    .map_err(AnchoredFreshStartupOperationError::ExternalAnchorTransport)?;
    if std::time::Instant::now() >= deadline {
        return Err(AnchoredFreshStartupOperationError::ExternalAnchorDeadlineExceeded);
    }
    let retained = parse_external_anchor_expectation(
        &response.authenticated_expectation_bytes,
        anchor_materials.expected_policy_sha256,
        remote.expected_state_identity,
        trusted_materials.expected_policy_sha256,
        remote.expected_policy_sha256,
    )
    .map_err(AnchoredFreshStartupOperationError::ExternalAnchorVerification)?;
    let verified = verify_external_anchor(
        &response.document_bytes,
        &policy,
        anchor_materials.expected_policy_sha256,
        &nonce,
        trusted_time,
        Some(&retained),
    )
    .map_err(AnchoredFreshStartupOperationError::ExternalAnchorVerification)?;
    verified
        .ensure_monotonic_freshness()
        .map_err(AnchoredFreshStartupOperationError::ExternalAnchorVerification)?;
    if std::time::Instant::now() >= deadline {
        return Err(AnchoredFreshStartupOperationError::ExternalAnchorDeadlineExceeded);
    }
    Ok(())
}

fn fetch_with_trusted_time<E, F>(
    materials: &RemoteFetchMaterials<'_>,
    trusted_time: &VerifiedTrustedTime,
    expected_trusted_time_policy_sha256: &str,
    transport: F,
) -> Result<bloch_local_state_remote_cursor::VerifiedRemoteCursor, FetchSessionError<E>>
where
    F: for<'session> FnOnce(RemoteCursorFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    fetch_verified_remote_cursor_with_trusted_time(
        materials.policy_bytes,
        materials.expected_policy_sha256,
        materials.expected_state_identity,
        materials.timeout,
        trusted_time,
        expected_trusted_time_policy_sha256,
        transport,
    )
}

fn map_coordinated<T, E>(
    result: Result<T, CoordinatedError<StartupOperationError<E>>>,
) -> Result<T, StartupRuntimeError<E>> {
    result.map_err(|error| match error {
        CoordinatedError::Coordination(error) => StartupRuntimeError::Coordination(error),
        CoordinatedError::Operation(StartupOperationError::Remote(error)) => {
            StartupRuntimeError::Remote(error)
        }
        CoordinatedError::Operation(StartupOperationError::Admission(error)) => {
            StartupRuntimeError::Admission(error)
        }
    })
}

fn map_fresh_coordinated<T, TE, CE>(
    result: Result<T, CoordinatedError<FreshStartupOperationError<TE, CE>>>,
) -> Result<T, FreshStartupRuntimeError<TE, CE>> {
    result.map_err(|error| match error {
        CoordinatedError::Coordination(error) => FreshStartupRuntimeError::Coordination(error),
        CoordinatedError::Operation(FreshStartupOperationError::TrustedTimeBoundary(error)) => {
            FreshStartupRuntimeError::TrustedTimeBoundary(error)
        }
        CoordinatedError::Operation(FreshStartupOperationError::TrustedTimeAcquisition(error)) => {
            FreshStartupRuntimeError::TrustedTimeAcquisition(error)
        }
        CoordinatedError::Operation(FreshStartupOperationError::Remote(error)) => {
            FreshStartupRuntimeError::Remote(error)
        }
        CoordinatedError::Operation(FreshStartupOperationError::Admission(error)) => {
            FreshStartupRuntimeError::Admission(error)
        }
    })
}

fn map_anchored_fresh_coordinated<T, TE, AE, CE>(
    result: Result<T, CoordinatedError<AnchoredFreshStartupOperationError<TE, AE, CE>>>,
) -> Result<T, AnchoredFreshStartupRuntimeError<TE, AE, CE>> {
    result.map_err(|error| match error {
        CoordinatedError::Coordination(error) => {
            AnchoredFreshStartupRuntimeError::Coordination(error)
        }
        CoordinatedError::Operation(AnchoredFreshStartupOperationError::TrustedTimeBoundary(
            error,
        )) => AnchoredFreshStartupRuntimeError::TrustedTimeBoundary(error),
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::TrustedTimeAcquisition(error),
        ) => AnchoredFreshStartupRuntimeError::TrustedTimeAcquisition(error),
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::ExternalAnchorConfiguration,
        ) => AnchoredFreshStartupRuntimeError::ExternalAnchorConfiguration,
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::ExternalAnchorTransport(error),
        ) => AnchoredFreshStartupRuntimeError::ExternalAnchorTransport(error),
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::ExternalAnchorDeadlineExceeded,
        ) => AnchoredFreshStartupRuntimeError::ExternalAnchorDeadlineExceeded,
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::ExternalAnchorVerification(error),
        ) => AnchoredFreshStartupRuntimeError::ExternalAnchorVerification(error),
        CoordinatedError::Operation(
            AnchoredFreshStartupOperationError::AuthenticatedTransportConfiguration,
        ) => AnchoredFreshStartupRuntimeError::AuthenticatedTransportConfiguration,
        CoordinatedError::Operation(AnchoredFreshStartupOperationError::Remote(error)) => {
            AnchoredFreshStartupRuntimeError::Remote(error)
        }
        CoordinatedError::Operation(AnchoredFreshStartupOperationError::Admission(error)) => {
            AnchoredFreshStartupRuntimeError::Admission(error)
        }
    })
}

fn startup<'a>(
    local: &'a LocalAdmissionMaterials<'a>,
    remote: &'a bloch_local_state_remote_cursor::VerifiedRemoteCursor,
) -> StartupAdmission<'a> {
    StartupAdmission {
        artifact_bytes: local.checkpoint_artifact_bytes,
        checkpoint_policy_bytes: local.checkpoint_policy_bytes,
        semantic_manifest_bytes: local.semantic_manifest_bytes,
        verified_remote_cursor: remote,
        cursor_store: local.cursor_store,
        state_store: local.state_store,
    }
}
