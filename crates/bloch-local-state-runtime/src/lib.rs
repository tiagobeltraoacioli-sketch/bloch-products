//! In-process remote-fetch plus coordinated product startup admission.

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

fn acquire_and_advance_trusted_time<TE, TR, TF, CE>(
    remote: &RemoteFetchMaterials<'_>,
    trusted: &TrustedTimeStartupMaterials<'_>,
    transport: TF,
) -> Result<VerifiedTrustedTime, FreshStartupOperationError<TE, CE>>
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
        .map_err(FreshStartupOperationError::TrustedTimeBoundary)?;
    let verified = acquire_verified_trusted_time(
        trusted.policy_bytes,
        trusted.expected_policy_sha256,
        remote.expected_state_identity,
        remote.expected_policy_sha256,
        Some(&retained),
        trusted.timeout,
        transport,
    )
    .map_err(FreshStartupOperationError::TrustedTimeAcquisition)?;
    let next = verified.rollback_boundary().map_err(|error| {
        FreshStartupOperationError::TrustedTimeAcquisition(
            TrustedTimeAcquisitionError::Authentication(error),
        )
    })?;
    advance_trusted_time_boundary(trusted.boundary_store, audience, &next)
        .map_err(FreshStartupOperationError::TrustedTimeBoundary)?;
    Ok(verified)
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
