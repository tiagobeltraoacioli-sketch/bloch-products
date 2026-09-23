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
