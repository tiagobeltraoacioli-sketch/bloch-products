//! Fresh, bounded, transport-neutral remote-cursor quorum collection.
//!
//! Collection authenticates configured signer identities. It does not prove
//! replica independence, consensus, linearizability, replication or fencing.

use bloch_local_state_cursor::CheckpointCursor;
use bloch_local_state_remote_cursor_replica_quorum::{
    ReplicaEvidence, ReplicaQuorumError, VerifiedReplicaQuorum, parse_replica_quorum_policy,
    verify_replica_quorum,
};
use bloch_local_state_remote_session::{
    BoundedIngressError, FetchSessionError, MonotonicDeadlineRead, RemoteCursorFetchRequest,
    fetch_verified_remote_cursor_with_trusted_time,
};
use bloch_trusted_time::VerifiedTrustedTime;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_QUORUM_COLLECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Borrowed request for exactly one configured replica.
pub struct ReplicaFetchRequest<'session> {
    replica_id: &'session str,
    inner: RemoteCursorFetchRequest<'session>,
}

impl ReplicaFetchRequest<'_> {
    pub fn replica_id(&self) -> &str {
        self.replica_id
    }

    pub fn request_nonce(&self) -> &str {
        self.inner.request_nonce()
    }

    pub fn expected_state_identity(&self) -> &str {
        self.inner.expected_state_identity()
    }

    pub fn deadline(&self) -> Instant {
        self.inner.deadline()
    }

    pub fn maximum_response_bytes(&self) -> usize {
        self.inner.maximum_response_bytes()
    }

    pub fn read_bounded_response<R>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<u8>, BoundedIngressError<R::Error>>
    where
        R: MonotonicDeadlineRead,
    {
        self.inner.read_bounded_response(reader)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaSessionFailure {
    InvalidConfiguration,
    DeadlineExceeded,
    ResponseTooLarge,
    InvalidSystemTime,
    TrustedTime,
    TrustedTimeContextMismatch,
    Authentication,
    NonceGeneration,
}

#[derive(Debug, Error)]
pub enum QuorumCollectionError<E: Debug> {
    #[error("quorum collection configuration is invalid")]
    InvalidConfiguration,
    #[error("replica-quorum policy was refused")]
    QuorumPolicy(#[source] ReplicaQuorumError),
    #[error("quorum collection exceeded its global monotonic deadline")]
    CollectionDeadlineExceeded,
    #[error("replica policy contains a duplicate replica")]
    DuplicateReplica,
    #[error("operating-system nonce generation repeated a nonce")]
    DuplicateNonce,
    #[error("transport failed while collecting replica {replica_id}")]
    Transport { replica_id: String, error: E },
    #[error("authenticated fetch failed for replica {replica_id}: {failure:?}")]
    ReplicaSession {
        replica_id: String,
        failure: ReplicaSessionFailure,
    },
    #[error("authenticated response does not belong to requested replica {replica_id}")]
    ReplicaIdentityMismatch { replica_id: String },
    #[error("replica quorum was refused")]
    Quorum(#[source] ReplicaQuorumError),
}

enum CallbackError<E> {
    Transport(E),
    DuplicateNonce,
}

/// Independently pinned inputs borrowed for one collection attempt.
pub struct QuorumCollectionMaterials<'a> {
    pub remote_cursor_policy_bytes: &'a [u8],
    pub expected_remote_cursor_policy_sha256: &'a str,
    pub replica_quorum_policy_bytes: &'a [u8],
    pub expected_replica_quorum_policy_sha256: &'a str,
    pub expected_previous: Option<&'a CheckpointCursor>,
    pub trusted_time: &'a VerifiedTrustedTime,
}

/// Monotonic bounds applied to the complete collection and each replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumCollectionLimits {
    pub collection_timeout: Duration,
    pub per_replica_timeout: Duration,
}

/// Collects one fresh authenticated observation from every configured replica
/// and returns only an opaque verified quorum.
///
/// The callback must route by `replica_id` and enforce the supplied absolute
/// deadline for all blocking operations. Partial observations, request nonces
/// and raw responses are dropped on every failure path.
pub fn collect_verified_replica_quorum<E, F>(
    materials: QuorumCollectionMaterials<'_>,
    limits: QuorumCollectionLimits,
    mut transport: F,
) -> Result<VerifiedReplicaQuorum, QuorumCollectionError<E>>
where
    E: Debug,
    F: for<'session> FnMut(ReplicaFetchRequest<'session>) -> Result<Vec<u8>, E>,
{
    if limits.collection_timeout.is_zero()
        || limits.collection_timeout > MAX_QUORUM_COLLECTION_TIMEOUT
        || limits.per_replica_timeout.is_zero()
        || limits.per_replica_timeout > MAX_QUORUM_COLLECTION_TIMEOUT
    {
        return Err(QuorumCollectionError::InvalidConfiguration);
    }

    let quorum_policy = parse_replica_quorum_policy(
        materials.replica_quorum_policy_bytes,
        materials.expected_replica_quorum_policy_sha256,
    )
    .map_err(QuorumCollectionError::QuorumPolicy)?;
    if quorum_policy.remote_cursor_policy_sha256 != materials.expected_remote_cursor_policy_sha256 {
        return Err(QuorumCollectionError::InvalidConfiguration);
    }

    let collection_deadline = Instant::now()
        .checked_add(limits.collection_timeout)
        .ok_or(QuorumCollectionError::InvalidConfiguration)?;
    let mut requested_replicas = BTreeSet::new();
    let mut request_nonces = BTreeSet::new();
    let mut observations = Vec::with_capacity(quorum_policy.replicas.len());

    for descriptor in &quorum_policy.replicas {
        if !requested_replicas.insert(descriptor.replica_id.as_str()) {
            return Err(QuorumCollectionError::DuplicateReplica);
        }
        let now = Instant::now();
        let remaining = collection_deadline
            .checked_duration_since(now)
            .ok_or(QuorumCollectionError::CollectionDeadlineExceeded)?;
        if remaining.is_zero() {
            return Err(QuorumCollectionError::CollectionDeadlineExceeded);
        }
        let timeout = limits.per_replica_timeout.min(remaining);
        let replica_id = descriptor.replica_id.as_str();
        let fetched = fetch_verified_remote_cursor_with_trusted_time(
            materials.remote_cursor_policy_bytes,
            materials.expected_remote_cursor_policy_sha256,
            &quorum_policy.state_identity,
            timeout,
            materials.trusted_time,
            &quorum_policy.trusted_time_policy_sha256,
            |request| {
                if !request_nonces.insert(request.request_nonce().to_owned()) {
                    return Err(CallbackError::DuplicateNonce);
                }
                transport(ReplicaFetchRequest {
                    replica_id,
                    inner: request,
                })
                .map_err(CallbackError::Transport)
            },
        )
        .map_err(|error| map_fetch_error(replica_id, error))?;

        if fetched.authority_ids() != descriptor.signer_authority_ids {
            return Err(QuorumCollectionError::ReplicaIdentityMismatch {
                replica_id: descriptor.replica_id.clone(),
            });
        }
        observations.push((descriptor.replica_id.clone(), fetched));
    }

    if Instant::now() >= collection_deadline {
        return Err(QuorumCollectionError::CollectionDeadlineExceeded);
    }
    let evidence = observations
        .iter()
        .map(|(replica_id, observation)| ReplicaEvidence {
            replica_id,
            observation,
        })
        .collect::<Vec<_>>();
    verify_replica_quorum(
        &evidence,
        &quorum_policy,
        materials.expected_replica_quorum_policy_sha256,
        materials.expected_previous,
        materials.trusted_time,
    )
    .map_err(QuorumCollectionError::Quorum)
}

fn map_fetch_error<E: Debug>(
    replica_id: &str,
    error: FetchSessionError<CallbackError<E>>,
) -> QuorumCollectionError<E> {
    let failure = match error {
        FetchSessionError::Transport(CallbackError::Transport(error)) => {
            return QuorumCollectionError::Transport {
                replica_id: replica_id.into(),
                error,
            };
        }
        FetchSessionError::Transport(CallbackError::DuplicateNonce) => {
            return QuorumCollectionError::DuplicateNonce;
        }
        FetchSessionError::InvalidConfiguration => ReplicaSessionFailure::InvalidConfiguration,
        FetchSessionError::DeadlineExceeded => ReplicaSessionFailure::DeadlineExceeded,
        FetchSessionError::ResponseTooLarge => ReplicaSessionFailure::ResponseTooLarge,
        FetchSessionError::InvalidSystemTime => ReplicaSessionFailure::InvalidSystemTime,
        FetchSessionError::TrustedTime(_) => ReplicaSessionFailure::TrustedTime,
        FetchSessionError::TrustedTimeContextMismatch => {
            ReplicaSessionFailure::TrustedTimeContextMismatch
        }
        FetchSessionError::Authentication(_) => ReplicaSessionFailure::Authentication,
        FetchSessionError::NonceGeneration => ReplicaSessionFailure::NonceGeneration,
    };
    QuorumCollectionError::ReplicaSession {
        replica_id: replica_id.into(),
        failure,
    }
}
