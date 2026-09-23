//! Fail-closed orchestration of one authenticated local-state transition.
//!
//! Network access, checkpoint signing and private keys remain outside this
//! crate. Callbacks may return only protocol objects already verified by the
//! checkpoint and remote-cursor crates. One host-local coordination capability
//! is held from initial admission through semantic postcheck.

use bloch_local_state_checkpoint::VerifiedRootCheckpoint;
use bloch_local_state_coordination::{
    CoordinatedError, CoordinationError, LocalStateCoordination, with_coordinated_state_transition,
};
use bloch_local_state_cursor::{
    CheckpointCursor, CursorError, admit_checkpoint, load_cursor, verify_admitted_checkpoint,
};
use bloch_local_state_remote_cursor::{
    ValidatedRemoteCursorCasRequest, VerifiedRemoteCursor, VerifiedRemoteCursorCasAcceptance,
    VerifiedRemoteCursorCasExchange, VerifiedRemoteCursorCasReceipt,
    VerifiedRemoteCursorCasRefusal,
};
use bloch_local_state_store::{
    StateRoot, StoreError, discard_prepared_state, load_state, prepare_state,
    promote_prepared_state,
};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display};
use std::path::Path;

mod journal;
use journal::Journal;
pub use journal::JournalError;

const JOURNAL_SCHEMA: &str = "bloch.products.local-state-transition-journal.v1";

/// Fixed local paths which must all belong to the same state identity.
#[derive(Clone, Copy, Debug)]
pub struct LocalStatePaths<'a> {
    pub coordination: &'a Path,
    pub state: &'a Path,
    pub cursor: &'a Path,
    pub journal: &'a Path,
}

/// External operations invoked while local coordination remains held.
///
/// Implementations must be bounded and must not re-enter the same coordination
/// domain. `submit_remote_cas` verifies its receipt against the exact request
/// derived from the supplied current cursor and successor checkpoint. Any
/// error from that method is conservatively an unknown CAS outcome.
pub trait TransitionCallbacks {
    type Error: Error + Send + Sync + 'static;

    fn fetch_remote_cursor(&mut self) -> Result<VerifiedRemoteCursor, Self::Error>;

    fn create_checkpoint(
        &mut self,
        root: &StateRoot,
    ) -> Result<VerifiedRootCheckpoint, Self::Error>;

    /// Builds and verifies the exact request without sending it.
    fn prepare_remote_cas(
        &mut self,
        current: &VerifiedRemoteCursor,
        successor: &VerifiedRootCheckpoint,
    ) -> Result<ValidatedRemoteCursorCasRequest, Self::Error>;

    /// Sends or exactly replays a request and verifies the complete exchange.
    fn submit_remote_cas(
        &mut self,
        request: &ValidatedRemoteCursorCasRequest,
    ) -> Result<VerifiedRemoteCursorCasExchange, Self::Error>;

    /// Revalidates canonical request bytes recovered from the durable journal.
    fn validate_retained_remote_cas_request(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<ValidatedRemoteCursorCasRequest, Self::Error>;

    /// Revalidates a retained exact request/receipt pair without network I/O.
    fn validate_retained_remote_cas_exchange(
        &mut self,
        request_bytes: &[u8],
        receipt_bytes: &[u8],
    ) -> Result<VerifiedRemoteCursorCasExchange, Self::Error>;

    fn validate_transition(
        &mut self,
        current_state: &[u8],
        successor_state: &[u8],
    ) -> Result<(), Self::Error>;

    fn semantic_postcheck(
        &mut self,
        admitted_state: &[u8],
        admitted_root: &StateRoot,
        admitted_cursor: &CheckpointCursor,
    ) -> Result<(), Self::Error>;
}

/// A CAS result whose remote outcome is known and signed.
#[derive(Debug)]
pub enum TransitionOutcome {
    Committed {
        root: StateRoot,
        cursor: CheckpointCursor,
        acceptance: Option<Box<VerifiedRemoteCursorCasAcceptance>>,
    },
    /// The signed exact refusal authorized abandoning `pending.json`.
    Refused {
        prepared_root: StateRoot,
        refusal: Box<VerifiedRemoteCursorCasRefusal>,
    },
}

/// Failure classification preserves whether remote mutation may have happened.
#[derive(Debug)]
pub enum TransitionError<E> {
    Coordination(CoordinationError),
    Store(StoreError),
    Cursor(CursorError),
    Journal(JournalError),
    External(E),
    RemoteOutcomeUnknown(E),
    RemoteOutcomeUnknownRelationship(&'static str),
    AcceptedButNotLocallyCommitted(E),
    AcceptedButCursor(CursorError),
    AcceptedButStore(StoreError),
    AcceptedButJournal(JournalError),
    AcceptedButRelationship(&'static str),
    CommittedButPostcheck(E),
    ExactRelationship(&'static str),
    RemoteConflict,
}

impl<E: Display> Display for TransitionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordination(error) => write!(formatter, "local coordination failed: {error}"),
            Self::Store(error) => write!(formatter, "local state store failed: {error}"),
            Self::Cursor(error) => write!(formatter, "local cursor store failed: {error}"),
            Self::Journal(error) => write!(formatter, "transition journal failed: {error}"),
            Self::External(error) => {
                write!(formatter, "external operation failed before CAS: {error}")
            }
            Self::RemoteOutcomeUnknown(error) => {
                write!(formatter, "remote CAS outcome is unknown: {error}")
            }
            Self::RemoteOutcomeUnknownRelationship(field) => write!(
                formatter,
                "remote CAS evidence is not bound to the exact request at {field}"
            ),
            Self::AcceptedButNotLocallyCommitted(error) => write!(
                formatter,
                "remote CAS was accepted but local completion failed: {error}"
            ),
            Self::AcceptedButCursor(error) => write!(
                formatter,
                "remote CAS was accepted but local cursor completion failed: {error}"
            ),
            Self::AcceptedButStore(error) => write!(
                formatter,
                "remote CAS was accepted but local state completion failed: {error}"
            ),
            Self::AcceptedButJournal(error) => write!(
                formatter,
                "remote CAS was accepted but its durable journal update failed: {error}"
            ),
            Self::AcceptedButRelationship(field) => write!(
                formatter,
                "remote CAS was accepted but authenticated artifacts disagree at {field}"
            ),
            Self::CommittedButPostcheck(error) => write!(
                formatter,
                "local cursor and state were committed but semantic postcheck failed: {error}"
            ),
            Self::ExactRelationship(field) => {
                write!(formatter, "authenticated artifacts disagree at {field}")
            }
            Self::RemoteConflict => formatter
                .write_str("remote cursor is neither the retained predecessor nor exact successor"),
        }
    }
}

impl<E: Error + 'static> Error for TransitionError<E> {}

/// Prepares, remotely admits and locally commits exactly one generation.
pub fn execute_transition<C: TransitionCallbacks>(
    paths: LocalStatePaths<'_>,
    current_checkpoint: &VerifiedRootCheckpoint,
    successor_state: &[u8],
    callbacks: &mut C,
) -> Result<TransitionOutcome, TransitionError<C::Error>> {
    coordinate(paths.coordination, |scope| {
        execute_locked(scope, paths, current_checkpoint, successor_state, callbacks)
    })
}

fn execute_locked<C: TransitionCallbacks>(
    scope: &LocalStateCoordination<'_>,
    paths: LocalStatePaths<'_>,
    current_checkpoint: &VerifiedRootCheckpoint,
    successor_state: &[u8],
    callbacks: &mut C,
) -> Result<TransitionOutcome, TransitionError<C::Error>> {
    require_scope(scope)?;
    let remote_current = callbacks
        .fetch_remote_cursor()
        .map_err(TransitionError::External)?;
    require_cursor_checkpoint(remote_current.cursor(), current_checkpoint)?;
    verify_admitted_checkpoint(paths.cursor, current_checkpoint, remote_current.cursor())
        .map_err(TransitionError::Cursor)?;
    let current_state =
        load_state(paths.state, current_checkpoint.root()).map_err(TransitionError::Store)?;
    callbacks
        .validate_transition(&current_state, successor_state)
        .map_err(TransitionError::External)?;

    let generation = current_checkpoint
        .root()
        .generation()
        .checked_add(1)
        .ok_or(TransitionError::ExactRelationship("generationOverflow"))?;
    let prepared = prepare_state(
        paths.state,
        current_checkpoint.root().state_identity(),
        generation,
        successor_state,
        current_checkpoint.root(),
    )
    .map_err(TransitionError::Store)?;
    let successor_checkpoint = callbacks
        .create_checkpoint(&prepared)
        .map_err(TransitionError::External)?;
    if successor_checkpoint.root() != &prepared {
        return Err(TransitionError::ExactRelationship("checkpointRoot"));
    }

    let request = callbacks
        .prepare_remote_cas(&remote_current, &successor_checkpoint)
        .map_err(TransitionError::External)?;
    require_request(&request, &remote_current, &successor_checkpoint)?;
    let mut durable = make_journal(
        &remote_current,
        current_checkpoint,
        &successor_checkpoint,
        &request,
    )?;
    journal::create(paths.journal, &durable).map_err(TransitionError::Journal)?;

    let exchange = callbacks
        .submit_remote_cas(&request)
        .map_err(TransitionError::RemoteOutcomeUnknown)?;
    require_cas_exchange(&exchange, &remote_current, &successor_checkpoint)
        .map_err(TransitionError::RemoteOutcomeUnknownRelationship)?;
    durable.receipt_hex = Some(hex::encode(exchange.receipt_bytes()));
    let accepted = matches!(
        exchange.receipt(),
        VerifiedRemoteCursorCasReceipt::Accepted(_)
    );
    journal::update(paths.journal, &durable).map_err(|error| {
        if accepted {
            TransitionError::AcceptedButJournal(error)
        } else {
            TransitionError::Journal(error)
        }
    })?;
    let acceptance = match exchange.receipt().clone() {
        VerifiedRemoteCursorCasReceipt::Refused(refusal) => {
            discard_prepared_state(paths.state, current_checkpoint.root(), &prepared)
                .map_err(TransitionError::Store)?;
            journal::clear(paths.journal).map_err(TransitionError::Journal)?;
            return Ok(TransitionOutcome::Refused {
                prepared_root: prepared,
                refusal: Box::new(refusal),
            });
        }
        VerifiedRemoteCursorCasReceipt::Accepted(acceptance) => acceptance,
    };
    require_cursor_checkpoint(acceptance.successor(), &successor_checkpoint)
        .map_err(as_accepted_relationship)?;

    let remote_successor = callbacks
        .fetch_remote_cursor()
        .map_err(TransitionError::AcceptedButNotLocallyCommitted)?;
    if remote_successor.cursor() != acceptance.successor()
        || remote_successor.remote_cursor_policy_sha256() != request.remote_cursor_policy_sha256()
    {
        return Err(TransitionError::AcceptedButRelationship(
            "acceptedSuccessorObservation",
        ));
    }
    require_cursor_checkpoint(remote_successor.cursor(), &successor_checkpoint)
        .map_err(as_accepted_relationship)?;

    let admitted = admit_checkpoint(
        paths.cursor,
        &successor_checkpoint,
        Some(remote_current.cursor()),
    )
    .map_err(TransitionError::AcceptedButCursor)?;
    if admitted != *remote_successor.cursor() {
        return Err(TransitionError::AcceptedButRelationship(
            "localSuccessorCursor",
        ));
    }
    let promoted = promote_prepared_state(
        paths.state,
        current_checkpoint.root(),
        successor_checkpoint.root(),
    )
    .map_err(TransitionError::AcceptedButStore)?;
    let state = load_state(paths.state, &promoted).map_err(TransitionError::AcceptedButStore)?;
    callbacks
        .semantic_postcheck(&state, &promoted, &admitted)
        .map_err(TransitionError::CommittedButPostcheck)?;
    journal::clear(paths.journal).map_err(TransitionError::AcceptedButJournal)?;

    Ok(TransitionOutcome::Committed {
        root: promoted,
        cursor: admitted,
        acceptance: Some(Box::new(acceptance)),
    })
}

/// Reconciles an unresolved durable request after process or response loss.
///
/// An observed predecessor causes an exact replay of the journaled request.
/// An observed successor completes locally. Any other cursor fails closed.
pub fn reconcile_transition<C: TransitionCallbacks>(
    paths: LocalStatePaths<'_>,
    current_checkpoint: &VerifiedRootCheckpoint,
    successor_checkpoint: &VerifiedRootCheckpoint,
    callbacks: &mut C,
) -> Result<TransitionOutcome, TransitionError<C::Error>> {
    coordinate(paths.coordination, |scope| {
        require_scope(scope)?;
        let mut durable = journal::load(paths.journal).map_err(TransitionError::Journal)?;
        let request = callbacks
            .validate_retained_remote_cas_request(&decode_hex(&durable.request_hex)?)
            .map_err(TransitionError::External)?;
        require_journal(&durable, current_checkpoint, successor_checkpoint, &request)?;
        let receipt_bytes = durable.receipt_hex.as_deref().map(decode_hex).transpose()?;
        let retained_exchange = receipt_bytes
            .as_deref()
            .map(|receipt| {
                callbacks.validate_retained_remote_cas_exchange(request.canonical_bytes(), receipt)
            })
            .transpose()
            .map_err(TransitionError::External)?;
        if let Some(exchange) = &retained_exchange {
            require_cas_exchange_request(exchange, &request)
                .map_err(TransitionError::RemoteOutcomeUnknownRelationship)?;
        }
        require_successor_lineage(current_checkpoint.root(), successor_checkpoint.root())
            .map_err(as_accepted_relationship)?;

        let mut remote = callbacks
            .fetch_remote_cursor()
            .map_err(TransitionError::AcceptedButNotLocallyCommitted)?;
        if remote.remote_cursor_policy_sha256() != request.remote_cursor_policy_sha256() {
            return Err(TransitionError::RemoteConflict);
        }
        let current_cursor = request
            .expected_current()
            .ok_or(TransitionError::ExactRelationship("expectedCurrentCursor"))?;

        if let Some(exchange) = &retained_exchange
            && let VerifiedRemoteCursorCasReceipt::Refused(refusal) = exchange.receipt()
        {
            if remote.cursor() == request.successor() {
                return Err(TransitionError::RemoteConflict);
            }
            if remote.cursor() == current_cursor {
                discard_prepared_state(
                    paths.state,
                    current_checkpoint.root(),
                    successor_checkpoint.root(),
                )
                .map_err(TransitionError::Store)?;
                journal::clear(paths.journal).map_err(TransitionError::Journal)?;
                return Ok(TransitionOutcome::Refused {
                    prepared_root: successor_checkpoint.root().clone(),
                    refusal: Box::new(refusal.clone()),
                });
            }
        }

        let acceptance = if remote.cursor() == request.successor() {
            retained_exchange
                .as_ref()
                .and_then(|exchange| match exchange.receipt() {
                    VerifiedRemoteCursorCasReceipt::Accepted(value) => Some(value.clone()),
                    VerifiedRemoteCursorCasReceipt::Refused(_) => None,
                })
        } else if remote.cursor() == current_cursor {
            let exchange = callbacks
                .submit_remote_cas(&request)
                .map_err(TransitionError::RemoteOutcomeUnknown)?;
            require_cas_exchange_request(&exchange, &request)
                .map_err(TransitionError::RemoteOutcomeUnknownRelationship)?;
            durable.receipt_hex = Some(hex::encode(exchange.receipt_bytes()));
            let accepted = matches!(
                exchange.receipt(),
                VerifiedRemoteCursorCasReceipt::Accepted(_)
            );
            journal::update(paths.journal, &durable).map_err(|error| {
                if accepted {
                    TransitionError::AcceptedButJournal(error)
                } else {
                    TransitionError::Journal(error)
                }
            })?;
            match exchange.receipt().clone() {
                VerifiedRemoteCursorCasReceipt::Refused(refusal) => {
                    discard_prepared_state(
                        paths.state,
                        current_checkpoint.root(),
                        successor_checkpoint.root(),
                    )
                    .map_err(TransitionError::Store)?;
                    journal::clear(paths.journal).map_err(TransitionError::Journal)?;
                    return Ok(TransitionOutcome::Refused {
                        prepared_root: successor_checkpoint.root().clone(),
                        refusal: Box::new(refusal),
                    });
                }
                VerifiedRemoteCursorCasReceipt::Accepted(acceptance) => {
                    remote = callbacks
                        .fetch_remote_cursor()
                        .map_err(TransitionError::AcceptedButNotLocallyCommitted)?;
                    Some(acceptance)
                }
            }
        } else {
            return Err(TransitionError::RemoteConflict);
        };
        if remote.cursor() != request.successor()
            || remote.remote_cursor_policy_sha256() != request.remote_cursor_policy_sha256()
        {
            return Err(TransitionError::AcceptedButRelationship(
                "acceptedSuccessorObservation",
            ));
        }
        require_cursor_checkpoint(remote.cursor(), successor_checkpoint)
            .map_err(as_accepted_relationship)?;

        let local_cursor = match load_cursor(paths.cursor, remote.cursor()) {
            Ok(cursor) => cursor,
            Err(CursorError::ExpectationMismatch) => {
                verify_admitted_checkpoint(paths.cursor, current_checkpoint, current_cursor)
                    .map_err(TransitionError::AcceptedButCursor)?;
                admit_checkpoint(paths.cursor, successor_checkpoint, Some(current_cursor))
                    .map_err(TransitionError::AcceptedButCursor)?
            }
            Err(error) => return Err(TransitionError::AcceptedButCursor(error)),
        };
        if local_cursor != *remote.cursor() {
            return Err(TransitionError::AcceptedButRelationship(
                "localSuccessorCursor",
            ));
        }
        let promoted = promote_prepared_state(
            paths.state,
            current_checkpoint.root(),
            successor_checkpoint.root(),
        )
        .map_err(TransitionError::AcceptedButStore)?;
        let state =
            load_state(paths.state, &promoted).map_err(TransitionError::AcceptedButStore)?;
        callbacks
            .semantic_postcheck(&state, &promoted, &local_cursor)
            .map_err(TransitionError::CommittedButPostcheck)?;
        journal::clear(paths.journal).map_err(TransitionError::AcceptedButJournal)?;
        Ok(TransitionOutcome::Committed {
            root: promoted,
            cursor: local_cursor,
            acceptance: acceptance.map(Box::new),
        })
    })
}

fn coordinate<T, E: Error + Send + Sync + 'static>(
    path: &Path,
    operation: impl for<'lock> FnOnce(&LocalStateCoordination<'lock>) -> Result<T, TransitionError<E>>,
) -> Result<T, TransitionError<E>> {
    match with_coordinated_state_transition(path, operation) {
        Ok(value) => Ok(value),
        Err(CoordinatedError::Coordination(error)) => Err(TransitionError::Coordination(error)),
        Err(CoordinatedError::Operation(error)) => Err(error),
    }
}

fn require_scope<E>(scope: &LocalStateCoordination<'_>) -> Result<(), TransitionError<E>> {
    if scope.local_exclusion_held() {
        Ok(())
    } else {
        Err(TransitionError::ExactRelationship("localCoordination"))
    }
}

fn as_accepted_relationship<E>(error: TransitionError<E>) -> TransitionError<E> {
    match error {
        TransitionError::ExactRelationship(field) => {
            TransitionError::AcceptedButRelationship(field)
        }
        TransitionError::Store(error) => TransitionError::AcceptedButStore(error),
        other => other,
    }
}

fn require_cursor_checkpoint<E>(
    cursor: &CheckpointCursor,
    checkpoint: &VerifiedRootCheckpoint,
) -> Result<(), TransitionError<E>> {
    let root_bytes = checkpoint
        .root()
        .canonical_bytes()
        .map_err(TransitionError::Store)?;
    if cursor.state_identity() != checkpoint.root().state_identity()
        || cursor.generation() != checkpoint.root().generation()
        || cursor.checkpoint_sha256() != checkpoint.checkpoint_sha256()
        || cursor.checkpoint_policy_sha256() != checkpoint.checkpoint_policy_sha256()
        || cursor.semantic_manifest_sha256() != checkpoint.semantic_manifest_sha256()
        || cursor.state_root_sha256() != hash(&root_bytes)
        || cursor.state_sha256() != checkpoint.root().state_sha256()
    {
        return Err(TransitionError::ExactRelationship("cursorCheckpoint"));
    }
    Ok(())
}

fn require_successor_lineage<E>(
    current: &StateRoot,
    successor: &StateRoot,
) -> Result<(), TransitionError<E>> {
    let current_hash = hash(&current.canonical_bytes().map_err(TransitionError::Store)?);
    let next_generation = current
        .generation()
        .checked_add(1)
        .ok_or(TransitionError::ExactRelationship("generationOverflow"))?;
    if successor.state_identity() != current.state_identity()
        || successor.generation() != next_generation
        || successor.previous_root_sha256() != Some(current_hash.as_str())
    {
        return Err(TransitionError::ExactRelationship("successorLineage"));
    }
    Ok(())
}

fn require_cas_exchange(
    exchange: &VerifiedRemoteCursorCasExchange,
    current: &VerifiedRemoteCursor,
    successor: &VerifiedRootCheckpoint,
) -> Result<(), &'static str> {
    require_request::<std::convert::Infallible>(exchange.request(), current, successor)
        .map_err(|_| "exactRequest")?;
    require_cas_exchange_request(exchange, exchange.request())
}

fn require_request<E>(
    request: &ValidatedRemoteCursorCasRequest,
    current: &VerifiedRemoteCursor,
    successor: &VerifiedRootCheckpoint,
) -> Result<(), TransitionError<E>> {
    if request.expected_current() != Some(current.cursor()) {
        return Err(TransitionError::ExactRelationship("expectedCurrentCursor"));
    }
    if request.remote_cursor_policy_sha256() != current.remote_cursor_policy_sha256() {
        return Err(TransitionError::ExactRelationship("remotePolicy"));
    }
    if request.successor_root() != successor.root() {
        return Err(TransitionError::ExactRelationship("successorRoot"));
    }
    require_cursor_checkpoint(request.successor(), successor)
}

fn require_cas_exchange_request(
    exchange: &VerifiedRemoteCursorCasExchange,
    request: &ValidatedRemoteCursorCasRequest,
) -> Result<(), &'static str> {
    if exchange.request_bytes() != request.canonical_bytes()
        || exchange.request().request_sha256() != request.request_sha256()
        || exchange.receipt().request_sha256() != request.request_sha256()
        || exchange.receipt().remote_cursor_policy_sha256() != request.remote_cursor_policy_sha256()
    {
        return Err("exactRequestExchange");
    }
    Ok(())
}

fn make_journal<E>(
    current: &VerifiedRemoteCursor,
    current_checkpoint: &VerifiedRootCheckpoint,
    successor_checkpoint: &VerifiedRootCheckpoint,
    request: &ValidatedRemoteCursorCasRequest,
) -> Result<Journal, TransitionError<E>> {
    require_request(request, current, successor_checkpoint)?;
    Ok(Journal {
        schema: JOURNAL_SCHEMA.into(),
        current_root_sha256: hash(
            &current_checkpoint
                .root()
                .canonical_bytes()
                .map_err(TransitionError::Store)?,
        ),
        current_checkpoint_sha256: current_checkpoint.checkpoint_sha256().into(),
        successor_root_sha256: hash(
            &successor_checkpoint
                .root()
                .canonical_bytes()
                .map_err(TransitionError::Store)?,
        ),
        successor_checkpoint_sha256: successor_checkpoint.checkpoint_sha256().into(),
        remote_policy_sha256: current.remote_cursor_policy_sha256().into(),
        request_sha256: request.request_sha256().into(),
        request_hex: hex::encode(request.canonical_bytes()),
        receipt_hex: None,
    })
}

fn require_journal<E>(
    durable: &Journal,
    current: &VerifiedRootCheckpoint,
    successor: &VerifiedRootCheckpoint,
    request: &ValidatedRemoteCursorCasRequest,
) -> Result<(), TransitionError<E>> {
    let current_root = hash(
        &current
            .root()
            .canonical_bytes()
            .map_err(TransitionError::Store)?,
    );
    let successor_root = hash(
        &successor
            .root()
            .canonical_bytes()
            .map_err(TransitionError::Store)?,
    );
    if durable.schema != JOURNAL_SCHEMA
        || durable.current_root_sha256 != current_root
        || durable.current_checkpoint_sha256 != current.checkpoint_sha256()
        || durable.successor_root_sha256 != successor_root
        || durable.successor_checkpoint_sha256 != successor.checkpoint_sha256()
        || durable.remote_policy_sha256 != request.remote_cursor_policy_sha256()
        || durable.request_sha256 != request.request_sha256()
        || durable.request_hex != hex::encode(request.canonical_bytes())
    {
        return Err(TransitionError::ExactRelationship("durableJournal"));
    }
    Ok(())
}

fn decode_hex<E>(value: &str) -> Result<Vec<u8>, TransitionError<E>> {
    hex::decode(value).map_err(|_| TransitionError::ExactRelationship("journalHex"))
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
