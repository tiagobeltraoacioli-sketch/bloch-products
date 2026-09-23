#![cfg(unix)]

use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    VerifiedRootCheckpoint, checkpoint_policy_sha256, checkpoint_signature_message,
    create_root_checkpoint, verify_root_checkpoint_exact,
};
use bloch_local_state_coordination::provision_local_state_coordination_directory;
use bloch_local_state_cursor::{CheckpointCursor, admit_checkpoint, load_cursor};
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasDecision,
    RemoteCursorCasRequestParameters, RemoteCursorPolicy, RemoteCursorSignature,
    VerifiedRemoteCursor, VerifiedRemoteCursorCasAcceptance, VerifiedRemoteCursorCasReceipt,
    create_remote_cursor_cas_receipt, create_remote_cursor_cas_request,
    create_remote_cursor_observation, parse_remote_cursor_cas_request,
    remote_cursor_cas_receipt_signature_message, remote_cursor_policy_sha256,
    remote_cursor_signature_message, verify_remote_cursor_cas_exchange,
    verify_remote_cursor_observation,
};
use bloch_local_state_store::{
    StateRoot, StoreError, discard_prepared_state, load_state, prepare_state, write_state,
};
use bloch_local_state_transition::{
    LocalStatePaths, TransitionCallbacks, TransitionError, TransitionOutcome, execute_transition,
    reconcile_transition,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fmt::{self, Display};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const NOW: u64 = 500;
const SEMANTIC_DIGEST: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CasMode {
    Accept,
    Refuse,
    Unknown,
}

#[derive(Debug)]
struct TestError(&'static str);

impl Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TestError {}

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-transition-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Environment {
    _tree: TempTree,
    coord: PathBuf,
    state: PathBuf,
    cursor: PathBuf,
    journal: PathBuf,
    current_root: StateRoot,
    current_checkpoint: VerifiedRootCheckpoint,
    current_cursor: CheckpointCursor,
    checkpoint_policy: CheckpointPolicy,
    checkpoint_pin: String,
    checkpoint_keys: Vec<SigningKey>,
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
}

impl Environment {
    fn new() -> Self {
        let tree = TempTree::new();
        let coord = tree.0.join("coord");
        provision_local_state_coordination_directory(&coord).unwrap();
        let state = tree.0.join("state");
        let cursor = tree.0.join("cursor");
        let journal = tree.0.join("journal");
        let mut journal_builder = DirBuilder::new();
        journal_builder.mode(0o700).create(&journal).unwrap();
        let current_root = write_state(&state, "data:tenant-a", 0, b"state-0", None).unwrap();

        let checkpoint_keys = keys(11);
        let checkpoint_policy = checkpoint_policy(&checkpoint_keys);
        let checkpoint_pin = checkpoint_policy_sha256(&checkpoint_policy).unwrap();
        let current_checkpoint = checkpoint(
            &current_root,
            &checkpoint_policy,
            &checkpoint_pin,
            &checkpoint_keys,
        );
        let current_cursor = admit_checkpoint(&cursor, &current_checkpoint, None).unwrap();

        let remote_keys = keys(31);
        let remote_policy = remote_policy(&remote_keys);
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        Self {
            _tree: tree,
            coord,
            state,
            cursor,
            journal,
            current_root,
            current_checkpoint,
            current_cursor,
            checkpoint_policy,
            checkpoint_pin,
            checkpoint_keys,
            remote_policy,
            remote_pin,
            remote_keys,
        }
    }

    fn paths(&self) -> LocalStatePaths<'_> {
        LocalStatePaths {
            coordination: self.coord(),
            state: self.state(),
            cursor: self.cursor(),
            journal: &self.journal,
        }
    }

    fn coord(&self) -> &Path {
        &self.coord
    }

    fn state(&self) -> &Path {
        &self.state
    }

    fn cursor(&self) -> &Path {
        &self.cursor
    }

    fn callbacks(&self, mode: CasMode) -> Callbacks {
        Callbacks {
            mode,
            checkpoint_policy: self.checkpoint_policy.clone(),
            checkpoint_pin: self.checkpoint_pin.clone(),
            checkpoint_keys: self.checkpoint_keys.clone(),
            remote_policy: self.remote_policy.clone(),
            remote_pin: self.remote_pin.clone(),
            remote_keys: self.remote_keys.clone(),
            current_cursor: self.current_cursor.clone(),
            remote_cursor: self.current_cursor.clone(),
            successor_checkpoint: None,
            acceptance: None,
            fail_successor_fetch: false,
            return_old_after_acceptance: false,
            fail_postcheck: false,
            sabotage_journal_after_cas: None,
            sabotage_journal_after_postcheck: None,
            fetches: 0,
        }
    }
}

struct Callbacks {
    mode: CasMode,
    checkpoint_policy: CheckpointPolicy,
    checkpoint_pin: String,
    checkpoint_keys: Vec<SigningKey>,
    remote_policy: RemoteCursorPolicy,
    remote_pin: String,
    remote_keys: Vec<SigningKey>,
    current_cursor: CheckpointCursor,
    remote_cursor: CheckpointCursor,
    successor_checkpoint: Option<VerifiedRootCheckpoint>,
    acceptance: Option<VerifiedRemoteCursorCasAcceptance>,
    fail_successor_fetch: bool,
    return_old_after_acceptance: bool,
    fail_postcheck: bool,
    sabotage_journal_after_cas: Option<PathBuf>,
    sabotage_journal_after_postcheck: Option<PathBuf>,
    fetches: usize,
}

impl Callbacks {
    fn observe(&self, cursor: &CheckpointCursor) -> VerifiedRemoteCursor {
        let nonce = "observation_nonce_0123456789abcdef0123456789abcdef";
        let message = remote_cursor_signature_message(
            cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            NOW,
        )
        .unwrap();
        let signatures = sign_remote(&self.remote_keys, &message);
        let bytes = create_remote_cursor_observation(
            cursor,
            &self.remote_policy,
            &self.remote_pin,
            nonce,
            NOW,
            &signatures,
        )
        .unwrap();
        verify_remote_cursor_observation(&bytes, &self.remote_policy, &self.remote_pin, nonce, NOW)
            .unwrap()
    }

    fn cas_receipt(
        &self,
        request: &bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest,
        decision: RemoteCursorCasDecision,
    ) -> bloch_local_state_remote_cursor::VerifiedRemoteCursorCasExchange {
        let message = remote_cursor_cas_receipt_signature_message(
            request.canonical_bytes(),
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            NOW,
        )
        .unwrap();
        let signatures = sign_remote(&self.remote_keys, &message);
        let receipt = create_remote_cursor_cas_receipt(
            request.canonical_bytes(),
            &self.remote_policy,
            &self.remote_pin,
            &decision,
            NOW,
            &signatures,
        )
        .unwrap();
        verify_remote_cursor_cas_exchange(
            &receipt,
            request.canonical_bytes(),
            &self.remote_policy,
            &self.remote_pin,
            NOW,
        )
        .unwrap()
    }
}

impl TransitionCallbacks for Callbacks {
    type Error = TestError;

    fn fetch_remote_cursor(&mut self) -> Result<VerifiedRemoteCursor, Self::Error> {
        self.fetches += 1;
        if self.fail_successor_fetch && self.fetches > 1 {
            return Err(TestError("successor fetch failed"));
        }
        let cursor = if self.return_old_after_acceptance && self.fetches > 1 {
            &self.current_cursor
        } else {
            &self.remote_cursor
        };
        Ok(self.observe(cursor))
    }

    fn create_checkpoint(
        &mut self,
        root: &StateRoot,
    ) -> Result<VerifiedRootCheckpoint, Self::Error> {
        let checkpoint = checkpoint(
            root,
            &self.checkpoint_policy,
            &self.checkpoint_pin,
            &self.checkpoint_keys,
        );
        self.successor_checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    fn prepare_remote_cas(
        &mut self,
        current: &VerifiedRemoteCursor,
        successor: &VerifiedRootCheckpoint,
    ) -> Result<bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest, Self::Error> {
        let successor_cursor = derive_cursor(current.cursor(), successor);
        let request = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: Some(current.cursor()),
                successor_cursor: &successor_cursor,
                successor_root: successor.root(),
                request_id: "transaction-0001",
                request_nonce: "cas_nonce_0123456789abcdef0123456789abcdef",
                requested_at_unix_seconds: NOW,
            },
            &self.remote_policy,
            &self.remote_pin,
        )
        .unwrap();
        Ok(
            parse_remote_cursor_cas_request(&request, &self.remote_policy, &self.remote_pin)
                .unwrap(),
        )
    }

    fn submit_remote_cas(
        &mut self,
        request: &bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest,
    ) -> Result<bloch_local_state_remote_cursor::VerifiedRemoteCursorCasExchange, Self::Error> {
        match self.mode {
            CasMode::Unknown => Err(TestError("transport lost")),
            CasMode::Refuse => Ok(self.cas_receipt(
                request,
                RemoteCursorCasDecision::Refused {
                    reason_code: "conflict".into(),
                },
            )),
            CasMode::Accept => {
                let exchange = self.cas_receipt(request, RemoteCursorCasDecision::Accepted);
                let acceptance = match exchange.receipt() {
                    VerifiedRemoteCursorCasReceipt::Accepted(value) => value.clone(),
                    VerifiedRemoteCursorCasReceipt::Refused(_) => unreachable!(),
                };
                self.remote_cursor = acceptance.successor().clone();
                self.acceptance = Some(acceptance);
                if let Some(path) = self.sabotage_journal_after_cas.take() {
                    std::fs::set_permissions(
                        path,
                        std::os::unix::fs::PermissionsExt::from_mode(0o500),
                    )
                    .unwrap();
                }
                Ok(exchange)
            }
        }
    }

    fn validate_retained_remote_cas_request(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<bloch_local_state_remote_cursor::ValidatedRemoteCursorCasRequest, Self::Error> {
        Ok(
            parse_remote_cursor_cas_request(request_bytes, &self.remote_policy, &self.remote_pin)
                .unwrap(),
        )
    }

    fn validate_retained_remote_cas_exchange(
        &mut self,
        request_bytes: &[u8],
        receipt_bytes: &[u8],
    ) -> Result<bloch_local_state_remote_cursor::VerifiedRemoteCursorCasExchange, Self::Error> {
        Ok(verify_remote_cursor_cas_exchange(
            receipt_bytes,
            request_bytes,
            &self.remote_policy,
            &self.remote_pin,
            NOW,
        )
        .unwrap())
    }

    fn validate_transition(
        &mut self,
        current_state: &[u8],
        successor_state: &[u8],
    ) -> Result<(), Self::Error> {
        if current_state == b"state-0" && successor_state == b"state-1" {
            Ok(())
        } else {
            Err(TestError("semantic transition rejected"))
        }
    }

    fn semantic_postcheck(
        &mut self,
        admitted_state: &[u8],
        admitted_root: &StateRoot,
        admitted_cursor: &CheckpointCursor,
    ) -> Result<(), Self::Error> {
        if self.fail_postcheck {
            return Err(TestError("postcheck crash"));
        }
        if admitted_state == b"state-1"
            && admitted_root.generation() == 1
            && admitted_cursor.generation() == 1
        {
            if let Some(path) = self.sabotage_journal_after_postcheck.take() {
                std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o500))
                    .unwrap();
            }
            Ok(())
        } else {
            Err(TestError("restore mismatch"))
        }
    }
}

#[test]
fn commits_only_after_accepted_successor_is_freshly_observed() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    let outcome = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, cursor, .. } = outcome else {
        panic!("expected commit")
    };
    assert_eq!(callbacks.fetches, 2);
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
    assert_eq!(load_cursor(env.cursor(), &cursor).unwrap(), cursor);
}

#[test]
fn unknown_outcome_retains_pending_and_old_local_state() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Unknown);
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(error, TransitionError::RemoteOutcomeUnknown(_)));
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );
    assert_eq!(
        load_cursor(env.cursor(), &env.current_cursor).unwrap(),
        env.current_cursor
    );
    let pending = callbacks.successor_checkpoint.unwrap().root().clone();
    assert_eq!(
        prepare_state(
            env.state(),
            env.current_root.state_identity(),
            1,
            b"state-1",
            &env.current_root,
        )
        .unwrap(),
        pending
    );
}

#[test]
fn durable_journal_blocks_a_second_cas_until_reconciliation() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Unknown);
    assert!(matches!(
        execute_transition(
            env.paths(),
            &env.current_checkpoint,
            b"state-1",
            &mut callbacks,
        ),
        Err(TransitionError::RemoteOutcomeUnknown(_))
    ));
    assert!(env.journal.join("transition.json").exists());

    callbacks.mode = CasMode::Accept;
    callbacks.fetches = 0;
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(error, TransitionError::Journal(_)));
    assert!(callbacks.acceptance.is_none());
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );
}

#[test]
fn unknown_outcome_replays_exact_durable_request_after_observing_predecessor() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Unknown);
    assert!(matches!(
        execute_transition(
            env.paths(),
            &env.current_checkpoint,
            b"state-1",
            &mut callbacks,
        ),
        Err(TransitionError::RemoteOutcomeUnknown(_))
    ));
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    callbacks.mode = CasMode::Accept;
    callbacks.fetches = 0;
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, cursor, .. } = outcome else {
        panic!("expected recovered commit")
    };
    assert_eq!(root.generation(), 1);
    assert_eq!(cursor.generation(), 1);
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
}

#[test]
fn journal_symlink_and_hardlink_objects_fail_closed_before_cas() {
    for hardlink in [false, true] {
        let env = Environment::new();
        let victim = env._tree.0.join("victim");
        std::fs::write(&victim, b"victim").unwrap();
        std::fs::set_permissions(&victim, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let journal_file = env.journal.join("transition.json");
        if hardlink {
            std::fs::hard_link(&victim, &journal_file).unwrap();
        } else {
            std::os::unix::fs::symlink(&victim, &journal_file).unwrap();
        }
        let mut callbacks = env.callbacks(CasMode::Accept);
        let error = execute_transition(
            env.paths(),
            &env.current_checkpoint,
            b"state-1",
            &mut callbacks,
        )
        .unwrap_err();
        assert!(matches!(error, TransitionError::Journal(_)));
        assert!(callbacks.acceptance.is_none());
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    }
}

#[test]
fn signed_refusal_is_distinct_and_allows_exact_abandonment() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Refuse);
    let outcome = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Refused {
        prepared_root,
        refusal,
    } = outcome
    else {
        panic!("expected refusal")
    };
    assert_eq!(refusal.reason_code(), "conflict");
    assert_eq!(prepared_root.generation(), 1);
    assert!(
        prepare_state(
            env.state(),
            env.current_root.state_identity(),
            1,
            b"different-state",
            &env.current_root,
        )
        .is_ok()
    );
}

#[test]
fn accepted_then_fetch_failure_is_classified_and_recoverable() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.fail_successor_fetch = true;
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        TransitionError::AcceptedButNotLocallyCommitted(_)
    ));
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );

    callbacks.fail_successor_fetch = false;
    callbacks.fetches = 0;
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, cursor, .. } = outcome else {
        panic!("expected recovered commit")
    };
    assert_eq!(root.generation(), 1);
    assert_eq!(cursor, callbacks.remote_cursor);
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
}

#[test]
fn accepted_before_receipt_persistence_recovers_from_remote_successor() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.sabotage_journal_after_cas = Some(env.journal.clone());
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(error, TransitionError::AcceptedButJournal(_)));
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );

    std::fs::set_permissions(
        &env.journal,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    callbacks.fetches = 0;
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed {
        root, acceptance, ..
    } = outcome
    else {
        panic!("expected recovered commit")
    };
    assert!(acceptance.is_none());
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
}

#[test]
fn accepted_but_wrong_fresh_observation_keeps_pending_and_is_classified() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.return_old_after_acceptance = true;
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        TransitionError::AcceptedButRelationship("acceptedSuccessorObservation")
    ));
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );
    assert!(matches!(
        prepare_state(
            env.state(),
            env.current_root.state_identity(),
            1,
            b"different-state",
            &env.current_root,
        ),
        Err(StoreError::PreparedStateConflict)
    ));
}

#[test]
fn postcheck_crash_is_accepted_phase_and_recovery_is_idempotent() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.fail_postcheck = true;
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(error, TransitionError::CommittedButPostcheck(_)));

    callbacks.fail_postcheck = false;
    callbacks.fetches = 0;
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    let recovered = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, .. } = recovered else {
        panic!("expected recovered commit")
    };
    assert_eq!(root.generation(), 1);
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
}

#[test]
fn journal_clear_failure_after_commit_is_recoverable() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.sabotage_journal_after_postcheck = Some(env.journal.clone());
    let error = execute_transition(
        env.paths(),
        &env.current_checkpoint,
        b"state-1",
        &mut callbacks,
    )
    .unwrap_err();
    assert!(matches!(error, TransitionError::AcceptedButJournal(_)));
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    assert_eq!(
        load_state(env.state(), successor.root()).unwrap(),
        b"state-1"
    );

    std::fs::set_permissions(
        &env.journal,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    callbacks.fetches = 0;
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, .. } = outcome else {
        panic!("expected recovered commit")
    };
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
    assert!(!env.journal.join("transition.json").exists());
}

#[test]
fn refusal_recovery_is_idempotent_after_prepared_unlink() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Unknown);
    assert!(matches!(
        execute_transition(
            env.paths(),
            &env.current_checkpoint,
            b"state-1",
            &mut callbacks,
        ),
        Err(TransitionError::RemoteOutcomeUnknown(_))
    ));
    let successor = callbacks.successor_checkpoint.clone().unwrap();

    let journal_path = env.journal.join("transition.json");
    let journal_bytes = std::fs::read(&journal_path).unwrap();
    let journal_value: serde_json::Value = serde_json::from_slice(&journal_bytes).unwrap();
    let request_bytes = hex::decode(journal_value["requestHex"].as_str().unwrap()).unwrap();
    let request = parse_remote_cursor_cas_request(
        &request_bytes,
        &callbacks.remote_policy,
        &callbacks.remote_pin,
    )
    .unwrap();
    let refusal = callbacks.cas_receipt(
        &request,
        RemoteCursorCasDecision::Refused {
            reason_code: "conflict".into(),
        },
    );
    let original = String::from_utf8(journal_bytes).unwrap();
    let retained = original.replace(
        "\"receiptHex\":null",
        &format!(
            "\"receiptHex\":\"{}\"",
            hex::encode(refusal.receipt_bytes())
        ),
    );
    assert_ne!(retained, original);
    std::fs::write(&journal_path, retained).unwrap();
    discard_prepared_state(env.state(), &env.current_root, successor.root()).unwrap();

    callbacks.fetches = 0;
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Refused { refusal, .. } = outcome else {
        panic!("expected recovered refusal")
    };
    assert_eq!(refusal.reason_code(), "conflict");
    assert!(!journal_path.exists());
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );
}

#[test]
fn recovery_promotes_pending_when_cursor_already_advanced() {
    let env = Environment::new();
    let mut callbacks = env.callbacks(CasMode::Accept);
    callbacks.fail_successor_fetch = true;
    assert!(
        execute_transition(
            env.paths(),
            &env.current_checkpoint,
            b"state-1",
            &mut callbacks,
        )
        .is_err()
    );
    let successor = callbacks.successor_checkpoint.clone().unwrap();
    let acceptance = callbacks.acceptance.clone().unwrap();
    let advanced = admit_checkpoint(env.cursor(), &successor, Some(&env.current_cursor)).unwrap();
    assert_eq!(advanced, *acceptance.successor());
    assert_eq!(
        load_state(env.state(), &env.current_root).unwrap(),
        b"state-0"
    );

    callbacks.fetches = 0;
    callbacks.fail_successor_fetch = false;
    let outcome = reconcile_transition(
        env.paths(),
        &env.current_checkpoint,
        &successor,
        &mut callbacks,
    )
    .unwrap();
    let TransitionOutcome::Committed { root, cursor, .. } = outcome else {
        panic!("expected recovered commit")
    };
    assert_eq!(cursor, advanced);
    assert_eq!(load_state(env.state(), &root).unwrap(), b"state-1");
}

fn keys(seed: u8) -> Vec<SigningKey> {
    vec![
        SigningKey::from_bytes(&[seed; 32]),
        SigningKey::from_bytes(&[seed + 1; 32]),
    ]
}

fn checkpoint_policy(keys: &[SigningKey]) -> CheckpointPolicy {
    CheckpointPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "checkpoint-policy".into(),
        checkpoint_domain: "transition-tests".into(),
        state_identity: "data:tenant-a".into(),
        threshold: 2,
        effective_at_unix_seconds: 1,
        expires_at_unix_seconds: 1_000,
        max_checkpoint_age_seconds: 900,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| CheckpointAuthority {
                authority_id: format!("checkpoint-authority-{index}"),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    }
}

fn checkpoint(
    root: &StateRoot,
    policy: &CheckpointPolicy,
    pin: &str,
    keys: &[SigningKey],
) -> VerifiedRootCheckpoint {
    let message = checkpoint_signature_message(root, policy, pin, SEMANTIC_DIGEST, NOW).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| DetachedCheckpointSignature {
            authority_id: format!("checkpoint-authority-{index}"),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let artifact =
        create_root_checkpoint(root, policy, pin, SEMANTIC_DIGEST, NOW, &signatures).unwrap();
    verify_root_checkpoint_exact(&artifact, policy, pin, root, SEMANTIC_DIGEST, NOW).unwrap()
}

fn remote_policy(keys: &[SigningKey]) -> RemoteCursorPolicy {
    RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: "remote-policy".into(),
        signature_domain: "transition-tests".into(),
        state_identity: "data:tenant-a".into(),
        threshold: 2,
        effective_at_unix_seconds: 1,
        expires_at_unix_seconds: 1_000,
        max_observation_age_seconds: 900,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorAuthority {
                authority_id: format!("remote-authority-{index}"),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    }
}

fn sign_remote(keys: &[SigningKey], message: &[u8]) -> Vec<RemoteCursorSignature> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| RemoteCursorSignature {
            authority_id: format!("remote-authority-{index}"),
            signature: format!("0x{}", hex::encode(key.sign(message).to_bytes())),
        })
        .collect()
}

fn derive_cursor(
    current: &CheckpointCursor,
    successor: &VerifiedRootCheckpoint,
) -> CheckpointCursor {
    let tree = TempTree::new();
    let initial_root = successor.root().previous_root_sha256().unwrap();
    // Cursor admission validates lineage using only the retained root digest;
    // reconstruct a canonical current cursor directly from its public bytes.
    assert_eq!(current.state_root_sha256(), initial_root);
    let path = tree.0.join("cursor");
    // Seed through a private test checkpoint is impossible; use a temporary
    // copy of the real cursor store created from its canonical representation.
    let mut builder = DirBuilder::new();
    builder.mode(0o700).create(&path).unwrap();
    std::fs::write(path.join("cursor.json"), current.canonical_bytes().unwrap()).unwrap();
    std::fs::set_permissions(
        path.join("cursor.json"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    admit_checkpoint(&path, successor, Some(current)).unwrap()
}
