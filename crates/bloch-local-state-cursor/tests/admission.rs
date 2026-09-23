#![cfg(unix)]

use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    VerifiedRootCheckpoint, checkpoint_policy_sha256, checkpoint_signature_message,
    create_root_checkpoint, verify_root_checkpoint,
};
use bloch_local_state_cursor::{
    CursorError, admit_checkpoint, load_cursor, parse_cursor, verify_admitted_checkpoint,
};
use bloch_local_state_store::{StateRoot, write_state};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-cursor-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy() -> (CheckpointPolicy, Vec<SigningKey>, String) {
    let keys = vec![
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[12; 32]),
    ];
    let authorities = keys
        .iter()
        .enumerate()
        .map(|(index, key)| CheckpointAuthority {
            authority_id: format!("authority-{}", index + 1),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
        })
        .collect();
    let policy = CheckpointPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "cursor-policy".into(),
        checkpoint_domain: "bloch-products-prod".into(),
        state_identity: "data:tenant-a:lifecycle".into(),
        threshold: 2,
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        max_checkpoint_age_seconds: 1_000,
        authorities,
    };
    let pin = checkpoint_policy_sha256(&policy).unwrap();
    (policy, keys, pin)
}

fn verified(root: &StateRoot, created: u64) -> VerifiedRootCheckpoint {
    verified_with_semantic(root, created, b"reviewed-product-semantics-v1")
}

fn verified_with_semantic(
    root: &StateRoot,
    created: u64,
    semantic_manifest: &[u8],
) -> VerifiedRootCheckpoint {
    let (policy, keys, pin) = policy();
    let semantic_digest = format!("0x{}", hex::encode(Sha256::digest(semantic_manifest)));
    let message =
        checkpoint_signature_message(root, &policy, &pin, &semantic_digest, created).unwrap();
    let signatures = keys
        .iter()
        .enumerate()
        .map(|(index, key)| DetachedCheckpointSignature {
            authority_id: format!("authority-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let artifact =
        create_root_checkpoint(root, &policy, &pin, &semantic_digest, created, &signatures)
            .unwrap();
    verify_root_checkpoint(
        &artifact,
        &policy,
        &pin,
        root.generation(),
        root.state_sha256(),
        &semantic_digest,
        created + 1,
    )
    .unwrap()
}

fn roots(state_dir: &Path) -> (StateRoot, StateRoot, StateRoot) {
    let zero = write_state(state_dir, "data:tenant-a:lifecycle", 0, b"zero", None).unwrap();
    let one = write_state(state_dir, "data:tenant-a:lifecycle", 1, b"one", Some(&zero)).unwrap();
    let two = write_state(state_dir, "data:tenant-a:lifecycle", 2, b"two", Some(&one)).unwrap();
    (zero, one, two)
}

#[test]
fn creates_once_advances_and_replays_exact_current() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, one, _) = roots(&state.0);
    let zero_checkpoint = verified(&zero, 200);
    let current = admit_checkpoint(&cursor.0, &zero_checkpoint, None).unwrap();
    assert_eq!(current.generation(), 0);
    assert!(matches!(
        admit_checkpoint(&cursor.0, &zero_checkpoint, None),
        Err(CursorError::ExpectationMismatch)
    ));
    assert_eq!(
        admit_checkpoint(&cursor.0, &zero_checkpoint, Some(&current)).unwrap(),
        current
    );

    let next = admit_checkpoint(&cursor.0, &verified(&one, 201), Some(&current)).unwrap();
    assert_eq!(next.generation(), 1);
    assert_eq!(load_cursor(&cursor.0, &next).unwrap(), next);
    assert_eq!(
        parse_cursor(&next.canonical_bytes().unwrap()).unwrap(),
        next
    );
}

#[test]
fn rejects_rollback_gap_and_stale_compare_and_swap() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, one, two) = roots(&state.0);
    let current = admit_checkpoint(&cursor.0, &verified(&zero, 200), None).unwrap();

    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&two, 202), Some(&current)),
        Err(CursorError::GenerationGap)
    ));
    let next = admit_checkpoint(&cursor.0, &verified(&one, 201), Some(&current)).unwrap();
    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&zero, 200), Some(&next)),
        Err(CursorError::Rollback)
    ));
    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&two, 202), Some(&current)),
        Err(CursorError::ExpectationMismatch)
    ));
}

#[test]
fn rejects_same_generation_fork_and_wrong_predecessor() {
    let state_a = Temp::new("state-a");
    let state_b = Temp::new("state-b");
    let cursor = Temp::new("store");
    let (zero_a, one_a, _) = roots(&state_a.0);
    let zero_b = write_state(
        &state_b.0,
        "data:tenant-a:lifecycle",
        0,
        b"other-zero",
        None,
    )
    .unwrap();
    let one_b = write_state(
        &state_b.0,
        "data:tenant-a:lifecycle",
        1,
        b"other-one",
        Some(&zero_b),
    )
    .unwrap();
    let current = admit_checkpoint(&cursor.0, &verified(&zero_a, 200), None).unwrap();

    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&zero_b, 200), Some(&current)),
        Err(CursorError::Fork)
    ));
    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&one_b, 201), Some(&current)),
        Err(CursorError::Fork)
    ));
    admit_checkpoint(&cursor.0, &verified(&one_a, 201), Some(&current)).unwrap();
}

#[test]
fn rejects_noncanonical_corruption_and_unsafe_objects() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, _, _) = roots(&state.0);
    let current = admit_checkpoint(&cursor.0, &verified(&zero, 200), None).unwrap();
    let path = cursor.0.join("cursor.json");
    let mut corrupted = current.canonical_bytes().unwrap();
    corrupted.push(b'\n');
    fs::write(&path, corrupted).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        load_cursor(&cursor.0, &current),
        Err(CursorError::InvalidCursor)
    ));

    fs::remove_file(&path).unwrap();
    symlink("missing", &path).unwrap();
    assert!(load_cursor(&cursor.0, &current).is_err());
}

#[test]
fn rejects_world_accessible_directory() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    fs::create_dir(&cursor.0).unwrap();
    fs::set_permissions(&cursor.0, fs::Permissions::from_mode(0o755)).unwrap();
    let (zero, _, _) = roots(&state.0);
    assert!(matches!(
        admit_checkpoint(&cursor.0, &verified(&zero, 200), None),
        Err(CursorError::UnsafeStore("directoryPermissions"))
    ));
}

#[test]
fn rejects_hardlinked_cursor() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, _, _) = roots(&state.0);
    let current = admit_checkpoint(&cursor.0, &verified(&zero, 200), None).unwrap();
    fs::hard_link(
        cursor.0.join("cursor.json"),
        cursor.0.join("cursor-copy.json"),
    )
    .unwrap();
    assert!(matches!(
        load_cursor(&cursor.0, &current),
        Err(CursorError::UnsafeStore("filePermissions"))
    ));
}

#[test]
fn startup_verification_is_read_only_and_rejects_a_valid_next_checkpoint() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, one, _) = roots(&state.0);
    let zero_checkpoint = verified(&zero, 200);
    let current = admit_checkpoint(&cursor.0, &zero_checkpoint, None).unwrap();

    assert_eq!(
        verify_admitted_checkpoint(&cursor.0, &zero_checkpoint, &current).unwrap(),
        current
    );
    assert!(matches!(
        verify_admitted_checkpoint(&cursor.0, &verified(&one, 201), &current),
        Err(CursorError::CheckpointMismatch)
    ));
    assert_eq!(load_cursor(&cursor.0, &current).unwrap(), current);
}

#[test]
fn semantic_manifest_digest_is_pinned_by_admission() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, _, _) = roots(&state.0);
    let first_checkpoint = verified_with_semantic(&zero, 200, b"semantic-a");
    let current = admit_checkpoint(&cursor.0, &first_checkpoint, None).unwrap();
    let expected = format!("0x{}", hex::encode(Sha256::digest(b"semantic-a")));
    assert_eq!(current.semantic_manifest_sha256(), expected);

    let changed = verified_with_semantic(&zero, 200, b"semantic-b");
    assert!(matches!(
        verify_admitted_checkpoint(&cursor.0, &changed, &current),
        Err(CursorError::CheckpointMismatch)
    ));
    assert!(matches!(
        admit_checkpoint(&cursor.0, &changed, Some(&current)),
        Err(CursorError::Fork)
    ));
    assert_eq!(load_cursor(&cursor.0, &current).unwrap(), current);
}

#[test]
fn writer_cleans_only_safely_identifiable_stale_temps() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, _, _) = roots(&state.0);
    let checkpoint = verified(&zero, 200);
    let current = admit_checkpoint(&cursor.0, &checkpoint, None).unwrap();
    let stale = cursor
        .0
        .join(".cursor.json.tmp-0123456789abcdef0123456789abcdef");
    let malformed = cursor.0.join(".cursor.json.tmp-not-a-valid-nonce");
    let unrelated = cursor.0.join("operator-note");
    for path in [&stale, &malformed, &unrelated] {
        fs::write(path, b"debris").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert_eq!(
        admit_checkpoint(&cursor.0, &checkpoint, Some(&current)).unwrap(),
        current
    );
    assert!(!stale.exists());
    assert!(malformed.exists());
    assert!(unrelated.exists());
}

#[test]
fn matching_temporary_symlink_fails_closed_without_deletion() {
    let state = Temp::new("state");
    let cursor = Temp::new("store");
    let (zero, _, _) = roots(&state.0);
    let checkpoint = verified(&zero, 200);
    let current = admit_checkpoint(&cursor.0, &checkpoint, None).unwrap();
    let link = cursor
        .0
        .join(".cursor.json.tmp-abcdefabcdefabcdefabcdefabcdefab");
    symlink("cursor.json", &link).unwrap();

    assert!(matches!(
        admit_checkpoint(&cursor.0, &checkpoint, Some(&current)),
        Err(CursorError::UnsafeStore("temporaryFile"))
    ));
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(load_cursor(&cursor.0, &current).unwrap(), current);
}
