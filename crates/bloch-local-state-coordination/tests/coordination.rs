#![cfg(unix)]

use bloch_local_state_coordination::{
    CoordinatedError, CoordinationError, provision_local_state_coordination_directory,
    with_coordinated_startup_admission, with_coordinated_state_transition,
    with_local_state_coordination,
};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);
const LOCK_NAME: &str = ".local-state.coordination.lock";

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-coordination-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn provisioned(label: &str) -> Self {
        let value = Self::new(label);
        provision_local_state_coordination_directory(&value.0).unwrap();
        value
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.0) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let _ = fs::remove_file(&self.0);
            }
            _ => {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
}

#[test]
fn scoped_capability_reports_only_local_exclusion() {
    let path = Temp::provisioned("scope");
    let value = with_local_state_coordination(&path.0, |scope| {
        assert!(scope.local_exclusion_held());
        assert!(!scope.cross_host_atomicity_proven());
        assert!(!scope.remote_fencing_proven());
        assert!(!scope.high_availability_proven());
        Ok::<_, std::io::Error>(42)
    })
    .unwrap();
    assert_eq!(value, 42);
    assert_eq!(
        fs::metadata(&path.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path.0.join(LOCK_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn named_startup_and_transition_entry_points_share_the_lock() {
    let path = Temp::provisioned("named-entry-points");
    with_coordinated_startup_admission(&path.0, |scope| {
        assert!(scope.local_exclusion_held());
        Ok::<_, std::io::Error>(())
    })
    .unwrap();
    with_coordinated_state_transition(&path.0, |scope| {
        assert!(scope.local_exclusion_held());
        Ok::<_, std::io::Error>(())
    })
    .unwrap();
}

#[test]
fn lock_contention_is_bounded_and_fails_closed() {
    let path = Temp::provisioned("busy");
    let worker_path = path.0.clone();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        with_local_state_coordination(&worker_path, |_scope| {
            held_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok::<_, std::io::Error>(())
        })
        .unwrap();
    });
    held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let result = with_local_state_coordination(&path.0, |_scope| Ok::<_, std::io::Error>(()));
    assert!(matches!(
        result,
        Err(CoordinatedError::Coordination(CoordinationError::Busy))
    ));
    release_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn operation_error_is_preserved_and_lock_is_released() {
    let path = Temp::provisioned("operation-error");
    let result = with_local_state_coordination(&path.0, |_scope| {
        Err::<(), _>(std::io::Error::other("expected"))
    });
    assert!(matches!(result, Err(CoordinatedError::Operation(_))));
    with_local_state_coordination(&path.0, |_scope| Ok::<_, std::io::Error>(())).unwrap();
}

#[test]
fn rejects_unsafe_directory_and_directory_symlink() {
    let path = Temp::new("unsafe-directory");
    fs::create_dir(&path.0).unwrap();
    fs::set_permissions(&path.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        with_local_state_coordination(&path.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(
            CoordinationError::UnsafeObject("directoryPermissions")
        ))
    ));

    let target = Temp::new("directory-target");
    fs::create_dir(&target.0).unwrap();
    fs::set_permissions(&target.0, fs::Permissions::from_mode(0o700)).unwrap();
    let link = Temp::new("directory-link");
    symlink(&target.0, &link.0).unwrap();
    assert!(matches!(
        with_local_state_coordination(&link.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(
            CoordinationError::UnsafeObject("directoryType")
        ))
    ));
}

#[test]
fn rejects_symlinked_and_hardlinked_lock_files() {
    let symlink_store = Temp::new("symlink-lock");
    fs::create_dir(&symlink_store.0).unwrap();
    fs::set_permissions(&symlink_store.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(symlink_store.0.join("target"), b"").unwrap();
    symlink("target", symlink_store.0.join(LOCK_NAME)).unwrap();
    assert!(matches!(
        with_local_state_coordination(&symlink_store.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(
            CoordinationError::UnsafeObject("lockType")
        ))
    ));

    let hardlink_store = Temp::provisioned("hardlink-lock");
    with_local_state_coordination(&hardlink_store.0, |_scope| Ok::<_, std::io::Error>(())).unwrap();
    fs::hard_link(
        hardlink_store.0.join(LOCK_NAME),
        hardlink_store.0.join("lock-copy"),
    )
    .unwrap();
    assert!(matches!(
        with_local_state_coordination(&hardlink_store.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(
            CoordinationError::UnsafeObject("lockPermissions")
        ))
    ));
}

#[test]
fn detects_lock_path_replacement_during_operation() {
    let path = Temp::provisioned("replaced-lock");
    let result = with_local_state_coordination(&path.0, |_scope| {
        fs::rename(path.0.join(LOCK_NAME), path.0.join("moved-lock")).unwrap();
        let replacement = path.0.join(LOCK_NAME);
        fs::write(&replacement, b"").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        Ok::<_, std::io::Error>(())
    });
    assert!(matches!(
        result,
        Err(CoordinatedError::Coordination(
            CoordinationError::UnsafeObject("lockChanged")
        ))
    ));
}

#[test]
fn operational_acquire_never_creates_a_missing_directory() {
    let path = Temp::new("missing");
    assert!(matches!(
        with_local_state_coordination(&path.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(CoordinationError::Io(_)))
    ));
    assert!(!path.0.exists());
}

#[test]
fn operational_acquire_never_recreates_a_missing_lock() {
    let path = Temp::provisioned("missing-lock");
    fs::remove_file(path.0.join(LOCK_NAME)).unwrap();
    assert!(matches!(
        with_local_state_coordination(&path.0, |_scope| Ok::<_, std::io::Error>(())),
        Err(CoordinatedError::Coordination(CoordinationError::Io(_)))
    ));
    assert!(!path.0.join(LOCK_NAME).exists());
}
