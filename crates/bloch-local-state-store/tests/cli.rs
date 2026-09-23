#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn init_verify_load_and_update_keep_state_off_stdout() {
    let root = private_directory("roundtrip");
    let store = root.join("store");
    let state0 = private_file(&root, "state-0.bin", b"canonical-state-zero");
    let root0 = root.join("root-0.json");

    let initialized = run(&[
        "init",
        "--store",
        path(&store),
        "--identity",
        "data:tenant-a:lifecycle",
        "--state-file",
        path(&state0),
        "--root-out",
        path(&root0),
    ]);
    assert_success_and_silent(&initialized);
    assert_private(&root0);
    assert_eq!(
        fs::metadata(&store).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let verified = run(&["verify", "--store", path(&store), "--root", path(&root0)]);
    assert_success_and_silent(&verified);

    let loaded = root.join("loaded.bin");
    let load = run(&[
        "load",
        "--store",
        path(&store),
        "--root",
        path(&root0),
        "--state-out",
        path(&loaded),
    ]);
    assert_success_and_silent(&load);
    assert_eq!(fs::read(&loaded).unwrap(), b"canonical-state-zero");
    assert_private(&loaded);

    let state1 = private_file(&root, "state-1.bin", b"canonical-state-one");
    let root1 = root.join("root-1.json");
    let updated = run(&[
        "update",
        "--store",
        path(&store),
        "--identity",
        "data:tenant-a:lifecycle",
        "--generation",
        "1",
        "--state-file",
        path(&state1),
        "--previous-root",
        path(&root0),
        "--root-out",
        path(&root1),
    ]);
    assert_success_and_silent(&updated);
    assert_private(&root1);

    let stale = run(&["verify", "--store", path(&store), "--root", path(&root0)]);
    assert_eq!(stale.status.code(), Some(2));
    assert!(stale.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("independent root"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsafe_inputs_and_create_only_output_conflicts_before_init() {
    let root = private_directory("unsafe");
    let store = root.join("store");
    let state = root.join("state.bin");
    fs::write(&state, b"state").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    let root_out = root.join("root.json");
    let unsafe_input = run(&[
        "init",
        "--store",
        path(&store),
        "--identity",
        "data:one",
        "--state-file",
        path(&state),
        "--root-out",
        path(&root_out),
    ]);
    assert_eq!(unsafe_input.status.code(), Some(2));
    assert!(!store.exists());

    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&root_out, b"do-not-overwrite").unwrap();
    fs::set_permissions(&root_out, fs::Permissions::from_mode(0o600)).unwrap();
    let conflict = run(&[
        "init",
        "--store",
        path(&store),
        "--identity",
        "data:one",
        "--state-file",
        path(&state),
        "--root-out",
        path(&root_out),
    ]);
    assert_eq!(conflict.status.code(), Some(2));
    assert!(!store.exists());
    assert_eq!(fs::read(&root_out).unwrap(), b"do-not-overwrite");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verify_rejects_symlinked_independent_root() {
    let root = private_directory("symlink");
    let store = root.join("store");
    let state = private_file(&root, "state.bin", b"state");
    let root_file = root.join("root.json");
    let initialized = run(&[
        "init",
        "--store",
        path(&store),
        "--identity",
        "pay:merchant-a:adjustments",
        "--state-file",
        path(&state),
        "--root-out",
        path(&root_file),
    ]);
    assert_success_and_silent(&initialized);
    let alias = root.join("root-alias.json");
    symlink(&root_file, &alias).unwrap();
    let rejected = run(&["verify", "--store", path(&store), "--root", path(&alias)]);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    fs::remove_dir_all(root).unwrap();
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloch-local-state-store"))
        .args(arguments)
        .output()
        .unwrap()
}

fn assert_success_and_silent(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn private_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bloch-state-cli-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn private_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn assert_private(path: &Path) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
