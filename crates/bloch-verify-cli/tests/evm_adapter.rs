use bloch_verify_core::NodeObservation;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPTURE: &[u8] = include_bytes!("../../../fixtures/valid-evm-rpc-capture.json");

#[test]
fn adapter_converts_strict_capture_and_refuses_output_reuse() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let capture_path = root.join("capture.json");
    let observation_path = root.join("observation.json");
    fs::write(&capture_path, CAPTURE).unwrap();

    let first = command(&capture_path, &observation_path).output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let observation: NodeObservation =
        serde_json::from_slice(&fs::read(&observation_path).unwrap()).unwrap();
    assert_eq!(observation.chain_id, 700_771);
    assert_eq!(observation.checkpoint_height, 42);

    let second = command(&capture_path, &observation_path).output().unwrap();
    assert_eq!(second.status.code(), Some(2));
    fs::remove_dir_all(root).unwrap();
}

fn command(capture: &std::path::Path, output: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-verify-evm-adapter"));
    command
        .arg("convert")
        .arg("--capture")
        .arg(capture)
        .arg("--observation-out")
        .arg(output);
    command
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-evm-adapter-{}-{nonce}",
        std::process::id()
    ))
}
