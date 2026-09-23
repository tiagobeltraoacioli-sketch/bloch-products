use bloch_verify_core::{JsonRpcRequest, parse_evm_rpc_capture};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPTURE: &[u8] = include_bytes!("../../../fixtures/valid-evm-rpc-capture.json");

#[test]
fn batch_request_and_unordered_response_form_a_valid_capture() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let request_path = root.join("request.json");
    let response_path = root.join("response.json");
    let output_path = root.join("capture.json");

    let request = command()
        .arg("request")
        .arg("--out")
        .arg(&request_path)
        .output()
        .unwrap();
    assert!(request.status.success());
    let requests: Vec<JsonRpcRequest> =
        serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[3].params, serde_json::json!(["finalized", false]));

    let capture = parse_evm_rpc_capture(CAPTURE).unwrap();
    let responses = vec![
        capture.finalized_block.response,
        capture.genesis_block.response,
        capture.chain_id.response,
        capture.client_version.response,
    ];
    fs::write(&response_path, serde_json::to_vec(&responses).unwrap()).unwrap();
    let imported = command()
        .arg("import")
        .arg("--response")
        .arg(&response_path)
        .arg("--observer-id")
        .arg("observer-a")
        .arg("--organization-id")
        .arg("organization-a")
        .arg("--endpoint-sha256")
        .arg(format!("0x{}", "1".repeat(64)))
        .arg("--observed-at")
        .arg("1790121600")
        .arg("--network")
        .arg("bloch-l2")
        .arg("--release-revision")
        .arg(format!("0x{}", "2".repeat(40)))
        .arg("--capture-out")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let imported_capture = parse_evm_rpc_capture(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(imported_capture.chain_id.response.result, "0xab163");

    let reused = command()
        .arg("request")
        .arg("--out")
        .arg(&request_path)
        .output()
        .unwrap();
    assert_eq!(reused.status.code(), Some(2));
    fs::remove_dir_all(root).unwrap();
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bloch-verify-evm-capture"))
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-evm-capture-{}-{nonce}",
        std::process::id()
    ))
}
