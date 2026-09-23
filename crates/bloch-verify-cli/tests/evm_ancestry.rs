use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const EVIDENCE: &[u8] = include_bytes!("../../../fixtures/valid-evm-ancestry.json");

#[test]
fn ancestry_cli_verifies_linkage_but_keeps_finality_closed() {
    let root = unique_directory();
    fs::create_dir(&root).unwrap();
    let evidence_path = root.join("evidence.json");
    let report_path = root.join("report.json");
    fs::write(&evidence_path, EVIDENCE).unwrap();

    let first = command(&evidence_path, &report_path).output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["parentHashLinkageVerified"], true);
    assert_eq!(report["consensusFinalityAuthenticated"], false);
    assert_eq!(report["productionQualified"], false);

    let reused = command(&evidence_path, &report_path).output().unwrap();
    assert_eq!(reused.status.code(), Some(2));
    fs::remove_dir_all(root).unwrap();
}

fn command(evidence: &std::path::Path, report: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-verify-evm-ancestry"));
    command
        .arg("verify")
        .arg("--evidence")
        .arg(evidence)
        .arg("--report-out")
        .arg(report);
    command
}

fn unique_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bloch-verify-evm-ancestry-{}-{nonce}",
        std::process::id()
    ))
}
