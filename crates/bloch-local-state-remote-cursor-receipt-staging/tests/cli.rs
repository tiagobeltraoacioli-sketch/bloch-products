#![cfg(unix)]

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bloch-receipt-staging"))
}

#[test]
fn help_identifies_ceremony_import_as_non_production() {
    let output = cli().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("export-signing-request"));
    assert!(stdout.contains("ceremony-import-receipt"));
    assert!(stdout.contains("acknowledge-operator-time-is-not-production"));
    assert!(output.stderr.is_empty());
}

#[test]
fn ceremony_import_fails_before_file_access_without_explicit_acknowledgement() {
    let output = cli()
        .args([
            "ceremony-import-receipt",
            "--store",
            "/does/not/exist",
            "--policy",
            "/does/not/exist",
            "--policy-sha256",
            &format!("0x{}", "11".repeat(32)),
            "--receipt",
            "/does/not/exist",
            "--evaluated-at-unix-seconds",
            "123",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("operator-time-is-not-production")
    );
}

#[test]
fn duplicate_and_unknown_options_fail_closed() {
    for arguments in [
        vec!["inspect", "--store", "/x", "--store", "/y"],
        vec!["inspect", "--store", "/x", "--unexpected", "value"],
    ] {
        let output = cli().args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
