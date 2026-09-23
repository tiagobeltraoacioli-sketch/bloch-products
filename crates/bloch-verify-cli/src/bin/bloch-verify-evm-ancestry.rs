use bloch_verify::secure_io::{read_secure, write_create};
use bloch_verify_core::{parse_evm_ancestry_evidence, verify_evm_ancestry_evidence};
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-verify-evm-ancestry refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("verify") {
        return Err(usage());
    }
    let arguments = collect(args)?;
    exact_options(&arguments, &["--evidence", "--report-out"])?;
    let evidence = parse_evm_ancestry_evidence(&read_secure(
        Path::new(one(&arguments, "--evidence")?),
        "ancestry evidence",
    )?)
    .map_err(|error| error.to_string())?;
    let report = verify_evm_ancestry_evidence(&evidence).map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec(&report)
        .map_err(|error| format!("cannot serialize ancestry report: {error}"))?;
    bytes.push(b'\n');
    write_create(Path::new(one(&arguments, "--report-out")?), &bytes)
}

fn collect(mut args: impl Iterator<Item = String>) -> Result<Vec<(String, String)>, String> {
    let mut result = Vec::new();
    while let Some(name) = args.next() {
        if !name.starts_with("--") {
            return Err(format!("unexpected argument: {name}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{name} requires a value"))?;
        result.push((name, value));
    }
    Ok(result)
}

fn exact_options(arguments: &[(String, String)], expected: &[&str]) -> Result<(), String> {
    for (name, _) in arguments {
        if !expected.contains(&name.as_str()) {
            return Err(format!("unknown option: {name}"));
        }
    }
    for name in expected {
        if arguments
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            != 1
        {
            return Err(format!("exactly one {name} is required"));
        }
    }
    Ok(())
}

fn one<'a>(arguments: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    arguments
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("exactly one {name} is required"))
}

fn usage() -> String {
    "usage: bloch-verify-evm-ancestry verify --evidence <json> --report-out <new-json>".into()
}
