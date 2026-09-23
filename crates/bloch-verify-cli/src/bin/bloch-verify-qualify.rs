use bloch_verify::secure_io::{read_secure, write_create};
use bloch_verify_core::qualification::evaluate_current_production_gates;
use bloch_verify_core::{
    assess_signed, network_identity_sha256, parse_network_identity, parse_signed_bundle,
    parse_trust_policy, verify_network_identity_sha256,
};
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("bloch-verify-qualify refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let arguments = collect(args)?;
    match command.as_str() {
        "digest-network" => {
            digest_network(&arguments)?;
            Ok(ExitCode::SUCCESS)
        }
        "assess-signed" => assess(&arguments),
        _ => Err(usage()),
    }
}

fn digest_network(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(arguments, &["--network"])?;
    let network = parse_network_identity(&read_secure(
        Path::new(one(arguments, "--network")?),
        "network identity",
    )?)
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        network_identity_sha256(&network).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn assess(arguments: &[(String, String)]) -> Result<ExitCode, String> {
    exact_options(
        arguments,
        &[
            "--bundle",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--expected-network",
            "--expected-network-sha256",
            "--at",
            "--report-out",
        ],
    )?;
    let bundle = parse_signed_bundle(&read_secure(
        Path::new(one(arguments, "--bundle")?),
        "signed bundle",
    )?)
    .map_err(|error| error.to_string())?;
    let trust_policy = parse_trust_policy(&read_secure(
        Path::new(one(arguments, "--trust-policy")?),
        "trust policy",
    )?)
    .map_err(|error| error.to_string())?;
    let expected_network = parse_network_identity(&read_secure(
        Path::new(one(arguments, "--expected-network")?),
        "expected network identity",
    )?)
    .map_err(|error| error.to_string())?;
    verify_network_identity_sha256(
        &expected_network,
        one(arguments, "--expected-network-sha256")?,
    )
    .map_err(|error| error.to_string())?;
    let evaluated_at = one(arguments, "--at")?
        .parse::<u64>()
        .map_err(|_| "--at must be canonical Unix seconds")?;
    let assessment = assess_signed(
        &bundle,
        &trust_policy,
        one(arguments, "--expected-trust-policy-sha256")?,
        evaluated_at,
    )
    .map_err(|error| error.to_string())?;
    let report = evaluate_current_production_gates(&assessment, &bundle.network, &expected_network)
        .map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec(&report)
        .map_err(|error| format!("cannot serialize qualification report: {error}"))?;
    bytes.push(b'\n');
    write_create(Path::new(one(arguments, "--report-out")?), &bytes)?;
    if report.production_qualified {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
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
    "usage:\n  bloch-verify-qualify digest-network --network <json>\n  bloch-verify-qualify assess-signed --bundle <json> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --expected-network <json> --expected-network-sha256 <0x-sha256> --at <unix-seconds> --report-out <new-json>".into()
}
