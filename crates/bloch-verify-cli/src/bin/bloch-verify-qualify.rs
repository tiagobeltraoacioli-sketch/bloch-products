use bloch_verify::secure_io::{read_secure, write_create};
use bloch_verify_core::organization_independence::{
    OrganizationIndependencePolicy, organization_independence_policy_bytes,
    organization_independence_policy_sha256, parse_organization_independence_policy,
    verify_organization_independence_evidence,
};
use bloch_verify_core::qualification::{
    evaluate_current_production_gates, evaluate_production_gates_with_organization_independence,
};
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
        "digest-independence-policy" => {
            digest_independence_policy(&arguments)?;
            Ok(ExitCode::SUCCESS)
        }
        "verify-independence" => {
            verify_independence(&arguments)?;
            Ok(ExitCode::SUCCESS)
        }
        "assess-signed" => assess(&arguments),
        _ => Err(usage()),
    }
}

fn digest_independence_policy(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(arguments, &["--policy"])?;
    let bytes = read_secure(
        Path::new(one(arguments, "--policy")?),
        "organization-independence policy",
    )?;
    let policy: OrganizationIndependencePolicy = serde_json::from_slice(&bytes)
        .map_err(|_| "organization-independence policy is invalid")?;
    let canonical =
        organization_independence_policy_bytes(&policy).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err("organization-independence policy is non-canonical".into());
    }
    println!(
        "{}",
        organization_independence_policy_sha256(&policy).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn verify_independence(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--evidence",
            "--policy",
            "--expected-policy-sha256",
            "--expected-bundle-sha256",
            "--expected-network",
            "--expected-network-sha256",
            "--at",
        ],
    )?;
    let expected_network_sha256 = verified_network_digest(arguments)?;
    let policy = read_independence_policy(arguments, "--policy", "--expected-policy-sha256")?;
    let evidence = read_secure(
        Path::new(one(arguments, "--evidence")?),
        "organization-independence evidence",
    )?;
    let evaluated_at = evaluated_at(arguments)?;
    let verified = verify_organization_independence_evidence(
        &evidence,
        &policy,
        one(arguments, "--expected-policy-sha256")?,
        one(arguments, "--expected-bundle-sha256")?,
        &expected_network_sha256,
        evaluated_at,
    )
    .map_err(|error| error.to_string())?;
    println!("{}", verified.evidence_sha256());
    Ok(())
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
    options_with_optional_group(
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
        &[
            "--independence-evidence",
            "--independence-policy",
            "--expected-independence-policy-sha256",
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
    let expected_network = read_expected_network(arguments)?;
    let expected_network_sha256 = one(arguments, "--expected-network-sha256")?;
    verify_network_identity_sha256(&expected_network, expected_network_sha256)
        .map_err(|error| error.to_string())?;
    let evaluated_at = evaluated_at(arguments)?;
    let assessment = assess_signed(
        &bundle,
        &trust_policy,
        one(arguments, "--expected-trust-policy-sha256")?,
        evaluated_at,
    )
    .map_err(|error| error.to_string())?;
    let report = if has(arguments, "--independence-evidence") {
        let policy = read_independence_policy(
            arguments,
            "--independence-policy",
            "--expected-independence-policy-sha256",
        )?;
        let evidence = read_secure(
            Path::new(one(arguments, "--independence-evidence")?),
            "organization-independence evidence",
        )?;
        let verified = verify_organization_independence_evidence(
            &evidence,
            &policy,
            one(arguments, "--expected-independence-policy-sha256")?,
            &assessment.bundle_sha256,
            expected_network_sha256,
            evaluated_at,
        )
        .map_err(|error| error.to_string())?;
        evaluate_production_gates_with_organization_independence(
            &assessment,
            &bundle.network,
            &expected_network,
            one(arguments, "--expected-independence-policy-sha256")?,
            &verified,
        )
    } else {
        evaluate_current_production_gates(&assessment, &bundle.network, &expected_network)
    }
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

fn read_expected_network(
    arguments: &[(String, String)],
) -> Result<bloch_verify_core::NetworkIdentity, String> {
    parse_network_identity(&read_secure(
        Path::new(one(arguments, "--expected-network")?),
        "expected network identity",
    )?)
    .map_err(|error| error.to_string())
}

fn verified_network_digest(arguments: &[(String, String)]) -> Result<String, String> {
    let network = read_expected_network(arguments)?;
    let expected = one(arguments, "--expected-network-sha256")?;
    verify_network_identity_sha256(&network, expected).map_err(|error| error.to_string())?;
    Ok(expected.into())
}

fn read_independence_policy(
    arguments: &[(String, String)],
    path_option: &str,
    digest_option: &str,
) -> Result<OrganizationIndependencePolicy, String> {
    parse_organization_independence_policy(
        &read_secure(
            Path::new(one(arguments, path_option)?),
            "organization-independence policy",
        )?,
        one(arguments, digest_option)?,
    )
    .map_err(|error| error.to_string())
}

fn evaluated_at(arguments: &[(String, String)]) -> Result<u64, String> {
    let value = one(arguments, "--at")?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "--at must be canonical Unix seconds")?;
    if parsed.to_string() != value {
        return Err("--at must be canonical Unix seconds".into());
    }
    Ok(parsed)
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

fn options_with_optional_group(
    arguments: &[(String, String)],
    required: &[&str],
    optional_group: &[&str],
) -> Result<(), String> {
    for (name, _) in arguments {
        if !required.contains(&name.as_str()) && !optional_group.contains(&name.as_str()) {
            return Err(format!("unknown option: {name}"));
        }
    }
    for name in required {
        if arguments
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            != 1
        {
            return Err(format!("exactly one {name} is required"));
        }
    }
    let supplied = optional_group
        .iter()
        .filter(|name| has(arguments, name))
        .count();
    if supplied != 0 && supplied != optional_group.len() {
        return Err(format!(
            "{} must be supplied together",
            optional_group.join(", ")
        ));
    }
    for name in optional_group {
        if arguments
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            > 1
        {
            return Err(format!("at most one {name} may be supplied"));
        }
    }
    Ok(())
}

fn has(arguments: &[(String, String)], name: &str) -> bool {
    arguments.iter().any(|(candidate, _)| candidate == name)
}

fn one<'a>(arguments: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    arguments
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("exactly one {name} is required"))
}

fn usage() -> String {
    "usage:\n  bloch-verify-qualify digest-network --network <json>\n  bloch-verify-qualify digest-independence-policy --policy <canonical-json>\n  bloch-verify-qualify verify-independence --evidence <canonical-json> --policy <canonical-json> --expected-policy-sha256 <0x-sha256> --expected-bundle-sha256 <0x-sha256> --expected-network <json> --expected-network-sha256 <0x-sha256> --at <unix-seconds>\n  bloch-verify-qualify assess-signed --bundle <json> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --expected-network <json> --expected-network-sha256 <0x-sha256> --at <unix-seconds> --report-out <new-json> [--independence-evidence <canonical-json> --independence-policy <canonical-json> --expected-independence-policy-sha256 <0x-sha256>]".into()
}
