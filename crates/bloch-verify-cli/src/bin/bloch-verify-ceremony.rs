use bloch_verify::secure_io::{create_private_directory, read_secure, write_create};
use bloch_verify_core::{
    assemble_signed_bundle, import_observation_signature, parse_observation, parse_signed_response,
    parse_signing_request, parse_trust_policy, prepare_signing_request,
};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-verify-ceremony refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("prepare") => prepare(collect(args)?)?,
        Some("import") => import(collect(args)?)?,
        Some("assemble") => assemble(collect(args)?)?,
        _ => return Err(usage()),
    }
    Ok(())
}

fn prepare(arguments: Vec<(String, String)>) -> Result<(), String> {
    let observation_path = one(&arguments, "--observation")?;
    let policy_path = one(&arguments, "--trust-policy")?;
    let expected = one(&arguments, "--expected-trust-policy-sha256")?;
    let output = PathBuf::from(one(&arguments, "--out-dir")?);
    exact_options(
        &arguments,
        &[
            "--observation",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--out-dir",
        ],
    )?;
    let observation = parse_observation(&read_secure(Path::new(observation_path), "observation")?)
        .map_err(|error| error.to_string())?;
    let policy = parse_trust_policy(&read_secure(Path::new(policy_path), "trust policy")?)
        .map_err(|error| error.to_string())?;
    let (request, message) = prepare_signing_request(&policy, expected, &observation)
        .map_err(|error| error.to_string())?;
    create_private_directory(&output)?;
    write_create(&output.join("message.bin"), &message)?;
    write_json_create(&output.join("request.json"), &request)?;
    println!("{}", output.display());
    Ok(())
}

fn import(arguments: Vec<(String, String)>) -> Result<(), String> {
    exact_options(&arguments, &["--request", "--signature", "--response-out"])?;
    let request = parse_signing_request(&read_secure(
        Path::new(one(&arguments, "--request")?),
        "request",
    )?)
    .map_err(|error| error.to_string())?;
    let signature = read_secure(Path::new(one(&arguments, "--signature")?), "signature")?;
    let response =
        import_observation_signature(&request, &signature).map_err(|error| error.to_string())?;
    write_json_create(Path::new(one(&arguments, "--response-out")?), &response)?;
    Ok(())
}

fn assemble(arguments: Vec<(String, String)>) -> Result<(), String> {
    exact_options(
        &arguments,
        &[
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--response",
            "--bundle-out",
        ],
    )?;
    let policy = parse_trust_policy(&read_secure(
        Path::new(one(&arguments, "--trust-policy")?),
        "trust policy",
    )?)
    .map_err(|error| error.to_string())?;
    let mut responses = Vec::new();
    for path in many(&arguments, "--response")? {
        responses.push(
            parse_signed_response(&read_secure(Path::new(path), "response")?)
                .map_err(|error| error.to_string())?,
        );
    }
    let bundle = assemble_signed_bundle(
        &policy,
        one(&arguments, "--expected-trust-policy-sha256")?,
        &responses,
    )
    .map_err(|error| error.to_string())?;
    write_json_create(Path::new(one(&arguments, "--bundle-out")?), &bundle)?;
    Ok(())
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
        if *name == "--response" {
            if !arguments.iter().any(|(candidate, _)| candidate == name) {
                return Err("at least one --response is required".into());
            }
        } else if arguments
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
    let values: Vec<_> = arguments
        .iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .collect();
    if values.len() != 1 {
        return Err(format!("exactly one {name} is required"));
    }
    Ok(values[0])
}

fn many<'a>(arguments: &'a [(String, String)], name: &str) -> Result<Vec<&'a str>, String> {
    let values: Vec<_> = arguments
        .iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .collect();
    if values.is_empty() {
        return Err(format!("at least one {name} is required"));
    }
    Ok(values)
}

fn write_json_create(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot serialize output: {error}"))?;
    bytes.push(b'\n');
    write_create(path, &bytes)
}

fn usage() -> String {
    "usage:\n  bloch-verify-ceremony prepare --observation <json> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --out-dir <new-directory>\n  bloch-verify-ceremony import --request <json> --signature <raw-64-byte-file> --response-out <new-json>\n  bloch-verify-ceremony assemble --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --response <json> [--response <json> ...] --bundle-out <new-json>".into()
}
