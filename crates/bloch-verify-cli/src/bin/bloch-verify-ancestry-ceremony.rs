use bloch_verify::secure_io::{read_secure, write_create};
use bloch_verify_core::checkpoint_ancestry::{
    AncestrySignature, CheckpointAncestryAudience, CheckpointAncestryPolicy,
    checkpoint_ancestry_policy_bytes, checkpoint_ancestry_policy_sha256,
    checkpoint_ancestry_signature_message, create_checkpoint_ancestry_evidence,
    parse_checkpoint_ancestry_policy,
};
use bloch_verify_core::{
    EvmAncestryEvidence, network_identity_sha256, parse_evm_ancestry_evidence,
    parse_network_identity, verify_network_identity_sha256,
};
use sha2::{Digest, Sha256};
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-verify-ancestry-ceremony refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let arguments = collect(args)?;
    match command.as_str() {
        "digest-policy" => digest_policy(&arguments),
        "prepare-message" => prepare_message(&arguments),
        "assemble-evidence" => assemble_evidence(&arguments),
        _ => Err(usage()),
    }
}

fn digest_policy(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(arguments, &["--policy"])?;
    let bytes = read_secure(Path::new(one(arguments, "--policy")?), "ancestry policy")?;
    let policy: CheckpointAncestryPolicy =
        serde_json::from_slice(&bytes).map_err(|_| "ancestry policy is invalid")?;
    let canonical = checkpoint_ancestry_policy_bytes(&policy).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err("ancestry policy is non-canonical".into());
    }
    println!(
        "{}",
        checkpoint_ancestry_policy_sha256(&policy).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn prepare_message(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(arguments, &ceremony_options("--message-out"))?;
    let inputs = read_ceremony_inputs(arguments)?;
    let message = checkpoint_ancestry_signature_message(
        &inputs.policy,
        inputs.policy_sha256,
        &inputs.ancestry,
        &inputs.audience(),
        inputs.attested_at,
        inputs.valid_until,
    )
    .map_err(|error| error.to_string())?;
    write_create(Path::new(one(arguments, "--message-out")?), &message)?;
    println!("{}", sha256(&message));
    Ok(())
}

fn assemble_evidence(arguments: &[(String, String)]) -> Result<(), String> {
    let mut expected = ceremony_options("--evidence-out");
    expected.push("--signatures");
    exact_options(arguments, &expected)?;
    let inputs = read_ceremony_inputs(arguments)?;
    let signature_bytes = read_secure(
        Path::new(one(arguments, "--signatures")?),
        "ancestry signatures",
    )?;
    let signatures: Vec<AncestrySignature> =
        serde_json::from_slice(&signature_bytes).map_err(|_| "ancestry signatures are invalid")?;
    let canonical =
        serde_json::to_vec(&signatures).map_err(|_| "ancestry signatures cannot be serialized")?;
    if canonical != signature_bytes {
        return Err("ancestry signatures are non-canonical".into());
    }
    let evidence = create_checkpoint_ancestry_evidence(
        &inputs.policy,
        inputs.policy_sha256,
        &inputs.ancestry,
        &inputs.audience(),
        inputs.attested_at,
        inputs.valid_until,
        signatures,
    )
    .map_err(|error| error.to_string())?;
    write_create(Path::new(one(arguments, "--evidence-out")?), &evidence)?;
    println!("{}", sha256(&evidence));
    Ok(())
}

struct CeremonyInputs<'a> {
    policy: CheckpointAncestryPolicy,
    policy_sha256: &'a str,
    ancestry: EvmAncestryEvidence,
    bundle_sha256: &'a str,
    network_sha256: String,
    attested_at: u64,
    valid_until: u64,
}

impl CeremonyInputs<'_> {
    fn audience(&self) -> CheckpointAncestryAudience<'_> {
        CheckpointAncestryAudience {
            assessed_bundle_sha256: self.bundle_sha256,
            expected_network_sha256: &self.network_sha256,
            expected_checkpoint: &self.ancestry.checkpoint,
        }
    }
}

fn read_ceremony_inputs<'a>(
    arguments: &'a [(String, String)],
) -> Result<CeremonyInputs<'a>, String> {
    let policy_sha256 = one(arguments, "--expected-policy-sha256")?;
    let policy = parse_checkpoint_ancestry_policy(
        &read_secure(Path::new(one(arguments, "--policy")?), "ancestry policy")?,
        policy_sha256,
    )
    .map_err(|error| error.to_string())?;
    let ancestry = parse_evm_ancestry_evidence(&read_secure(
        Path::new(one(arguments, "--ancestry")?),
        "EVM ancestry evidence",
    )?)
    .map_err(|error| error.to_string())?;
    let network = parse_network_identity(&read_secure(
        Path::new(one(arguments, "--expected-network")?),
        "expected network identity",
    )?)
    .map_err(|error| error.to_string())?;
    let network_sha256 = one(arguments, "--expected-network-sha256")?;
    verify_network_identity_sha256(&network, network_sha256).map_err(|error| error.to_string())?;
    if network_identity_sha256(&ancestry.network).map_err(|error| error.to_string())?
        != network_sha256
    {
        return Err("ancestry evidence does not match the expected network pin".into());
    }
    Ok(CeremonyInputs {
        policy,
        policy_sha256,
        ancestry,
        bundle_sha256: one(arguments, "--expected-bundle-sha256")?,
        network_sha256: network_sha256.into(),
        attested_at: canonical_u64(arguments, "--attested-at")?,
        valid_until: canonical_u64(arguments, "--valid-until")?,
    })
}

fn ceremony_options(output: &'static str) -> Vec<&'static str> {
    vec![
        "--policy",
        "--expected-policy-sha256",
        "--ancestry",
        "--expected-bundle-sha256",
        "--expected-network",
        "--expected-network-sha256",
        "--attested-at",
        "--valid-until",
        output,
    ]
}

fn canonical_u64(arguments: &[(String, String)], option: &str) -> Result<u64, String> {
    let value = one(arguments, option)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{option} must be canonical Unix seconds"))?;
    if parsed.to_string() != value {
        return Err(format!("{option} must be canonical Unix seconds"));
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

fn one<'a>(arguments: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    arguments
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("exactly one {name} is required"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn usage() -> String {
    "usage:\n  bloch-verify-ancestry-ceremony digest-policy --policy <canonical-json>\n  bloch-verify-ancestry-ceremony prepare-message --policy <canonical-json> --expected-policy-sha256 <0x-sha256> --ancestry <json> --expected-bundle-sha256 <0x-sha256> --expected-network <json> --expected-network-sha256 <0x-sha256> --attested-at <unix-seconds> --valid-until <unix-seconds> --message-out <new-binary>\n  bloch-verify-ancestry-ceremony assemble-evidence --policy <canonical-json> --expected-policy-sha256 <0x-sha256> --ancestry <json> --expected-bundle-sha256 <0x-sha256> --expected-network <json> --expected-network-sha256 <0x-sha256> --attested-at <unix-seconds> --valid-until <unix-seconds> --signatures <canonical-json-array> --evidence-out <new-json>".into()
}
