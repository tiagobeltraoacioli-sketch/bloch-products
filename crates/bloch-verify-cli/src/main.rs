use bloch_verify_core::{
    assess, assess_signed, parse_bundle, parse_signed_bundle, parse_trust_policy,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 1_048_576;

enum Mode {
    Unsigned,
    Signed {
        trust_policy: PathBuf,
        expected_trust_policy_sha256: String,
    },
}

struct Arguments {
    mode: Mode,
    bundle: PathBuf,
    evaluated_at: u64,
    require_comparison: bool,
    require_authenticated_comparison: bool,
    require_production_qualified: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("bloch-verify refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let arguments = arguments()?;
    let bundle_bytes = read_safe(&arguments.bundle, "bundle")?;
    let report = match &arguments.mode {
        Mode::Unsigned => {
            let bundle = parse_bundle(&bundle_bytes).map_err(|error| error.to_string())?;
            assess(&bundle, arguments.evaluated_at).map_err(|error| error.to_string())?
        }
        Mode::Signed {
            trust_policy,
            expected_trust_policy_sha256,
        } => {
            let policy_bytes = read_safe(trust_policy, "trust policy")?;
            let bundle = parse_signed_bundle(&bundle_bytes).map_err(|error| error.to_string())?;
            let policy = parse_trust_policy(&policy_bytes).map_err(|error| error.to_string())?;
            assess_signed(
                &bundle,
                &policy,
                expected_trust_policy_sha256,
                arguments.evaluated_at,
            )
            .map_err(|error| error.to_string())?
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    if (arguments.require_comparison && !report.comparison_passed)
        || (arguments.require_authenticated_comparison && !report.authenticated_comparison_passed)
        || (arguments.require_production_qualified && !report.production_qualified)
    {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn read_safe(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("{label} is empty or exceeds 1 MiB"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "{label} must be single-link and not group/world writable"
            ));
        }
    }
    fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))
}

fn arguments() -> Result<Arguments, String> {
    let mut values = env::args().skip(1);
    let command = values.next().ok_or_else(usage)?;
    let signed = match command.as_str() {
        "assess" => false,
        "assess-signed" => true,
        _ => return Err(usage()),
    };
    let mut bundle = None;
    let mut trust_policy = None;
    let mut expected_trust_policy_sha256 = None;
    let mut evaluated_at = None;
    let mut require_comparison = false;
    let mut require_authenticated_comparison = false;
    let mut require_production_qualified = false;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--bundle" => set_path(&mut bundle, values.next(), "--bundle")?,
            "--trust-policy" => set_path(&mut trust_policy, values.next(), "--trust-policy")?,
            "--expected-trust-policy-sha256" => set_string(
                &mut expected_trust_policy_sha256,
                values.next(),
                "--expected-trust-policy-sha256",
            )?,
            "--at" => {
                if evaluated_at.is_some() {
                    return Err("--at supplied more than once".into());
                }
                evaluated_at = Some(
                    values
                        .next()
                        .ok_or("--at requires Unix seconds")?
                        .parse::<u64>()
                        .map_err(|_| "--at must be canonical Unix seconds")?,
                );
            }
            "--require-comparison" => require_comparison = true,
            "--require-authenticated-comparison" => require_authenticated_comparison = true,
            "--require-production-qualified" => require_production_qualified = true,
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !signed && (trust_policy.is_some() || expected_trust_policy_sha256.is_some()) {
        return Err("trust-policy arguments require assess-signed".into());
    }
    if !signed && require_authenticated_comparison {
        return Err("--require-authenticated-comparison requires assess-signed".into());
    }
    let mode = if signed {
        Mode::Signed {
            trust_policy: trust_policy.ok_or("--trust-policy is required")?,
            expected_trust_policy_sha256: expected_trust_policy_sha256
                .ok_or("--expected-trust-policy-sha256 is required")?,
        }
    } else {
        Mode::Unsigned
    };
    Ok(Arguments {
        mode,
        bundle: bundle.ok_or("--bundle is required")?,
        evaluated_at: evaluated_at.ok_or("--at is required")?,
        require_comparison,
        require_authenticated_comparison,
        require_production_qualified,
    })
}

fn set_path(slot: &mut Option<PathBuf>, value: Option<String>, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} supplied more than once"));
    }
    *slot = Some(PathBuf::from(
        value.ok_or_else(|| format!("{name} requires a path"))?,
    ));
    Ok(())
}

fn set_string(slot: &mut Option<String>, value: Option<String>, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} supplied more than once"));
    }
    *slot = Some(value.ok_or_else(|| format!("{name} requires a value"))?);
    Ok(())
}

fn usage() -> String {
    "usage:\n  bloch-verify assess --bundle <evidence.json> --at <unix-seconds> [--require-comparison] [--require-production-qualified]\n  bloch-verify assess-signed --bundle <signed-evidence.json> --trust-policy <policy.json> --expected-trust-policy-sha256 <0x-sha256> --at <unix-seconds> [--require-comparison] [--require-authenticated-comparison] [--require-production-qualified]".into()
}
