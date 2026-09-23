use bloch_verify_core::{assess, parse_bundle};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 1_048_576;

struct Arguments {
    bundle: PathBuf,
    evaluated_at: u64,
    require_comparison: bool,
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
    let metadata = fs::symlink_metadata(&arguments.bundle)
        .map_err(|error| format!("cannot inspect bundle: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("bundle must be a regular non-symlink file".into());
    }
    if metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err("bundle is empty or exceeds 1 MiB".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o022 != 0 {
            return Err("bundle must be single-link and not group/world writable".into());
        }
    }
    let bytes =
        fs::read(&arguments.bundle).map_err(|error| format!("cannot read bundle: {error}"))?;
    let bundle = parse_bundle(&bytes).map_err(|error| error.to_string())?;
    let report = assess(&bundle, arguments.evaluated_at).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    if (arguments.require_comparison && !report.comparison_passed)
        || (arguments.require_production_qualified && !report.production_qualified)
    {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn arguments() -> Result<Arguments, String> {
    let mut values = env::args().skip(1);
    if values.next().as_deref() != Some("assess") {
        return Err(usage());
    }
    let mut bundle = None;
    let mut evaluated_at = None;
    let mut require_comparison = false;
    let mut require_production_qualified = false;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--bundle" => {
                if bundle.is_some() {
                    return Err("--bundle supplied more than once".into());
                }
                bundle = Some(PathBuf::from(
                    values.next().ok_or("--bundle requires a path")?,
                ));
            }
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
            "--require-production-qualified" => require_production_qualified = true,
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Arguments {
        bundle: bundle.ok_or("--bundle is required")?,
        evaluated_at: evaluated_at.ok_or("--at is required")?,
        require_comparison,
        require_production_qualified,
    })
}

fn usage() -> String {
    "usage: bloch-verify assess --bundle <evidence.json> --at <unix-seconds> [--require-comparison] [--require-production-qualified]".into()
}
