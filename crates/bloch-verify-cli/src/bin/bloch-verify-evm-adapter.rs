use bloch_verify_core::{observation_from_evm_rpc_capture, parse_evm_rpc_capture};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 1_048_576;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-verify-evm-adapter refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("convert") {
        return Err(usage());
    }
    let arguments = collect(args)?;
    exact_options(&arguments, &["--capture", "--observation-out"])?;
    let capture_path = PathBuf::from(one(&arguments, "--capture")?);
    let output_path = PathBuf::from(one(&arguments, "--observation-out")?);
    let capture = parse_evm_rpc_capture(&read_safe(&capture_path, "RPC capture")?)
        .map_err(|error| error.to_string())?;
    let observation =
        observation_from_evm_rpc_capture(&capture).map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec(&observation)
        .map_err(|error| format!("cannot serialize observation: {error}"))?;
    bytes.push(b'\n');
    write_create(&output_path, &bytes)?;
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

fn write_create(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))?;
    if let Some(parent) = path.parent() {
        let directory = fs::File::open(parent)
            .map_err(|error| format!("cannot open output directory: {error}"))?;
        directory
            .sync_all()
            .map_err(|error| format!("cannot sync output directory: {error}"))?;
    }
    Ok(())
}

fn usage() -> String {
    "usage: bloch-verify-evm-adapter convert --capture <json> --observation-out <new-json>".into()
}
