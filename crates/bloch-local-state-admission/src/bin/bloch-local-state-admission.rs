//! Fail-closed read-only startup admission. Successful execution is silent.

use bloch_local_state_admission::{
    DataLifecycleAdmission, MAX_SEMANTIC_MANIFEST_BYTES, PayAdjustmentAdmission, StartupAdmission,
    admit_data_lifecycle_coordinated, admit_pay_adjustment_coordinated,
};
use bloch_local_state_checkpoint::{MAX_ARTIFACT_BYTES, MAX_POLICY_BYTES};
use bloch_local_state_remote_cursor::{
    MAX_REMOTE_CURSOR_OBSERVATION_BYTES, MAX_REMOTE_CURSOR_POLICY_BYTES,
    parse_remote_cursor_policy, verify_remote_cursor_observation,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PRODUCT_POLICY_BYTES: usize = 256 * 1024;
const MAX_PIN_BYTES: usize = 66;
const MAX_NONCE_BYTES: usize = 128;
const MAX_IDENTITY_BYTES: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Product {
    Data,
    Pay,
}

#[derive(Clone, Copy)]
enum InputMode {
    Systemd,
    Manual,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-local-state-admission: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let (mode, product, arguments) = parse_arguments()?;
    let allowed = match (mode, product) {
        (InputMode::Systemd, Product::Data | Product::Pay) => SYSTEMD_ARGUMENTS,
        (InputMode::Manual, Product::Data) => MANUAL_DATA_ARGUMENTS,
        (InputMode::Manual, Product::Pay) => MANUAL_PAY_ARGUMENTS,
    };
    require_exact(&arguments, allowed)?;

    let read_input = |flag: &str, credential: &str, maximum: usize, label: &str| match mode {
        InputMode::Systemd => read_systemd_credential(credential, maximum, label),
        InputMode::Manual => read_owner_private(required_path(&arguments, flag)?, maximum, label),
    };
    let artifact = read_input(
        "--artifact",
        "checkpoint-artifact",
        MAX_ARTIFACT_BYTES,
        "checkpoint artifact",
    )?;
    let checkpoint_policy = read_input(
        "--checkpoint-policy",
        "checkpoint-policy",
        MAX_POLICY_BYTES,
        "checkpoint policy",
    )?;
    let semantic = read_input(
        "--semantic-manifest",
        "semantic-manifest",
        MAX_SEMANTIC_MANIFEST_BYTES,
        "semantic manifest",
    )?;
    let remote_observation = read_input(
        "--remote-observation",
        "remote-observation",
        MAX_REMOTE_CURSOR_OBSERVATION_BYTES,
        "remote cursor observation",
    )?;
    let remote_policy_bytes = read_input(
        "--remote-policy",
        "remote-policy",
        MAX_REMOTE_CURSOR_POLICY_BYTES,
        "remote cursor policy",
    )?;
    let remote_policy_pin_bytes = read_input(
        "--remote-policy-pin",
        "remote-policy-pin",
        MAX_PIN_BYTES,
        "remote cursor policy pin",
    )?;
    let request_nonce_bytes = read_input(
        "--request-nonce",
        "request-nonce",
        MAX_NONCE_BYTES,
        "remote cursor request nonce",
    )?;
    let expected_identity_bytes = read_input(
        "--expected-state-identity",
        "expected-state-identity",
        MAX_IDENTITY_BYTES,
        "expected state identity",
    )?;
    let remote_policy_pin = std::str::from_utf8(&remote_policy_pin_bytes)
        .map_err(|_| "remote cursor policy pin must be UTF-8")?;
    let request_nonce = std::str::from_utf8(&request_nonce_bytes)
        .map_err(|_| "remote cursor request nonce must be UTF-8")?;
    let expected_identity = std::str::from_utf8(&expected_identity_bytes)
        .map_err(|_| "expected state identity must be UTF-8")?;
    let remote_policy = parse_remote_cursor_policy(&remote_policy_bytes, remote_policy_pin)
        .map_err(|error| error.to_string())?;
    if remote_policy.state_identity != expected_identity
        || !product_identity_matches(product, expected_identity)
    {
        return Err("remote cursor policy has the wrong product identity".into());
    }
    let evaluated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs();
    let remote_cursor = verify_remote_cursor_observation(
        &remote_observation,
        &remote_policy,
        remote_policy_pin,
        request_nonce,
        evaluated_at,
    )
    .map_err(|error| error.to_string())?;
    let startup = StartupAdmission {
        artifact_bytes: &artifact,
        checkpoint_policy_bytes: &checkpoint_policy,
        semantic_manifest_bytes: &semantic,
        verified_remote_cursor: &remote_cursor,
        cursor_store: required_path(&arguments, "--cursor-store")?,
        state_store: required_path(&arguments, "--state-store")?,
    };
    let coordination_directory = required_path(&arguments, "--coordination-directory")?;

    match product {
        Product::Data => {
            let lifecycle_policy = read_input(
                "--lifecycle-policy",
                "lifecycle-policy",
                MAX_PRODUCT_POLICY_BYTES,
                "lifecycle policy",
            )?;
            admit_data_lifecycle_coordinated(
                coordination_directory,
                DataLifecycleAdmission {
                    startup,
                    lifecycle_policy_bytes: &lifecycle_policy,
                },
            )
            .map_err(|error| error.to_string())?;
        }
        Product::Pay => {
            admit_pay_adjustment_coordinated(
                coordination_directory,
                PayAdjustmentAdmission { startup },
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

const SYSTEMD_ARGUMENTS: &[&str] = &[
    "--coordination-directory",
    "--cursor-store",
    "--expected-state-identity",
    "--state-store",
];
const MANUAL_PAY_ARGUMENTS: &[&str] = &[
    "--artifact",
    "--checkpoint-policy",
    "--coordination-directory",
    "--cursor-store",
    "--expected-state-identity",
    "--remote-observation",
    "--remote-policy",
    "--remote-policy-pin",
    "--request-nonce",
    "--semantic-manifest",
    "--state-store",
];
const MANUAL_DATA_ARGUMENTS: &[&str] = &[
    "--artifact",
    "--checkpoint-policy",
    "--coordination-directory",
    "--cursor-store",
    "--expected-state-identity",
    "--lifecycle-policy",
    "--remote-observation",
    "--remote-policy",
    "--remote-policy-pin",
    "--request-nonce",
    "--semantic-manifest",
    "--state-store",
];

fn parse_arguments() -> Result<(InputMode, Product, BTreeMap<String, OsString>), String> {
    let mut raw = std::env::args_os().skip(1);
    let command = raw
        .next()
        .ok_or("expected product: data or pay")?
        .into_string()
        .map_err(|_| "product must be UTF-8")?;
    let (mode, product) = match command.as_str() {
        "data" => (InputMode::Systemd, Product::Data),
        "pay" => (InputMode::Systemd, Product::Pay),
        "manual-data" => (InputMode::Manual, Product::Data),
        "manual-pay" => (InputMode::Manual, Product::Pay),
        _ => return Err("product must be data, pay, manual-data or manual-pay".into()),
    };
    let mut arguments = BTreeMap::new();
    while let Some(flag) = raw.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "argument flag must be UTF-8")?;
        if !flag.starts_with("--") {
            return Err("unexpected positional argument".into());
        }
        let value = raw
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if arguments.insert(flag.clone(), value).is_some() {
            return Err("duplicate argument".into());
        }
    }
    Ok((mode, product, arguments))
}

fn product_identity_matches(product: Product, identity: &str) -> bool {
    match product {
        Product::Data => identity.starts_with("data:"),
        Product::Pay => identity.starts_with("pay:"),
    }
}

fn require_exact(arguments: &BTreeMap<String, OsString>, allowed: &[&str]) -> Result<(), String> {
    if arguments
        .keys()
        .any(|argument| !allowed.contains(&argument.as_str()))
    {
        return Err("unknown argument".into());
    }
    if let Some(missing) = allowed
        .iter()
        .find(|required| !arguments.contains_key(**required))
    {
        return Err(format!("missing required argument: {missing}"));
    }
    Ok(())
}

fn required_path<'a>(
    arguments: &'a BTreeMap<String, OsString>,
    name: &str,
) -> Result<&'a Path, String> {
    arguments
        .get(name)
        .map(Path::new)
        .ok_or_else(|| format!("missing required argument: {name}"))
}

#[derive(Clone, Copy)]
enum InputTrust {
    OwnerPrivate,
    SystemdCredential,
}

fn read_owner_private(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    read_secure(path, maximum, label, InputTrust::OwnerPrivate)
}

fn read_systemd_credential(name: &str, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or("CREDENTIALS_DIRECTORY is required")?;
    if !directory.is_absolute() || name.is_empty() || name.contains('/') {
        return Err("systemd credential configuration is invalid".into());
    }
    let path = directory.join(name);
    read_secure(&path, maximum, label, InputTrust::SystemdCredential)
}

fn read_secure(
    path: &Path,
    maximum: usize,
    label: &str,
    trust: InputTrust,
) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot securely open {label}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("cannot inspect {label}: {error}"))?;
    validate_input(path, &before, maximum, label, trust)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    validate_input(path, &after, maximum, label, trust)?;
    if bytes.len() as u64 != after.len() || !same_snapshot(&before, &after) {
        return Err(format!("{label} changed while it was being read"));
    }
    Ok(bytes)
}

fn validate_input(
    path: &Path,
    metadata: &Metadata,
    maximum: usize,
    label: &str,
    trust: InputTrust,
) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(format!(
            "{label} must be a non-empty regular file at most {maximum} bytes"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o7777;
        let owner_private =
            metadata.uid() == unsafe { libc::geteuid() } && mode & 0o077 == 0 && mode & 0o6000 == 0;
        let systemd_credential =
            secure_systemd_credential(path, metadata) && metadata.uid() == 0 && mode == 0o440;
        let trusted = match trust {
            InputTrust::OwnerPrivate => owner_private,
            InputTrust::SystemdCredential => systemd_credential,
        };
        if metadata.nlink() != 1 || !trusted {
            return Err(format!(
                "{label} does not satisfy its required single-link trust mode"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secure_systemd_credential(path: &Path, metadata: &Metadata) -> bool {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return false;
    };
    let directory = PathBuf::from(directory);
    if !directory.is_absolute() || !path.is_absolute() || path.parent() != Some(directory.as_path())
    {
        return false;
    }
    let Some(name) = path.file_name() else {
        return false;
    };
    let Ok(name) = std::ffi::CString::new(name.as_encoded_bytes()) else {
        return false;
    };
    let Ok(directory_file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&directory)
    else {
        return false;
    };
    let Ok(directory_metadata) = directory_file.metadata() else {
        return false;
    };
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.permissions().mode() & 0o022 != 0
    {
        return false;
    }
    let mut status = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory_file.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return false;
    }
    let status = unsafe { status.assume_init() };
    status.st_mode & libc::S_IFMT == libc::S_IFREG
        && status.st_dev as u128 == u128::from(metadata.dev())
        && u128::from(status.st_ino) == u128::from(metadata.ino())
        && status.st_nlink == 1
        && status.st_uid == 0
        && status.st_mode & 0o7777 == 0o440
}

#[cfg(unix)]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
}
