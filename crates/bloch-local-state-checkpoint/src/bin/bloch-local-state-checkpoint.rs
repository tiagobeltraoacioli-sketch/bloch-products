//! Offline checkpoint ceremony CLI. Private keys are never accepted.

use bloch_local_state_checkpoint::{
    DetachedCheckpointSignature, MAX_ARTIFACT_BYTES, MAX_POLICY_BYTES,
    checkpoint_signature_message, create_root_checkpoint, parse_checkpoint_policy,
    verify_root_checkpoint_exact,
};
use bloch_local_state_store::{MAX_ROOT_BYTES, StateRoot, parse_state_root};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const REQUEST_SCHEMA: &str = "bloch.products.local-state-checkpoint-signing-request.v2";
const SIGNATURE_SET_SCHEMA: &str = "bloch.products.local-state-checkpoint-signatures.v1";
const RECEIPT_SCHEMA: &str = "bloch.products.local-state-checkpoint-verification.v2";
const MAX_CEREMONY_BYTES: usize = 256 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningRequest<'a> {
    schema: &'static str,
    checkpoint_policy_sha256: &'a str,
    semantic_manifest_sha256: &'a str,
    state_root: &'a StateRoot,
    created_at_unix_seconds: u64,
    signing_message_sha256: String,
    signing_message: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignatureSet {
    schema: String,
    signatures: Vec<DetachedCheckpointSignature>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationReceipt<'a> {
    schema: &'static str,
    checkpoint_policy_sha256: &'a str,
    checkpoint_sha256: &'a str,
    semantic_manifest_sha256: &'a str,
    evaluated_at_unix_seconds: u64,
    state_root: &'a StateRoot,
    authority_ids: &'a [String],
    anti_rollback_expectation_matched: bool,
    authority_independence_proven: bool,
    high_availability_proven: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-local-state-checkpoint: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let (command, arguments) = parse_arguments()?;
    match command.as_str() {
        "request" => request(&arguments),
        "assemble" => assemble(&arguments),
        "verify" => verify(&arguments),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn request(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &[
            "--root",
            "--policy",
            "--policy-sha256",
            "--semantic-manifest-sha256",
            "--created-at",
            "--request-out",
            "--message-out",
        ],
    )?;
    let pin = required_utf8(arguments, "--policy-sha256")?;
    let semantic_pin = required_utf8(arguments, "--semantic-manifest-sha256")?;
    let policy = read_policy(required_path(arguments, "--policy")?, pin)?;
    let root = read_root(required_path(arguments, "--root")?)?;
    let created_at = required_u64(arguments, "--created-at")?;
    let message = checkpoint_signature_message(&root, &policy, pin, semantic_pin, created_at)
        .map_err(|error| error.to_string())?;
    let request = SigningRequest {
        schema: REQUEST_SCHEMA,
        checkpoint_policy_sha256: pin,
        semantic_manifest_sha256: semantic_pin,
        state_root: &root,
        created_at_unix_seconds: created_at,
        signing_message_sha256: hash(&message),
        signing_message: format!("0x{}", hex::encode(&message)),
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let mut request_output = ReservedOutput::create(required_path(arguments, "--request-out")?)?;
    let mut message_output = ReservedOutput::create(required_path(arguments, "--message-out")?)?;
    request_output.write(&request_bytes)?;
    message_output.write(&message)?;
    request_output.publish();
    message_output.publish();
    Ok(())
}

fn assemble(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &[
            "--root",
            "--policy",
            "--policy-sha256",
            "--semantic-manifest-sha256",
            "--created-at",
            "--signatures",
            "--artifact-out",
        ],
    )?;
    let pin = required_utf8(arguments, "--policy-sha256")?;
    let semantic_pin = required_utf8(arguments, "--semantic-manifest-sha256")?;
    let policy = read_policy(required_path(arguments, "--policy")?, pin)?;
    let root = read_root(required_path(arguments, "--root")?)?;
    let created_at = required_u64(arguments, "--created-at")?;
    let signature_bytes = read_private(
        required_path(arguments, "--signatures")?,
        MAX_CEREMONY_BYTES,
        "detached signature set",
    )?;
    let signature_set: SignatureSet = serde_json::from_slice(&signature_bytes)
        .map_err(|_| "detached signature set is invalid".to_owned())?;
    if signature_set.schema != SIGNATURE_SET_SCHEMA
        || serde_json::to_vec(&signature_set).map_err(|error| error.to_string())? != signature_bytes
    {
        return Err("detached signature set is invalid or non-canonical".to_owned());
    }
    let artifact = create_root_checkpoint(
        &root,
        &policy,
        pin,
        semantic_pin,
        created_at,
        &signature_set.signatures,
    )
    .map_err(|error| error.to_string())?;
    let mut output = ReservedOutput::create(required_path(arguments, "--artifact-out")?)?;
    output.write(&artifact)?;
    output.publish();
    Ok(())
}

fn verify(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &[
            "--artifact",
            "--policy",
            "--policy-sha256",
            "--expected-semantic-manifest-sha256",
            "--expected-root",
            "--evaluated-at",
            "--receipt-out",
        ],
    )?;
    let pin = required_utf8(arguments, "--policy-sha256")?;
    let expected_semantic_pin = required_utf8(arguments, "--expected-semantic-manifest-sha256")?;
    let policy = read_policy(required_path(arguments, "--policy")?, pin)?;
    let expected_root = read_root(required_path(arguments, "--expected-root")?)?;
    let artifact = read_private(
        required_path(arguments, "--artifact")?,
        MAX_ARTIFACT_BYTES,
        "checkpoint artifact",
    )?;
    let evaluated_at = required_u64(arguments, "--evaluated-at")?;
    let verified = verify_root_checkpoint_exact(
        &artifact,
        &policy,
        pin,
        &expected_root,
        expected_semantic_pin,
        evaluated_at,
    )
    .map_err(|error| error.to_string())?;
    let receipt = VerificationReceipt {
        schema: RECEIPT_SCHEMA,
        checkpoint_policy_sha256: verified.checkpoint_policy_sha256(),
        checkpoint_sha256: verified.checkpoint_sha256(),
        semantic_manifest_sha256: verified.semantic_manifest_sha256(),
        evaluated_at_unix_seconds: evaluated_at,
        state_root: verified.root(),
        authority_ids: verified.authority_ids(),
        anti_rollback_expectation_matched: true,
        authority_independence_proven: verified.authority_independence_proven(),
        high_availability_proven: verified.high_availability_proven(),
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
    let mut output = ReservedOutput::create(required_path(arguments, "--receipt-out")?)?;
    output.write(&bytes)?;
    output.publish();
    Ok(())
}

fn read_policy(
    path: &Path,
    expected_policy_sha256: &str,
) -> Result<bloch_local_state_checkpoint::CheckpointPolicy, String> {
    let bytes = read_private(path, MAX_POLICY_BYTES, "checkpoint policy")?;
    parse_checkpoint_policy(&bytes, expected_policy_sha256).map_err(|error| error.to_string())
}

fn read_root(path: &Path) -> Result<StateRoot, String> {
    let bytes = read_private(path, MAX_ROOT_BYTES, "independent state root")?;
    parse_state_root(&bytes).map_err(|error| error.to_string())
}

fn parse_arguments() -> Result<(String, BTreeMap<String, OsString>), String> {
    let mut raw = std::env::args_os().skip(1);
    let command = raw
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| "command must be UTF-8".to_owned())?;
    let mut values = BTreeMap::new();
    while let Some(flag) = raw.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "argument flag must be UTF-8".to_owned())?;
        if !flag.starts_with("--") {
            return Err(format!("unexpected positional argument: {flag}"));
        }
        let value = raw
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if values.insert(flag.clone(), value).is_some() {
            return Err(format!("duplicate argument: {flag}"));
        }
    }
    Ok((command, values))
}

fn usage() -> String {
    "expected command: request, assemble, or verify".to_owned()
}

fn require_only(arguments: &BTreeMap<String, OsString>, allowed: &[&str]) -> Result<(), String> {
    if let Some(unknown) = arguments
        .keys()
        .find(|argument| !allowed.contains(&argument.as_str()))
    {
        return Err(format!("unknown argument: {unknown}"));
    }
    for required in allowed {
        if !arguments.contains_key(*required) {
            return Err(format!("missing required argument: {required}"));
        }
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

fn required_utf8<'a>(
    arguments: &'a BTreeMap<String, OsString>,
    name: &str,
) -> Result<&'a str, String> {
    arguments
        .get(name)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{name} must be UTF-8"))
}

fn required_u64(arguments: &BTreeMap<String, OsString>, name: &str) -> Result<u64, String> {
    required_utf8(arguments, name)?
        .parse()
        .map_err(|_| format!("{name} must be an unsigned decimal integer"))
}

fn read_private(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot securely open {label}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("cannot inspect {label}: {error}"))?;
    validate_input(&before, maximum, label)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    validate_input(&after, maximum, label)?;
    if bytes.len() as u64 != after.len() || !same_snapshot(&before, &after) {
        return Err(format!("{label} changed while it was being read"));
    }
    Ok(bytes)
}

fn validate_input(metadata: &Metadata, maximum: usize, label: &str) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(format!(
            "{label} must be a non-empty regular file at most {maximum} bytes"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.permissions().mode() & 0o6000 != 0
        {
            return Err(format!(
                "{label} must be owner-operated, owner-only and single-link"
            ));
        }
    }
    Ok(())
}

struct ReservedOutput {
    path: PathBuf,
    parent: File,
    file: Option<File>,
    #[cfg(unix)]
    name: CString,
    published: bool,
}

impl ReservedOutput {
    #[cfg(unix)]
    fn create(path: &Path) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let leaf = path
            .file_name()
            .filter(|name| *name != "." && *name != "..")
            .ok_or("output path must have a file name")?;
        let link = std::fs::symlink_metadata(parent_path)
            .map_err(|error| format!("cannot inspect output parent: {error}"))?;
        if link.file_type().is_symlink() || !link.is_dir() {
            return Err("output parent must be a real directory".to_owned());
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)
            .map_err(|error| format!("cannot open output parent: {error}"))?;
        let opened = parent
            .metadata()
            .map_err(|error| format!("cannot inspect output parent: {error}"))?;
        validate_private_directory(&opened)?;
        if !same_object(&link, &opened) {
            return Err("output parent changed while it was opened".to_owned());
        }
        let name = CString::new(leaf.as_bytes()).map_err(|_| "output name contains NUL")?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(format!(
                "cannot reserve create-only output {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_created_file(&file.metadata().map_err(|error| error.to_string())?)?;
        Ok(Self {
            path: path.to_owned(),
            parent,
            file: Some(file),
            name,
            published: false,
        })
    }

    #[cfg(not(unix))]
    fn create(_path: &Path) -> Result<Self, String> {
        Err("secure create-only output is unsupported on this platform".to_owned())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_CEREMONY_BYTES {
            return Err("refusing empty or oversized ceremony output".to_owned());
        }
        let file = self.file.as_mut().ok_or("output is already closed")?;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", self.path.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", self.path.display()))?;
        validate_created_file(&file.metadata().map_err(|error| error.to_string())?)?;
        self.parent
            .sync_all()
            .map_err(|error| format!("cannot sync output parent: {error}"))
    }

    fn publish(&mut self) {
        self.published = true;
    }
}

#[cfg(unix)]
impl Drop for ReservedOutput {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        if self.published {
            return;
        }
        let Some(file) = self.file.as_ref() else {
            return;
        };
        let Ok(opened) = file.metadata() else {
            return;
        };
        let Ok(named) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if same_object(&opened, &named) {
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
            let _ = self.parent.sync_all();
        }
    }
}

fn validate_private_directory(metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_dir() {
        return Err("output parent is not a directory".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("output parent must be owner-only and owner-operated".to_owned());
        }
    }
    Ok(())
}

fn validate_created_file(metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err("output is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err("output does not have safe ownership, mode, or link count".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_object(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(left, right)
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

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
