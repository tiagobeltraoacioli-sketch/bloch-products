//! Offline operational CLI for remote cursor fetch composition.

use bloch_local_state_cursor::MAX_CURSOR_BYTES;
use bloch_local_state_remote_cursor::{
    MAX_REMOTE_CURSOR_OBSERVATION_BYTES, MAX_REMOTE_CURSOR_POLICY_BYTES,
    parse_remote_cursor_policy, verify_remote_cursor_observation,
};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE_BYTES: usize = 32;
const MAX_NONCE_FILE_BYTES: usize = 128;

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-local-state-remote-cursor: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let (command, arguments) = parse_arguments()?;
    match command.as_str() {
        "nonce" => generate_nonce(&arguments),
        "verify" => verify_response(&arguments),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn generate_nonce(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(arguments, &["--out"])?;
    let mut random = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut random).map_err(|_| "secure random nonce generation failed")?;
    let nonce = hex::encode(random);
    let mut output = ReservedOutput::create(required_path(arguments, "--out")?)?;
    output.commit(nonce.as_bytes())
}

fn verify_response(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &[
            "--observation",
            "--policy",
            "--policy-sha256",
            "--nonce",
            "--cursor-out",
        ],
    )?;
    let policy_pin = required_utf8(arguments, "--policy-sha256")?;
    let policy_bytes = read_private(
        required_path(arguments, "--policy")?,
        MAX_REMOTE_CURSOR_POLICY_BYTES,
        "remote cursor policy",
    )?;
    let policy =
        parse_remote_cursor_policy(&policy_bytes, policy_pin).map_err(|error| error.to_string())?;
    let nonce_bytes = read_private(
        required_path(arguments, "--nonce")?,
        MAX_NONCE_FILE_BYTES,
        "request nonce",
    )?;
    let nonce = std::str::from_utf8(&nonce_bytes)
        .map_err(|_| "request nonce must be UTF-8 without a trailing newline")?;
    let observation = read_private(
        required_path(arguments, "--observation")?,
        MAX_REMOTE_CURSOR_OBSERVATION_BYTES,
        "remote cursor observation",
    )?;
    let evaluated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs();
    let verified =
        verify_remote_cursor_observation(&observation, &policy, policy_pin, nonce, evaluated_at)
            .map_err(|error| error.to_string())?;
    let cursor = verified
        .cursor()
        .canonical_bytes()
        .map_err(|error| error.to_string())?;
    if cursor.len() > MAX_CURSOR_BYTES {
        return Err("verified cursor exceeds its byte limit".to_owned());
    }
    let mut output = ReservedOutput::create(required_path(arguments, "--cursor-out")?)?;
    output.commit(&cursor)
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
    "expected command: nonce or verify".to_owned()
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
    committed: bool,
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
        let linked = std::fs::symlink_metadata(parent_path)
            .map_err(|error| format!("cannot inspect output parent: {error}"))?;
        if linked.file_type().is_symlink() || !linked.is_dir() {
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
        if !same_object(&linked, &opened) {
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
            committed: false,
        })
    }

    #[cfg(not(unix))]
    fn create(_path: &Path) -> Result<Self, String> {
        Err("secure create-only output is unsupported on this platform".to_owned())
    }

    fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_CURSOR_BYTES.max(MAX_NONCE_FILE_BYTES) {
            return Err("refusing empty or oversized output".to_owned());
        }
        let file = self.file.as_mut().ok_or("output is already closed")?;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", self.path.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", self.path.display()))?;
        validate_created_file(&file.metadata().map_err(|error| error.to_string())?)?;
        self.parent
            .sync_all()
            .map_err(|error| format!("cannot sync output parent: {error}"))?;
        self.committed = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ReservedOutput {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        if self.committed {
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
