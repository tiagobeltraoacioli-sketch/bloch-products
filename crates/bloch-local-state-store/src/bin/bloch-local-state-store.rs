//! Offline CLI for local persistence integrity only.
//!
//! Product code must still semantically validate every loaded Bloch Data or
//! Bloch Pay state before use. This binary performs no such product validation.

use bloch_local_state_store::{
    MAX_ROOT_BYTES, MAX_STATE_BYTES, StateRoot, load_state, parse_state_root, write_state,
};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-local-state-store: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let (command, arguments) = parse_arguments()?;
    match command.as_str() {
        "init" => initialize(&arguments),
        "update" => update(&arguments),
        "load" => load(&arguments),
        "verify" => verify(&arguments),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn initialize(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &["--store", "--identity", "--state-file", "--root-out"],
    )?;
    let store = required_path(arguments, "--store")?;
    let identity = required_utf8(arguments, "--identity")?;
    let state = read_private(
        required_path(arguments, "--state-file")?,
        MAX_STATE_BYTES,
        "state",
    )?;
    let mut root_output = ReservedOutput::create(required_path(arguments, "--root-out")?)?;
    let root = write_state(store, identity, 0, &state, None).map_err(store_error)?;
    root_output.commit(&root.canonical_bytes().map_err(store_error)?)
}

fn update(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(
        arguments,
        &[
            "--store",
            "--identity",
            "--generation",
            "--state-file",
            "--previous-root",
            "--root-out",
        ],
    )?;
    let store = required_path(arguments, "--store")?;
    let identity = required_utf8(arguments, "--identity")?;
    let generation = required_utf8(arguments, "--generation")?
        .parse::<u64>()
        .map_err(|_| "--generation must be an unsigned decimal integer".to_owned())?;
    let state = read_private(
        required_path(arguments, "--state-file")?,
        MAX_STATE_BYTES,
        "state",
    )?;
    let previous = read_root(required_path(arguments, "--previous-root")?)?;
    let mut root_output = ReservedOutput::create(required_path(arguments, "--root-out")?)?;
    let root =
        write_state(store, identity, generation, &state, Some(&previous)).map_err(store_error)?;
    root_output.commit(&root.canonical_bytes().map_err(store_error)?)
}

fn load(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(arguments, &["--store", "--root", "--state-out"])?;
    let root = read_root(required_path(arguments, "--root")?)?;
    let mut state_output = ReservedOutput::create(required_path(arguments, "--state-out")?)?;
    let state = load_state(required_path(arguments, "--store")?, &root).map_err(store_error)?;
    state_output.commit(&state)
}

fn verify(arguments: &BTreeMap<String, OsString>) -> Result<(), String> {
    require_only(arguments, &["--store", "--root"])?;
    let root = read_root(required_path(arguments, "--root")?)?;
    load_state(required_path(arguments, "--store")?, &root)
        .map(|_| ())
        .map_err(store_error)
}

fn read_root(path: &Path) -> Result<StateRoot, String> {
    let bytes = if systemd_credential_path(path) {
        read_systemd_credential(path, MAX_ROOT_BYTES, "independent root")?
    } else {
        read_private(path, MAX_ROOT_BYTES, "independent root")?
    };
    parse_state_root(&bytes).map_err(store_error)
}

fn systemd_credential_path(path: &Path) -> bool {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .is_some_and(|directory| path == directory.join("state-root"))
}

fn store_error(error: impl std::fmt::Display) -> String {
    error.to_string()
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
    "expected command: init, update, load, or verify".to_owned()
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
    read_bounded_file(path, maximum, label, false)
}

fn read_systemd_credential(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    read_bounded_file(path, maximum, label, true)
}

fn read_bounded_file(
    path: &Path,
    maximum: usize,
    label: &str,
    systemd_credential: bool,
) -> Result<Vec<u8>, String> {
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
    validate_input_file(&before, maximum, label, systemd_credential)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    validate_input_file(&after, maximum, label, systemd_credential)?;
    if bytes.len() as u64 != after.len() || !same_snapshot(&before, &after) {
        return Err(format!("{label} changed while it was being read"));
    }
    Ok(bytes)
}

fn validate_input_file(
    metadata: &Metadata,
    maximum: usize,
    label: &str,
    systemd_credential: bool,
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
        let ownership_valid = if systemd_credential {
            metadata.uid() == 0 && metadata.gid() == 0 && mode == 0o440
        } else {
            metadata.uid() == unsafe { libc::geteuid() } && mode & 0o077 == 0
        };
        if !ownership_valid || metadata.nlink() != 1 || mode & 0o6000 != 0 {
            return Err(format!("{label} has unsafe ownership, mode, or link count"));
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
            committed: false,
        })
    }

    #[cfg(not(unix))]
    fn create(_path: &Path) -> Result<Self, String> {
        Err("secure create-only output is unsupported on this platform".to_owned())
    }

    fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Err("refusing to write an empty output".to_owned());
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
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("output must be owner-only, owner-operated, and single-link".to_owned());
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
