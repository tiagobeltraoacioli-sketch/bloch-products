use bloch_local_state_rebootstrap::rebootstrap_v1_to_v2;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-local-state-rebootstrap: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    require_only(
        &arguments,
        &[
            "--legacy-artifact",
            "--legacy-policy",
            "--legacy-policy-sha256",
            "--legacy-cursor",
            "--expected-legacy-cursor-sha256",
            "--new-artifact",
            "--new-policy",
            "--new-policy-sha256",
            "--expected-semantic-manifest-sha256",
            "--new-cursor",
            "--expected-new-cursor-sha256",
            "--cursor-out",
        ],
    )?;
    let legacy_artifact = read_private(
        required_path(&arguments, "--legacy-artifact")?,
        "legacy artifact",
    )?;
    let legacy_policy = read_private(
        required_path(&arguments, "--legacy-policy")?,
        "legacy policy",
    )?;
    let legacy_cursor = read_private(
        required_path(&arguments, "--legacy-cursor")?,
        "legacy cursor",
    )?;
    let new_artifact = read_private(required_path(&arguments, "--new-artifact")?, "new artifact")?;
    let new_policy = read_private(required_path(&arguments, "--new-policy")?, "new policy")?;
    let new_cursor = read_private(required_path(&arguments, "--new-cursor")?, "new cursor")?;

    let output = rebootstrap_v1_to_v2(
        &legacy_artifact,
        &legacy_policy,
        required_utf8(&arguments, "--legacy-policy-sha256")?,
        &legacy_cursor,
        required_utf8(&arguments, "--expected-legacy-cursor-sha256")?,
        &new_artifact,
        &new_policy,
        required_utf8(&arguments, "--new-policy-sha256")?,
        required_utf8(&arguments, "--expected-semantic-manifest-sha256")?,
        &new_cursor,
        required_utf8(&arguments, "--expected-new-cursor-sha256")?,
    )
    .map_err(|error| error.to_string())?;
    write_create_only(required_path(&arguments, "--cursor-out")?, &output)
}

fn parse_arguments() -> Result<BTreeMap<String, OsString>, String> {
    let mut raw = std::env::args_os().skip(1);
    let command = raw
        .next()
        .ok_or("expected command: rebootstrap")?
        .into_string()
        .map_err(|_| "command must be UTF-8")?;
    if command != "rebootstrap" {
        return Err(format!("unknown command: {command}"));
    }
    let mut values = BTreeMap::new();
    while let Some(flag) = raw.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "argument flag must be UTF-8")?;
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
    Ok(values)
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

fn read_private(path: &Path, label: &str) -> Result<Vec<u8>, String> {
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
    validate_private_file(&before, label)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    validate_private_file(&after, label)?;
    if bytes.len() as u64 != after.len() || !same_snapshot(&before, &after) {
        return Err(format!("{label} changed while it was being read"));
    }
    Ok(bytes)
}

fn validate_private_file(metadata: &Metadata, label: &str) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(format!("{label} has invalid type or size"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "{label} must be owner-only, owner-operated, and single-link"
            ));
        }
    }
    Ok(())
}

fn write_create_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let leaf = path
            .file_name()
            .ok_or("output path must have a file name")?;
        let link = std::fs::symlink_metadata(parent_path)
            .map_err(|error| format!("cannot inspect output parent: {error}"))?;
        if link.file_type().is_symlink() || !link.is_dir() {
            return Err("output parent must be a real directory".into());
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)
            .map_err(|error| format!("cannot open output parent: {error}"))?;
        let opened = parent.metadata().map_err(|error| error.to_string())?;
        validate_private_directory(&opened)?;
        if !same_object(&link, &opened) {
            return Err("output parent changed while it was opened".into());
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
                "cannot create output {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let result = (|| {
            file.write_all(bytes).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            validate_private_file(
                &file.metadata().map_err(|error| error.to_string())?,
                "output",
            )?;
            parent.sync_all().map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let opened = file.metadata().ok();
            let named = std::fs::symlink_metadata(path).ok();
            if opened
                .as_ref()
                .zip(named.as_ref())
                .is_some_and(|(opened, named)| same_object(opened, named))
            {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                }
                let _ = parent.sync_all();
            }
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err("secure create-only output is unsupported on this platform".into())
    }
}

fn validate_private_directory(metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_dir() {
        return Err("output parent is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("output parent must be owner-only and owner-operated".into());
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn output_is_private_create_only_and_never_overwritten() {
        let directory = private_directory();
        let output = directory.join("cursor-v2.json");
        write_create_only(&output, b"canonical-v2-cursor").unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_create_only(&output, b"replacement").is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"canonical-v2-cursor");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_input_reader_rejects_symlinks_and_hardlinks() {
        let directory = private_directory();
        let original = directory.join("cursor.json");
        let symbolic = directory.join("cursor-symlink.json");
        let hard = directory.join("cursor-hardlink.json");
        std::fs::write(&original, b"cursor").unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&original, &symbolic).unwrap();
        std::fs::hard_link(&original, &hard).unwrap();

        assert!(read_private(&symbolic, "cursor").is_err());
        assert!(read_private(&original, "cursor").is_err());
        assert!(read_private(&hard, "cursor").is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn private_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bloch-rebootstrap-cli-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
