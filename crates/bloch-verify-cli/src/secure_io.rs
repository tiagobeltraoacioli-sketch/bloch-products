use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

pub const MAX_INPUT_BYTES: u64 = 1_048_576;

pub fn read_secure(path: &Path, label: &str) -> Result<Vec<u8>, String> {
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
        .map_err(|error| format!("cannot inspect opened {label}: {error}"))?;
    validate_input_metadata(&before, label)?;

    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("{label} is empty or exceeds 1 MiB"));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect opened {label}: {error}"))?;
    validate_input_metadata(&after, label)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(format!("{label} changed while it was being read"));
    }
    Ok(bytes)
}

pub fn write_create(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = secure_parent(path)?;
    let name = leaf_name(path)?;
    let mut file = create_file_at(&parent, name)?;
    validate_created_file(
        &file
            .metadata()
            .map_err(|error| format!("cannot inspect newly created {}: {error}", path.display()))?,
    )?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot publish {} privately: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {} permissions: {error}", path.display()))?;
    }
    validate_created_file(&file.metadata().map_err(|error| {
        format!(
            "cannot re-inspect newly created {}: {error}",
            path.display()
        )
    })?)?;
    parent
        .sync_all()
        .map_err(|error| format!("cannot sync output directory: {error}"))?;
    Ok(())
}

pub fn create_private_directory(path: &Path) -> Result<(), String> {
    let parent = secure_parent(path)?;
    let name = leaf_name(path)?;
    create_directory_at(&parent, name)
        .map_err(|error| format!("cannot create output directory: {error}"))?;
    let directory = open_directory_at(&parent, name)
        .map_err(|error| format!("cannot securely open output directory: {error}"))?;
    validate_private_directory(
        &directory
            .metadata()
            .map_err(|error| format!("cannot inspect newly created output directory: {error}"))?,
    )?;
    directory
        .sync_all()
        .map_err(|error| format!("cannot sync output directory: {error}"))?;
    parent
        .sync_all()
        .map_err(|error| format!("cannot sync parent directory: {error}"))?;
    Ok(())
}

fn secure_parent(path: &Path) -> Result<File, String> {
    let parent_path = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let link_metadata = fs::symlink_metadata(parent_path)
        .map_err(|error| format!("cannot inspect output directory: {error}"))?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_dir() {
        return Err("output directory must be a real directory, not a symlink".into());
    }
    let parent = File::open(parent_path)
        .map_err(|error| format!("cannot open output directory: {error}"))?;
    let opened = parent
        .metadata()
        .map_err(|error| format!("cannot inspect opened output directory: {error}"))?;
    if !same_object(&link_metadata, &opened) {
        return Err("output directory changed while it was being opened".into());
    }
    validate_parent_directory(&opened)?;
    Ok(parent)
}

fn leaf_name(path: &Path) -> Result<&std::ffi::OsStr, String> {
    path.file_name()
        .filter(|name| *name != "." && *name != "..")
        .ok_or_else(|| "output path must have a file name".into())
}

#[cfg(unix)]
fn create_file_at(parent: &File, name: &std::ffi::OsStr) -> Result<File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    // SAFETY: `parent` owns a live directory descriptor and `name` is a
    // NUL-terminated single path component. A successful descriptor is
    // transferred exactly once into `File` below.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o000,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: `descriptor` is nonnegative and newly owned by this function.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn create_file_at(_: &File, _: &std::ffi::OsStr) -> Result<File, String> {
    Err("secure create-only output is unsupported on this platform".into())
}

#[cfg(unix)]
fn create_directory_at(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let name = c_name(name).map_err(std::io::Error::other)?;
    // SAFETY: `parent` is a live directory descriptor and `name` is a
    // NUL-terminated single path component.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn create_directory_at(_: &File, _: &std::ffi::OsStr) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "secure directory creation is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name).map_err(std::io::Error::other)?;
    // SAFETY: `parent` owns a live directory descriptor and `name` is a
    // NUL-terminated single path component. A successful descriptor is
    // transferred exactly once into `File` below.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `descriptor` is nonnegative and newly owned by this function.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(not(unix))]
fn open_directory_at(_: &File, _: &std::ffi::OsStr) -> std::io::Result<File> {
    Err(std::io::Error::other(
        "secure directory opening is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(|_| "output name contains NUL".into())
}

fn validate_input_metadata(metadata: &Metadata, label: &str) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} must be a non-empty regular file at most 1 MiB"
        ));
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
    Ok(())
}

fn validate_parent_directory(metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_dir() {
        return Err("output parent is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("output directory must not be group/world writable".into());
        }
    }
    Ok(())
}

fn validate_private_directory(metadata: &Metadata) -> Result<(), String> {
    validate_parent_directory(metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("output directory must be private (mode 0700 or stricter)".into());
        }
    }
    Ok(())
}

fn validate_created_file(metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err("new output is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "new output must be single-link and private (mode 0600 or stricter)".into(),
            );
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
fn same_object(_: &Metadata, _: &Metadata) -> bool {
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn refuses_symlink_and_hardlink_inputs() {
        let root = private_temp_directory();
        let original = root.join("original.json");
        let symbolic = root.join("symbolic.json");
        let hard = root.join("hard.json");
        fs::write(&original, b"{}\n").unwrap();
        symlink(&original, &symbolic).unwrap();
        fs::hard_link(&original, &hard).unwrap();

        assert!(read_secure(&symbolic, "input").is_err());
        assert!(read_secure(&original, "input").is_err());
        assert!(read_secure(&hard, "input").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_only_outputs_are_private_and_parent_symlinks_are_refused() {
        let root = private_temp_directory();
        let output = root.join("output.json");
        write_create(&output, b"{}\n").unwrap();
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_create(&output, b"replacement\n").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"{}\n");

        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let alias = root.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(write_create(&alias.join("escaped.json"), b"{}\n").is_err());
        assert!(!real.join("escaped.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn private_temp_directory() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bloch-verify-secure-io-{}-{nonce}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
}
