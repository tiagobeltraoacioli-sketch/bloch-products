use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use thiserror::Error;

const FILE: &str = "transition.json";
const MAX: u64 = 512 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    pub schema: String,
    pub current_root_sha256: String,
    pub current_checkpoint_sha256: String,
    pub successor_root_sha256: String,
    pub successor_checkpoint_sha256: String,
    pub remote_policy_sha256: String,
    pub request_sha256: String,
    pub request_hex: String,
    pub receipt_hex: Option<String>,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("an unresolved durable transition journal already exists")]
    Pending,
    #[error("durable transition journal is missing")]
    Missing,
    #[error("durable transition journal is invalid")]
    Invalid,
    #[error("unsafe durable transition journal: {0}")]
    Unsafe(&'static str),
    #[error("durable transition journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn create(directory: &Path, journal: &Journal) -> Result<(), JournalError> {
    if read(directory)?.is_some() {
        return Err(JournalError::Pending);
    }
    replace(directory, journal)
}

pub(crate) fn update(directory: &Path, journal: &Journal) -> Result<(), JournalError> {
    if read(directory)?.is_none() {
        return Err(JournalError::Missing);
    }
    replace(directory, journal)
}

pub(crate) fn load(directory: &Path) -> Result<Journal, JournalError> {
    read(directory)?.ok_or(JournalError::Missing)
}

pub(crate) fn clear(directory: &Path) -> Result<(), JournalError> {
    read(directory)?.ok_or(JournalError::Missing)?;
    let dir = open_dir(directory)?;
    let name = c(FILE)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all()?;
    Ok(())
}

fn read(path: &Path) -> Result<Option<Journal>, JournalError> {
    let dir = open_dir(path)?;
    let name = c(FILE)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata()?;
    valid_file(&before)?;
    named(&dir, FILE, &before)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    valid_file(&after)?;
    named(&dir, FILE, &after)?;
    if !same(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(JournalError::Unsafe("fileChanged"));
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| JournalError::Invalid)?;
    if serde_json::to_vec(&journal).map_err(|_| JournalError::Invalid)? != bytes {
        return Err(JournalError::Invalid);
    }
    Ok(Some(journal))
}

fn replace(path: &Path, journal: &Journal) -> Result<(), JournalError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| JournalError::Invalid)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX {
        return Err(JournalError::Invalid);
    }
    let dir = open_dir(path)?;
    let mut random = [0u8; 16];
    getrandom(&mut random).map_err(|_| JournalError::Unsafe("random"))?;
    let temp_name = format!(".transition.{}.tmp", hex::encode(random));
    let temp = c(&temp_name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        valid_file(&file.metadata()?)?;
        drop(file);
        let destination = c(FILE)?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(JournalError::Io(std::io::Error::last_os_error()));
        }
        dir.sync_all()?;
        read(path)?.ok_or(JournalError::Missing)?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
    }
    result
}

fn open_dir(path: &Path) -> Result<File, JournalError> {
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(JournalError::Unsafe("directoryType"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    valid_dir(&file.metadata()?)?;
    if !same(&link, &file.metadata()?) {
        return Err(JournalError::Unsafe("directoryChanged"));
    }
    Ok(file)
}

fn valid_dir(metadata: &Metadata) -> Result<(), JournalError> {
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(JournalError::Unsafe("directoryPermissions"));
    }
    Ok(())
}

fn valid_file(metadata: &Metadata) -> Result<(), JournalError> {
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX
    {
        return Err(JournalError::Unsafe("filePermissions"));
    }
    Ok(())
}

fn named(dir: &File, name: &str, metadata: &Metadata) -> Result<(), JournalError> {
    let name = c(name)?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(JournalError::Unsafe("fileChanged"));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_dev as u128 != u128::from(metadata.dev())
        || u128::from(status.st_ino) != u128::from(metadata.ino())
    {
        return Err(JournalError::Unsafe("fileChanged"));
    }
    Ok(())
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn c(value: &str) -> Result<std::ffi::CString, JournalError> {
    std::ffi::CString::new(value).map_err(|_| JournalError::Unsafe("fileName"))
}
