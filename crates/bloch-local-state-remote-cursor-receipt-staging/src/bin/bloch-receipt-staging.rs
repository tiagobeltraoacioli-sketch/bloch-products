#[cfg(unix)]
mod unix_cli {
    use bloch_local_state_remote_cursor::parse_remote_cursor_policy;
    use bloch_local_state_remote_cursor_receipt_staging::{
        assemble_receipt_from_signature_bundle, ceremony_import_receipt_with_operator_time,
        export_receipt_signing_request, inspect_receipt_staging,
    };
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const USAGE: &str = "usage:\n  bloch-receipt-staging inspect --store PATH\n  bloch-receipt-staging export-signing-request --store PATH --out FILE\n  bloch-receipt-staging assemble-receipt --store PATH --policy FILE --policy-sha256 0x... --signature-bundle FILE --out FILE\n  bloch-receipt-staging ceremony-import-receipt --store PATH --policy FILE --policy-sha256 0x... --receipt FILE --evaluated-at-unix-seconds N --acknowledge-operator-time-is-not-production\n";

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let Some(command) = args.next() else {
            return Err(USAGE.into());
        };
        if command == "help" || command == "--help" || command == "-h" {
            print!("{USAGE}");
            return Ok(());
        }
        let options = parse_options(args)?;
        match command.as_str() {
            "inspect" => {
                reject_unknown(&options, &["store"])?;
                let inspection = inspect_receipt_staging(&required_path(&options, "store")?)
                    .map_err(|e| e.to_string())?;
                let encoded = serde_json::to_vec(&inspection).map_err(|e| e.to_string())?;
                std::io::stdout()
                    .write_all(&encoded)
                    .map_err(|e| e.to_string())?;
                std::io::stdout()
                    .write_all(b"\n")
                    .map_err(|e| e.to_string())?;
            }
            "export-signing-request" => {
                reject_unknown(&options, &["store", "out"])?;
                let bytes = export_receipt_signing_request(&required_path(&options, "store")?)
                    .map_err(|e| e.to_string())?;
                create_once(&required_path(&options, "out")?, &bytes)?;
                eprintln!("signing request exported to owner-only create-once file");
            }
            "assemble-receipt" => {
                reject_unknown(
                    &options,
                    &[
                        "store",
                        "policy",
                        "policy-sha256",
                        "signature-bundle",
                        "out",
                    ],
                )?;
                let pin = required(&options, "policy-sha256")?;
                let policy_bytes =
                    read_secure_bounded(&required_path(&options, "policy")?, 64 * 1024)?;
                let policy =
                    parse_remote_cursor_policy(&policy_bytes, pin).map_err(|e| e.to_string())?;
                let bundle =
                    read_secure_bounded(&required_path(&options, "signature-bundle")?, 128 * 1024)?;
                let receipt = assemble_receipt_from_signature_bundle(
                    &required_path(&options, "store")?,
                    &policy,
                    pin,
                    &bundle,
                )
                .map_err(|e| e.to_string())?;
                create_once(&required_path(&options, "out")?, &receipt)?;
                eprintln!(
                    "receipt assembled and verified into owner-only create-once file; it has not been admitted for production"
                );
            }
            "ceremony-import-receipt" => {
                reject_unknown(
                    &options,
                    &[
                        "store",
                        "policy",
                        "policy-sha256",
                        "receipt",
                        "evaluated-at-unix-seconds",
                        "acknowledge-operator-time-is-not-production",
                    ],
                )?;
                if options
                    .get("acknowledge-operator-time-is-not-production")
                    .and_then(|v| v.as_deref())
                    != Some("true")
                {
                    return Err("ceremony import requires --acknowledge-operator-time-is-not-production; use the trusted-time API for production".into());
                }
                let pin = required(&options, "policy-sha256")?;
                let policy_bytes =
                    read_secure_bounded(&required_path(&options, "policy")?, 64 * 1024)?;
                let policy =
                    parse_remote_cursor_policy(&policy_bytes, pin).map_err(|e| e.to_string())?;
                let receipt =
                    read_secure_bounded(&required_path(&options, "receipt")?, 128 * 1024)?;
                let evaluated = required(&options, "evaluated-at-unix-seconds")?
                    .parse::<u64>()
                    .map_err(|_| {
                        "evaluated-at-unix-seconds must be an unsigned integer".to_string()
                    })?;
                let staged = ceremony_import_receipt_with_operator_time(
                    &required_path(&options, "store")?,
                    &policy,
                    pin,
                    &receipt,
                    evaluated,
                )
                .map_err(|e| e.to_string())?;
                eprintln!(
                    "ceremony receipt imported (sha256 {}); this is not a production trusted-time admission",
                    staged.receipt_sha256()
                );
            }
            _ => return Err(format!("unknown command {command:?}\n{USAGE}")),
        }
        Ok(())
    }

    fn parse_options(
        args: impl Iterator<Item = String>,
    ) -> Result<BTreeMap<String, Option<String>>, String> {
        let mut values = BTreeMap::new();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected positional argument {arg:?}"));
            };
            if values.contains_key(name) {
                return Err(format!("duplicate option --{name}"));
            }
            if name == "acknowledge-operator-time-is-not-production" {
                values.insert(name.into(), Some("true".into()));
                continue;
            }
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for --{name}"))?;
            if value.starts_with("--") {
                return Err(format!("missing value for --{name}"));
            }
            values.insert(name.into(), Some(value));
        }
        Ok(values)
    }

    fn reject_unknown(
        options: &BTreeMap<String, Option<String>>,
        allowed: &[&str],
    ) -> Result<(), String> {
        if let Some(name) = options
            .keys()
            .find(|name| !allowed.contains(&name.as_str()))
        {
            return Err(format!("unknown option --{name}"));
        }
        Ok(())
    }

    fn required<'a>(
        options: &'a BTreeMap<String, Option<String>>,
        name: &str,
    ) -> Result<&'a str, String> {
        options
            .get(name)
            .and_then(|v| v.as_deref())
            .ok_or_else(|| format!("missing required option --{name}"))
    }

    fn required_path(
        options: &BTreeMap<String, Option<String>>,
        name: &str,
    ) -> Result<PathBuf, String> {
        Ok(PathBuf::from(required(options, name)?))
    }

    fn read_secure_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("cannot securely open {}: {e}", path.display()))?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.nlink() != 1
            || before.permissions().mode() & 0o077 != 0
            || before.len() == 0
            || before.len() > maximum
        {
            return Err(format!("unsafe or invalid input file {}", path.display()));
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || bytes.len() as u64 != after.len()
        {
            return Err(format!(
                "input file changed while reading {}",
                path.display()
            ));
        }
        Ok(bytes)
    }

    fn create_once(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| "output path has no file name".to_string())?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|e| format!("cannot securely open output directory: {e}"))?;
        let directory_before = directory.metadata().map_err(|e| e.to_string())?;
        validate_output_directory(&directory_before)?;
        let name = CString::new(name.as_encoded_bytes())
            .map_err(|_| "output file name contains NUL".to_string())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "cannot create output file exactly once: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err("created output file failed safety validation".into());
        }
        directory.sync_all().map_err(|e| e.to_string())?;
        let directory_after = directory.metadata().map_err(|e| e.to_string())?;
        validate_output_directory(&directory_after)?;
        if directory_before.dev() != directory_after.dev()
            || directory_before.ino() != directory_after.ino()
        {
            return Err("output directory changed while exporting".into());
        }
        Ok(())
    }

    fn validate_output_directory(metadata: &std::fs::Metadata) -> Result<(), String> {
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(
                "unsafe output directory: expected a real owner-controlled 0700 directory".into(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        #[test]
        fn create_once_refuses_group_or_world_accessible_directory() {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "bloch-receipt-cli-output-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
            let output = directory.join("signing-request.json");
            let error = create_once(&output, b"{}").unwrap_err();
            assert!(error.contains("unsafe output directory"));
            assert!(!output.exists());
            std::fs::remove_dir(&directory).unwrap();
        }

        #[test]
        fn create_once_uses_owner_only_mode_and_refuses_replacement() {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "bloch-receipt-cli-private-output-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = directory.join("signing-request.json");
            create_once(&output, b"{}").unwrap();
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
                0o600
            );
            assert!(create_once(&output, b"replacement").is_err());
            std::fs::remove_file(output).unwrap();
            std::fs::remove_dir(directory).unwrap();
        }
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = unix_cli::run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("error: bloch-receipt-staging is supported only on Unix");
    std::process::exit(2);
}
