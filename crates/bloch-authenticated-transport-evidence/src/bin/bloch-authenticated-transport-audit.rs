#[cfg(unix)]
mod unix_cli {
    use bloch_authenticated_transport_evidence::{
        MAX_TRANSPORT_EVIDENCE_BYTES, MAX_TRANSPORT_POLICY_BYTES, TransportExchangeExpectation,
        TransportPurpose, parse_authenticated_transport_policy,
        verify_authenticated_transport_exchange_evidence,
    };
    use bloch_trusted_time::{
        MAX_TRUSTED_TIME_POLICY_BYTES, MAX_TRUSTED_TIME_TOKEN_BYTES, parse_trusted_time_policy,
        verify_trusted_time_token,
    };
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
    const USAGE: &str = "usage:\n  bloch-authenticated-transport-audit verify-exchange --transport-policy FILE --transport-policy-sha256 0x... --trusted-time-policy FILE --trusted-time-policy-sha256 0x... --trusted-time-token FILE --trusted-time-nonce 0x... --evidence FILE --request-nonce 0x... --request FILE --response FILE --purpose trusted-time|remote-cursor|remote-cursor-cas|external-time-anchor\n\nThis is an offline diagnostic verifier, not a production transport or freshness gate.\n";

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuditResult<'a> {
        verified: bool,
        service_id: &'a str,
        purpose: &'a str,
        transport_policy_sha256: &'a str,
        request_sha256: &'a str,
        response_sha256: &'a str,
        evidence_sha256: &'a str,
        authority_ids: &'a [String],
        production_qualified: bool,
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let Some(command) = args.next() else {
            return Err(USAGE.into());
        };
        if matches!(command.as_str(), "help" | "--help" | "-h") {
            print!("{USAGE}");
            return Ok(());
        }
        if command != "verify-exchange" {
            return Err(format!("unknown command {command:?}\n{USAGE}"));
        }
        let options = parse_options(args)?;
        let allowed = [
            "transport-policy",
            "transport-policy-sha256",
            "trusted-time-policy",
            "trusted-time-policy-sha256",
            "trusted-time-token",
            "trusted-time-nonce",
            "evidence",
            "request-nonce",
            "request",
            "response",
            "purpose",
        ];
        if let Some(name) = options
            .keys()
            .find(|name| !allowed.contains(&name.as_str()))
        {
            return Err(format!("unknown option --{name}"));
        }

        let transport_pin = required(&options, "transport-policy-sha256")?;
        let transport_policy_bytes = read_secure_bounded(
            &required_path(&options, "transport-policy")?,
            MAX_TRANSPORT_POLICY_BYTES as u64,
        )?;
        let transport_policy =
            parse_authenticated_transport_policy(&transport_policy_bytes, transport_pin)
                .map_err(|error| error.to_string())?;

        let trusted_time_pin = required(&options, "trusted-time-policy-sha256")?;
        let trusted_time_policy_bytes = read_secure_bounded(
            &required_path(&options, "trusted-time-policy")?,
            MAX_TRUSTED_TIME_POLICY_BYTES as u64,
        )?;
        let trusted_time_policy =
            parse_trusted_time_policy(&trusted_time_policy_bytes, trusted_time_pin)
                .map_err(|error| error.to_string())?;
        let trusted_time_token = read_secure_bounded(
            &required_path(&options, "trusted-time-token")?,
            MAX_TRUSTED_TIME_TOKEN_BYTES as u64,
        )?;
        let trusted_time = verify_trusted_time_token(
            &trusted_time_token,
            &trusted_time_policy,
            trusted_time_pin,
            required(&options, "trusted-time-nonce")?,
            None,
        )
        .map_err(|error| error.to_string())?;

        let request = read_secure_bounded(&required_path(&options, "request")?, MAX_REQUEST_BYTES)?;
        let response = read_secure_bounded(
            &required_path(&options, "response")?,
            transport_policy.max_response_bytes,
        )?;
        let evidence = read_secure_bounded(
            &required_path(&options, "evidence")?,
            MAX_TRANSPORT_EVIDENCE_BYTES as u64,
        )?;
        let purpose_text = required(&options, "purpose")?;
        let purpose = parse_purpose(purpose_text)?;
        let verified = verify_authenticated_transport_exchange_evidence(
            &evidence,
            &transport_policy,
            transport_pin,
            TransportExchangeExpectation {
                purpose,
                request_nonce: required(&options, "request-nonce")?,
                request_bytes: &request,
                response_bytes: &response,
            },
            &trusted_time,
        )
        .map_err(|error| error.to_string())?;

        let result = AuditResult {
            verified: true,
            service_id: verified.service_id(),
            purpose: purpose_text,
            transport_policy_sha256: verified.policy_sha256(),
            request_sha256: verified.request_sha256(),
            response_sha256: verified.response_sha256(),
            evidence_sha256: verified.evidence_sha256(),
            authority_ids: verified.authority_ids(),
            production_qualified: false,
        };
        let encoded = serde_json::to_vec(&result).map_err(|error| error.to_string())?;
        std::io::stdout()
            .write_all(&encoded)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|error| error.to_string())
    }

    fn parse_options(
        args: impl Iterator<Item = String>,
    ) -> Result<BTreeMap<String, String>, String> {
        let mut values = BTreeMap::new();
        let mut args = args.peekable();
        while let Some(argument) = args.next() {
            let Some(name) = argument.strip_prefix("--") else {
                return Err(format!("unexpected positional argument {argument:?}"));
            };
            let value = args
                .next()
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("missing value for --{name}"))?;
            if values.insert(name.into(), value).is_some() {
                return Err(format!("duplicate option --{name}"));
            }
        }
        Ok(values)
    }

    fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
        options
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required option --{name}"))
    }

    fn required_path(options: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, String> {
        Ok(PathBuf::from(required(options, name)?))
    }

    fn parse_purpose(value: &str) -> Result<TransportPurpose, String> {
        match value {
            "trusted-time" => Ok(TransportPurpose::TrustedTime),
            "remote-cursor" => Ok(TransportPurpose::RemoteCursor),
            "remote-cursor-cas" => Ok(TransportPurpose::RemoteCursorCas),
            "external-time-anchor" => Ok(TransportPurpose::ExternalTimeAnchor),
            _ => Err("purpose is invalid".into()),
        }
    }

    fn read_secure_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
        if maximum == 0 {
            return Err("input size limit is zero".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| format!("cannot securely open {}: {error}", path.display()))?;
        let before = file.metadata().map_err(|error| error.to_string())?;
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
            .map_err(|error| error.to_string())?;
        let after = file.metadata().map_err(|error| error.to_string())?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || bytes.len() as u64 != after.len()
        {
            return Err(format!("input changed while reading {}", path.display()));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static NEXT: AtomicU64 = AtomicU64::new(1);

        #[test]
        fn purpose_parser_is_closed() {
            assert_eq!(
                parse_purpose("remote-cursor").unwrap(),
                TransportPurpose::RemoteCursor
            );
            assert!(parse_purpose("anything-else").is_err());
        }

        #[test]
        fn duplicate_options_are_refused() {
            let options = vec![
                "--request".into(),
                "a".into(),
                "--request".into(),
                "b".into(),
            ];
            assert!(parse_options(options.into_iter()).is_err());
        }

        #[test]
        fn secure_reader_refuses_group_or_world_access() {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "bloch-transport-audit-{}-{unique}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            let input = directory.join("input.json");
            std::fs::write(&input, b"{}").unwrap();
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_secure_bounded(&input, 1024).is_err());
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_secure_bounded(&input, 1024).unwrap(), b"{}");
            std::fs::remove_file(input).unwrap();
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
    eprintln!("error: bloch-authenticated-transport-audit is supported only on Unix");
    std::process::exit(2);
}
