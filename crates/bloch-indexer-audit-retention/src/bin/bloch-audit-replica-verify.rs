use bloch_indexer_audit::MAX_AUDIT_POLICY_BYTES;
use bloch_indexer_audit_retention::{
    MAX_REPLICA_MANIFEST_BYTES, MAX_RETENTION_CHECKPOINT_BYTES,
    MAX_RETENTION_CHECKPOINT_POLICY_BYTES, ReplicaVerificationInput, parse_replica_manifest,
    verify_audit_replicas, verify_retention_checkpoint,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("bloch-audit-replica-verify: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let manifest_bytes = read_bounded(
        required(&arguments, "--manifest")?,
        MAX_REPLICA_MANIFEST_BYTES,
    )?;
    let manifest = parse_replica_manifest(&manifest_bytes).map_err(|error| error.to_string())?;
    let audit_policy = read_bounded(
        required(&arguments, "--audit-policy")?,
        MAX_AUDIT_POLICY_BYTES,
    )?;
    let checkpoint_policy = read_bounded(
        required(&arguments, "--checkpoint-policy")?,
        MAX_RETENTION_CHECKPOINT_POLICY_BYTES,
    )?;
    let previous = previous_checkpoint(&arguments, &checkpoint_policy)?;
    let mut replicas = Vec::with_capacity(manifest.replicas.len());
    for replica in manifest.replicas {
        let checkpoint = read_bounded(&replica.checkpoint_path, MAX_RETENTION_CHECKPOINT_BYTES)?;
        let signature = read_bounded(&replica.signature_path, 64)?;
        if signature.len() != 64 {
            return Err(format!(
                "replica {} signature must be 64 raw bytes",
                replica.replica_id
            ));
        }
        replicas.push(ReplicaVerificationInput {
            replica_id: replica.replica_id,
            ledger: replica.ledger_path,
            checkpoint_bytes: checkpoint,
            signer_id: replica.signer_id,
            signature_bytes: signature,
        });
    }
    let report = verify_audit_replicas(
        &replicas,
        manifest.required_quorum,
        &audit_policy,
        required(&arguments, "--audit-policy-sha256")?
            .to_str()
            .ok_or("audit policy pin must be UTF-8")?,
        &checkpoint_policy,
        required(&arguments, "--checkpoint-policy-sha256")?
            .to_str()
            .ok_or("checkpoint policy pin must be UTF-8")?,
        previous.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let mut output = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
    output.push(b'\n');
    std::io::stdout()
        .write_all(&output)
        .map_err(|error| error.to_string())
}

fn parse_arguments() -> Result<BTreeMap<String, PathBuf>, String> {
    let mut values = BTreeMap::new();
    let mut arguments = std::env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "argument flag must be UTF-8")?;
        if !matches!(
            flag.as_str(),
            "--manifest"
                | "--audit-policy"
                | "--audit-policy-sha256"
                | "--checkpoint-policy"
                | "--checkpoint-policy-sha256"
                | "--previous-checkpoint"
                | "--previous-signer-id"
                | "--previous-signature"
        ) {
            return Err(format!("unknown argument: {flag}"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if values.insert(flag.clone(), value.into()).is_some() {
            return Err(format!("duplicate argument: {flag}"));
        }
    }
    Ok(values)
}

fn previous_checkpoint(
    arguments: &BTreeMap<String, PathBuf>,
    checkpoint_policy: &[u8],
) -> Result<Option<bloch_indexer_audit_retention::VerifiedRetentionCheckpoint>, String> {
    let fields = [
        arguments.get("--previous-checkpoint"),
        arguments.get("--previous-signer-id"),
        arguments.get("--previous-signature"),
    ];
    if fields.iter().all(|field| field.is_none()) {
        return Ok(None);
    }
    if fields.iter().any(|field| field.is_none()) {
        return Err(
            "previous checkpoint, signer ID and signature must be supplied together".into(),
        );
    }
    let checkpoint = read_bounded(
        fields[0].expect("checked above"),
        MAX_RETENTION_CHECKPOINT_BYTES,
    )?;
    let signature = read_bounded(fields[2].expect("checked above"), 64)?;
    if signature.len() != 64 {
        return Err("previous signature must be 64 raw bytes".into());
    }
    let signer_id = fields[1]
        .expect("checked above")
        .to_str()
        .ok_or("previous signer ID must be UTF-8")?;
    verify_retention_checkpoint(
        &checkpoint,
        signer_id,
        &signature,
        checkpoint_policy,
        required(arguments, "--checkpoint-policy-sha256")?
            .to_str()
            .ok_or("checkpoint policy pin must be UTF-8")?,
    )
    .map(Some)
    .map_err(|error| format!("previous checkpoint: {error}"))
}

fn required<'a>(arguments: &'a BTreeMap<String, PathBuf>, name: &str) -> Result<&'a Path, String> {
    arguments
        .get(name)
        .map(PathBuf::as_path)
        .ok_or_else(|| format!("missing required argument: {name}"))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(format!("{} has invalid size or type", path.display()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(format!("{} changed or exceeded its limit", path.display()));
    }
    Ok(bytes)
}
