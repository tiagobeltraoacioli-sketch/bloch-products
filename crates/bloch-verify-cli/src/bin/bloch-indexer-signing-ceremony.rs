use bloch_indexer_core::{ChainIdentity, outbox::OutboxRecord};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, build_delivery_signature_message, build_receipt_signature_message,
    canonical_record_bytes, encode_accepted_receipt, encode_delivery, parse_trust_policy,
    verify_accepted_receipt, verify_delivery,
};
use bloch_indexer_receiver_core::{
    AcceptanceStatus, import_acceptance_signature, prepare_acceptance,
};
use bloch_verify::secure_io::{read_secure, write_create};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{env, path::Path, process::ExitCode};

const DELIVERY_REQUEST_SCHEMA: &str = "bloch.data.delivery-signing-request.v1";
const RECEIPT_REQUEST_SCHEMA: &str = "bloch.data.receipt-signing-request.v1";
const MAX_REQUEST_BYTES: usize = 768 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryRequest {
    schema: String,
    trust_policy_sha256: String,
    destination_domain: String,
    network: ChainIdentity,
    signer_id: String,
    attempt: u32,
    generation: u64,
    canonical_record_hex: String,
    message_hex: String,
    message_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReceiptRequest {
    schema: String,
    trust_policy_sha256: String,
    destination_domain: String,
    network: ChainIdentity,
    signer_id: String,
    canonical_delivery_hex: String,
    delivery_sha256: String,
    record_id: String,
    attempt: u32,
    generation: u64,
    message_hex: String,
    message_sha256: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-indexer-signing-ceremony refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    let options = collect(arguments)?;
    match command.as_str() {
        "prepare-delivery" => prepare_delivery(&options),
        "import-delivery" => import_delivery(&options),
        "prepare-receipt" => prepare_receipt(&options),
        "import-receipt" => import_receipt(&options),
        "receiver-prepare" => receiver_prepare(&options),
        "receiver-import" => receiver_import(&options),
        _ => Err(usage()),
    }
}

fn receiver_prepare(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--transport-request",
            "--store",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--receiver-id",
            "--message-out",
            "--response-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let request = read_secure(
        Path::new(one(arguments, "--transport-request")?),
        "authenticated transport request",
    )?;
    let status = prepare_acceptance(
        Path::new(one(arguments, "--store")?),
        &request,
        &policy,
        pin,
        one(arguments, "--receiver-id")?,
    )
    .map_err(stringify)?;
    match status {
        AcceptanceStatus::AwaitingSignature(prepared) => recoverable_write(
            Path::new(one(arguments, "--message-out")?),
            prepared.receipt_signature_message(),
        ),
        AcceptanceStatus::Completed(response) => recoverable_write(
            Path::new(one(arguments, "--response-out")?),
            response.response_bytes(),
        ),
    }
}

fn receiver_import(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--transport-request",
            "--store",
            "--signature",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--receiver-id",
            "--response-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let request = read_secure(
        Path::new(one(arguments, "--transport-request")?),
        "authenticated transport request",
    )?;
    let signature = signature(arguments)?;
    let response = import_acceptance_signature(
        Path::new(one(arguments, "--store")?),
        &request,
        &signature,
        &policy,
        pin,
        one(arguments, "--receiver-id")?,
    )
    .map_err(stringify)?;
    recoverable_write(
        Path::new(one(arguments, "--response-out")?),
        response.response_bytes(),
    )
}

fn prepare_delivery(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--record",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--sender-id",
            "--attempt",
            "--generation",
            "--request-out",
            "--message-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let signer_id = one(arguments, "--sender-id")?;
    require_signer(&policy, signer_id, true)?;
    let record_bytes = read_secure(Path::new(one(arguments, "--record")?), "outbox record")?;
    let record: OutboxRecord = serde_json::from_slice(&record_bytes)
        .map_err(|error| format!("invalid outbox record JSON: {error}"))?;
    let canonical_record = canonical_record_bytes(&record).map_err(stringify)?;
    let attempt = number::<u32>(arguments, "--attempt")?;
    let generation = number::<u64>(arguments, "--generation")?;
    let message = build_delivery_signature_message(
        &policy.destination_domain,
        &policy.network,
        signer_id,
        attempt,
        generation,
        &canonical_record,
    )
    .map_err(stringify)?;
    let request = DeliveryRequest {
        schema: DELIVERY_REQUEST_SCHEMA.into(),
        trust_policy_sha256: pin.into(),
        destination_domain: policy.destination_domain,
        network: policy.network,
        signer_id: signer_id.into(),
        attempt,
        generation,
        canonical_record_hex: encode_hex(&canonical_record),
        message_hex: encode_hex(&message),
        message_sha256: sha256(&message),
    };
    recoverable_write(
        Path::new(one(arguments, "--request-out")?),
        &serde_json::to_vec(&request).map_err(stringify)?,
    )?;
    recoverable_write(Path::new(one(arguments, "--message-out")?), &message)
}

fn import_delivery(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--request",
            "--signature",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--delivery-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let request: DeliveryRequest = canonical_request(
        &read_secure(
            Path::new(one(arguments, "--request")?),
            "delivery signing request",
        )?,
        DELIVERY_REQUEST_SCHEMA,
    )?;
    if request.trust_policy_sha256 != pin
        || request.destination_domain != policy.destination_domain
        || request.network != policy.network
    {
        return Err("request does not match the independently pinned trust policy".into());
    }
    require_signer(&policy, &request.signer_id, true)?;
    let record = decode_hex(
        &request.canonical_record_hex,
        64 * 1024,
        "canonicalRecordHex",
    )?;
    let message = build_delivery_signature_message(
        &request.destination_domain,
        &request.network,
        &request.signer_id,
        request.attempt,
        request.generation,
        &record,
    )
    .map_err(stringify)?;
    verify_request_message(&message, &request.message_hex, &request.message_sha256)?;
    let signature = signature(arguments)?;
    let delivery = encode_delivery(
        &request.destination_domain,
        &request.network,
        &request.signer_id,
        request.attempt,
        request.generation,
        &record,
        &signature,
    )
    .map_err(stringify)?;
    verify_delivery(&delivery, &policy).map_err(stringify)?;
    recoverable_write(Path::new(one(arguments, "--delivery-out")?), &delivery)
}

fn prepare_receipt(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--delivery",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--receiver-id",
            "--request-out",
            "--message-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let signer_id = one(arguments, "--receiver-id")?;
    require_signer(&policy, signer_id, false)?;
    let delivery_bytes = read_secure(Path::new(one(arguments, "--delivery")?), "delivery")?;
    let delivery = verify_delivery(&delivery_bytes, &policy).map_err(stringify)?;
    let message = build_receipt_signature_message(
        &policy.destination_domain,
        &policy.network,
        signer_id,
        delivery.sha256(),
        &delivery.record().id,
        delivery.attempt(),
        delivery.generation(),
    )
    .map_err(stringify)?;
    let request = ReceiptRequest {
        schema: RECEIPT_REQUEST_SCHEMA.into(),
        trust_policy_sha256: pin.into(),
        destination_domain: policy.destination_domain,
        network: policy.network,
        signer_id: signer_id.into(),
        canonical_delivery_hex: encode_hex(&delivery_bytes),
        delivery_sha256: delivery.sha256().into(),
        record_id: delivery.record().id.clone(),
        attempt: delivery.attempt(),
        generation: delivery.generation(),
        message_hex: encode_hex(&message),
        message_sha256: sha256(&message),
    };
    recoverable_write(
        Path::new(one(arguments, "--request-out")?),
        &serde_json::to_vec(&request).map_err(stringify)?,
    )?;
    recoverable_write(Path::new(one(arguments, "--message-out")?), &message)
}

fn import_receipt(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--request",
            "--signature",
            "--trust-policy",
            "--expected-trust-policy-sha256",
            "--receipt-out",
        ],
    )?;
    let pin = one(arguments, "--expected-trust-policy-sha256")?;
    let policy = policy(arguments, pin)?;
    let request: ReceiptRequest = canonical_request(
        &read_secure(
            Path::new(one(arguments, "--request")?),
            "receipt signing request",
        )?,
        RECEIPT_REQUEST_SCHEMA,
    )?;
    if request.trust_policy_sha256 != pin
        || request.destination_domain != policy.destination_domain
        || request.network != policy.network
    {
        return Err("request does not match the independently pinned trust policy".into());
    }
    require_signer(&policy, &request.signer_id, false)?;
    let delivery_bytes = decode_hex(
        &request.canonical_delivery_hex,
        256 * 1024,
        "canonicalDeliveryHex",
    )?;
    let delivery = verify_delivery(&delivery_bytes, &policy).map_err(stringify)?;
    if delivery.sha256() != request.delivery_sha256
        || delivery.record().id != request.record_id
        || delivery.attempt() != request.attempt
        || delivery.generation() != request.generation
    {
        return Err("receipt request does not match its authenticated delivery".into());
    }
    let message = build_receipt_signature_message(
        &request.destination_domain,
        &request.network,
        &request.signer_id,
        &request.delivery_sha256,
        &request.record_id,
        request.attempt,
        request.generation,
    )
    .map_err(stringify)?;
    verify_request_message(&message, &request.message_hex, &request.message_sha256)?;
    let signature = signature(arguments)?;
    let receipt = encode_accepted_receipt(
        &request.destination_domain,
        &request.network,
        &request.signer_id,
        &delivery,
        &signature,
    )
    .map_err(stringify)?;
    verify_accepted_receipt(&receipt, &delivery_bytes, &policy).map_err(stringify)?;
    recoverable_write(Path::new(one(arguments, "--receipt-out")?), &receipt)
}

fn policy(arguments: &[(String, String)], pin: &str) -> Result<TrustPolicy, String> {
    let bytes = read_secure(
        Path::new(one(arguments, "--trust-policy")?),
        "delivery trust policy",
    )?;
    parse_trust_policy(&bytes, pin).map_err(stringify)
}

fn require_signer(policy: &TrustPolicy, signer_id: &str, sender: bool) -> Result<(), String> {
    let signers = if sender {
        &policy.senders
    } else {
        &policy.receivers
    };
    if signers.iter().any(|signer| signer.signer_id == signer_id) {
        Ok(())
    } else {
        Err(format!(
            "{} is not trusted for the requested signer role",
            signer_id
        ))
    }
}

fn canonical_request<T>(bytes: &[u8], schema: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("signing request exceeds its byte limit".into());
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid signing request JSON: {error}"))?;
    let canonical = serde_json::to_vec(&value).map_err(stringify)?;
    if canonical != bytes {
        return Err("signing request is not canonical JSON".into());
    }
    let document: serde_json::Value = serde_json::from_slice(bytes).map_err(stringify)?;
    if document.get("schema").and_then(|value| value.as_str()) != Some(schema) {
        return Err("unexpected signing request schema".into());
    }
    Ok(value)
}

fn verify_request_message(message: &[u8], encoded: &str, digest: &str) -> Result<(), String> {
    if decode_hex(encoded, 512 * 1024, "messageHex")? != message || sha256(message) != digest {
        return Err("signing request message commitment mismatch".into());
    }
    Ok(())
}

fn signature(arguments: &[(String, String)]) -> Result<Vec<u8>, String> {
    let bytes = read_secure(
        Path::new(one(arguments, "--signature")?),
        "raw Ed25519 signature",
    )?;
    if bytes.len() != 64 {
        return Err("Ed25519 signature must contain exactly 64 raw bytes".into());
    }
    Ok(bytes)
}

fn recoverable_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match write_create(path, bytes) {
        Ok(()) => Ok(()),
        Err(create_error) => match read_secure(path, "existing ceremony output") {
            Ok(existing) if existing == bytes => Ok(()),
            _ => Err(format!(
                "cannot create {} and no identical recoverable output exists: {create_error}",
                path.display()
            )),
        },
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decode_hex(value: &str, maximum: usize, field: &str) -> Result<Vec<u8>, String> {
    if !value.starts_with("0x")
        || !value.len().is_multiple_of(2)
        || value.len().saturating_sub(2) / 2 > maximum
        || !value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!("invalid {field}"));
    }
    hex::decode(&value[2..]).map_err(|_| format!("invalid {field}"))
}

fn sha256(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn collect(mut args: impl Iterator<Item = String>) -> Result<Vec<(String, String)>, String> {
    let mut result = Vec::new();
    while let Some(name) = args.next() {
        if !name.starts_with("--") {
            return Err(format!("unexpected argument: {name}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{name} requires a value"))?;
        result.push((name, value));
    }
    Ok(result)
}

fn exact_options(arguments: &[(String, String)], expected: &[&str]) -> Result<(), String> {
    if arguments.len() != expected.len() {
        return Err("missing or repeated command options".into());
    }
    for expected_name in expected {
        if arguments
            .iter()
            .filter(|(name, _)| name == expected_name)
            .count()
            != 1
        {
            return Err(format!("exactly one {expected_name} is required"));
        }
    }
    if let Some((name, _)) = arguments
        .iter()
        .find(|(name, _)| !expected.contains(&name.as_str()))
    {
        return Err(format!("unknown option: {name}"));
    }
    Ok(())
}

fn one<'a>(arguments: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    arguments
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("exactly one {name} is required"))
}

fn number<T>(arguments: &[(String, String)], name: &str) -> Result<T, String>
where
    T: std::str::FromStr + ToString,
{
    let encoded = one(arguments, name)?;
    let parsed = encoded
        .parse::<T>()
        .map_err(|_| format!("{name} must be a canonical unsigned integer"))?;
    if parsed.to_string() != encoded {
        return Err(format!("{name} must be a canonical unsigned integer"));
    }
    Ok(parsed)
}

fn stringify(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn usage() -> String {
    "usage:\n  bloch-indexer-signing-ceremony prepare-delivery --record <json> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --sender-id <id> --attempt <u32> --generation <u64> --request-out <new-json> --message-out <new-bin>\n  bloch-indexer-signing-ceremony import-delivery --request <json> --signature <raw-64-byte-file> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --delivery-out <new-json>\n  bloch-indexer-signing-ceremony prepare-receipt --delivery <json> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --receiver-id <id> --request-out <new-json> --message-out <new-bin>\n  bloch-indexer-signing-ceremony import-receipt --request <json> --signature <raw-64-byte-file> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --receipt-out <new-json>\n  bloch-indexer-signing-ceremony receiver-prepare --transport-request <json> --store <private-dir> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --receiver-id <id> --message-out <new-bin> --response-out <new-json>\n  bloch-indexer-signing-ceremony receiver-import --transport-request <json> --store <private-dir> --signature <raw-64-byte-file> --trust-policy <json> --expected-trust-policy-sha256 <0x-sha256> --receiver-id <id> --response-out <new-json>".into()
}
