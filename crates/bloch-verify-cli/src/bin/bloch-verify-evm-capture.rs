use bloch_verify::secure_io::{read_secure, write_create};
use bloch_verify_core::{
    EvmRpcCapture, JsonRpcExchange, JsonRpcRequest, parse_evm_rpc_capture, parse_json_rpc_responses,
};
use std::collections::BTreeMap;
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloch-verify-evm-capture refused: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let arguments = collect(args)?;
    match command.as_str() {
        "request" => create_request(&arguments),
        "import" => import_response(&arguments),
        _ => Err(usage()),
    }
}

fn create_request(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(arguments, &["--out"])?;
    write_json_create(Path::new(one(arguments, "--out")?), &requests())
}

fn import_response(arguments: &[(String, String)]) -> Result<(), String> {
    exact_options(
        arguments,
        &[
            "--response",
            "--observer-id",
            "--organization-id",
            "--endpoint-sha256",
            "--observed-at",
            "--network",
            "--release-revision",
            "--capture-out",
        ],
    )?;
    let response_bytes = read_secure(Path::new(one(arguments, "--response")?), "RPC response")?;
    let responses = parse_json_rpc_responses(&response_bytes).map_err(|error| error.to_string())?;
    if responses.len() != 4 {
        return Err("batch response must contain exactly four entries".into());
    }
    let mut by_id = BTreeMap::new();
    for response in responses {
        let id = response.id;
        if by_id.insert(id, response).is_some() {
            return Err(format!("duplicate response id: {id}"));
        }
    }
    let mut request_by_id: BTreeMap<_, _> = requests()
        .into_iter()
        .map(|request| (request.id, request))
        .collect();
    let mut exchange = |id: u64| -> Result<JsonRpcExchange, String> {
        Ok(JsonRpcExchange {
            request: request_by_id
                .remove(&id)
                .ok_or_else(|| format!("internal request id missing: {id}"))?,
            response: by_id
                .remove(&id)
                .ok_or_else(|| format!("response id missing: {id}"))?,
        })
    };
    let capture = EvmRpcCapture {
        schema: "bloch.verify.evm-rpc-capture.v1".into(),
        observer_id: one(arguments, "--observer-id")?.into(),
        organization_id: one(arguments, "--organization-id")?.into(),
        endpoint_sha256: one(arguments, "--endpoint-sha256")?.into(),
        observed_at_unix_seconds: one(arguments, "--observed-at")?
            .parse()
            .map_err(|_| "--observed-at must be canonical Unix seconds")?,
        network: one(arguments, "--network")?.into(),
        release_revision: one(arguments, "--release-revision")?.into(),
        client_version: exchange(1)?,
        chain_id: exchange(2)?,
        genesis_block: exchange(3)?,
        finalized_block: exchange(4)?,
    };
    if !by_id.is_empty() {
        return Err("batch response contains an unknown response id".into());
    }
    let bytes = serde_json::to_vec(&capture)
        .map_err(|error| format!("cannot serialize capture: {error}"))?;
    parse_evm_rpc_capture(&bytes).map_err(|error| error.to_string())?;
    write_json_create(Path::new(one(arguments, "--capture-out")?), &capture)
}

fn requests() -> Vec<JsonRpcRequest> {
    vec![
        request(1, "web3_clientVersion", serde_json::json!([])),
        request(2, "eth_chainId", serde_json::json!([])),
        request(3, "eth_getBlockByNumber", serde_json::json!(["0x0", false])),
        request(
            4,
            "eth_getBlockByNumber",
            serde_json::json!(["finalized", false]),
        ),
    ]
}

fn request(id: u64, method: &str, params: serde_json::Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id,
        method: method.into(),
        params,
    }
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
    for (name, _) in arguments {
        if !expected.contains(&name.as_str()) {
            return Err(format!("unknown option: {name}"));
        }
    }
    for name in expected {
        if arguments
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            != 1
        {
            return Err(format!("exactly one {name} is required"));
        }
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

fn write_json_create(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot serialize output: {error}"))?;
    bytes.push(b'\n');
    write_create(path, &bytes)
}

fn usage() -> String {
    "usage:\n  bloch-verify-evm-capture request --out <new-json>\n  bloch-verify-evm-capture import --response <batch-json> --observer-id <id> --organization-id <id> --endpoint-sha256 <0x-sha256> --observed-at <unix-seconds> --network <id> --release-revision <0x-git-revision> --capture-out <new-json>".into()
}
