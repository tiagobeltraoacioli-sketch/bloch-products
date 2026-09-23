//! Crash-safe, single-host staging for externally signed CAS receipts.

use bloch_local_state_remote_cursor::{
    RemoteCursorCasDecision, RemoteCursorCasError, RemoteCursorPolicy, RemoteCursorSignature,
    VerifiedRemoteCursorCasReceipt, create_remote_cursor_cas_receipt,
    parse_remote_cursor_cas_request, remote_cursor_cas_receipt_signature_message,
    verify_remote_cursor_cas_receipt,
};
use bloch_local_state_remote_cursor_control_plane::ControlPlaneDecision;
use bloch_trusted_time::VerifiedTrustedTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};
use thiserror::Error;

pub const RECEIPT_STAGING_SCHEMA: &str = "bloch.products.remote-cursor-receipt-staging.v1";
pub const RECEIPT_SIGNING_REQUEST_SCHEMA: &str =
    "bloch.products.remote-cursor-receipt-signing-request.v1";
pub const RECEIPT_SIGNATURE_BUNDLE_SCHEMA: &str =
    "bloch.products.remote-cursor-receipt-signature-bundle.v1";
pub const MAX_RECEIPT_SIGNATURE_BUNDLE_BYTES: usize = 128 * 1024;
const MAX_STATE_BYTES: u64 = 256 * 1024;
#[cfg(unix)]
const MAX_LOCK_WAIT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableState {
    schema: String,
    remote_cursor_policy_sha256: String,
    signature_domain: String,
    state_identity: String,
    request_sha256: String,
    request_bytes: Vec<u8>,
    decision: RemoteCursorCasDecision,
    decided_at_unix_seconds: u64,
    signing_message_sha256: String,
    signing_message: Vec<u8>,
    receipt_sha256: Option<String>,
    receipt_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiptSigning {
    request_sha256: String,
    signing_message_sha256: String,
    signing_message: Vec<u8>,
    imported_receipt_sha256: Option<String>,
}

impl PreparedReceiptSigning {
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn signing_message_sha256(&self) -> &str {
        &self.signing_message_sha256
    }
    pub fn signing_message(&self) -> &[u8] {
        &self.signing_message
    }
    pub fn imported_receipt_sha256(&self) -> Option<&str> {
        self.imported_receipt_sha256.as_deref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedReceipt {
    receipt_sha256: String,
    receipt_bytes: Vec<u8>,
}

/// Non-secret metadata suitable for operational inspection. Exact request,
/// signing-message, receipt, and signatures are deliberately omitted.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptStagingInspection {
    pub schema: &'static str,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub request_sha256: String,
    pub decision: RemoteCursorCasDecision,
    pub decided_at_unix_seconds: u64,
    pub signing_message_sha256: String,
    pub receipt_sha256: Option<String>,
}

/// Canonical artifact transferred to an offline signer. This contains no
/// private key or signature, but the signing message is ceremony material and
/// should be exported only to an owner-only file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReceiptSigningRequest {
    pub schema: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub signature_domain: String,
    pub request_sha256: String,
    pub decision: RemoteCursorCasDecision,
    pub decided_at_unix_seconds: u64,
    pub signing_message_sha256: String,
    pub signing_message_hex: String,
}

/// Canonical detached signatures returned by external authorities/HSMs.
///
/// Every audience field is repeated deliberately so a bundle cannot be moved
/// between staged operations. Signatures must be strictly ordered by authority
/// ID; parsing never silently normalizes an ambiguous or duplicate bundle.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReceiptSignatureBundle {
    pub schema: String,
    pub state_identity: String,
    pub remote_cursor_policy_sha256: String,
    pub signature_domain: String,
    pub request_sha256: String,
    pub signing_message_sha256: String,
    pub signatures: Vec<RemoteCursorSignature>,
}

impl StagedReceipt {
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
}

pub struct ReceiptImport<'a> {
    pub request_bytes: &'a [u8],
    pub policy: &'a RemoteCursorPolicy,
    pub expected_policy_sha256: &'a str,
    pub decision: &'a RemoteCursorCasDecision,
    pub decided_at_unix_seconds: u64,
    pub evaluated_at_unix_seconds: u64,
}

#[derive(Debug, Error)]
pub enum ReceiptStagingError {
    #[error("receipt staging input is invalid")]
    InvalidInput,
    #[error("receipt staging operation is missing")]
    StateMissing,
    #[error("receipt staging operation conflicts with an existing operation")]
    Conflict,
    #[error("trusted-time capability does not match the CAS audience")]
    TrustedTimeAudienceMismatch,
    #[error("trusted-time capability has expired")]
    TrustedTimeExpired,
    #[error("receipt staging store is busy")]
    StoreBusy,
    #[error("receipt staging state is invalid or non-canonical")]
    InvalidState,
    #[error("receipt signature bundle is invalid or non-canonical")]
    InvalidSignatureBundle,
    #[error("unsafe receipt staging store: {0}")]
    UnsafeStore(&'static str),
    #[error("receipt staging is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("remote cursor receipt validation failed: {0}")]
    Receipt(#[from] RemoteCursorCasError),
    #[error("receipt staging I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Parses an exact canonical detached-signature bundle.
pub fn parse_receipt_signature_bundle(
    bytes: &[u8],
) -> Result<ReceiptSignatureBundle, ReceiptStagingError> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_SIGNATURE_BUNDLE_BYTES {
        return Err(ReceiptStagingError::InvalidSignatureBundle);
    }
    let bundle: ReceiptSignatureBundle =
        serde_json::from_slice(bytes).map_err(|_| ReceiptStagingError::InvalidSignatureBundle)?;
    let canonical =
        serde_json::to_vec(&bundle).map_err(|_| ReceiptStagingError::InvalidSignatureBundle)?;
    if canonical != bytes
        || bundle.schema != RECEIPT_SIGNATURE_BUNDLE_SCHEMA
        || !valid_sha256(&bundle.remote_cursor_policy_sha256)
        || !valid_sha256(&bundle.request_sha256)
        || !valid_sha256(&bundle.signing_message_sha256)
        || bundle.signatures.is_empty()
    {
        return Err(ReceiptStagingError::InvalidSignatureBundle);
    }
    let mut previous: Option<&str> = None;
    for signature in &bundle.signatures {
        if signature.authority_id.is_empty()
            || previous.is_some_and(|found| found >= signature.authority_id.as_str())
        {
            return Err(ReceiptStagingError::InvalidSignatureBundle);
        }
        previous = Some(&signature.authority_id);
    }
    Ok(bundle)
}

/// Offline-only assembly from immutable staging and detached signatures.
///
/// This uses the decision time retained in staging, performs no wall-clock or
/// network access, verifies the signature threshold against the pinned policy,
/// and does not publish the receipt into the production staging state.
#[cfg(unix)]
pub fn assemble_receipt_from_signature_bundle(
    store: &Path,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    bundle_bytes: &[u8],
) -> Result<Vec<u8>, ReceiptStagingError> {
    let bundle = parse_receipt_signature_bundle(bundle_bytes)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    let expected = make_pending(
        &state.request_bytes,
        policy,
        expected_policy_sha256,
        &state.decision,
        state.decided_at_unix_seconds,
    )?;
    if !same_operation(&state, &expected)
        || bundle.state_identity != state.state_identity
        || bundle.remote_cursor_policy_sha256 != state.remote_cursor_policy_sha256
        || bundle.signature_domain != state.signature_domain
        || bundle.request_sha256 != state.request_sha256
        || bundle.signing_message_sha256 != state.signing_message_sha256
    {
        return Err(ReceiptStagingError::Conflict);
    }
    let receipt = create_remote_cursor_cas_receipt(
        &state.request_bytes,
        policy,
        expected_policy_sha256,
        &state.decision,
        state.decided_at_unix_seconds,
        &bundle.signatures,
    )?;
    // Re-run the complete verifier using the staged decision time only. This
    // authenticates the request, audience, threshold and detached signatures;
    // it deliberately does not assert current freshness.
    let verified = verify_remote_cursor_cas_receipt(
        &receipt,
        &state.request_bytes,
        policy,
        expected_policy_sha256,
        state.decided_at_unix_seconds,
    )?;
    if !decision_matches(&verified, &state.decision) {
        return Err(ReceiptStagingError::Conflict);
    }
    Ok(receipt)
}

#[cfg(not(unix))]
pub fn assemble_receipt_from_signature_bundle(
    _: &Path,
    _: &RemoteCursorPolicy,
    _: &str,
    _: &[u8],
) -> Result<Vec<u8>, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

/// Reads validated staging metadata without exposing the staged payloads.
#[cfg(unix)]
pub fn inspect_receipt_staging(
    store: &Path,
) -> Result<ReceiptStagingInspection, ReceiptStagingError> {
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    Ok(ReceiptStagingInspection {
        schema: RECEIPT_STAGING_SCHEMA,
        state_identity: state.state_identity,
        remote_cursor_policy_sha256: state.remote_cursor_policy_sha256,
        request_sha256: state.request_sha256,
        decision: state.decision,
        decided_at_unix_seconds: state.decided_at_unix_seconds,
        signing_message_sha256: state.signing_message_sha256,
        receipt_sha256: state.receipt_sha256,
    })
}

/// Returns the exact canonical signing request for create-once file export.
#[cfg(unix)]
pub fn export_receipt_signing_request(store: &Path) -> Result<Vec<u8>, ReceiptStagingError> {
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    let export = ReceiptSigningRequest {
        schema: RECEIPT_SIGNING_REQUEST_SCHEMA.into(),
        state_identity: state.state_identity,
        remote_cursor_policy_sha256: state.remote_cursor_policy_sha256,
        signature_domain: state.signature_domain,
        request_sha256: state.request_sha256,
        decision: state.decision,
        decided_at_unix_seconds: state.decided_at_unix_seconds,
        signing_message_sha256: state.signing_message_sha256,
        signing_message_hex: format!("0x{}", hex_string(&state.signing_message)),
    };
    serde_json::to_vec(&export).map_err(|_| ReceiptStagingError::InvalidState)
}

#[cfg(not(unix))]
pub fn inspect_receipt_staging(_: &Path) -> Result<ReceiptStagingInspection, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub fn export_receipt_signing_request(_: &Path) -> Result<Vec<u8>, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

/// Preferred preparation path: the request, decision, and decision time come
/// from independently opaque capabilities rather than operator-selected data.
pub fn prepare_from_control_plane_decision(
    store: &Path,
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    control: &ControlPlaneDecision,
    trusted_time: &VerifiedTrustedTime,
) -> Result<PreparedReceiptSigning, ReceiptStagingError> {
    bind_control_decision(request_bytes, policy, expected_policy_sha256, control)?;
    let decided_at = trusted_time_for_policy(trusted_time, policy, expected_policy_sha256)?;
    prepare_remote_cursor_cas_receipt(
        store,
        request_bytes,
        policy,
        expected_policy_sha256,
        control.decision(),
        decided_at,
    )
}

/// Compatibility/offline-ceremony preparation with operator-supplied time.
#[cfg(unix)]
pub fn prepare_remote_cursor_cas_receipt(
    store: &Path,
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    decision: &RemoteCursorCasDecision,
    decided_at_unix_seconds: u64,
) -> Result<PreparedReceiptSigning, ReceiptStagingError> {
    let expected = make_pending(
        request_bytes,
        policy,
        expected_policy_sha256,
        decision,
        decided_at_unix_seconds,
    )?;
    match std::fs::symlink_metadata(store) {
        Ok(_) => {
            let directory = open_store(store)?;
            let _lock = StoreLock::acquire(&directory)?;
            verify_store_path(store, &directory)?;
            let found = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
            if !same_operation(&found, &expected) {
                return Err(ReceiptStagingError::Conflict);
            }
            prepared(&found)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(error) = builder.create(store) {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    let directory = open_store(store)?;
                    let _lock = StoreLock::acquire(&directory)?;
                    verify_store_path(store, &directory)?;
                    let found = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
                    if !same_operation(&found, &expected) {
                        return Err(ReceiptStagingError::Conflict);
                    }
                    return prepared(&found);
                }
                return Err(error.into());
            }
            let directory = open_directory(store)?;
            sync_parent_directory(store)?;
            let lock = create_file_exclusive(&directory, "store.lock")?;
            validate_file(&lock.metadata()?)?;
            lock.sync_all()?;
            directory.sync_all()?;
            let _lock = StoreLock::acquire(&directory)?;
            atomic_replace(&directory, &encode_state(&expected)?)?;
            let found = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
            if found != expected {
                return Err(ReceiptStagingError::InvalidState);
            }
            verify_store_path(store, &directory)?;
            prepared(&found)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
pub fn prepare_remote_cursor_cas_receipt(
    _: &Path,
    _: &[u8],
    _: &RemoteCursorPolicy,
    _: &str,
    _: &RemoteCursorCasDecision,
    _: u64,
) -> Result<PreparedReceiptSigning, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

/// Compatibility/offline-ceremony path with operator-supplied evaluation time.
pub fn import_remote_cursor_cas_signatures(
    store: &Path,
    import: ReceiptImport<'_>,
    signatures: &[RemoteCursorSignature],
) -> Result<StagedReceipt, ReceiptStagingError> {
    let receipt = create_remote_cursor_cas_receipt(
        import.request_bytes,
        import.policy,
        import.expected_policy_sha256,
        import.decision,
        import.decided_at_unix_seconds,
        signatures,
    )?;
    import_remote_cursor_cas_receipt(store, import, &receipt)
}

/// Preferred import path for detached authority signatures.
pub fn import_remote_cursor_cas_signatures_with_trusted_time(
    store: &Path,
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    control: &ControlPlaneDecision,
    signatures: &[RemoteCursorSignature],
    trusted_time: &VerifiedTrustedTime,
) -> Result<StagedReceipt, ReceiptStagingError> {
    let staged = load_bound_operation(
        store,
        request_bytes,
        policy,
        expected_policy_sha256,
        control,
    )?;
    let evaluated_at = trusted_time_for_policy(trusted_time, policy, expected_policy_sha256)?;
    let receipt = create_remote_cursor_cas_receipt(
        request_bytes,
        policy,
        expected_policy_sha256,
        control.decision(),
        staged.decided_at_unix_seconds,
        signatures,
    )?;
    import_receipt_core(
        store,
        ReceiptImport {
            request_bytes,
            policy,
            expected_policy_sha256,
            decision: control.decision(),
            decided_at_unix_seconds: staged.decided_at_unix_seconds,
            evaluated_at_unix_seconds: evaluated_at,
        },
        &receipt,
        || {
            trusted_time
                .unix_seconds()
                .map(|_| ())
                .map_err(|_| ReceiptStagingError::TrustedTimeExpired)
        },
    )
}

/// Compatibility/offline-ceremony path with operator-supplied evaluation time.
#[cfg(unix)]
pub fn import_remote_cursor_cas_receipt(
    store: &Path,
    import: ReceiptImport<'_>,
    receipt_bytes: &[u8],
) -> Result<StagedReceipt, ReceiptStagingError> {
    import_receipt_core(store, import, receipt_bytes, || Ok(()))
}

/// Explicit offline-ceremony compatibility path. It binds the import to the
/// immutable operation already in the store, but its evaluation time is
/// operator supplied and therefore this function is not a production gate.
#[cfg(unix)]
pub fn ceremony_import_receipt_with_operator_time(
    store: &Path,
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    receipt_bytes: &[u8],
    evaluated_at_unix_seconds: u64,
) -> Result<StagedReceipt, ReceiptStagingError> {
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let state = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    drop(_lock);
    drop(directory);
    if state.remote_cursor_policy_sha256 != expected_policy_sha256
        || state.state_identity != policy.state_identity
        || state.signature_domain != policy.signature_domain
    {
        return Err(ReceiptStagingError::Conflict);
    }
    let expected = make_pending(
        &state.request_bytes,
        policy,
        expected_policy_sha256,
        &state.decision,
        state.decided_at_unix_seconds,
    )?;
    if !same_operation(&state, &expected) {
        return Err(ReceiptStagingError::Conflict);
    }
    import_remote_cursor_cas_receipt(
        store,
        ReceiptImport {
            request_bytes: &state.request_bytes,
            policy,
            expected_policy_sha256,
            decision: &state.decision,
            decided_at_unix_seconds: state.decided_at_unix_seconds,
            evaluated_at_unix_seconds,
        },
        receipt_bytes,
    )
}

#[cfg(not(unix))]
pub fn ceremony_import_receipt_with_operator_time(
    _: &Path,
    _: &RemoteCursorPolicy,
    _: &str,
    _: &[u8],
    _: u64,
) -> Result<StagedReceipt, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

#[cfg(unix)]
fn import_receipt_core(
    store: &Path,
    import: ReceiptImport<'_>,
    receipt_bytes: &[u8],
    mut freshness_guard: impl FnMut() -> Result<(), ReceiptStagingError>,
) -> Result<StagedReceipt, ReceiptStagingError> {
    let expected = make_pending(
        import.request_bytes,
        import.policy,
        import.expected_policy_sha256,
        import.decision,
        import.decided_at_unix_seconds,
    )?;
    let verified = verify_remote_cursor_cas_receipt(
        receipt_bytes,
        import.request_bytes,
        import.policy,
        import.expected_policy_sha256,
        import.evaluated_at_unix_seconds,
    )?;
    if !decision_matches(&verified, import.decision) {
        return Err(ReceiptStagingError::Conflict);
    }
    let receipt_sha256 = hash(receipt_bytes);
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    cleanup_stale_temporary_files(&directory)?;
    let current = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    if !same_operation(&current, &expected) {
        return Err(ReceiptStagingError::Conflict);
    }
    if let (Some(found_hash), Some(found_bytes)) = (&current.receipt_sha256, &current.receipt_bytes)
    {
        return if found_hash == &receipt_sha256 && found_bytes == receipt_bytes {
            freshness_guard()?;
            Ok(StagedReceipt {
                receipt_sha256,
                receipt_bytes: receipt_bytes.to_vec(),
            })
        } else {
            Err(ReceiptStagingError::Conflict)
        };
    }
    if current.receipt_sha256.is_some() || current.receipt_bytes.is_some() {
        return Err(ReceiptStagingError::InvalidState);
    }
    let mut next = current;
    next.receipt_sha256 = Some(receipt_sha256.clone());
    next.receipt_bytes = Some(receipt_bytes.to_vec());
    atomic_replace_guarded(&directory, &encode_state(&next)?, &mut freshness_guard)?;
    let published = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    if published != next {
        return Err(ReceiptStagingError::InvalidState);
    }
    verify_store_path(store, &directory)?;
    Ok(StagedReceipt {
        receipt_sha256,
        receipt_bytes: receipt_bytes.to_vec(),
    })
}

/// Preferred import path for a complete externally assembled receipt.
pub fn import_remote_cursor_cas_receipt_with_trusted_time(
    store: &Path,
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    expected_policy_sha256: &str,
    control: &ControlPlaneDecision,
    receipt_bytes: &[u8],
    trusted_time: &VerifiedTrustedTime,
) -> Result<StagedReceipt, ReceiptStagingError> {
    let staged = load_bound_operation(
        store,
        request_bytes,
        policy,
        expected_policy_sha256,
        control,
    )?;
    let evaluated_at = trusted_time_for_policy(trusted_time, policy, expected_policy_sha256)?;
    import_receipt_core(
        store,
        ReceiptImport {
            request_bytes,
            policy,
            expected_policy_sha256,
            decision: control.decision(),
            decided_at_unix_seconds: staged.decided_at_unix_seconds,
            evaluated_at_unix_seconds: evaluated_at,
        },
        receipt_bytes,
        || {
            trusted_time
                .unix_seconds()
                .map(|_| ())
                .map_err(|_| ReceiptStagingError::TrustedTimeExpired)
        },
    )
}

#[cfg(not(unix))]
pub fn import_remote_cursor_cas_receipt(
    _: &Path,
    _: ReceiptImport<'_>,
    _: &[u8],
) -> Result<StagedReceipt, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

fn make_pending(
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    pin: &str,
    decision: &RemoteCursorCasDecision,
    decided: u64,
) -> Result<DurableState, ReceiptStagingError> {
    let request = parse_remote_cursor_cas_request(request_bytes, policy, pin)?;
    let signing_message =
        remote_cursor_cas_receipt_signature_message(request_bytes, policy, pin, decision, decided)?;
    Ok(DurableState {
        schema: RECEIPT_STAGING_SCHEMA.into(),
        remote_cursor_policy_sha256: pin.into(),
        signature_domain: policy.signature_domain.clone(),
        state_identity: policy.state_identity.clone(),
        request_sha256: request.request_sha256().into(),
        request_bytes: request_bytes.to_vec(),
        decision: decision.clone(),
        decided_at_unix_seconds: decided,
        signing_message_sha256: hash(&signing_message),
        signing_message,
        receipt_sha256: None,
        receipt_bytes: None,
    })
}

fn bind_control_decision(
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    pin: &str,
    control: &ControlPlaneDecision,
) -> Result<(), ReceiptStagingError> {
    let request = parse_remote_cursor_cas_request(request_bytes, policy, pin)?;
    if request.request_sha256() != control.request_sha256()
        || request.request_id() != control.request_id()
    {
        return Err(ReceiptStagingError::Conflict);
    }
    Ok(())
}

fn trusted_time_for_policy(
    trusted_time: &VerifiedTrustedTime,
    policy: &RemoteCursorPolicy,
    pin: &str,
) -> Result<u64, ReceiptStagingError> {
    if trusted_time.state_identity() != policy.state_identity
        || trusted_time.remote_cursor_policy_sha256() != pin
    {
        return Err(ReceiptStagingError::TrustedTimeAudienceMismatch);
    }
    trusted_time
        .unix_seconds()
        .map_err(|_| ReceiptStagingError::TrustedTimeExpired)
}

#[cfg(unix)]
fn load_bound_operation(
    store: &Path,
    request_bytes: &[u8],
    policy: &RemoteCursorPolicy,
    pin: &str,
    control: &ControlPlaneDecision,
) -> Result<DurableState, ReceiptStagingError> {
    bind_control_decision(request_bytes, policy, pin, control)?;
    let directory = open_store(store)?;
    let _lock = StoreLock::acquire(&directory)?;
    verify_store_path(store, &directory)?;
    let found = read_state(&directory)?.ok_or(ReceiptStagingError::StateMissing)?;
    let expected = make_pending(
        request_bytes,
        policy,
        pin,
        control.decision(),
        found.decided_at_unix_seconds,
    )?;
    if !same_operation(&found, &expected) {
        return Err(ReceiptStagingError::Conflict);
    }
    Ok(found)
}

#[cfg(not(unix))]
fn load_bound_operation(
    _: &Path,
    _: &[u8],
    _: &RemoteCursorPolicy,
    _: &str,
    _: &ControlPlaneDecision,
) -> Result<DurableState, ReceiptStagingError> {
    Err(ReceiptStagingError::UnsupportedPlatform)
}

fn same_operation(left: &DurableState, right: &DurableState) -> bool {
    left.schema == right.schema
        && left.remote_cursor_policy_sha256 == right.remote_cursor_policy_sha256
        && left.signature_domain == right.signature_domain
        && left.state_identity == right.state_identity
        && left.request_sha256 == right.request_sha256
        && left.request_bytes == right.request_bytes
        && left.decision == right.decision
        && left.decided_at_unix_seconds == right.decided_at_unix_seconds
        && left.signing_message_sha256 == right.signing_message_sha256
        && left.signing_message == right.signing_message
}

fn decision_matches(
    receipt: &VerifiedRemoteCursorCasReceipt,
    expected: &RemoteCursorCasDecision,
) -> bool {
    match (receipt, expected) {
        (VerifiedRemoteCursorCasReceipt::Accepted(_), RemoteCursorCasDecision::Accepted) => true,
        (
            VerifiedRemoteCursorCasReceipt::Refused(found),
            RemoteCursorCasDecision::Refused { reason_code },
        ) => found.reason_code() == reason_code,
        _ => false,
    }
}

fn prepared(state: &DurableState) -> Result<PreparedReceiptSigning, ReceiptStagingError> {
    validate_state(state)?;
    Ok(PreparedReceiptSigning {
        request_sha256: state.request_sha256.clone(),
        signing_message_sha256: state.signing_message_sha256.clone(),
        signing_message: state.signing_message.clone(),
        imported_receipt_sha256: state.receipt_sha256.clone(),
    })
}

fn validate_state(state: &DurableState) -> Result<(), ReceiptStagingError> {
    let receipt_pair = state.receipt_sha256.is_some() == state.receipt_bytes.is_some();
    if state.schema != RECEIPT_STAGING_SCHEMA
        || !valid_sha256(&state.remote_cursor_policy_sha256)
        || !valid_sha256(&state.request_sha256)
        || !valid_sha256(&state.signing_message_sha256)
        || state.request_bytes.is_empty()
        || state.request_bytes.len() > 64 * 1024
        || state.signing_message.is_empty()
        || state.signing_message.len() > 128 * 1024
        || hash(&state.request_bytes) != state.request_sha256
        || hash(&state.signing_message) != state.signing_message_sha256
        || !receipt_pair
        || state
            .receipt_bytes
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128 * 1024)
        || state
            .receipt_bytes
            .as_ref()
            .zip(state.receipt_sha256.as_ref())
            .is_some_and(|(b, h)| hash(b) != *h)
    {
        return Err(ReceiptStagingError::InvalidState);
    }
    Ok(())
}

fn encode_state(state: &DurableState) -> Result<Vec<u8>, ReceiptStagingError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| ReceiptStagingError::InvalidState)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ReceiptStagingError::InvalidState);
    }
    Ok(bytes)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex_string(&Sha256::digest(bytes)))
}
fn hex_string(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<File, ReceiptStagingError> {
    let d = open_directory(path)?;
    let l = open_existing_file(&d, "store.lock")?;
    validate_file(&l.metadata()?)?;
    validate_named_file(&d, "store.lock", &l.metadata()?)?;
    Ok(d)
}
#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, ReceiptStagingError> {
    use std::os::unix::fs::OpenOptionsExt;
    let linked = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReceiptStagingError::StateMissing
        } else {
            e.into()
        }
    })?;
    if linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(ReceiptStagingError::UnsafeStore("directory"));
    }
    let d = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = d.metadata()?;
    validate_directory(&opened)?;
    if !same_object(&linked, &opened) {
        return Err(ReceiptStagingError::UnsafeStore("directoryChanged"));
    }
    Ok(d)
}
#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ReceiptStagingError> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    f.sync_all()?;
    Ok(())
}
#[cfg(unix)]
fn verify_store_path(path: &Path, d: &File) -> Result<(), ReceiptStagingError> {
    let linked = std::fs::symlink_metadata(path)?;
    let opened = d.metadata()?;
    if linked.file_type().is_symlink() || !same_object(&linked, &opened) {
        return Err(ReceiptStagingError::UnsafeStore("directoryChanged"));
    }
    validate_directory(&opened)
}
#[cfg(unix)]
fn open_existing_file(d: &File, name: &str) -> Result<File, ReceiptStagingError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let n = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            n.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::NotFound {
            Err(ReceiptStagingError::StateMissing)
        } else {
            Err(e.into())
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
fn create_file_exclusive(d: &File, name: &str) -> Result<File, ReceiptStagingError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let n = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            n.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
struct StoreLock {
    file: File,
}
#[cfg(unix)]
impl StoreLock {
    fn acquire(d: &File) -> Result<Self, ReceiptStagingError> {
        use std::os::fd::AsRawFd;
        let f = open_existing_file(d, "store.lock")?;
        validate_file(&f.metadata()?)?;
        validate_named_file(d, "store.lock", &f.metadata()?)?;
        let deadline = Instant::now() + MAX_LOCK_WAIT;
        loop {
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { file: f });
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) && e.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(e.into());
            }
            if Instant::now() >= deadline {
                return Err(ReceiptStagingError::StoreBusy);
            }
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
    }
}
#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}
#[cfg(unix)]
fn read_state(d: &File) -> Result<Option<DurableState>, ReceiptStagingError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let n = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            n.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e.into())
        };
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    let before = f.metadata()?;
    validate_file(&before)?;
    validate_named_file(d, "state.json", &before)?;
    if before.len() == 0 || before.len() > MAX_STATE_BYTES {
        return Err(ReceiptStagingError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut f)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    validate_file(&after)?;
    validate_named_file(d, "state.json", &after)?;
    if !same_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(ReceiptStagingError::UnsafeStore("fileChanged"));
    }
    let s: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| ReceiptStagingError::InvalidState)?;
    if encode_state(&s)? != bytes {
        return Err(ReceiptStagingError::InvalidState);
    }
    Ok(Some(s))
}
#[cfg(unix)]
fn atomic_replace(d: &File, bytes: &[u8]) -> Result<(), ReceiptStagingError> {
    atomic_replace_guarded(d, bytes, &mut || Ok(()))
}
#[cfg(unix)]
fn atomic_replace_guarded(
    d: &File,
    bytes: &[u8],
    freshness_guard: &mut impl FnMut() -> Result<(), ReceiptStagingError>,
) -> Result<(), ReceiptStagingError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ReceiptStagingError::InvalidState);
    }
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|e| ReceiptStagingError::Io(std::io::Error::other(e.to_string())))?;
    let temp = format!(".state.json.tmp-{}", hex_string(&random));
    let t = c_name(&temp)?;
    let dest = c_name("state.json")?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            t.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        freshness_guard()?;
        if unsafe { libc::renameat(d.as_raw_fd(), t.as_ptr(), d.as_raw_fd(), dest.as_ptr()) } != 0 {
            return Err(ReceiptStagingError::Io(std::io::Error::last_os_error()));
        }
        d.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(d.as_raw_fd(), t.as_ptr(), 0) };
    }
    result
}
#[cfg(unix)]
fn cleanup_stale_temporary_files(d: &File) -> Result<(), ReceiptStagingError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    let dup = unsafe { libc::fcntl(d.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe { libc::close(dup) };
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            return Ok(());
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(".state.json.tmp-") else {
            continue;
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            continue;
        }
        let c = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                d.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        use std::os::fd::FromRawFd;
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        validate_file(&metadata)?;
        validate_named_file(d, name, &metadata)?;
        if unsafe { libc::unlinkat(d.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        d.sync_all()?;
    })();
    unsafe { libc::closedir(stream) };
    result
}
#[cfg(unix)]
fn validate_directory(m: &Metadata) -> Result<(), ReceiptStagingError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
        return Err(ReceiptStagingError::UnsafeStore("directoryPermissions"));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_file(m: &Metadata) -> Result<(), ReceiptStagingError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ReceiptStagingError::UnsafeStore("filePermissions"));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_named_file(d: &File, name: &str, m: &Metadata) -> Result<(), ReceiptStagingError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let n = c_name(name)?;
    let mut status = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            d.as_raw_fd(),
            n.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(ReceiptStagingError::UnsafeStore("fileChanged"));
    }
    let s = unsafe { status.assume_init() };
    if s.st_mode & libc::S_IFMT != libc::S_IFREG
        || s.st_dev as u128 != u128::from(m.dev())
        || u128::from(s.st_ino) != u128::from(m.ino())
        || s.st_nlink != 1
    {
        return Err(ReceiptStagingError::UnsafeStore("fileChanged"));
    }
    Ok(())
}
#[cfg(unix)]
fn same_object(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(unix)]
fn same_snapshot(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_object(a, b)
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, ReceiptStagingError> {
    std::ffi::CString::new(name).map_err(|_| ReceiptStagingError::InvalidInput)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use bloch_local_state_cursor::{CheckpointCursor, parse_cursor};
    use bloch_local_state_remote_cursor::{
        REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasRequestParameters,
        create_remote_cursor_cas_request, remote_cursor_policy_sha256,
    };
    use bloch_local_state_remote_cursor_caller_auth::{
        CALLER_AUTH_POLICY_SCHEMA, CallerAuthority, CallerAuthorizationPolicy, CallerSignature,
        bind_consumed_challenge, caller_authorization_policy_sha256,
        caller_authorization_signature_message, create_caller_authorization,
        verify_caller_authorization,
    };
    use bloch_local_state_remote_cursor_challenge_store::{
        ChallengeAudience, consume_challenge, issue_challenge, provision_challenge_store,
    };
    use bloch_local_state_remote_cursor_control_plane::{
        apply_request, provision_control_plane_store,
    };
    use bloch_local_state_store::{StateRoot, write_state};
    use bloch_trusted_time::{
        TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
        create_trusted_time_token, trusted_time_policy_sha256, trusted_time_signature_message,
        verify_trusted_time_token,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const NONCE: &str = "staging_nonce_0123456789abcdef0123456789abcdef";
    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: std::path::PathBuf,
        store: std::path::PathBuf,
        request: Vec<u8>,
        policy: RemoteCursorPolicy,
        pin: String,
        keys: Vec<SigningKey>,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "bloch-receipt-stage-{}-{unique}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            let states = root.join("states");
            let current_root =
                write_state(&states, "data:tenant-a:lifecycle", 0, b"zero", None).unwrap();
            let successor_root = write_state(
                &states,
                "data:tenant-a:lifecycle",
                1,
                b"one",
                Some(&current_root),
            )
            .unwrap();
            let current = cursor_for(&current_root, 11);
            let successor = cursor_for(&successor_root, 21);
            let keys = vec![
                SigningKey::from_bytes(&[71; 32]),
                SigningKey::from_bytes(&[72; 32]),
            ];
            let policy = RemoteCursorPolicy {
                schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
                policy_id: "remote-cas-policy".into(),
                signature_domain: "bloch-control-plane-cas".into(),
                state_identity: "data:tenant-a:lifecycle".into(),
                threshold: 2,
                effective_at_unix_seconds: 100,
                expires_at_unix_seconds: 1000,
                max_observation_age_seconds: 60,
                authorities: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| RemoteCursorAuthority {
                        authority_id: format!("authority-{}", i + 1),
                        ed25519_public_key: format!(
                            "0x{}",
                            encode_hex(k.verifying_key().as_bytes())
                        ),
                    })
                    .collect(),
            };
            let pin = remote_cursor_policy_sha256(&policy).unwrap();
            let request = create_remote_cursor_cas_request(
                RemoteCursorCasRequestParameters {
                    expected_current: Some(&current),
                    successor_cursor: &successor,
                    successor_root: &successor_root,
                    request_id: "request-1",
                    request_nonce: NONCE,
                    requested_at_unix_seconds: 200,
                },
                &policy,
                &pin,
            )
            .unwrap();
            let store = root.join("operation");
            Self {
                root,
                store,
                request,
                policy,
                pin,
                keys,
            }
        }

        fn signatures(&self, decision: &RemoteCursorCasDecision) -> Vec<RemoteCursorSignature> {
            let message = remote_cursor_cas_receipt_signature_message(
                &self.request,
                &self.policy,
                &self.pin,
                decision,
                210,
            )
            .unwrap();
            self.keys
                .iter()
                .enumerate()
                .map(|(i, k)| RemoteCursorSignature {
                    authority_id: format!("authority-{}", i + 1),
                    signature: format!("0x{}", encode_hex(&k.sign(&message).to_bytes())),
                })
                .collect()
        }

        fn signature_bundle(&self, decision: &RemoteCursorCasDecision) -> ReceiptSignatureBundle {
            let signing_message = remote_cursor_cas_receipt_signature_message(
                &self.request,
                &self.policy,
                &self.pin,
                decision,
                210,
            )
            .unwrap();
            ReceiptSignatureBundle {
                schema: RECEIPT_SIGNATURE_BUNDLE_SCHEMA.into(),
                state_identity: self.policy.state_identity.clone(),
                remote_cursor_policy_sha256: self.pin.clone(),
                signature_domain: self.policy.signature_domain.clone(),
                request_sha256: hash(&self.request),
                signing_message_sha256: hash(&signing_message),
                signatures: self.signatures(decision),
            }
        }

        fn import<'a>(&'a self, decision: &'a RemoteCursorCasDecision) -> ReceiptImport<'a> {
            ReceiptImport {
                request_bytes: &self.request,
                policy: &self.policy,
                expected_policy_sha256: &self.pin,
                decision,
                decided_at_unix_seconds: 210,
                evaluated_at_unix_seconds: 220,
            }
        }

        fn control_decision(&self) -> ControlPlaneDecision {
            let request =
                parse_remote_cursor_cas_request(&self.request, &self.policy, &self.pin).unwrap();
            let caller_key = SigningKey::from_bytes(&[81; 32]);
            let caller_policy = CallerAuthorizationPolicy {
                schema: CALLER_AUTH_POLICY_SCHEMA.into(),
                policy_id: "receipt-staging-caller".into(),
                signature_domain: "bloch-receipt-staging-caller".into(),
                state_identity: self.policy.state_identity.clone(),
                remote_cursor_policy_sha256: self.pin.clone(),
                threshold: 1,
                effective_at_unix_seconds: 100,
                expires_at_unix_seconds: 1_000,
                max_authorization_age_seconds: 100,
                max_authorization_lifetime_seconds: 100,
                authorities: vec![CallerAuthority {
                    authority_id: "caller-1".into(),
                    ed25519_public_key: format!(
                        "0x{}",
                        encode_hex(caller_key.verifying_key().as_bytes())
                    ),
                }],
            };
            let caller_pin = caller_authorization_policy_sha256(&caller_policy).unwrap();
            let control_store = self.root.join("control");
            provision_control_plane_store(
                &control_store,
                &self.policy.state_identity,
                &self.pin,
                &self.policy.signature_domain,
                &caller_pin,
            )
            .unwrap();
            let challenge_store = self.root.join("challenges");
            provision_challenge_store(&challenge_store).unwrap();
            let audience = ChallengeAudience {
                caller_policy_sha256: &caller_pin,
                remote_cursor_policy_sha256: &self.pin,
                state_identity: &self.policy.state_identity,
            };
            let issued =
                issue_challenge(&challenge_store, audience, Duration::from_secs(10)).unwrap();
            let nonce = issued.nonce().to_owned();
            let message = caller_authorization_signature_message(
                &request,
                &caller_policy,
                &caller_pin,
                &nonce,
                200,
                250,
            )
            .unwrap();
            let authorization_bytes = create_caller_authorization(
                &request,
                &caller_policy,
                &caller_pin,
                &nonce,
                200,
                250,
                &[CallerSignature {
                    authority_id: "caller-1".into(),
                    signature: format!("0x{}", encode_hex(&caller_key.sign(&message).to_bytes())),
                }],
            )
            .unwrap();
            let verified = verify_caller_authorization(
                &authorization_bytes,
                &request,
                &caller_policy,
                &caller_pin,
                &nonce,
                210,
            )
            .unwrap();
            let consumed = consume_challenge(&challenge_store, audience, issued, &nonce).unwrap();
            let authorization = bind_consumed_challenge(verified, consumed).unwrap();
            apply_request(
                &control_store,
                &self.policy.state_identity,
                &request,
                authorization,
            )
            .unwrap()
        }

        fn trusted_time(
            &self,
            lifetime_seconds: u64,
            remote_pin: &str,
            state_identity: &str,
        ) -> VerifiedTrustedTime {
            let key = SigningKey::from_bytes(&[91; 32]);
            let policy = TrustedTimePolicy {
                schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
                policy_id: "receipt-staging-time".into(),
                signature_domain: "bloch-receipt-staging-time".into(),
                state_identity: state_identity.into(),
                remote_cursor_policy_sha256: remote_pin.into(),
                threshold: 1,
                effective_at_unix_seconds: 100,
                expires_at_unix_seconds: 1_000,
                max_token_lifetime_seconds: 30,
                authorities: vec![TrustedTimeAuthority {
                    authority_id: "time-1".into(),
                    ed25519_public_key: format!("0x{}", encode_hex(key.verifying_key().as_bytes())),
                }],
            };
            let pin = trusted_time_policy_sha256(&policy).unwrap();
            let message =
                trusted_time_signature_message(&policy, &pin, NONCE, 210, 210 + lifetime_seconds)
                    .unwrap();
            let token = create_trusted_time_token(
                &policy,
                &pin,
                NONCE,
                210,
                210 + lifetime_seconds,
                &[TrustedTimeSignature {
                    authority_id: "time-1".into(),
                    signature: format!("0x{}", encode_hex(&key.sign(&message).to_bytes())),
                }],
            )
            .unwrap();
            verify_trusted_time_token(&token, &policy, &pin, NONCE, None).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn cursor_for(root: &StateRoot, marker: u8) -> CheckpointCursor {
        let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
        let root_digest = hash(&root.canonical_bytes().unwrap());
        let bytes = format!(
            "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":{},\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
            root.state_identity(),
            root.generation(),
            digest(marker),
            digest(marker + 1),
            digest(marker + 2),
            root_digest,
            root.state_sha256()
        );
        parse_cursor(bytes.as_bytes()).unwrap()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        hex_string(bytes)
    }

    #[test]
    fn accepted_and_refused_receipts_are_staged_and_replay_idempotently() {
        for decision in [
            RemoteCursorCasDecision::Accepted,
            RemoteCursorCasDecision::Refused {
                reason_code: "compare_mismatch".into(),
            },
        ] {
            let f = Fixture::new();
            let prepared = prepare_remote_cursor_cas_receipt(
                &f.store, &f.request, &f.policy, &f.pin, &decision, 210,
            )
            .unwrap();
            let signatures = f.signatures(&decision);
            let staged =
                import_remote_cursor_cas_signatures(&f.store, f.import(&decision), &signatures)
                    .unwrap();
            let replay = import_remote_cursor_cas_receipt(
                &f.store,
                f.import(&decision),
                staged.receipt_bytes(),
            )
            .unwrap();
            assert_eq!(staged, replay);
            assert_eq!(
                prepare_remote_cursor_cas_receipt(
                    &f.store, &f.request, &f.policy, &f.pin, &decision, 210
                )
                .unwrap()
                .imported_receipt_sha256(),
                Some(staged.receipt_sha256())
            );
            assert!(!prepared.signing_message().is_empty());
        }
    }

    #[test]
    fn request_decision_policy_and_signature_substitution_fail_closed() {
        let f = Fixture::new();
        let accepted = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &accepted, 210)
            .unwrap();
        let refused = RemoteCursorCasDecision::Refused {
            reason_code: "compare_mismatch".into(),
        };
        assert!(matches!(
            prepare_remote_cursor_cas_receipt(
                &f.store, &f.request, &f.policy, &f.pin, &refused, 210
            ),
            Err(ReceiptStagingError::Conflict)
        ));
        let refused_receipt = create_remote_cursor_cas_receipt(
            &f.request,
            &f.policy,
            &f.pin,
            &refused,
            210,
            &f.signatures(&refused),
        )
        .unwrap();
        assert!(matches!(
            import_remote_cursor_cas_receipt(&f.store, f.import(&accepted), &refused_receipt),
            Err(ReceiptStagingError::Conflict)
        ));
        let mut request = f.request.clone();
        request.push(b' ');
        assert!(
            prepare_remote_cursor_cas_receipt(
                &f.store, &request, &f.policy, &f.pin, &accepted, 210
            )
            .is_err()
        );
        let mut wrong_pin = f.pin.clone();
        wrong_pin.replace_range(64..66, "00");
        assert!(
            prepare_remote_cursor_cas_receipt(
                &f.store, &f.request, &f.policy, &wrong_pin, &accepted, 210
            )
            .is_err()
        );
        let mut signatures = f.signatures(&accepted);
        signatures[0].signature.replace_range(2..4, "00");
        assert!(
            import_remote_cursor_cas_signatures(&f.store, f.import(&accepted), &signatures,)
                .is_err()
        );
    }

    #[test]
    fn crash_temporary_is_removed_before_import() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        let stale = f
            .store
            .join(".state.json.tmp-00000000000000000000000000000000");
        std::fs::write(&stale, b"partial").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600)).unwrap();
        import_remote_cursor_cas_signatures(
            &f.store,
            f.import(&decision),
            &f.signatures(&decision),
        )
        .unwrap();
        assert!(!stale.exists());
    }

    #[test]
    fn symlink_and_hardlink_stores_are_refused() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        let link = f.root.join("link");
        symlink(&f.root, &link).unwrap();
        assert!(
            prepare_remote_cursor_cas_receipt(&link, &f.request, &f.policy, &f.pin, &decision, 210)
                .is_err()
        );
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        std::fs::hard_link(f.store.join("state.json"), f.root.join("state-copy")).unwrap();
        assert!(
            prepare_remote_cursor_cas_receipt(
                &f.store, &f.request, &f.policy, &f.pin, &decision, 210
            )
            .is_err()
        );
    }

    #[test]
    fn concurrent_exact_imports_are_idempotent() {
        let f = Arc::new(Fixture::new());
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        let signatures = f.signatures(&decision);
        let receipt = create_remote_cursor_cas_receipt(
            &f.request,
            &f.policy,
            &f.pin,
            &decision,
            210,
            &signatures,
        )
        .unwrap();
        let mut threads = Vec::new();
        for _ in 0..2 {
            let f = Arc::clone(&f);
            let r = receipt.clone();
            let d = decision.clone();
            threads.push(std::thread::spawn(move || {
                let retry_deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match import_remote_cursor_cas_receipt(&f.store, f.import(&d), &r) {
                        Ok(staged) => break staged.receipt_sha256().to_owned(),
                        Err(ReceiptStagingError::StoreBusy) if Instant::now() < retry_deadline => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("concurrent exact import failed: {error}"),
                    }
                }
            }));
        }
        let a = threads.remove(0).join().unwrap();
        let b = threads.remove(0).join().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn preferred_control_plane_and_trusted_time_path_stages_receipt() {
        let f = Fixture::new();
        let control = f.control_decision();
        let trusted = f.trusted_time(30, &f.pin, &f.policy.state_identity);
        let prepared = prepare_from_control_plane_decision(
            &f.store, &f.request, &f.policy, &f.pin, &control, &trusted,
        )
        .unwrap();
        assert_eq!(prepared.request_sha256(), control.request_sha256());
        let staged = import_remote_cursor_cas_signatures_with_trusted_time(
            &f.store,
            &f.request,
            &f.policy,
            &f.pin,
            &control,
            &f.signatures(control.decision()),
            &trusted,
        )
        .unwrap();
        assert!(!staged.receipt_bytes().is_empty());
        let replay = import_remote_cursor_cas_receipt_with_trusted_time(
            &f.store,
            &f.request,
            &f.policy,
            &f.pin,
            &control,
            staged.receipt_bytes(),
            &trusted,
        )
        .unwrap();
        assert_eq!(replay, staged);
    }

    #[test]
    fn preferred_path_rejects_cross_audience_and_control_substitution() {
        let f = Fixture::new();
        let control = f.control_decision();
        let wrong_audience = f.trusted_time(
            30,
            &format!("0x{}", "44".repeat(32)),
            &f.policy.state_identity,
        );
        assert!(matches!(
            prepare_from_control_plane_decision(
                &f.store,
                &f.request,
                &f.policy,
                &f.pin,
                &control,
                &wrong_audience
            ),
            Err(ReceiptStagingError::TrustedTimeAudienceMismatch)
        ));

        let substituted = String::from_utf8(f.request.clone())
            .unwrap()
            .replace("request-1", "request-2")
            .into_bytes();
        let trusted = f.trusted_time(30, &f.pin, &f.policy.state_identity);
        assert!(matches!(
            prepare_from_control_plane_decision(
                &f.store,
                &substituted,
                &f.policy,
                &f.pin,
                &control,
                &trusted
            ),
            Err(ReceiptStagingError::Conflict)
        ));

        let refused = RemoteCursorCasDecision::Refused {
            reason_code: "compare_mismatch".into(),
        };
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &refused, 210)
            .unwrap();
        assert!(matches!(
            prepare_from_control_plane_decision(
                &f.store, &f.request, &f.policy, &f.pin, &control, &trusted
            ),
            Err(ReceiptStagingError::Conflict)
        ));
    }

    #[test]
    fn preferred_path_rejects_expired_trusted_time() {
        let f = Fixture::new();
        let control = f.control_decision();
        let trusted = f.trusted_time(1, &f.pin, &f.policy.state_identity);
        std::thread::sleep(Duration::from_millis(1_050));
        assert!(matches!(
            prepare_from_control_plane_decision(
                &f.store, &f.request, &f.policy, &f.pin, &control, &trusted
            ),
            Err(ReceiptStagingError::TrustedTimeExpired)
        ));
    }

    #[test]
    fn inspection_omits_payloads_and_signing_export_is_canonical() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        let prepared = prepare_remote_cursor_cas_receipt(
            &f.store, &f.request, &f.policy, &f.pin, &decision, 210,
        )
        .unwrap();
        let inspection = inspect_receipt_staging(&f.store).unwrap();
        let inspection_bytes = serde_json::to_vec(&inspection).unwrap();
        assert_eq!(inspection.request_sha256, prepared.request_sha256());
        assert!(
            !inspection_bytes
                .windows(b"requestBytes".len())
                .any(|window| window == b"requestBytes")
        );
        assert!(
            !inspection_bytes
                .windows(b"signingMessageHex".len())
                .any(|window| window == b"signingMessageHex")
        );

        let bytes = export_receipt_signing_request(&f.store).unwrap();
        let export: ReceiptSigningRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&export).unwrap(), bytes);
        assert_eq!(
            export.signing_message_sha256,
            prepared.signing_message_sha256()
        );
        assert_eq!(
            export.signing_message_hex,
            format!("0x{}", hex_string(prepared.signing_message()))
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        let decoded: ReceiptSigningRequest = serde_json::from_slice(&noncanonical).unwrap();
        assert_ne!(serde_json::to_vec(&decoded).unwrap(), noncanonical);
    }

    #[test]
    fn ceremony_import_is_exactly_bound_to_staged_operation() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        let receipt = create_remote_cursor_cas_receipt(
            &f.request,
            &f.policy,
            &f.pin,
            &decision,
            210,
            &f.signatures(&decision),
        )
        .unwrap();
        let staged =
            ceremony_import_receipt_with_operator_time(&f.store, &f.policy, &f.pin, &receipt, 220)
                .unwrap();
        assert_eq!(staged.receipt_bytes(), receipt);

        let mut wrong_policy = f.policy.clone();
        wrong_policy.signature_domain.push_str("-wrong");
        assert!(
            ceremony_import_receipt_with_operator_time(
                &f.store,
                &wrong_policy,
                &f.pin,
                &receipt,
                220
            )
            .is_err()
        );
    }

    #[test]
    fn detached_bundle_assembles_verified_receipt_without_importing_it() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        let bundle = serde_json::to_vec(&f.signature_bundle(&decision)).unwrap();
        let receipt =
            assemble_receipt_from_signature_bundle(&f.store, &f.policy, &f.pin, &bundle).unwrap();
        let verified =
            verify_remote_cursor_cas_receipt(&receipt, &f.request, &f.policy, &f.pin, 210).unwrap();
        assert!(matches!(
            verified,
            VerifiedRemoteCursorCasReceipt::Accepted(_)
        ));
        assert_eq!(
            inspect_receipt_staging(&f.store).unwrap().receipt_sha256,
            None
        );
    }

    #[test]
    fn detached_bundle_rejects_substitution_and_wrong_authority() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        for mutate in ["request", "message", "state"] {
            let mut bundle = f.signature_bundle(&decision);
            match mutate {
                "request" => bundle.request_sha256 = format!("0x{}", "11".repeat(32)),
                "message" => bundle.signing_message_sha256 = format!("0x{}", "22".repeat(32)),
                "state" => bundle.state_identity.push_str("-other"),
                _ => unreachable!(),
            }
            assert!(matches!(
                assemble_receipt_from_signature_bundle(
                    &f.store,
                    &f.policy,
                    &f.pin,
                    &serde_json::to_vec(&bundle).unwrap()
                ),
                Err(ReceiptStagingError::Conflict)
            ));
        }

        let mut bundle = f.signature_bundle(&decision);
        bundle.signatures[0].authority_id = "authority-0".into();
        assert!(
            assemble_receipt_from_signature_bundle(
                &f.store,
                &f.policy,
                &f.pin,
                &serde_json::to_vec(&bundle).unwrap()
            )
            .is_err()
        );

        let mut below_threshold = f.signature_bundle(&decision);
        below_threshold.signatures.pop();
        assert!(
            assemble_receipt_from_signature_bundle(
                &f.store,
                &f.policy,
                &f.pin,
                &serde_json::to_vec(&below_threshold).unwrap()
            )
            .is_err()
        );

        let mut invalid_signature = f.signature_bundle(&decision);
        invalid_signature.signatures[0].signature = format!("0x{}", "00".repeat(64));
        assert!(
            assemble_receipt_from_signature_bundle(
                &f.store,
                &f.policy,
                &f.pin,
                &serde_json::to_vec(&invalid_signature).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn detached_bundle_rejects_duplicate_and_noncanonical_input() {
        let f = Fixture::new();
        let decision = RemoteCursorCasDecision::Accepted;
        prepare_remote_cursor_cas_receipt(&f.store, &f.request, &f.policy, &f.pin, &decision, 210)
            .unwrap();
        let mut duplicate = f.signature_bundle(&decision);
        duplicate.signatures[1].authority_id = duplicate.signatures[0].authority_id.clone();
        assert!(matches!(
            parse_receipt_signature_bundle(&serde_json::to_vec(&duplicate).unwrap()),
            Err(ReceiptStagingError::InvalidSignatureBundle)
        ));

        let mut noncanonical = serde_json::to_vec(&f.signature_bundle(&decision)).unwrap();
        noncanonical.push(b'\n');
        assert!(matches!(
            parse_receipt_signature_bundle(&noncanonical),
            Err(ReceiptStagingError::InvalidSignatureBundle)
        ));
    }
}
