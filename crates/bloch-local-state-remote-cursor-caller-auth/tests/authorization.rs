use bloch_local_state_cursor::parse_cursor;
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorCasRequestParameters,
    RemoteCursorPolicy, ValidatedRemoteCursorCasRequest, create_remote_cursor_cas_request,
    parse_remote_cursor_cas_request, remote_cursor_policy_sha256,
};
use bloch_local_state_remote_cursor_caller_auth::{
    CALLER_AUTH_POLICY_SCHEMA, CallerAuthority, CallerAuthorizationError,
    CallerAuthorizationPolicy, CallerSignature, caller_authorization_policy_sha256,
    caller_authorization_signature_message, create_caller_authorization,
    verify_caller_authorization,
};
use bloch_local_state_store::write_state;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY: &str = "data:tenant-a:lifecycle";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_NONCE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    _path: PathBuf,
    request: ValidatedRemoteCursorCasRequest,
    remote_pin: String,
    policy: CallerAuthorizationPolicy,
    pin: String,
    keys: Vec<SigningKey>,
}

impl Fixture {
    fn new(identity: &str, marker: u8) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bloch-caller-auth-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root = write_state(&path, identity, 0, &[marker], None).unwrap();
        let digest = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
        let cursor_bytes = format!(
            "{{\"schema\":\"bloch.products.local-state-checkpoint-cursor.v2\",\"stateIdentity\":\"{}\",\"generation\":0,\"checkpointSha256\":\"{}\",\"checkpointPolicySha256\":\"{}\",\"semanticManifestSha256\":\"{}\",\"stateRootSha256\":\"{}\",\"stateSha256\":\"{}\"}}",
            identity,
            digest(marker),
            digest(marker.wrapping_add(1)),
            digest(marker.wrapping_add(2)),
            sha(&root.canonical_bytes().unwrap()),
            root.state_sha256()
        );
        let cursor = parse_cursor(cursor_bytes.as_bytes()).unwrap();
        let remote_policy = remote_policy(identity, marker);
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let request_bytes = create_remote_cursor_cas_request(
            RemoteCursorCasRequestParameters {
                expected_current: None,
                successor_cursor: &cursor,
                successor_root: &root,
                request_id: "request-1",
                request_nonce: "request_nonce_0123456789abcdef0123456789abcdef",
                requested_at_unix_seconds: 1_100,
            },
            &remote_policy,
            &remote_pin,
        )
        .unwrap();
        let request =
            parse_remote_cursor_cas_request(&request_bytes, &remote_policy, &remote_pin).unwrap();
        let keys = vec![
            SigningKey::from_bytes(&[11; 32]),
            SigningKey::from_bytes(&[12; 32]),
            SigningKey::from_bytes(&[13; 32]),
        ];
        let policy = caller_policy(identity, &remote_pin, &keys, marker);
        let pin = caller_authorization_policy_sha256(&policy).unwrap();
        Self {
            _path: path,
            request,
            remote_pin,
            policy,
            pin,
            keys,
        }
    }

    fn authorization(&self, signatures: usize) -> Result<Vec<u8>, CallerAuthorizationError> {
        let message = caller_authorization_signature_message(
            &self.request,
            &self.policy,
            &self.pin,
            NONCE,
            1_110,
            1_130,
        )?;
        let signatures = self
            .keys
            .iter()
            .take(signatures)
            .enumerate()
            .map(|(index, key)| CallerSignature {
                authority_id: format!("caller-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_caller_authorization(
            &self.request,
            &self.policy,
            &self.pin,
            NONCE,
            1_110,
            1_130,
            &signatures,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self._path);
    }
}

#[test]
fn threshold_authorizes_exact_canonical_request() {
    let fixture = Fixture::new(IDENTITY, 31);
    let bytes = fixture.authorization(2).unwrap();
    let verified = verify_caller_authorization(
        &bytes,
        &fixture.request,
        &fixture.policy,
        &fixture.pin,
        NONCE,
        1_120,
    )
    .unwrap();
    assert_eq!(verified.request_sha256(), fixture.request.request_sha256());
    assert_eq!(
        verified.canonical_request(),
        fixture.request.canonical_bytes()
    );
    assert_eq!(verified.caller_policy_sha256(), fixture.pin);
    assert_eq!(verified.remote_cursor_policy_sha256(), fixture.remote_pin);
    assert_eq!(verified.state_identity(), IDENTITY);
    assert_eq!(verified.authority_ids(), &["caller-1", "caller-2"]);
}

#[test]
fn rejects_replay_nonce_and_expired_authorization() {
    let fixture = Fixture::new(IDENTITY, 32);
    let bytes = fixture.authorization(2).unwrap();
    assert_eq!(
        verify_caller_authorization(
            &bytes,
            &fixture.request,
            &fixture.policy,
            &fixture.pin,
            OTHER_NONCE,
            1_120
        ),
        Err(CallerAuthorizationError::NonceMismatch)
    );
    assert_eq!(
        verify_caller_authorization(
            &bytes,
            &fixture.request,
            &fixture.policy,
            &fixture.pin,
            NONCE,
            1_131
        ),
        Err(CallerAuthorizationError::OutsideFreshnessWindow)
    );
}

#[test]
fn rejects_request_substitution_and_cross_identity() {
    let fixture = Fixture::new(IDENTITY, 33);
    let other = Fixture::new(IDENTITY, 34);
    let bytes = fixture.authorization(2).unwrap();
    assert_eq!(
        verify_caller_authorization(
            &bytes,
            &other.request,
            &fixture.policy,
            &fixture.pin,
            NONCE,
            1_120
        ),
        Err(CallerAuthorizationError::RequestMismatch)
    );

    let cross = Fixture::new("pay:tenant-a:lifecycle", 35);
    assert_eq!(
        verify_caller_authorization(
            &bytes,
            &cross.request,
            &fixture.policy,
            &fixture.pin,
            NONCE,
            1_120
        ),
        Err(CallerAuthorizationError::RequestMismatch)
    );
}

#[test]
fn rejects_cross_policy_and_below_threshold() {
    let fixture = Fixture::new(IDENTITY, 36);
    assert_eq!(
        fixture.authorization(1),
        Err(CallerAuthorizationError::ThresholdNotMet)
    );
    let bytes = fixture.authorization(2).unwrap();
    let mut changed = fixture.policy.clone();
    changed.policy_id = "different-callers".into();
    let changed_pin = caller_authorization_policy_sha256(&changed).unwrap();
    assert_eq!(
        verify_caller_authorization(
            &bytes,
            &fixture.request,
            &changed,
            &changed_pin,
            NONCE,
            1_120
        ),
        Err(CallerAuthorizationError::InvalidAuthorization)
    );
}

#[test]
fn monotonic_deadline_uses_remaining_max_age_before_lifetime() {
    let fixture = Fixture::new(IDENTITY, 37);
    let mut policy = fixture.policy.clone();
    policy.max_authorization_age_seconds = 2;
    let pin = caller_authorization_policy_sha256(&policy).unwrap();
    let message = caller_authorization_signature_message(
        &fixture.request,
        &policy,
        &pin,
        NONCE,
        1_110,
        1_130,
    )
    .unwrap();
    let signatures = fixture
        .keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| CallerSignature {
            authority_id: format!("caller-{}", index + 1),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect::<Vec<_>>();
    let bytes = create_caller_authorization(
        &fixture.request,
        &policy,
        &pin,
        NONCE,
        1_110,
        1_130,
        &signatures,
    )
    .unwrap();
    let verified =
        verify_caller_authorization(&bytes, &fixture.request, &policy, &pin, NONCE, 1_111).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(
        verified.ensure_monotonic_freshness(),
        Err(CallerAuthorizationError::OutsideFreshnessWindow)
    );
}

#[test]
fn rejects_duplicate_and_weak_authority_public_keys() {
    let fixture = Fixture::new(IDENTITY, 38);
    let mut duplicate = fixture.policy.clone();
    duplicate.authorities[1].ed25519_public_key =
        duplicate.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        caller_authorization_policy_sha256(&duplicate),
        Err(CallerAuthorizationError::InvalidPolicy)
    );

    let mut weak = fixture.policy.clone();
    weak.authorities[0].ed25519_public_key = format!("0x01{}", "00".repeat(31));
    assert_eq!(
        caller_authorization_policy_sha256(&weak),
        Err(CallerAuthorizationError::InvalidPolicy)
    );
}

fn caller_policy(
    identity: &str,
    remote_pin: &str,
    keys: &[SigningKey],
    marker: u8,
) -> CallerAuthorizationPolicy {
    CallerAuthorizationPolicy {
        schema: CALLER_AUTH_POLICY_SCHEMA.into(),
        policy_id: format!("caller-policy-{marker}"),
        signature_domain: "bloch-products-cas-caller-v1".into(),
        state_identity: identity.into(),
        remote_cursor_policy_sha256: remote_pin.into(),
        threshold: 2,
        effective_at_unix_seconds: 1_000,
        expires_at_unix_seconds: 2_000,
        max_authorization_age_seconds: 30,
        max_authorization_lifetime_seconds: 30,
        authorities: keys
            .iter()
            .enumerate()
            .map(|(index, key)| CallerAuthority {
                authority_id: format!("caller-{}", index + 1),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect(),
    }
}

fn remote_policy(identity: &str, marker: u8) -> RemoteCursorPolicy {
    let key = SigningKey::from_bytes(&[marker; 32]);
    RemoteCursorPolicy {
        schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
        policy_id: format!("remote-policy-{marker}"),
        signature_domain: "bloch-products-remote-cursor-v1".into(),
        state_identity: identity.into(),
        threshold: 1,
        effective_at_unix_seconds: 1_000,
        expires_at_unix_seconds: 2_000,
        max_observation_age_seconds: 100,
        authorities: vec![RemoteCursorAuthority {
            authority_id: "remote-1".into(),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
        }],
    }
}

fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
