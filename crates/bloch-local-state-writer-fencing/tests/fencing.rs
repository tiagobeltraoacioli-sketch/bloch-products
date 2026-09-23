use bloch_local_state_writer_fencing::{
    FencingAuthority, FencingSignature, WRITER_FENCING_POLICY_SCHEMA, WriterFencingError,
    WriterFencingPolicy, WriterLeaseParameters, create_writer_fencing_certificate,
    verify_successor_writer_lease, writer_fencing_policy_sha256, writer_fencing_signature_message,
};
use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    VerifiedTrustedTime, create_trusted_time_token, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use ed25519_dalek::{Signer, SigningKey};

const REMOTE_PIN: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const CAS_PIN: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn lease_parameters(
    writer_id: &str,
    epoch: u64,
    effective_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> WriterLeaseParameters<'_> {
    WriterLeaseParameters {
        writer_id,
        epoch,
        effective_at_unix_seconds,
        expires_at_unix_seconds,
    }
}

struct Fixture {
    keys: Vec<SigningKey>,
    policy: WriterFencingPolicy,
    policy_pin: String,
    time: VerifiedTrustedTime,
}

impl Fixture {
    fn new() -> Self {
        Self::with_time_audience("bloch-data:prod", REMOTE_PIN)
    }

    fn with_time_audience(time_state: &str, time_remote_pin: &str) -> Self {
        let keys: Vec<_> = [1_u8, 2, 3]
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .into();
        let time_keys: Vec<_> = [11_u8, 12, 13]
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .into();
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "time-policy".into(),
            signature_domain: "bloch:time".into(),
            state_identity: time_state.into(),
            remote_cursor_policy_sha256: time_remote_pin.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_token_lifetime_seconds: 60,
            authorities: time_keys
                .iter()
                .enumerate()
                .map(|(i, k)| TrustedTimeAuthority {
                    authority_id: format!("time-{}", i + 1),
                    ed25519_public_key: format!("0x{}", hex::encode(k.verifying_key().to_bytes())),
                })
                .collect(),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let time_message =
            trusted_time_signature_message(&time_policy, &time_pin, NONCE, 200, 230).unwrap();
        let time_signatures: Vec<_> = time_keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, key)| TrustedTimeSignature {
                authority_id: format!("time-{}", i + 1),
                signature: format!("0x{}", hex::encode(key.sign(&time_message).to_bytes())),
            })
            .collect();
        let token =
            create_trusted_time_token(&time_policy, &time_pin, NONCE, 200, 230, &time_signatures)
                .unwrap();
        let time = verify_trusted_time_token(&token, &time_policy, &time_pin, NONCE, None).unwrap();
        let policy = WriterFencingPolicy {
            schema: WRITER_FENCING_POLICY_SCHEMA.into(),
            policy_id: "fence-policy".into(),
            signature_domain: "bloch:fence".into(),
            state_identity: "bloch-data:prod".into(),
            remote_cursor_policy_sha256: REMOTE_PIN.into(),
            cas_service_id: "cas-primary".into(),
            cas_policy_sha256: CAS_PIN.into(),
            trusted_time_policy_sha256: time_pin,
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 500,
            max_lease_lifetime_seconds: 60,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(i, k)| FencingAuthority {
                    authority_id: format!("fence-{}", i + 1),
                    ed25519_public_key: format!("0x{}", hex::encode(k.verifying_key().to_bytes())),
                })
                .collect(),
        };
        let policy_pin = writer_fencing_policy_sha256(&policy).unwrap();
        Self {
            keys,
            policy,
            policy_pin,
            time,
        }
    }

    fn certificate(&self, writer: &str, epoch: u64, effective: u64, expires: u64) -> Vec<u8> {
        let message = writer_fencing_signature_message(
            &self.policy,
            &self.policy_pin,
            lease_parameters(writer, epoch, effective, expires),
        )
        .unwrap();
        let signatures = self
            .keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, key)| FencingSignature {
                authority_id: format!("fence-{}", i + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect();
        create_writer_fencing_certificate(
            &self.policy,
            &self.policy_pin,
            lease_parameters(writer, epoch, effective, expires),
            signatures,
        )
        .unwrap()
    }
}

#[test]
fn verifies_successor_and_exposes_exact_non_authoritative_claims() {
    let f = Fixture::new();
    let certificate = f.certificate("writer-a", 8, 190, 250);
    let lease =
        verify_successor_writer_lease(&certificate, &f.policy, &f.policy_pin, 7, &f.time).unwrap();
    assert_eq!(lease.epoch(), 8);
    assert_eq!(lease.writer_id(), "writer-a");
    assert_eq!(lease.expires_at_unix_seconds(), 250);
    assert_eq!(lease.deadline_unix_seconds(), 230);
    assert_eq!(lease.cas_service_id(), "cas-primary");
    assert!(!lease.is_expired());
    lease.ensure_monotonic_freshness().unwrap();
    assert!(!lease.leader_election_proven());
    assert!(!lease.consensus_proven());
    assert!(!lease.linearizable_issuer_proven());
    assert!(!lease.floor_persistence_proven());
}

#[test]
fn rejects_future_and_stale_lease() {
    let f = Fixture::new();
    let future = f.certificate("writer-a", 8, 210, 220);
    assert_eq!(
        verify_successor_writer_lease(&future, &f.policy, &f.policy_pin, 7, &f.time).unwrap_err(),
        WriterFencingError::LeaseNotEffective
    );
    let stale = f.certificate("writer-a", 8, 180, 200);
    assert_eq!(
        verify_successor_writer_lease(&stale, &f.policy, &f.policy_pin, 7, &f.time).unwrap_err(),
        WriterFencingError::LeaseNotEffective
    );
}

#[test]
fn rejects_epoch_equal_to_or_below_independent_floor() {
    let f = Fixture::new();
    let certificate = f.certificate("writer-a", 8, 190, 220);
    assert_eq!(
        verify_successor_writer_lease(&certificate, &f.policy, &f.policy_pin, 8, &f.time)
            .unwrap_err(),
        WriterFencingError::EpochRollback
    );
    assert_eq!(
        verify_successor_writer_lease(&certificate, &f.policy, &f.policy_pin, 9, &f.time)
            .unwrap_err(),
        WriterFencingError::EpochRollback
    );
}

#[test]
fn rejects_cross_audience_trusted_time() {
    let f = Fixture::with_time_audience("other-state", REMOTE_PIN);
    let certificate = f.certificate("writer-a", 8, 190, 220);
    assert_eq!(
        verify_successor_writer_lease(&certificate, &f.policy, &f.policy_pin, 7, &f.time)
            .unwrap_err(),
        WriterFencingError::TrustedTimeAudienceMismatch
    );
}

#[test]
fn rejects_duplicate_authority_keys() {
    let mut f = Fixture::new();
    f.policy.authorities[1].ed25519_public_key = f.policy.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        writer_fencing_policy_sha256(&f.policy).unwrap_err(),
        WriterFencingError::InvalidPolicy
    );
}

#[test]
fn rejects_duplicate_and_invalid_signatures() {
    let f = Fixture::new();
    let parameters = lease_parameters("writer-a", 8, 190, 220);
    let message = writer_fencing_signature_message(&f.policy, &f.policy_pin, parameters).unwrap();
    let one = FencingSignature {
        authority_id: "fence-1".into(),
        signature: format!("0x{}", hex::encode(f.keys[0].sign(&message).to_bytes())),
    };
    let duplicate = create_writer_fencing_certificate(
        &f.policy,
        &f.policy_pin,
        parameters,
        vec![one.clone(), one],
    );
    assert_eq!(
        duplicate.unwrap_err(),
        WriterFencingError::DuplicateSignature
    );

    let bad = vec![
        FencingSignature {
            authority_id: "fence-1".into(),
            signature: format!("0x{}", "00".repeat(64)),
        },
        FencingSignature {
            authority_id: "fence-2".into(),
            signature: format!("0x{}", hex::encode(f.keys[1].sign(&message).to_bytes())),
        },
    ];
    assert_eq!(
        create_writer_fencing_certificate(&f.policy, &f.policy_pin, parameters, bad).unwrap_err(),
        WriterFencingError::InvalidSignature
    );
    let one_valid = vec![FencingSignature {
        authority_id: "fence-1".into(),
        signature: format!("0x{}", hex::encode(f.keys[0].sign(&message).to_bytes())),
    }];
    assert_eq!(
        create_writer_fencing_certificate(&f.policy, &f.policy_pin, parameters, one_valid)
            .unwrap_err(),
        WriterFencingError::ThresholdNotMet
    );
}

#[test]
fn rejects_writer_and_epoch_substitution() {
    let f = Fixture::new();
    let mut substituted = f.certificate("writer-a", 8, 190, 220);
    let writer_offset = substituted
        .windows(b"writer-a".len())
        .position(|window| window == b"writer-a")
        .unwrap();
    substituted[writer_offset..writer_offset + b"writer-a".len()].copy_from_slice(b"writer-b");
    let epoch_pattern = b"\"epoch\":8";
    let epoch_offset = substituted
        .windows(epoch_pattern.len())
        .position(|window| window == epoch_pattern)
        .unwrap();
    substituted[epoch_offset + epoch_pattern.len() - 1] = b'9';
    assert_eq!(
        verify_successor_writer_lease(&substituted, &f.policy, &f.policy_pin, 7, &f.time)
            .unwrap_err(),
        WriterFencingError::InvalidSignature
    );
}
