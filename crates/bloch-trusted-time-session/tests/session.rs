use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    create_trusted_time_token, trusted_time_policy_bytes, trusted_time_policy_sha256,
    trusted_time_signature_message, verify_trusted_time_token,
};
use bloch_trusted_time_session::{
    MonotonicDeadlineRead, TrustedTimeAcquisitionError, acquire_verified_trusted_time,
};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::RefCell;
use std::convert::Infallible;
use std::time::{Duration, Instant};

const STATE_IDENTITY: &str = "data:tenant-a:lifecycle";
const REMOTE_POLICY_PIN: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";

struct Fixture {
    policy: TrustedTimePolicy,
    policy_bytes: Vec<u8>,
    policy_pin: String,
    keys: Vec<SigningKey>,
}

impl Fixture {
    fn new() -> Self {
        let keys = vec![
            SigningKey::from_bytes(&[71; 32]),
            SigningKey::from_bytes(&[72; 32]),
        ];
        let policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "trusted-time-session-test".into(),
            signature_domain: "bloch-products-trusted-time-session".into(),
            state_identity: STATE_IDENTITY.into(),
            remote_cursor_policy_sha256: REMOTE_POLICY_PIN.into(),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            max_token_lifetime_seconds: 60,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| TrustedTimeAuthority {
                    authority_id: format!("time-authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let policy_pin = trusted_time_policy_sha256(&policy).unwrap();
        let policy_bytes = trusted_time_policy_bytes(&policy).unwrap();
        Self {
            policy,
            policy_bytes,
            policy_pin,
            keys,
        }
    }

    fn token(&self, nonce: &str, attested_at: u64) -> Vec<u8> {
        let valid_until = attested_at + 30;
        let message = trusted_time_signature_message(
            &self.policy,
            &self.policy_pin,
            nonce,
            attested_at,
            valid_until,
        )
        .unwrap();
        let signatures = self
            .keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        create_trusted_time_token(
            &self.policy,
            &self.policy_pin,
            nonce,
            attested_at,
            valid_until,
            &signatures,
        )
        .unwrap()
    }

    fn acquire<R, F>(
        &self,
        boundary: Option<&bloch_trusted_time::TrustedTimeBoundary>,
        timeout: Duration,
        transport: F,
    ) -> Result<bloch_trusted_time::VerifiedTrustedTime, TrustedTimeAcquisitionError<Infallible>>
    where
        R: MonotonicDeadlineRead<Error = Infallible>,
        F: for<'session> FnOnce(
            bloch_trusted_time_session::TrustedTimeFetchRequest<'session>,
        ) -> Result<R, Infallible>,
    {
        acquire_verified_trusted_time(
            &self.policy_bytes,
            &self.policy_pin,
            STATE_IDENTITY,
            REMOTE_POLICY_PIN,
            boundary,
            timeout,
            transport,
        )
    }
}

struct BytesReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl BytesReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl MonotonicDeadlineRead for BytesReader {
    type Error = Infallible;

    fn read_with_deadline(
        &mut self,
        buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, Self::Error> {
        let count = buffer.len().min(self.bytes.len() - self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn returns_only_verified_time_for_expected_audience() {
    let fixture = Fixture::new();
    let verified = fixture
        .acquire(None, Duration::from_secs(1), |request| {
            assert_eq!(request.expected_policy_sha256(), fixture.policy_pin);
            assert_eq!(request.expected_state_identity(), STATE_IDENTITY);
            assert_eq!(
                request.expected_remote_cursor_policy_sha256(),
                REMOTE_POLICY_PIN
            );
            assert_eq!(request.request_nonce().len(), 64);
            assert!(request.deadline() > Instant::now());
            assert_eq!(
                request.maximum_response_bytes(),
                bloch_trusted_time::MAX_TRUSTED_TIME_TOKEN_BYTES
            );
            Ok(BytesReader::new(
                fixture.token(request.request_nonce(), 2_000),
            ))
        })
        .unwrap();
    assert_eq!(verified.state_identity(), STATE_IDENTITY);
    assert_eq!(verified.remote_cursor_policy_sha256(), REMOTE_POLICY_PIN);
    assert_eq!(verified.trusted_time_policy_sha256(), fixture.policy_pin);
}

#[test]
fn fresh_nonce_rejects_a_replayed_token() {
    let fixture = Fixture::new();
    let captured = RefCell::new(None);
    fixture
        .acquire(None, Duration::from_secs(1), |request| {
            let token = fixture.token(request.request_nonce(), 2_000);
            captured.replace(Some(token.clone()));
            Ok(BytesReader::new(token))
        })
        .unwrap();

    let replay = fixture.acquire(None, Duration::from_secs(1), |_request| {
        Ok(BytesReader::new(captured.borrow().clone().unwrap()))
    });
    assert!(matches!(
        replay,
        Err(TrustedTimeAcquisitionError::Authentication(
            bloch_trusted_time::TrustedTimeError::NonceMismatch
        ))
    ));
}

#[test]
fn rejects_cross_policy_and_cross_audience_before_transport() {
    let fixture = Fixture::new();
    let called = RefCell::new(false);
    let wrong_pin = format!("0x{}", "22".repeat(32));
    let policy_result = acquire_verified_trusted_time(
        &fixture.policy_bytes,
        &wrong_pin,
        STATE_IDENTITY,
        REMOTE_POLICY_PIN,
        None,
        Duration::from_secs(1),
        |_request| {
            called.replace(true);
            Ok::<_, Infallible>(BytesReader::new(Vec::new()))
        },
    );
    assert!(matches!(
        policy_result,
        Err(TrustedTimeAcquisitionError::Authentication(
            bloch_trusted_time::TrustedTimeError::PolicyPinMismatch
        ))
    ));
    assert!(!*called.borrow());

    let audience_result = acquire_verified_trusted_time(
        &fixture.policy_bytes,
        &fixture.policy_pin,
        "pay:merchant-a:adjustment",
        REMOTE_POLICY_PIN,
        None,
        Duration::from_secs(1),
        |_request| {
            called.replace(true);
            Ok::<_, Infallible>(BytesReader::new(Vec::new()))
        },
    );
    assert!(matches!(
        audience_result,
        Err(TrustedTimeAcquisitionError::InvalidConfiguration)
    ));
    assert!(!*called.borrow());
}

#[test]
fn enforces_rollback_boundary() {
    let fixture = Fixture::new();
    let prior_nonce = "trusted_time_prior_nonce_0123456789abcdef0123456789abcdef";
    let prior = verify_trusted_time_token(
        &fixture.token(prior_nonce, 2_100),
        &fixture.policy,
        &fixture.policy_pin,
        prior_nonce,
        None,
    )
    .unwrap();
    let boundary = prior.rollback_boundary().unwrap();
    let result = fixture.acquire(Some(&boundary), Duration::from_secs(1), |request| {
        Ok(BytesReader::new(
            fixture.token(request.request_nonce(), 2_000),
        ))
    });
    assert!(matches!(
        result,
        Err(TrustedTimeAcquisitionError::Authentication(
            bloch_trusted_time::TrustedTimeError::RollbackDetected
        ))
    ));
}

#[test]
fn rejects_a_late_reader() {
    let fixture = Fixture::new();
    let result = fixture.acquire(None, Duration::from_millis(1), |request| {
        let bytes = fixture.token(request.request_nonce(), 2_000);
        let mut first = true;
        Ok(move |buffer: &mut [u8], _deadline: Instant| {
            if first {
                first = false;
                std::thread::sleep(Duration::from_millis(5));
                let count = bytes.len().min(buffer.len());
                buffer[..count].copy_from_slice(&bytes[..count]);
                Ok::<usize, Infallible>(count)
            } else {
                Ok(0)
            }
        })
    });
    assert!(matches!(
        result,
        Err(TrustedTimeAcquisitionError::DeadlineExceeded)
    ));
}

#[test]
fn bounds_an_infinite_or_oversized_reader() {
    let fixture = Fixture::new();
    let result = fixture.acquire(None, Duration::from_secs(1), |_request| {
        Ok(|buffer: &mut [u8], _deadline: Instant| {
            buffer.fill(0xaa);
            Ok::<usize, Infallible>(buffer.len())
        })
    });
    assert!(matches!(
        result,
        Err(TrustedTimeAcquisitionError::ResponseTooLarge)
    ));
}
