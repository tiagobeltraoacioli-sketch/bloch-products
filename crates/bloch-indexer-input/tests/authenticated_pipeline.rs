use bloch_indexer_core::{ApplyOutcome, BlockAnchor, CanonicalIndexer, ChainIdentity};
use bloch_indexer_input::authenticated::{
    AuthenticationPolicy, TrustedProducer, authentication_policy_sha256, build_signature_message,
    canonical_authentication_policy_bytes, parse_authentication_policy, verify_authenticated_block,
};
use bloch_indexer_query::{FinalityStatus, ReadApiV1};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn authenticated_bytes_flow_into_network_bound_nonfinal_read_state() {
    let network = ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('9'),
    };
    let anchor = BlockAnchor {
        height: 100,
        block_hash: hash('1'),
        state_root: hash('8'),
    };
    let block_bytes = serde_json::to_vec(&json!({
        "schema": "bloch.data.canonical-block.v1",
        "network": network,
        "height": 101,
        "blockHash": hash('2'),
        "parentHash": hash('1'),
        "stateRoot": hash('a'),
        "timestampUnixSeconds": 1_790_000_101_u64,
        "events": [],
    }))
    .unwrap();
    let signing_key = SigningKey::from_bytes(&[11; 32]);
    let configured_policy = AuthenticationPolicy {
        deployment_domain: "bloch-l2-prod-indexer-1".into(),
        network: network.clone(),
        anchor: anchor.clone(),
        producers: vec![TrustedProducer {
            producer_id: "producer-1".into(),
            ed25519_public_key: format!(
                "0x{}",
                hex::encode(signing_key.verifying_key().as_bytes())
            ),
        }],
    };
    let policy_bytes = canonical_authentication_policy_bytes(&configured_policy).unwrap();
    let expected_policy_sha256 = authentication_policy_sha256(&configured_policy).unwrap();
    let policy = parse_authentication_policy(&policy_bytes, &expected_policy_sha256).unwrap();
    let message = build_signature_message(
        &policy.deployment_domain,
        &network,
        &anchor,
        "producer-1",
        &block_bytes,
    )
    .unwrap();
    let envelope = serde_json::to_vec(&json!({
        "schema": "bloch.indexer.authenticated-block.v1",
        "deploymentDomain": policy.deployment_domain,
        "network": network,
        "anchor": anchor,
        "producerId": "producer-1",
        "canonicalBlockHex": format!("0x{}", hex::encode(&block_bytes)),
        "canonicalBlockSha256": format!(
            "0x{}",
            hex::encode(Sha256::digest(&block_bytes))
        ),
        "signature": format!("0x{}", hex::encode(signing_key.sign(&message).to_bytes())),
    }))
    .unwrap();

    let authenticated = verify_authenticated_block(&envelope, &policy).unwrap();
    let mut indexer = CanonicalIndexer::new(network, anchor, 8).unwrap();
    assert!(matches!(
        indexer.apply(authenticated.block),
        Ok(ApplyOutcome::Applied { height: 101, .. })
    ));

    let status = ReadApiV1::new(&indexer).status();
    assert_eq!(status.network.chain_id, 700_771);
    assert_eq!(status.tip.height, 101);
    assert_eq!(status.finality, FinalityStatus::NotEstablished);
}

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
