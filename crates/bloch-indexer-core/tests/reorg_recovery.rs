use bloch_indexer_core::{
    ApplyOutcome, BlockAnchor, CanonicalBlock, CanonicalIndexer, ChainIdentity,
};

#[test]
fn previously_seen_orphan_can_return_only_with_identical_content() {
    let mut indexer = indexer();
    let canonical_101 = block(101, '2', '1');
    let canonical_102 = block(102, '3', '2');
    indexer.apply(canonical_101.clone()).unwrap();
    indexer.apply(canonical_102.clone()).unwrap();

    let competing_101 = block(101, '4', '1');
    assert!(matches!(
        indexer.apply(competing_101).unwrap(),
        ApplyOutcome::Reorganized { height: 101, .. }
    ));
    assert_eq!(indexer.tip(), (101, hash('4').as_str()));

    assert!(matches!(
        indexer.apply(canonical_101).unwrap(),
        ApplyOutcome::Reorganized { height: 101, .. }
    ));
    assert!(matches!(
        indexer.apply(canonical_102).unwrap(),
        ApplyOutcome::Applied { height: 102, .. }
    ));
    assert_eq!(indexer.tip(), (102, hash('3').as_str()));
}

fn indexer() -> CanonicalIndexer {
    CanonicalIndexer::new(
        network(),
        BlockAnchor {
            height: 100,
            block_hash: hash('1'),
            state_root: hash('a'),
        },
        4,
    )
    .unwrap()
}

fn block(height: u64, block_hash: char, parent_hash: char) -> CanonicalBlock {
    CanonicalBlock {
        schema: "bloch.data.canonical-block.v1".into(),
        network: network(),
        height,
        block_hash: hash(block_hash),
        parent_hash: hash(parent_hash),
        state_root: hash('a'),
        timestamp_unix_seconds: 1_790_000_000 + height,
        events: vec![],
    }
}

fn network() -> ChainIdentity {
    ChainIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: hash('9'),
    }
}

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
