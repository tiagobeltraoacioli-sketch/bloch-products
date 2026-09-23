use bloch_indexer_core::{
    ApplyOutcome, BlockAnchor, CanonicalBlock, CanonicalEvent, CanonicalIndexer, ChainIdentity,
};
use bloch_indexer_protocol::{
    ErrorCode, MAX_REQUEST_JSON_BYTES, REQUEST_SCHEMA, ReadRequest, ReadResult, RequestEnvelope,
    ResponseOutcome, SdkError, decode_response, dispatch, encode_request,
};

#[test]
fn dispatches_all_read_methods_and_preserves_versioning() {
    let indexer = indexer_with_blocks("bloch-l2", 2);
    let cases = [
        (ReadRequest::Status {}, "status"),
        (ReadRequest::Tip {}, "tip"),
        (ReadRequest::Block { height: 101 }, "block"),
        (
            ReadRequest::Blocks {
                limit: 10,
                cursor: None,
            },
            "blocks",
        ),
        (
            ReadRequest::Events {
                limit: 10,
                cursor: None,
            },
            "events",
        ),
    ];

    for (request, expected) in cases {
        let response = call(&indexer, "request-1", request);
        assert_eq!(response.request_id.as_deref(), Some("request-1"));
        let ResponseOutcome::Ok { result } = response.outcome else {
            panic!("expected successful response");
        };
        let actual = match result {
            ReadResult::Status(value) => {
                assert_eq!(
                    value.finality,
                    bloch_indexer_query::FinalityStatus::NotEstablished
                );
                "status"
            }
            ReadResult::Tip(value) => {
                assert_eq!(
                    value.finality,
                    bloch_indexer_query::FinalityStatus::NotEstablished
                );
                "tip"
            }
            ReadResult::Block(value) => {
                assert_eq!(
                    value.finality,
                    bloch_indexer_query::FinalityStatus::NotEstablished
                );
                "block"
            }
            ReadResult::Blocks(value) => {
                assert_eq!(
                    value.finality,
                    bloch_indexer_query::FinalityStatus::NotEstablished
                );
                "blocks"
            }
            ReadResult::Events(value) => {
                assert_eq!(
                    value.finality,
                    bloch_indexer_query::FinalityStatus::NotEstablished
                );
                "events"
            }
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn strict_decoder_rejects_duplicates_unknown_fields_and_trailing_json() {
    let indexer = indexer_with_blocks("bloch-l2", 1);
    let malformed = [
        r#"{"schema":"bloch.data.query-request.v1","schema":"bloch.data.query-request.v1","requestId":"x","request":{"method":"status"}}"#,
        r#"{"schema":"bloch.data.query-request.v1","requestId":"x","request":{"method":"status","method":"status"}}"#,
        r#"{"schema":"bloch.data.query-request.v1","requestId":"x","request":{"method":"status","height":101}}"#,
        r#"{"schema":"bloch.data.query-request.v1","requestId":"x","request":{"method":"status"},"write":true}"#,
        r#"{"schema":"bloch.data.query-request.v1","requestId":"x","request":{"method":"status"}} {}"#,
        r#"{"schema":"bloch.data.query-request.v2","requestId":"x","request":{"method":"status"}}"#,
    ];
    for request in malformed {
        assert_error(
            &dispatch(&indexer, request.as_bytes()),
            ErrorCode::InvalidRequest,
            None,
        );
    }
}

#[test]
fn empty_oversized_and_invalid_identifiers_fail_without_echoing_input() {
    let indexer = indexer_with_blocks("bloch-l2", 1);
    assert_error(&dispatch(&indexer, b""), ErrorCode::InvalidRequest, None);
    assert_error(
        &dispatch(&indexer, &vec![b' '; MAX_REQUEST_JSON_BYTES + 1]),
        ErrorCode::InvalidRequest,
        None,
    );
    let invalid_id = br#"{"schema":"bloch.data.query-request.v1","requestId":"secret\nvalue","request":{"method":"status"}}"#;
    assert_error(
        &dispatch(&indexer, invalid_id),
        ErrorCode::InvalidRequest,
        None,
    );
}

#[test]
fn limits_and_ranges_have_stable_public_errors() {
    let indexer = indexer_with_blocks("bloch-l2", 1);
    let invalid_limits = [
        ReadRequest::Blocks {
            limit: 0,
            cursor: None,
        },
        ReadRequest::Events {
            limit: 101,
            cursor: None,
        },
    ];
    for request in invalid_limits {
        let response = call(&indexer, "limit", request);
        assert_outcome_error(response.outcome, ErrorCode::InvalidLimit);
    }
    let response = call(&indexer, "height", ReadRequest::Block { height: 999 });
    assert_outcome_error(response.outcome, ErrorCode::HeightOutsideCanonicalRange);
}

#[test]
fn cursors_remain_opaque_and_fail_closed_across_kind_and_network() {
    let first = indexer_with_blocks("bloch-l2", 3);
    let page = call(
        &first,
        "page",
        ReadRequest::Blocks {
            limit: 1,
            cursor: None,
        },
    );
    let ResponseOutcome::Ok {
        result: ReadResult::Blocks(page),
    } = page.outcome
    else {
        panic!("expected block page");
    };
    let cursor = page.next_cursor.expect("next cursor");

    let wrong_kind = call(
        &first,
        "kind",
        ReadRequest::Events {
            limit: 1,
            cursor: Some(cursor.clone()),
        },
    );
    assert_outcome_error(wrong_kind.outcome, ErrorCode::CursorKindMismatch);

    let other = indexer_with_blocks("other-l2", 3);
    let wrong_network = call(
        &other,
        "network",
        ReadRequest::Blocks {
            limit: 1,
            cursor: Some(cursor.clone()),
        },
    );
    assert_outcome_error(wrong_network.outcome, ErrorCode::CursorNetworkMismatch);

    let invalid = call(
        &first,
        "invalid",
        ReadRequest::Blocks {
            limit: 1,
            cursor: Some(format!("{cursor}x")),
        },
    );
    assert_outcome_error(invalid.outcome, ErrorCode::InvalidCursor);
}

#[test]
fn reorganization_invalidates_snapshot_cursor() {
    let mut indexer = indexer_with_blocks("bloch-l2", 3);
    let first = call(
        &indexer,
        "page",
        ReadRequest::Blocks {
            limit: 1,
            cursor: None,
        },
    );
    let ResponseOutcome::Ok {
        result: ReadResult::Blocks(page),
    } = first.outcome
    else {
        panic!("expected block page");
    };
    let cursor = page.next_cursor.unwrap();
    indexer
        .apply(block(102, hash('e'), hash('2'), "bloch-l2"))
        .unwrap();
    let response = call(
        &indexer,
        "stale",
        ReadRequest::Blocks {
            limit: 1,
            cursor: Some(cursor),
        },
    );
    assert_outcome_error(response.outcome, ErrorCode::CursorStale);
}

#[test]
fn sdk_enforces_request_and_response_contracts() {
    let typed = RequestEnvelope {
        schema: REQUEST_SCHEMA.into(),
        request_id: "sdk:1".into(),
        request: ReadRequest::Tip {},
    };
    let encoded = encode_request(&typed).unwrap();
    assert_eq!(
        decode_response(&dispatch(&indexer_with_blocks("bloch-l2", 0), &encoded))
            .unwrap()
            .request_id
            .as_deref(),
        Some("sdk:1")
    );

    let mut oversized = typed;
    oversized.request_id = "x".repeat(129);
    assert_eq!(encode_request(&oversized), Err(SdkError::InvalidMessage));

    let duplicate_response = br#"{"schema":"bloch.data.query-response.v1","schema":"bloch.data.query-response.v1","requestId":null,"outcome":{"type":"error","error":{"code":"invalidRequest","message":"request does not satisfy the v1 contract"}}}"#;
    assert_eq!(
        decode_response(duplicate_response),
        Err(SdkError::InvalidMessage)
    );
    let leaking_message = br#"{"schema":"bloch.data.query-response.v1","requestId":null,"outcome":{"type":"error","error":{"code":"invalidRequest","message":"serde line 1 column 9"}}}"#;
    assert_eq!(
        decode_response(leaking_message),
        Err(SdkError::InvalidMessage)
    );

    let unknown = br#"{"schema":"bloch.data.query-response.v1","requestId":null,"outcome":{"type":"error","error":{"code":"invalidRequest","message":"request does not satisfy the v1 contract"}},"extra":true}"#;
    assert_eq!(decode_response(unknown), Err(SdkError::InvalidMessage));
    let trailing = br#"{"schema":"bloch.data.query-response.v1","requestId":null,"outcome":{"type":"error","error":{"code":"invalidRequest","message":"request does not satisfy the v1 contract"}}} {}"#;
    assert_eq!(decode_response(trailing), Err(SdkError::InvalidMessage));

    let valid = dispatch(&indexer_with_blocks("bloch-l2", 0), &encoded);
    let mut result_extra: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    result_extra["outcome"]["result"]["extra"] = serde_json::Value::Bool(true);
    assert_eq!(
        decode_response(&serde_json::to_vec(&result_extra).unwrap()),
        Err(SdkError::InvalidMessage)
    );
}

#[test]
fn protocol_does_not_expose_write_or_finality_request_variants() {
    let indexer = indexer_with_blocks("bloch-l2", 0);
    for method in ["write", "finalize", "submitBlock"] {
        let request = format!(
            r#"{{"schema":"bloch.data.query-request.v1","requestId":"x","request":{{"method":"{method}"}}}}"#
        );
        assert_error(
            &dispatch(&indexer, request.as_bytes()),
            ErrorCode::InvalidRequest,
            None,
        );
    }
}

fn call(
    indexer: &CanonicalIndexer,
    request_id: &str,
    request: ReadRequest,
) -> bloch_indexer_protocol::ResponseEnvelope {
    let request = RequestEnvelope {
        schema: REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        request,
    };
    decode_response(&dispatch(indexer, &encode_request(&request).unwrap())).unwrap()
}

fn assert_error(bytes: &[u8], code: ErrorCode, request_id: Option<&str>) {
    let response = decode_response(bytes).unwrap();
    assert_eq!(response.request_id.as_deref(), request_id);
    assert_outcome_error(response.outcome, code);
}

fn assert_outcome_error(outcome: ResponseOutcome, code: ErrorCode) {
    let ResponseOutcome::Error { error } = outcome else {
        panic!("expected error response");
    };
    assert_eq!(error.code, code);
    assert_eq!(error.message, code.message());
}

fn indexer_with_blocks(network: &str, count: u64) -> CanonicalIndexer {
    let mut indexer = CanonicalIndexer::new(
        ChainIdentity {
            network: network.into(),
            chain_id: 700_771,
            genesis_hash: hash('9'),
        },
        BlockAnchor {
            height: 100,
            block_hash: hash('1'),
            state_root: hash('a'),
        },
        8,
    )
    .unwrap();
    let mut parent = hash('1');
    for offset in 1..=count {
        let height = 100 + offset;
        let block_hash = match height {
            101 => hash('2'),
            102 => hash('3'),
            _ => hash('4'),
        };
        assert!(matches!(
            indexer.apply(block(height, block_hash.clone(), parent, network)),
            Ok(ApplyOutcome::Applied { .. })
        ));
        parent = block_hash;
    }
    indexer
}

fn block(height: u64, block_hash: String, parent_hash: String, network: &str) -> CanonicalBlock {
    CanonicalBlock {
        schema: "bloch.data.canonical-block.v1".into(),
        network: ChainIdentity {
            network: network.into(),
            chain_id: 700_771,
            genesis_hash: hash('9'),
        },
        height,
        block_hash,
        parent_hash,
        state_root: hash('a'),
        timestamp_unix_seconds: 1_790_000_000 + height,
        events: vec![CanonicalEvent {
            transaction_hash: hash('b'),
            transaction_index: 0,
            log_index: 0,
            address: format!("0x{}", "c".repeat(40)),
            topics: vec![hash('d')],
            data: "0x".into(),
        }],
    }
}

fn hash(character: char) -> String {
    format!("0x{}", character.to_string().repeat(64))
}
