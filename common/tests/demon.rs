use red_cell_common::demon::{
    DEMON_MAGIC_VALUE, DemonCallback, DemonCommand, DemonEnvelope, DemonHeader, DemonInjectError,
    DemonMessage, DemonPackage, DemonProtocolError, DemonSocketCommand, DemonSocketType,
    DemonTransferCommand, MIN_ENVELOPE_SIZE,
};

#[test]
fn demon_header_round_trip_preserves_big_endian_wire_format() {
    let header = DemonHeader::new(0x1122_3344, 5).expect("header construction should succeed");
    let bytes = header.to_bytes();

    assert_eq!(bytes, [0x00, 0x00, 0x00, 0x0d, 0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44,]);

    let parsed = DemonHeader::from_bytes(&bytes).expect("header decoding should succeed");

    assert_eq!(parsed, header);
    assert_eq!(parsed.magic, DEMON_MAGIC_VALUE);
}

#[test]
fn demon_envelope_round_trip_preserves_payload() {
    let envelope = DemonEnvelope::new(0xaabb_ccdd, vec![0x10, 0x20, 0x30])
        .expect("envelope construction should succeed");
    let bytes = envelope.to_bytes();

    let parsed = DemonEnvelope::from_bytes(&bytes).expect("envelope decoding should succeed");

    assert_eq!(parsed, envelope);
}

#[test]
fn demon_package_round_trip_uses_little_endian_layout() {
    let package =
        DemonPackage::new(DemonCommand::CommandCheckin, 0x0102_0304, vec![0xaa, 0xbb, 0xcc]);
    let bytes = package.to_bytes().expect("package encoding should succeed");

    assert_eq!(
        bytes,
        [0x64, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc,]
    );

    let parsed = DemonPackage::from_bytes(&bytes).expect("package decoding should succeed");

    assert_eq!(parsed, package);
    assert_eq!(
        parsed.command().expect("command id should be recognized"),
        DemonCommand::CommandCheckin
    );
}

#[test]
fn demon_message_round_trip_preserves_multiple_packages() {
    let message = DemonMessage::new(vec![
        DemonPackage::new(DemonCommand::CommandGetJob, 1, Vec::new()),
        DemonPackage::new(DemonCommand::CommandSocket, 2, vec![0xde, 0xad, 0xbe, 0xef]),
    ]);

    let bytes = message.to_bytes().expect("message encoding should succeed");
    let parsed = DemonMessage::from_bytes(&bytes).expect("message decoding should succeed");

    assert_eq!(parsed, message);
}

#[test]
fn demon_message_round_trip_preserves_empty_stream() {
    let message = DemonMessage::new(Vec::new());

    let bytes = message.to_bytes().expect("empty message should encode");
    let parsed = DemonMessage::from_bytes(&bytes).expect("empty message should decode");

    assert!(bytes.is_empty());
    assert_eq!(parsed, message);
}

#[test]
fn demon_header_accepts_maximum_wire_payload_length() {
    let header = DemonHeader::new(0xface_cafe, u32::MAX as usize - 8)
        .expect("largest wire-representable payload should fit");

    assert_eq!(header.size, u32::MAX);
    assert_eq!(header.agent_id, 0xface_cafe);
}

#[test]
fn demon_header_rejects_payload_length_overflow() {
    let error = DemonHeader::new(7, u32::MAX as usize - 7)
        .expect_err("payload larger than wire format must fail");

    assert_eq!(
        error,
        DemonProtocolError::LengthOverflow {
            context: "Demon header payload",
            length: u32::MAX as usize - 7,
        }
    );
}

#[test]
fn demon_envelope_rejects_declared_size_mismatch() {
    let error = DemonEnvelope::from_bytes(&[
        0x00, 0x00, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0xaa,
    ])
    .expect_err("mismatched transport size must fail");

    assert_eq!(error, DemonProtocolError::SizeMismatch { declared: 8, actual: 9 });
}

#[test]
fn demon_package_round_trip_supports_empty_payload() {
    let package = DemonPackage::new(DemonCommand::CommandNoJob, 99, Vec::new());

    let bytes = package.to_bytes().expect("package should encode");
    let parsed = DemonPackage::from_bytes(&bytes).expect("package should decode");

    assert_eq!(bytes.len(), 12);
    assert_eq!(parsed, package);
}

#[test]
fn demon_package_encoded_len_reports_header_size_for_empty_payload() {
    let package = DemonPackage::new(DemonCommand::CommandNoJob, 99, Vec::new());

    assert_eq!(package.encoded_len(), 12);
}

#[test]
fn demon_package_encoded_len_matches_encoded_buffer_for_non_empty_payload() {
    let package =
        DemonPackage::new(DemonCommand::CommandCheckin, 0x1234_5678, vec![0xaa, 0xbb, 0xcc]);

    let bytes = package.to_bytes().expect("package should encode");

    assert_eq!(package.encoded_len(), bytes.len());
    assert_eq!(package.encoded_len(), 12 + package.payload.len());
}

#[test]
fn demon_package_encoded_len_matches_large_payload_and_message_aggregation() {
    let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let package = DemonPackage::new(DemonCommand::CommandSocket, 0x0bad_f00d, payload.clone());
    let message = DemonMessage::new(vec![
        DemonPackage::new(DemonCommand::CommandGetJob, 7, Vec::new()),
        package.clone(),
    ]);

    let package_bytes = package.to_bytes().expect("package should encode");
    let message_bytes = message.to_bytes().expect("message should encode");
    let expected_message_len: usize = message.packages.iter().map(DemonPackage::encoded_len).sum();

    assert_eq!(package.encoded_len(), 12 + payload.len());
    assert_eq!(package.encoded_len(), package_bytes.len());
    assert_eq!(message_bytes.len(), expected_message_len);
}

#[test]
fn demon_package_rejects_trailing_bytes() {
    let bytes =
        [0x5c, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb];

    let error = DemonPackage::from_bytes(&bytes).expect_err("trailing bytes must be rejected");

    assert_eq!(error, DemonProtocolError::SizeMismatch { declared: 13, actual: 14 });
}

#[test]
fn demon_message_rejects_truncated_second_package() {
    let first = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new())
        .to_bytes()
        .expect("first package should encode");
    let second = [0x64, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xaa];
    let mut bytes = first;
    bytes.extend_from_slice(&second);

    let error = DemonMessage::from_bytes(&bytes).expect_err("truncated package stream must fail");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "Demon package payload",
            expected: 2,
            actual: 1,
        }
    );
}

#[test]
fn rejects_invalid_magic_value() {
    let bytes = [0x00, 0x00, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xee, 0x00, 0x00, 0x00, 0x01];

    let error = DemonHeader::from_bytes(&bytes).expect_err("invalid magic must be rejected");

    assert_eq!(
        error,
        DemonProtocolError::InvalidMagic { expected: DEMON_MAGIC_VALUE, actual: 0xdead_beee }
    );
}

#[test]
fn rejects_truncated_package_payload() {
    let bytes =
        [0x5a, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x00, 0x00, 0xaa, 0xbb];

    let error = DemonPackage::from_bytes(&bytes).expect_err("truncated payload must fail");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "Demon package payload",
            expected: 4,
            actual: 2,
        }
    );
}

#[test]
fn demon_header_rejects_buffer_shorter_than_header() {
    let error = DemonHeader::from_bytes(&[0u8; 4])
        .expect_err("buffer shorter than 12 bytes must be rejected");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort { context: "Demon header", expected: 12, actual: 4 }
    );
}

#[test]
fn demon_header_from_bytes_accepts_oversized_buffer() {
    let header = DemonHeader::new(0x1122_3344, 5).expect("header construction should succeed");
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF; 32]);

    let parsed = DemonHeader::from_bytes(&bytes).expect("oversized buffer must still parse header");
    assert_eq!(parsed, header);
}

#[test]
fn demon_envelope_rejects_buffer_shorter_than_header() {
    let error = DemonEnvelope::from_bytes(&[0u8; 8])
        .expect_err("buffer shorter than 12 bytes must be rejected");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 8,
        }
    );
}

#[test]
fn demon_envelope_rejects_empty_buffer() {
    let error = DemonEnvelope::from_bytes(&[]).expect_err("empty buffer must be rejected early");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 0,
        }
    );
}

#[test]
fn demon_envelope_rejects_one_byte_buffer() {
    let error =
        DemonEnvelope::from_bytes(&[0xde]).expect_err("1-byte buffer must be rejected early");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 1,
        }
    );
}

#[test]
fn demon_envelope_rejects_two_byte_buffer() {
    let error =
        DemonEnvelope::from_bytes(&[0xde, 0xad]).expect_err("2-byte buffer must be rejected early");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 2,
        }
    );
}

#[test]
fn demon_envelope_rejects_three_byte_buffer() {
    let error = DemonEnvelope::from_bytes(&[0xde, 0xad, 0xbe])
        .expect_err("3-byte buffer must be rejected early");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 3,
        }
    );
}

#[test]
fn demon_package_rejects_buffer_too_short_for_command_id() {
    let error = DemonPackage::from_bytes(&[0u8; 2])
        .expect_err("buffer shorter than 4 bytes must be rejected");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "Demon package command id",
            expected: 4,
            actual: 2,
        }
    );
}

#[test]
fn demon_package_rejects_buffer_too_short_for_request_id() {
    for actual in 1..=3 {
        let bytes = vec![0u8; 4 + actual];
        let error = DemonPackage::from_bytes(&bytes)
            .expect_err("buffer shorter than 8 bytes must reject request id parsing");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package request id",
                expected: 4,
                actual,
            }
        );
    }
}

#[test]
fn demon_package_rejects_buffer_too_short_for_payload_length() {
    for actual in 1..=3 {
        let bytes = vec![0u8; 8 + actual];
        let error = DemonPackage::from_bytes(&bytes)
            .expect_err("buffer shorter than 12 bytes must reject payload length parsing");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package payload length",
                expected: 4,
                actual,
            }
        );
    }
}

#[test]
fn enum_conversions_match_havoc_constants() {
    assert_eq!(u32::from(DemonCommand::DemonInit), 99);
    assert_eq!(u32::from(DemonCommand::CommandKerberos), 2550);
    assert_eq!(u32::from(DemonCallback::File), 0x02);
    assert_eq!(u32::from(DemonTransferCommand::Remove), 3);
    assert_eq!(u32::from(DemonSocketCommand::Connect), 0x14);
    assert_eq!(u32::from(DemonSocketType::Client), 0x3);
    assert_eq!(u32::from(DemonInjectError::ProcessArchMismatch), 3);
}

#[test]
fn enum_try_from_rejects_unknown_values() {
    let error =
        DemonCommand::try_from(0xffff_ffff).expect_err("unknown command should be rejected");

    assert_eq!(
        error,
        DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xffff_ffff }
    );
}

#[test]
fn demon_package_command_returns_error_for_unrecognized_command_id() {
    let package = DemonPackage { command_id: 0xffff_ffff, request_id: 1, payload: vec![] };
    let bytes = package.to_bytes().expect("package encoding should succeed");
    let parsed = DemonPackage::from_bytes(&bytes).expect("package decoding should succeed");

    let result = parsed.command();

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xffff_ffff })
    ));
}

// ── Golden-vector tests ────────────────────────────────────────────────
//
// These tests verify decoding and re-encoding of hand-constructed byte
// sequences that match the original Havoc Demon binary protocol layout.
// They pin the on-wire format so that internal refactors cannot silently
// drift from Havoc compatibility.

/// Golden vector: DemonEnvelope carrying a two-package DemonMessage.
///
/// Wire layout (41 bytes total):
///   Header (12 bytes, big-endian):
///     size    = 0x00000025 (37 = 29 payload + 8)
///     magic   = 0xDEADBEEF
///     agent_id= 0xCAFEBABE
///   Package 1 (12 bytes, little-endian): CommandGetJob(1), req=0, 0-byte payload
///   Package 2 (17 bytes, little-endian): CommandOutput(90), req=0x42, 5-byte payload "Hello"
#[test]
fn golden_vector_envelope_with_two_packages() {
    #[rustfmt::skip]
    let wire: &[u8] = &[
        // -- DemonHeader (big-endian) --
        0x00, 0x00, 0x00, 0x25, // size = 37
        0xDE, 0xAD, 0xBE, 0xEF, // magic
        0xCA, 0xFE, 0xBA, 0xBE, // agent_id
        // -- Package 1: CommandGetJob --
        0x01, 0x00, 0x00, 0x00, // command_id = 1 (LE)
        0x00, 0x00, 0x00, 0x00, // request_id = 0 (LE)
        0x00, 0x00, 0x00, 0x00, // payload_len = 0 (LE)
        // -- Package 2: CommandOutput --
        0x5A, 0x00, 0x00, 0x00, // command_id = 90 (LE)
        0x42, 0x00, 0x00, 0x00, // request_id = 0x42 (LE)
        0x05, 0x00, 0x00, 0x00, // payload_len = 5 (LE)
        0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
    ];

    let envelope = DemonEnvelope::from_bytes(wire).expect("golden vector must decode");
    assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
    assert_eq!(envelope.header.agent_id, 0xCAFE_BABE);

    let message =
        DemonMessage::from_bytes(&envelope.payload).expect("packages must decode from payload");
    assert_eq!(message.packages.len(), 2, "expected exactly two packages");

    let pkg1 = &message.packages[0];
    assert_eq!(pkg1.command().expect("should recognize"), DemonCommand::CommandGetJob);
    assert_eq!(pkg1.request_id, 0);
    assert!(pkg1.payload.is_empty());

    let pkg2 = &message.packages[1];
    assert_eq!(pkg2.command().expect("should recognize"), DemonCommand::CommandOutput);
    assert_eq!(pkg2.request_id, 0x42);
    assert_eq!(pkg2.payload, b"Hello");

    let reencoded = envelope.to_bytes();
    assert_eq!(reencoded.as_slice(), wire, "re-encoded envelope must match golden vector");
}

/// Golden vector: single-package envelope with CommandExit.
///
/// Wire layout (28 bytes total):
///   Header (12 bytes, big-endian):
///     size    = 0x00000018 (24 = 16 payload + 8)
///     magic   = 0xDEADBEEF
///     agent_id= 0x00001337
///   Package (16 bytes, little-endian):
///     CommandExit(92), req=0xFF, 4-byte payload: exit_method=2 (LE)
#[test]
fn golden_vector_single_package_command_exit() {
    #[rustfmt::skip]
    let wire: &[u8] = &[
        // -- DemonHeader (big-endian) --
        0x00, 0x00, 0x00, 0x18, // size = 24
        0xDE, 0xAD, 0xBE, 0xEF, // magic
        0x00, 0x00, 0x13, 0x37, // agent_id
        // -- Package: CommandExit --
        0x5C, 0x00, 0x00, 0x00, // command_id = 92 (LE)
        0xFF, 0x00, 0x00, 0x00, // request_id = 0xFF (LE)
        0x04, 0x00, 0x00, 0x00, // payload_len = 4 (LE)
        0x02, 0x00, 0x00, 0x00, // exit_method = 2 (LE, process exit)
    ];

    let envelope = DemonEnvelope::from_bytes(wire).expect("golden vector must decode");
    assert_eq!(envelope.header.agent_id, 0x0000_1337);

    let message = DemonMessage::from_bytes(&envelope.payload).expect("packages must decode");
    assert_eq!(message.packages.len(), 1);

    let pkg = &message.packages[0];
    assert_eq!(pkg.command().expect("should recognize"), DemonCommand::CommandExit);
    assert_eq!(pkg.request_id, 0xFF);
    assert_eq!(pkg.payload, [0x02, 0x00, 0x00, 0x00]);

    let reencoded = envelope.to_bytes();
    assert_eq!(reencoded.as_slice(), wire, "re-encoded envelope must match golden vector");
}

/// Golden vector: multi-package message stream ordering.
///
/// Verifies that DemonMessage preserves the exact package order from
/// the wire, which matters for command dispatch sequencing.
#[test]
fn golden_vector_message_stream_ordering() {
    #[rustfmt::skip]
    let packages_wire: &[u8] = &[
        // Package 1: CommandCheckin(100), req=1, empty
        0x64, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // Package 2: CommandGetJob(1), req=2, empty
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // Package 3: CommandNoJob(10), req=3, empty
        0x0A, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let message = DemonMessage::from_bytes(packages_wire).expect("message must decode");
    assert_eq!(message.packages.len(), 3, "expected exactly three packages");

    assert_eq!(message.packages[0].command().expect("cmd"), DemonCommand::CommandCheckin);
    assert_eq!(message.packages[0].request_id, 1);

    assert_eq!(message.packages[1].command().expect("cmd"), DemonCommand::CommandGetJob);
    assert_eq!(message.packages[1].request_id, 2);

    assert_eq!(message.packages[2].command().expect("cmd"), DemonCommand::CommandNoJob);
    assert_eq!(message.packages[2].request_id, 3);

    let reencoded = message.to_bytes().expect("message must encode");
    assert_eq!(reencoded.as_slice(), packages_wire, "re-encoded message must match golden vector");
}

/// Verify that `DemonPackage::from_bytes` safely rejects a payload_len of
/// `u32::MAX` (4 GiB) without attempting the allocation. The `read_vec`
/// length check must fire before any `Vec::with_capacity` or `to_vec` call.
#[test]
fn demon_package_rejects_u32_max_payload_len_without_allocating() {
    #[rustfmt::skip]
    let bytes: [u8; 12] = [
        0x01, 0x00, 0x00, 0x00, // command_id = 1 (LE)
        0x02, 0x00, 0x00, 0x00, // request_id = 2 (LE)
        0xFF, 0xFF, 0xFF, 0xFF, // payload_len = u32::MAX (LE)
    ];

    let error = DemonPackage::from_bytes(&bytes)
        .expect_err("u32::MAX payload_len with no trailing data must fail");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "Demon package payload",
            expected: u32::MAX as usize,
            actual: 0,
        }
    );
}
