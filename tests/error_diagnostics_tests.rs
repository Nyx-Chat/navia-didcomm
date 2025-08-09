//! Tests for enhanced error handling and diagnostics
//!
//! This test suite verifies the structured error reporting,
//! contextual information, and logging capabilities.

use navia_didcomm::error::{Error, ErrorContext, ErrorKind};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_error_categorization() {
    let crypto_error = Error::msg(ErrorKind::EncryptionFailed, "Encryption failed");
    assert!(crypto_error.is_crypto_error());
    assert!(!crypto_error.is_protocol_error());
    assert!(!crypto_error.is_did_error());
    assert!(!crypto_error.is_retryable());

    let protocol_error = Error::msg(ErrorKind::ProtocolViolation, "Invalid message format");
    assert!(!protocol_error.is_crypto_error());
    assert!(protocol_error.is_protocol_error());
    assert!(!protocol_error.is_did_error());
    assert!(!protocol_error.is_retryable());

    let did_error = Error::msg(ErrorKind::DIDNotResolved, "DID not found");
    assert!(!did_error.is_crypto_error());
    assert!(!did_error.is_protocol_error());
    assert!(did_error.is_did_error());
    assert!(!did_error.is_retryable());

    let retryable_error = Error::msg(ErrorKind::Timeout, "Operation timed out");
    assert!(!retryable_error.is_crypto_error());
    assert!(!retryable_error.is_protocol_error());
    assert!(!retryable_error.is_did_error());
    assert!(retryable_error.is_retryable());
}

#[test]
fn test_error_context_creation() {
    let context = ErrorContext::new()
        .with_operation("pack_encrypted")
        .with_did("did:example:alice")
        .with_message_id("msg-123")
        .with_algorithm("ML-KEM-768")
        .with_detail("recipient_count", "2")
        .with_detail("key_type", "ML-DSA-65");

    assert_eq!(context.operation, Some("pack_encrypted".to_string()));
    assert_eq!(context.did, Some("did:example:alice".to_string()));
    assert_eq!(context.message_id, Some("msg-123".to_string()));
    assert_eq!(context.algorithm, Some("ML-KEM-768".to_string()));
    assert_eq!(
        context.details.get("recipient_count"),
        Some(&"2".to_string())
    );
    assert_eq!(
        context.details.get("key_type"),
        Some(&"ML-DSA-65".to_string())
    );
}

#[test]
fn test_error_with_context() {
    let context = ErrorContext::new()
        .with_operation("message_encryption")
        .with_did("did:example:bob")
        .with_algorithm("ML-KEM-768");

    let error = Error::msg_with_context(
        ErrorKind::EncryptionFailed,
        "Failed to encrypt message payload",
        context,
    );

    assert_eq!(error.kind(), ErrorKind::EncryptionFailed);

    let error_context = error.context().unwrap();
    assert_eq!(
        error_context.operation,
        Some("message_encryption".to_string())
    );
    assert_eq!(error_context.did, Some("did:example:bob".to_string()));
    assert_eq!(error_context.algorithm, Some("ML-KEM-768".to_string()));
}

#[test]
fn test_error_diagnostic_output() {
    let context = ErrorContext::new()
        .with_operation("sign_message")
        .with_did("did:example:signer")
        .with_message_id("msg-456")
        .with_detail("key_id", "did:example:signer#key-1");

    let error = Error::msg_with_context(
        ErrorKind::SignatureCreationFailed,
        "Unable to create digital signature",
        context,
    );

    let diagnostic = error.to_diagnostic();

    assert_eq!(
        diagnostic["kind"],
        json!(ErrorKind::SignatureCreationFailed)
    );
    assert_eq!(
        diagnostic["message"],
        json!("Unable to create digital signature")
    );
    assert_eq!(diagnostic["is_crypto_error"], json!(true));
    assert_eq!(diagnostic["is_protocol_error"], json!(false));
    assert_eq!(diagnostic["is_retryable"], json!(false));

    let context_json = &diagnostic["context"];
    assert_eq!(context_json["operation"], json!("sign_message"));
    assert_eq!(context_json["did"], json!("did:example:signer"));
    assert_eq!(context_json["message_id"], json!("msg-456"));
    assert_eq!(
        context_json["details"]["key_id"],
        json!("did:example:signer#key-1")
    );
}

#[test]
fn test_error_context_builder_pattern() {
    let mut details = HashMap::new();
    details.insert("curve".to_string(), "ML-DSA-65".to_string());
    details.insert("key_size".to_string(), "256".to_string());

    let context = ErrorContext {
        operation: Some("key_derivation".to_string()),
        did: Some("did:example:test".to_string()),
        message_id: None,
        algorithm: Some("ML-DSA".to_string()),
        details,
    };

    let error =
        Error::msg(ErrorKind::KeyDerivationFailed, "Key derivation failed").add_context(context);

    let error_context = error.context().unwrap();
    assert_eq!(error_context.operation, Some("key_derivation".to_string()));
    assert_eq!(error_context.algorithm, Some("ML-DSA".to_string()));
    assert_eq!(
        error_context.details.get("curve"),
        Some(&"ML-DSA-65".to_string())
    );
}

#[test]
fn test_comprehensive_error_kinds() {
    // Test all new error kinds are properly categorized
    let test_cases = vec![
        // DID errors
        (ErrorKind::DIDNotResolved, true, false, false, false),
        (ErrorKind::DIDUrlNotFound, true, false, false, false),
        (ErrorKind::DIDDocumentInvalid, true, false, false, false),
        // Crypto errors
        (ErrorKind::InvalidKeyMaterial, false, true, false, false),
        (ErrorKind::KeyDerivationFailed, false, true, false, false),
        (ErrorKind::EncryptionFailed, false, true, false, false),
        (ErrorKind::DecryptionFailed, false, true, false, false),
        (
            ErrorKind::SignatureVerificationFailed,
            false,
            true,
            false,
            false,
        ),
        (
            ErrorKind::SignatureCreationFailed,
            false,
            true,
            false,
            false,
        ),
        (ErrorKind::CryptoOperationFailed, false, true, false, false),
        (ErrorKind::NoCompatibleCrypto, false, true, false, false),
        // Protocol errors
        (ErrorKind::ProtocolViolation, false, false, true, false),
        (ErrorKind::UnsupportedFormat, false, false, true, false),
        (ErrorKind::MissingRequiredField, false, false, true, false),
        (ErrorKind::Malformed, false, false, true, false),
        // Retryable errors
        (ErrorKind::Timeout, false, false, false, true),
        (ErrorKind::IoError, false, false, false, true),
        (ErrorKind::ResourceExhausted, false, false, false, true),
    ];

    for (kind, is_did, is_crypto, is_protocol, is_retryable) in test_cases {
        let error = Error::msg(kind, format!("Test error for {kind:?}"));

        assert_eq!(
            error.is_did_error(),
            is_did,
            "DID error check failed for {kind:?}"
        );
        assert_eq!(
            error.is_crypto_error(),
            is_crypto,
            "Crypto error check failed for {kind:?}"
        );
        assert_eq!(
            error.is_protocol_error(),
            is_protocol,
            "Protocol error check failed for {kind:?}"
        );
        assert_eq!(
            error.is_retryable(),
            is_retryable,
            "Retryable check failed for {kind:?}"
        );
    }
}

#[test]
fn test_error_serialization() {
    let context = ErrorContext::new()
        .with_operation("test_operation")
        .with_did("did:example:test")
        .with_detail("test_key", "test_value");

    // Test ErrorKind serialization
    let kind_json = serde_json::to_string(&ErrorKind::EncryptionFailed).unwrap();
    assert_eq!(kind_json, "\"EncryptionFailed\"");

    // Test ErrorContext serialization
    let context_json = serde_json::to_value(&context).unwrap();
    assert_eq!(context_json["operation"], json!("test_operation"));
    assert_eq!(context_json["did"], json!("did:example:test"));
    assert_eq!(context_json["details"]["test_key"], json!("test_value"));
}

#[cfg(feature = "tracing")]
#[test]
fn test_error_logging_levels() {
    use tracing_test::traced_test;

    #[traced_test]
    fn test_logging() {
        // Test critical error logging
        let critical_error =
            Error::msg(ErrorKind::CryptoOperationFailed, "Critical crypto failure");
        critical_error.log();

        // Test warning level logging
        let warning_error = Error::msg(ErrorKind::DIDNotResolved, "DID not found");
        warning_error.log();

        // Test debug level logging
        let debug_error = Error::msg(ErrorKind::Malformed, "Invalid message format");
        debug_error.log();

        // Test trace level logging
        let trace_error = Error::msg(ErrorKind::InvalidState, "Invalid state");
        trace_error.log();
    }

    test_logging();
}
