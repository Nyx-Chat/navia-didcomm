use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::error::Category;

#[cfg(feature = "tracing")]
use tracing::{debug, error, trace, warn};

/// Structured error kinds with detailed categorization for better diagnostics
#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorKind {
    // DID Resolution Errors
    #[error("DID not resolved")]
    DIDNotResolved,

    #[error("DID URL not found")]
    DIDUrlNotFound,

    #[error("DID document invalid or malformed")]
    DIDDocumentInvalid,

    // Secret/Key Management Errors
    #[error("Secret not found")]
    SecretNotFound,

    #[error("Key material invalid or corrupted")]
    InvalidKeyMaterial,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    // Message Processing Errors
    #[error("Message malformed or invalid")]
    Malformed,

    #[error("Message encryption failed")]
    EncryptionFailed,

    #[error("Message decryption failed")]
    DecryptionFailed,

    #[error("Message signature verification failed")]
    SignatureVerificationFailed,

    #[error("Message signature creation failed")]
    SignatureCreationFailed,

    // Protocol Errors
    #[error("DIDComm protocol violation")]
    ProtocolViolation,

    #[error("Message format not supported")]
    UnsupportedFormat,

    #[error("Required header or field missing")]
    MissingRequiredField,

    // Cryptographic Errors
    #[error("No compatible cryptographic algorithms found")]
    NoCompatibleCrypto,

    #[error("Cryptographic operation failed")]
    CryptoOperationFailed,

    #[error("Unsupported cryptographic algorithm or method")]
    Unsupported,

    // System/Runtime Errors
    #[error("IO operation failed")]
    IoError,

    #[error("Invalid system state")]
    InvalidState,

    #[error("Illegal argument provided")]
    IllegalArgument,

    #[error("Operation timeout")]
    Timeout,

    #[error("Resource exhausted")]
    ResourceExhausted,
}

/// Contextual information for enhanced error diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Operation being performed when error occurred
    pub operation: Option<String>,

    /// DID involved in the operation
    pub did: Option<String>,

    /// Message ID if applicable
    pub message_id: Option<String>,

    /// Algorithm or method being used
    pub algorithm: Option<String>,

    /// Additional key-value context
    pub details: HashMap<String, String>,
}

/// Enhanced error structure with contextual information for better diagnostics
#[derive(Debug, thiserror::Error)]
#[error("{kind}: {source:#}")]
pub struct Error {
    kind: ErrorKind,
    pub source: anyhow::Error,
    /// Contextual information about the error
    pub context: Option<ErrorContext>,
}

impl Error {
    /// Get the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Get the error context if available
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Create a new error with a source error
    pub fn new<E>(kind: ErrorKind, source: E) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::new(source),
            context: None,
        }
    }

    /// Create a new error with a message
    pub fn msg<D>(kind: ErrorKind, msg: D) -> Error
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::msg(msg),
            context: None,
        }
    }

    /// Create a new error with context
    pub fn with_context<E>(kind: ErrorKind, source: E, context: ErrorContext) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::new(source),
            context: Some(context),
        }
    }

    /// Create a new error with message and context
    pub fn msg_with_context<D>(kind: ErrorKind, msg: D, context: ErrorContext) -> Error
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::msg(msg),
            context: Some(context),
        }
    }

    /// Add context to an existing error
    pub fn add_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Check if this is a cryptographic error
    pub fn is_crypto_error(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::NoCompatibleCrypto
                | ErrorKind::CryptoOperationFailed
                | ErrorKind::EncryptionFailed
                | ErrorKind::DecryptionFailed
                | ErrorKind::SignatureVerificationFailed
                | ErrorKind::SignatureCreationFailed
                | ErrorKind::InvalidKeyMaterial
                | ErrorKind::KeyDerivationFailed
        )
    }

    /// Check if this is a protocol error
    pub fn is_protocol_error(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::ProtocolViolation
                | ErrorKind::UnsupportedFormat
                | ErrorKind::MissingRequiredField
                | ErrorKind::Malformed
        )
    }

    /// Check if this is a DID resolution error
    pub fn is_did_error(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::DIDNotResolved | ErrorKind::DIDUrlNotFound | ErrorKind::DIDDocumentInvalid
        )
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Timeout | ErrorKind::IoError | ErrorKind::ResourceExhausted
        )
    }

    /// Get a structured representation of the error for logging/debugging
    pub fn to_diagnostic(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "message": self.source.to_string(),
            "context": self.context,
            "is_crypto_error": self.is_crypto_error(),
            "is_protocol_error": self.is_protocol_error(),
            "is_did_error": self.is_did_error(),
            "is_retryable": self.is_retryable()
        })
    }

    /// Log this error with appropriate level based on severity
    #[cfg(feature = "tracing")]
    pub fn log(&self) {
        let diagnostic = self.to_diagnostic();

        match self.kind {
            // Critical errors that should always be logged as errors
            ErrorKind::CryptoOperationFailed
            | ErrorKind::EncryptionFailed
            | ErrorKind::DecryptionFailed
            | ErrorKind::SignatureVerificationFailed
            | ErrorKind::InvalidKeyMaterial
            | ErrorKind::ProtocolViolation => {
                error!(
                    error.kind = ?self.kind,
                    error.message = %self.source,
                    error.context = ?self.context,
                    error.diagnostic = ?diagnostic,
                    "Critical DIDComm error occurred"
                );
            }

            // Warnings for expected but problematic situations
            ErrorKind::DIDNotResolved
            | ErrorKind::SecretNotFound
            | ErrorKind::NoCompatibleCrypto
            | ErrorKind::Unsupported
            | ErrorKind::Timeout => {
                warn!(
                    error.kind = ?self.kind,
                    error.message = %self.source,
                    error.context = ?self.context,
                    "DIDComm operation warning"
                );
            }

            // Debug level for validation and input errors
            ErrorKind::Malformed
            | ErrorKind::IllegalArgument
            | ErrorKind::MissingRequiredField
            | ErrorKind::UnsupportedFormat => {
                debug!(
                    error.kind = ?self.kind,
                    error.message = %self.source,
                    error.context = ?self.context,
                    "DIDComm validation error"
                );
            }

            // Trace level for less critical errors
            _ => {
                trace!(
                    error.kind = ?self.kind,
                    error.message = %self.source,
                    error.context = ?self.context,
                    "DIDComm operation failed"
                );
            }
        }
    }

    /// Log this error without the tracing feature (no-op)
    #[cfg(not(feature = "tracing"))]
    pub fn log(&self) {
        // No-op when tracing is disabled
    }

    /// Create and log an error in one step
    #[cfg(feature = "tracing")]
    pub fn log_and_return<T>(
        kind: ErrorKind,
        msg: impl fmt::Display + fmt::Debug + Send + Sync + 'static,
    ) -> Result<T> {
        let error = Self::msg(kind, msg);
        error.log();
        Err(error)
    }

    /// Create and log an error in one step (no-op without tracing)
    #[cfg(not(feature = "tracing"))]
    pub fn log_and_return<T>(
        kind: ErrorKind,
        msg: impl fmt::Display + fmt::Debug + Send + Sync + 'static,
    ) -> Result<T> {
        Err(Self::msg(kind, msg))
    }

    /// Create and log an error with context in one step
    #[cfg(feature = "tracing")]
    pub fn log_and_return_with_context<T>(
        kind: ErrorKind,
        msg: impl fmt::Display + fmt::Debug + Send + Sync + 'static,
        context: ErrorContext,
    ) -> Result<T> {
        let error = Self::msg_with_context(kind, msg, context);
        error.log();
        Err(error)
    }

    /// Create and log an error with context in one step (no-op without tracing)
    #[cfg(not(feature = "tracing"))]
    pub fn log_and_return_with_context<T>(
        kind: ErrorKind,
        msg: impl fmt::Display + fmt::Debug + Send + Sync + 'static,
        context: ErrorContext,
    ) -> Result<T> {
        Err(Self::msg_with_context(kind, msg, context))
    }
}

impl ErrorContext {
    /// Create a new empty error context
    pub fn new() -> Self {
        Self {
            operation: None,
            did: None,
            message_id: None,
            algorithm: None,
            details: HashMap::new(),
        }
    }

    /// Set the operation context
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Set the DID context
    pub fn with_did(mut self, did: impl Into<String>) -> Self {
        self.did = Some(did.into());
        self
    }

    /// Set the message ID context
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    /// Set the algorithm context
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = Some(algorithm.into());
        self
    }

    /// Add a detail entry
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ResultExt<T, E> {
    fn kind<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T, E> ResultExt<T, E> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn kind<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|e| Error {
            kind,
            source: anyhow::Error::new(e).context(msg),
            context: None,
        })
    }
}

pub trait ResultExtNoContext<T, E> {
    fn to_error_kind(self, kind: ErrorKind) -> std::result::Result<T, ErrorKind>;

    fn kind_no_context<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T, E> ResultExtNoContext<T, E> for std::result::Result<T, E> {
    fn to_error_kind(self, kind: ErrorKind) -> std::result::Result<T, ErrorKind> {
        self.map_err(|_| kind)
    }

    fn kind_no_context<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|_| Error::msg(kind, msg))
    }
}

pub trait ResultContext<T> {
    fn context<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T> ResultContext<T> for Result<T> {
    fn context<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|e| {
            let Error {
                kind,
                source,
                context,
            } = e;

            Error {
                kind,
                source: source.context(msg),
                context,
            }
        })
    }
}

pub trait ToResult<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T> ToResult<T> for serde_json::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl<T> ToResult<T> for bs58::decode::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl<T> ToResult<T> for bs58::encode::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        match err.classify() {
            Category::Io | Category::Eof => Error::msg(ErrorKind::InvalidState, err.to_string()),
            _ => Error::msg(ErrorKind::Malformed, err.to_string()),
        }
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Self {
        match err {
            bs58::decode::Error::BufferTooSmall => {
                Error::msg(ErrorKind::InvalidState, err.to_string())
            }
            _ => Error::msg(ErrorKind::Malformed, err.to_string()),
        }
    }
}

impl From<bs58::encode::Error> for Error {
    fn from(err: bs58::encode::Error) -> Self {
        Error::msg(ErrorKind::InvalidState, err.to_string())
    }
}

pub fn err_msg<D>(kind: ErrorKind, msg: D) -> Error
where
    D: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    Error::msg(kind, msg)
}
