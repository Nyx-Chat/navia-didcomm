# navia-didcomm API Reference

Complete API documentation for the navia-didcomm library.

## Core Functions

### Message Packing

#### `pack_encrypted`
Pack a message with encryption for specific recipients.

```rust
pub async fn pack_encrypted(
    message: &Message,
    sender_id: &str,
    recipients_ids: &[String],
    sign_by: Option<&str>,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
    options: &PackEncryptedOptions,
) -> Result<String>
```

**Parameters:**
- `message`: The message to pack
- `sender_id`: DID or DID URL of the sender
- `recipients_ids`: List of recipient DIDs or DID URLs
- `sign_by`: Optional DID for message signing (None for anoncrypt, Some for authcrypt)
- `did_resolver`: Resolver for DID documents
- `secrets_resolver`: Resolver for cryptographic secrets
- `options`: Packing options (forwarding, etc.)

**Returns:** JWE-encrypted message as JSON string

#### `pack_signed`
Pack a message with signature only (no encryption).

```rust
pub async fn pack_signed(
    message: &Message,
    sign_by: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
) -> Result<String>
```

#### `pack_plaintext`
Pack a message as plaintext (no encryption or signature).

```rust
pub fn pack_plaintext(message: &Message) -> Result<String>
```

### Message Unpacking

#### `unpack`
Unpack any type of DIDComm message.

```rust
pub async fn unpack(
    packed_msg: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
    options: &UnpackOptions,
) -> Result<(Message, MessageMetadata)>
```

**Returns:** Tuple of (unpacked message, metadata about the message)

### Message Types

#### `Message`
Core DIDComm message structure.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub type_: String,
    pub body: Value,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub created_time: Option<u64>,
    pub expires_time: Option<u64>,
    pub from_prior: Option<String>,
    pub attachments: Option<Vec<Attachment>>,
    pub thid: Option<String>,
    pub pthid: Option<String>,
    pub extra_headers: HashMap<String, Value>,
}
```

#### `MessageBuilder`
Builder pattern for creating messages.

```rust
impl MessageBuilder {
    pub fn id(mut self, id: String) -> Self
    pub fn type_(mut self, type_: String) -> Self  
    pub fn body(mut self, body: Value) -> Self
    pub fn from(mut self, from: String) -> Self
    pub fn to(mut self, to: Vec<String>) -> Self
    pub fn thid(mut self, thid: String) -> Self
    pub fn pthid(mut self, pthid: String) -> Self
    pub fn created_time(mut self, created_time: u64) -> Self
    pub fn expires_time(mut self, expires_time: u64) -> Self
    pub fn from_prior(mut self, from_prior: String) -> Self
    pub fn attachment(mut self, attachment: Attachment) -> Self
    pub fn attachments(mut self, attachments: Vec<Attachment>) -> Self
    pub fn header(mut self, key: String, value: Value) -> Self
    pub fn finalize(self) -> Message
}
```

### Attachments

#### `Attachment`
Message attachment with various data formats.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Option<String>,
    pub description: Option<String>,
    pub filename: Option<String>,
    pub media_type: Option<String>,
    pub format: Option<String>,
    pub lastmod_time: Option<u64>,
    pub byte_count: Option<u64>,
    pub data: AttachmentData,
}
```

#### `AttachmentData`
Different ways to include attachment data.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttachmentData {
    Base64 { base64: String },
    Json { json: Value },
    Links { links: Vec<String>, hash: String },
}
```

## DID Resolution

### `DIDResolver` Trait
Interface for resolving DID documents.

```rust
#[async_trait]
pub trait DIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>>;
}
```

### `CachingDIDResolver`
Thread-safe caching wrapper for DID resolution.

```rust
impl<'r> CachingDIDResolver<'r> {
    pub fn new(resolver: &'r dyn DIDResolver) -> Self
}
```

### `DIDDoc`
DID document structure following DID Core specification.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDoc {
    pub id: String,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub key_agreement: Vec<String>,
    pub service: Option<Vec<Service>>,
}
```

## Secrets Resolution

### `SecretsResolver` Trait
Interface for resolving cryptographic secrets.

```rust
#[async_trait]
pub trait SecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>>;
}
```

### `Secret`
Cryptographic key material.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub type_: SecretType,
    pub secret_material: SecretMaterial,
}
```

## Protocols

### Routing Protocol

#### `try_parse_forward`
Parse a message to check if it's a forward routing message.

```rust
pub fn try_parse_forward(msg: &Message) -> Option<ParsedForward<'_>>
```

#### `wrap_in_forward`
Wrap a message for routing through mediators.

```rust
pub async fn wrap_in_forward(
    msg: Message,
    next: String,
    routing_keys: &[String],
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
) -> Result<Message>
```

## Error Handling

### `Error`
Main error type with structured error reporting.

```rust
impl Error {
    pub fn kind(&self) -> ErrorKind
    pub fn context(&self) -> &ErrorContext
}
```

### `ErrorKind`
Categorized error types.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    // DID-related errors
    DIDNotResolved,
    DIDUrlNotFound,
    DIDDocumentInvalid,
    
    // Cryptographic errors
    SecretNotFound,
    InvalidKeyMaterial,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    SignatureVerificationFailed,
    SignatureCreationFailed,
    
    // Protocol errors
    Malformed,
    ProtocolViolation,
    UnsupportedFormat,
    MissingRequiredField,
    
    // System errors
    InvalidState,
    IllegalArgument,
    Unsupported,
    IoError,
    Timeout,
    ResourceExhausted,
}
```

### Error Extension Traits

#### `ResultExt`
Add context to Results.

```rust
use navia_didcomm::error::{ResultExt, ErrorKind};

let result = some_operation()
    .kind(ErrorKind::InvalidState, "Operation failed in specific context");
```

## Options and Configuration

### `PackEncryptedOptions`
Options for encrypted message packing.

```rust
#[derive(Debug, Clone)]
pub struct PackEncryptedOptions {
    pub forward: bool,
    pub messaging_service_id: Option<String>,
    pub enc_alg_anon: EncAlgorithm,
    pub enc_alg_auth: EncAlgorithm,
    pub protect_sender: bool,
}
```

### `UnpackOptions`
Options for message unpacking.

```rust
#[derive(Debug, Clone)]
pub struct UnpackOptions {
    pub expect_decrypt_by_all_keys: bool,
    pub unwrap_re_wrapping_forward: bool,
}
```

## Supported Algorithms

### Key Agreement
- **X25519**: Curve25519 ECDH (fastest, ~103-178µs)
- **P-256**: NIST P-256 ECDH (~659-1,228µs)
- **P-384**: NIST P-384 ECDH
- **K-256**: secp256k1 ECDH (~303-986µs)

### Signatures
- **Ed25519**: EdDSA with Curve25519
- **ES256**: ECDSA with P-256
- **ES256K**: ECDSA with secp256k1

### Encryption
- **A256GCM**: AES-256-GCM
- **A256CBC-HS512**: AES-256-CBC with HMAC-SHA512
- **XC20P**: XChaCha20-Poly1305

## Constants

### Message Types
```rust
pub const DIDCOMM_ENCRYPTED_MEDIA_TYPE: &str = "application/didcomm-encrypted+json";
pub const DIDCOMM_SIGNED_MEDIA_TYPE: &str = "application/didcomm-signed+json";  
pub const DIDCOMM_PLAIN_MEDIA_TYPE: &str = "application/didcomm-plain+json";
```

### Forward Message Type
```rust
pub const FORWARD_MSG_TYPE: &str = "https://didcomm.org/routing/2.0/forward";
```