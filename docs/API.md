# navia-didcomm API Reference

Complete API documentation for the navia-didcomm library.

## Core Functions

### Message Packing

#### `pack_encrypted`
Pack a message with encryption for one or more recipients.

```rust
pub async fn pack_encrypted(
    &self,
    to: &[&str],
    from: Option<&str>,
    sign_by: Option<&str>,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
    options: &PackEncryptedOptions,
) -> Result<Vec<(String, PackEncryptedMetadata)>>
```

**Parameters:**
- `to`: Array of recipient DIDs or DID URLs (supports multiple recipients)
- `from`: Optional sender DID (None for anoncrypt, Some for authcrypt)
- `sign_by`: Optional DID for message signing (adds non-repudiation)
- `did_resolver`: Resolver for DID documents
- `secrets_resolver`: Resolver for cryptographic secrets
- `options`: Packing options (forwarding, algorithms, etc.)

**Returns:** Vector of (encrypted message, metadata) tuples - one per routing destination

**Features:**
- **Multi-recipient support**: Single encryption for multiple recipients with shared CEK
- **Automatic deduplication**: Silently removes duplicate recipients
- **Routing optimization**: Minimizes messages when recipients share mediators
- **Anoncrypt**: Set `from` to `None` for anonymous encryption
- **Authcrypt**: Set `from` to sender DID for authenticated encryption. The message must then carry `from` (the same DID) and both `created_time` and `expires_time`, or the call fails with `IllegalArgument`
- **Non-repudiation**: Set `sign_by` to add digital signature (a signature alone never proves the sender on unpack)

#### `pack_signed`
Pack a message with signature only (no encryption).

```rust
pub async fn pack_signed(
    &self,
    sign_by: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
) -> Result<(String, PackSignedMetadata)>
```

**Parameters:**
- `sign_by`: DID for message signing
- `did_resolver`: Resolver for DID documents
- `secrets_resolver`: Resolver for cryptographic secrets

**Returns:** Tuple of (signed message, metadata)

#### `pack_plaintext`
Pack a message as plaintext (no encryption or signature).

```rust
pub fn pack_plaintext(&self, did_resolver: &dyn DIDResolver) -> Result<String>
```

**Parameters:**
- `did_resolver`: Resolver for DID documents (for validation)

**Returns:** Plaintext DIDComm message as JSON string

### Message Unpacking

#### `unpack`
Unpack any type of DIDComm message (encrypted, signed, or plaintext).

```rust
pub async fn unpack(
    packed_msg: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
    options: &UnpackOptions,
) -> Result<(Message, UnpackMetadata)>
```

**Parameters:**
- `packed_msg`: JWE, JWS, or plaintext JSON message
- `did_resolver`: Resolver for DID documents
- `secrets_resolver`: Resolver for cryptographic secrets
- `options`: Unpacking options

**Returns:** Tuple of (unpacked message, metadata about the message)

**Features:**
- Automatically detects message type (encrypted/signed/plaintext)
- Supports multi-recipient messages (each recipient can unpack independently)
- Provides detailed metadata about encryption, authentication, and routing
- Fails closed on the sender: by default (`SenderRequirement::Proven`) a message is returned only when its sender is proven, see below

**Sender proof.** The sender is proven when all of these hold: the message has an authcrypt layer, `from` is present, `from` is the DID of the authcrypt `skid`, and, if the message is also signed, the DID of the signer is `from`. A signature alone never proves the sender. Any mismatch between these is an error in both modes.

- `SenderRequirement::Proven` (default): a message whose sender is not proven fails with `SenderNotProven`. Plaintext and bare JWS messages always fail.
- `SenderRequirement::AllowAnonymous`: a message without a proven sender is returned with `from` and `from_prior` set to `None` and `sender_proven == false`. Use it for mediators, which open only the outer anoncrypt layer of a forward, and for anoncrypt recipients.

**Time fields.** When the sender is proven, both `created_time` and `expires_time` are required (`Malformed` if either is missing). `expires_time <= now` or `created_time > now + future_skew_secs` fails with `Expired`. When the sender is not proven the fields are checked only if present. `Message::check_times(now, future_skew_secs)` applies the same rule to any message.

**`from_prior`.** `iss` must be the DID of the key that signed the JWT, `sub` must be the message `from`, and `exp` and `nbf` are checked against `now` like the message times. A mismatch is `Malformed` (`iss`, `sub`) or `Expired` (`exp`, `nbf`).

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

### Metadata Types

#### `PackEncryptedMetadata`
Metadata returned when packing an encrypted message.

```rust
#[derive(Debug, Clone)]
pub struct PackEncryptedMetadata {
    pub messaging_service: Option<MessagingServiceMetadata>,
    pub from_kid: Option<String>,
    pub sign_by_kid: Option<String>,
    pub to_kids: Vec<String>,
    pub message_ids: Vec<String>,
}
```

**Fields:**
- `messaging_service`: Service endpoint for message delivery (if routing enabled)
- `from_kid`: Key ID of the sender (for authcrypt)
- `sign_by_kid`: Key ID used for signing (if non-repudiation enabled)
- `to_kids`: Key IDs of all recipients
- `message_ids`: IDs of all messages in the chain, the outermost forward first and the message itself last (the order `unpack` reports them in)

#### `UnpackMetadata`
Metadata returned when unpacking a message.

```rust
#[derive(Debug, Clone)]
pub struct UnpackMetadata {
    pub encrypted: bool,
    pub sender_proven: bool,
    pub anonymous_sender: bool,
    pub encrypted_from_kid: Option<String>,
    pub encrypted_to_kids: Option<Vec<String>>,
    pub sign_from: Option<String>,
    pub enc_alg_auth: Option<AuthCryptAlg>,
    pub enc_alg_anon: Option<AnonCryptAlg>,
    pub message_ids: Vec<String>,
}
```

**Fields:**
- `encrypted`: Whether message was encrypted
- `sender_proven`: Whether the sender was proven (see "Sender proof" under `unpack`). Always `true` with `SenderRequirement::Proven`
- `anonymous_sender`: Whether sender is anonymous
- `encrypted_from_kid`: Sender's key ID (if authenticated encryption)
- `encrypted_to_kids`: All recipient key IDs (supports multi-recipient)
- `sign_from`: Signer's key ID (if signed). A signature alone does not set `sender_proven`
- `enc_alg_auth`: Authenticated encryption algorithm used
- `enc_alg_anon`: Anonymous encryption algorithm used
- `message_ids`: IDs of all messages in the chain

#### `PackSignedMetadata`
Metadata returned when packing a signed message.

```rust
#[derive(Debug, Clone)]
pub struct PackSignedMetadata {
    pub sign_by_kid: String,
    pub sign_alg: SignAlg,
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
#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub type_: SecretType,
    pub secret_material: SecretMaterial,
}
```

`Debug` of `Secret` and `SecretMaterial` prints `<redacted>` instead of the private key. The private key strings of a `SecretMaterial` are wiped from memory when it is dropped, so the key cannot be moved out of one: borrow it (`match &secret.secret_material { ... }`). `Serialize` still writes the key, so protect what you serialize.

## Protocols

### Routing Protocol

The library supports both standard DIDComm 2.0 routing and the routing-multi/1.0 extension for optimized multi-recipient routing.

#### `try_parse_forward`
Parse a message to check if it's a standard DIDComm 2.0 forward routing message.

```rust
pub fn try_parse_forward(msg: &Message) -> Option<ParsedForward<'_>>
```

**Returns:** Parsed forward message containing the next destination and forwarded message attachment.

#### `try_parse_forward_multi`
Parse a message to check if it's a routing-multi/1.0 forward message with multiple destinations.

```rust
pub fn try_parse_forward_multi(msg: &Message) -> Option<ParsedForwardMulti<'_>>
```

**Returns:** Parsed routing-multi forward message containing array of NextDestination objects.

**Features:**
- Supports multiple next-hop destinations with separate attachments
- Enables single message to route to multiple mediators
- Used automatically when `pack_encrypted` detects optimization opportunities

#### `wrap_in_forward`
Wrap a packed message in forward messages for routing through mediators (standard DIDComm 2.0 protocol). The library calls it from `pack_encrypted`; there is no separate "wrap if needed" function.

```rust
pub async fn wrap_in_forward<'dr>(
    msg: &str,
    headers: Option<&HashMap<String, Value>>,
    to: &str,
    routing_keys: &[String],
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<(String, Vec<String>)>
```

**Returns:** The outermost forward and the ids of the forwards, outermost first. `routing_keys` must not be empty (`IllegalArgument`).

**Note:** The library automatically uses routing-multi/1.0 optimization when beneficial.

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
    SenderNotProven,
    Expired,
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
    /// `Proven` (default) or `AllowAnonymous`
    pub sender: SenderRequirement,
    /// Seconds since the Unix epoch; `None` reads the system clock (`InvalidState` on wasm32)
    pub now: Option<u64>,
    /// How far ahead of `now` a `created_time` may be, 86 400 by default
    pub future_skew_secs: u64,
}
```

`UnpackOptions::default()` refuses messages whose sender is not proven. Set `sender: SenderRequirement::AllowAnonymous` for the layers that cannot have a proven sender (see `unpack`).

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

### Forward Message Types
```rust
// Standard DIDComm 2.0 forward message
pub const FORWARD_MSG_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

// Routing-mod/1.0 forward message with multiple destinations
pub const FORWARD_MULTI_MSG_TYPE: &str = "https://didcomm.org/routing-multi/1.0/forward";
```