# Navia-DIDComm

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](./LICENSE)
[![GitHub Package Registry](https://img.shields.io/badge/GitHub%20Packages-private-blue.svg)](https://github.com/nyx-chat/navia-didcomm/packages)
[![Build Status](https://github.com/nyx-chat/navia-didcomm/workflows/PR%20Validation/badge.svg)](https://github.com/nyx-chat/navia-didcomm/actions)
[![Tests](https://img.shields.io/badge/tests-62%20passing-green.svg)](https://github.com/nyx-chat/navia-didcomm/actions)

**Production-ready DIDComm v2 implementation for secure peer-to-peer messaging**

Navia-DIDComm is a complete, modern implementation of the [DIDComm v2 specification](https://identity.foundation/didcomm-messaging/spec/) built for production use in the [Nyx](https://github.com/Nyx-Chat) ecosystem.

## ✨ Features

- 🔒 **Complete DIDComm v2 Support** - Full specification implementation
- 🚀 **Production Ready** - Comprehensive testing, security audits, modern dependencies
- 🛡️ **Post-Quantum Cryptography** - ML-KEM-768/1024 (NIST FIPS 203), ML-DSA-65/87 (NIST FIPS 204)
- 📨 **Secure Messaging** - Encrypted (anoncrypt/authcrypt) and signed messages  
- 🔄 **Message Routing** - Forward protocol and mediation support
- 🔑 **DID Rotation** - Full `fromPrior` field support
- ⚡ **High Performance** - Optimized for speed and low memory usage

## 🔮 Cryptographic Security

- **✅ Post-Quantum Ready** - Complete implementation with NIST-standardized algorithms
- **🔬 Quantum Resistant** - ML-KEM key encapsulation and ML-DSA digital signatures
- **🏛️ NIST Compliant** - FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) certified algorithms

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
# For navia (UniFFI wrapper) and mediator servers
navia-didcomm = { git = "https://github.com/nyx-chat/navia-didcomm", version = "1.0.0" }
```

> **Note**: This is a private library for the Nyx ecosystem. Access requires authentication to the nyx-chat GitHub organization.

## Run examples

Use `cargo run --example {example-name}` for example `cargo run --example basic`.

## Assumptions and Limitations
- Rust 2018 edition is required.
- In order to use the library, `SecretsResolver` and `DIDResolver` traits must be implemented on the application level. 
  Implementation of that traits is out of DIDComm library scope, but we provide 2 simple implementation `ExampleDIDResolver`
  and `ExampleSecretsResolver` that allows resolve locally known DID docs and secrets for tests/demo purposes.
  - Post-quantum key materials are supported in multibase encoding format.
    - ML-KEM key pairs support both public-key-only and full key pair representations.
    - ML-DSA key pairs require combined private+public key format for proper security.
    - All key material uses NIST-standardized PQC algorithms (ML-KEM-768/1024, ML-DSA-65/87).
  - Key IDs (kids) used in `SecretsResolver` must match the corresponding key IDs from DID Doc verification methods.
  - Key IDs (kids) in DID Doc verification methods and secrets must be a full [DID Fragment](https://www.w3.org/TR/did-core/#fragment), that is `did#key-id`.
  - Verification methods referencing another DID Document are not supported (see [Referring to Verification Methods](https://www.w3.org/TR/did-core/#referring-to-verification-methods)).
- The following post-quantum algorithms are supported:
  - Key Encapsulation (KEM):
     - ML-KEM-768 (NIST FIPS 203) - 192-bit quantum security level
     - ML-KEM-1024 (NIST FIPS 203) - 256-bit quantum security level
     - Content encryption algorithms: 
       - XChaCha20-Poly1305 (default for anoncrypt)
       - AES-256-GCM (default for authcrypt)
  - Digital Signatures:
    - ML-DSA-65 (NIST FIPS 204, Dilithium3) - 192-bit quantum security level
    - ML-DSA-87 (NIST FIPS 204, Dilithium5) - 256-bit quantum security level
- Forward protocol is implemented and used by default.
- DID rotation (`fromPrior` field) is supported.
- DIDComm has been implemented under the following [Assumptions](https://hackmd.io/i3gLqgHQR2ihVFV5euyhqg)   


## Examples

See [examples](examples/) for details.

A general usage of the API is the following:
- Sender Side:
  - Build a `Message` (plaintext, payload).
  - Convert a message to a DIDComm Message for further transporting by calling one of the following:
     - `Message::pack_encrypted` to build an Encrypted DIDComm message
     - `Message::pack_signed` to build a Signed DIDComm message
     - `Message::pack_plaintext` to build a Plaintext DIDComm message
- Receiver side:
  - Call `Message::unpack` on receiver side that will decrypt the message, verify signature if needed
  and return a `Message` for further processing on the application level.

### 1. Build an Encrypted DIDComm message for the given recipient

This is the most common DIDComm message to be used in most of the applications.

A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that 
- hides its content from all but authorized recipients
- (optionally) discloses and proves the sender to only those recipients
- provides message integrity guarantees

It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm
applications, and is the safest format for storing DIDComm data at rest.

See `Message::pack_encrypted` documentation for more details.

**Authentication encryption** example (most common case):

```rust
// --- Build message from ALICE to BOB ---
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

// --- Pack encrypted and authenticated message ---
let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        Some(ALICE_DID),
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");

println!("Encryption metadata is\n{:?}\n", metadata);

// --- Send message ---
println!("Sending message \n{}\n", msg);

// --- Unpacking message ---
let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");

println!("Receved message is \n{:?}\n", msg);
println!("Receved message unpack metadata is \n{:?}\n", metadata);
```

**Anonymous encryption** example:

```rust
let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        None, // Keep sender as None here
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");
```

**Encryption with non-repudiation** example:

```rust
let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        Some(ALICE_DID),
        Some(ALICE_DID), // Provide information about signer here
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");
```

### 2. Build an unencrypted but Signed DIDComm message

Signed messages are only necessary when
- the origin of plaintext must be provable to third parties
- or the sender can't be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a
broadcast scenario).
 
Adding a signature when one is not needed can degrade rather than enhance security because it
relinquishes the sender's ability to speak off the record.

See `Message::pack_signed` documentation for more details.

```rust
// ALICE
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

let (msg, metadata) = msg
    .pack_signed(ALICE_DID, &did_resolver, &secrets_resolver)
    .await
    .expect("Unable pack_signed");

// BOB
let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");
```

### 3. Build a Plaintext DIDComm message

A DIDComm message in its plaintext form that 
- is not packaged into any protective envelope
- lacks confidentiality and integrity guarantees
- repudiable

They are therefore not normally transported across security boundaries. 

```rust
// ALICE
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

let msg = msg
    .pack_plaintext(&did_resolver)
    .expect("Unable pack_plaintext");

// BOB
let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");
```

## 📖 API Reference

### Core Functions

#### Message Packing

**`pack_encrypted`** - Pack a message with encryption for specific recipients:

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

**`pack_signed`** - Pack a message with signature only:

```rust
pub async fn pack_signed(
    message: &Message,
    sign_by: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
) -> Result<String>
```

**`pack_plaintext`** - Pack a message as plaintext:

```rust
pub fn pack_plaintext(message: &Message) -> Result<String>
```

#### Message Unpacking

**`unpack`** - Unpack any type of DIDComm message:

```rust
pub async fn unpack(
    packed_msg: &str,
    did_resolver: &dyn DIDResolver,
    secrets_resolver: &dyn SecretsResolver,
    options: &UnpackOptions,
) -> Result<(Message, MessageMetadata)>
```

### Message Types

**`Message`** - Core DIDComm message structure:

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

**`MessageBuilder`** - Builder pattern for creating messages:

```rust
impl MessageBuilder {
    pub fn id(mut self, id: String) -> Self
    pub fn type_(mut self, type_: String) -> Self  
    pub fn body(mut self, body: Value) -> Self
    pub fn from(mut self, from: String) -> Self
    pub fn to(mut self, to: Vec<String>) -> Self
    pub fn finalize(self) -> Message
    // ... more builder methods
}
```

### Error Handling

**`ErrorKind`** - Categorized error types:

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
    EncryptionFailed,
    DecryptionFailed,
    SignatureVerificationFailed,
    
    // Protocol errors
    Malformed,
    ProtocolViolation,
    UnsupportedFormat,
    
    // System errors
    InvalidState,
    IllegalArgument,
    IoError,
    Timeout,
}
```

## 🔗 Integration Guide

### For navia (Rust + UniFFI Bindings)

Add to your `rust/navia-core/Cargo.toml`:

```toml
[dependencies]
navia-didcomm = { git = "https://github.com/nyx-chat/navia-didcomm", version = "1.0.0" }
```

**Basic Usage:**

```rust
use navia_didcomm::{Message, pack_encrypted, unpack, PackEncryptedOptions};
use navia_didcomm::did::resolvers::ExampleDIDResolver;
use navia_didcomm::secrets::resolvers::ExampleSecretsResolver;

// Initialize resolvers with your DID documents and secrets
let did_resolver = ExampleDIDResolver::new(did_docs);
let secrets_resolver = ExampleSecretsResolver::new(secrets);

// Pack an encrypted message
let message = Message::build("alice_did", "bob_did", "hello".to_string())
    .finalize();

let packed_msg = pack_encrypted(
    &message,
    "alice_did", 
    &["bob_did"],
    None, // No sign_by for anoncrypt
    &did_resolver,
    &secrets_resolver,
    &PackEncryptedOptions::default()
).await?;

// Unpack a received message  
let (unpacked_msg, metadata) = unpack(
    &received_msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default()
).await?;
```

**Integration with UniFFI:**

```rust
use navia_didcomm::{Message, pack_encrypted, unpack};

#[uniffi::export]
pub async fn pack_didcomm_message(
    message: Message,
    sender_did: String,
    recipient_dids: Vec<String>
) -> Result<String, Error> {
    // Your wrapper implementation
}

#[uniffi::export] 
pub async fn unpack_didcomm_message(
    packed_message: String
) -> Result<(Message, MessageMetadata), Error> {
    // Your wrapper implementation
}
```

### For Mediator Server (Pure Rust)

```rust
use navia_didcomm::{
    Message, pack_encrypted, unpack, forward_message,
    did::resolvers::ExampleDIDResolver,
    secrets::resolvers::ExampleSecretsResolver,
    protocols::routing::try_parse_forward
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let did_resolver = setup_did_resolver().await;
    let secrets_resolver = setup_secrets_resolver().await;
    
    // Handle incoming messages
    while let Ok(incoming_msg) = receive_message().await {
        let (message, metadata) = unpack(
            &incoming_msg,
            &did_resolver, 
            &secrets_resolver,
            &Default::default()
        ).await?;
        
        // Check if this is a forward message
        if let Some(forward) = try_parse_forward(&message) {
            route_message(forward.next, forward.forwarded_msg).await?;
        } else {
            process_direct_message(message, metadata).await?;
        }
    }
    
    Ok(())
}
```

### Error Handling

```rust
use navia_didcomm::error::{Error, ErrorKind};

match pack_encrypted(/* ... */).await {
    Ok(packed_msg) => { /* Success */ },
    Err(e) => {
        match e.kind() {
            ErrorKind::DIDNotResolved => { /* Handle DID resolution failure */ },
            ErrorKind::SecretNotFound => { /* Handle missing cryptographic key */ },
            ErrorKind::EncryptionFailed => { /* Handle encryption failure */ },
            _ => eprintln!("DIDComm error: {}", e),
        }
    }
}
```

### Performance & Caching

Use the `CachingDIDResolver` for better performance:

```rust
use navia_didcomm::did::caching_resolver::CachingDIDResolver;

let caching_resolver = CachingDIDResolver::new(&base_resolver);
// DID documents are automatically cached after first resolution
```

## 🔧 Development

### Features

Enable specific features in your `Cargo.toml`:

```toml
[dependencies]
navia-didcomm = { 
    git = "https://github.com/nyx-chat/navia-didcomm", 
    version = "1.0.0",
    features = ["tracing"] # Optional: Enable logging/tracing support
}
```

### Testing

Run the full test suite:

```bash
cargo test --all-features
```

Specific test categories:
```bash
cargo test --lib                        # Unit tests
cargo test --test integration_tests     # Integration tests
cargo test --test error_diagnostics_tests # Error handling
```

### Security Notes

- All key comparisons use constant-time operations to prevent timing attacks
- Memory handling uses `SecretBytes` for cryptographic material
- Thread-safe DID resolution caching with `RwLock`
- Comprehensive input validation and sanitization

## 📚 Documentation

For detailed PQC implementation details, see [`docs/PQC_GUIDE.md`](docs/PQC_GUIDE.md).

## Contribution
PRs are welcome!

The following CI checks are run against every PR:
- No warnings from `cargo check --all-targets`
- All tests must pass with `cargo test`
- Code must be formatted by `cargo fmt --all`
