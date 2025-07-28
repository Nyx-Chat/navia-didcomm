# navia-didcomm Integration Guide

This guide shows how to integrate navia-didcomm into your Rust projects.

## For navia (Rust + UniFFI Bindings)

Add to your `rust/navia-core/Cargo.toml`:

```toml
[dependencies]
navia-didcomm = { git = "https://github.com/nyx-chat/navia-didcomm", version = "1.0.0" }
```

### Basic Usage in navia

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

### Integration with UniFFI

Export the main functions through your UniFFI interface:

```rust
// In your uniffi interface file
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

## For Mediator Server (Pure Rust)

Add to your `Cargo.toml`:

```toml
[dependencies]
navia-didcomm = { git = "https://github.com/nyx-chat/navia-didcomm", version = "1.0.0" }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage in Mediator

```rust
use navia_didcomm::{
    Message, pack_encrypted, unpack, forward_message,
    did::resolvers::ExampleDIDResolver,
    secrets::resolvers::ExampleSecretsResolver,
    protocols::routing::try_parse_forward
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with your mediator's DID and routing capabilities
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
            // Route to next recipient
            route_message(forward.next, forward.forwarded_msg).await?;
        } else {
            // Handle direct message
            process_direct_message(message, metadata).await?;
        }
    }
    
    Ok(())
}
```

## Error Handling

navia-didcomm provides structured error handling:

```rust
use navia_didcomm::error::{Error, ErrorKind};

match pack_encrypted(/* ... */).await {
    Ok(packed_msg) => {
        // Success
    },
    Err(e) => {
        match e.kind() {
            ErrorKind::DIDNotResolved => {
                // Handle DID resolution failure
            },
            ErrorKind::SecretNotFound => {
                // Handle missing cryptographic key
            },
            ErrorKind::EncryptionFailed => {
                // Handle encryption failure
            },
            _ => {
                // Handle other errors
                eprintln!("DIDComm error: {}", e);
            }
        }
    }
}
```

## Performance Considerations

### Cryptographic Performance
- **X25519**: ~103-178µs (recommended for mobile)
- **P-256**: 659-1,228µs (good compatibility)
- **K-256**: 303-986µs (blockchain integration)

### Caching
Use the `CachingDIDResolver` for better performance:

```rust
use navia_didcomm::did::caching_resolver::CachingDIDResolver;

let caching_resolver = CachingDIDResolver::new(&base_resolver);
// DID documents are automatically cached after first resolution
```

## Features

Enable specific features in your `Cargo.toml`:

```toml
[dependencies]
navia-didcomm = { 
    git = "https://github.com/nyx-chat/navia-didcomm", 
    version = "1.0.0",
    features = ["tracing"] # Optional: Enable logging/tracing support
}
```

### Available Features
- `tracing`: Structured logging and diagnostic tracing
- `default`: Core DIDComm functionality (always enabled)

## Security Notes

- All key comparisons use constant-time operations to prevent timing attacks
- Memory handling uses `SecretBytes` for cryptographic material
- Thread-safe DID resolution caching with `RwLock`
- Comprehensive input validation and sanitization

## Testing

Run the full test suite:

```bash
cargo test --all-features
```

Specific test categories:
```bash
cargo test --lib                        # Unit tests (172)
cargo test --test integration_tests     # Integration tests (11) 
cargo test --test error_diagnostics_tests # Error handling (7)
```