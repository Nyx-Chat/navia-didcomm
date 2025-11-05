# Navia-DIDComm

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](./LICENSE)
[![GitHub Package Registry](https://img.shields.io/badge/GitHub%20Packages-private-blue.svg)](https://github.com/nyx-chat/navia-didcomm/packages)
[![Build Status](https://github.com/nyx-chat/navia-didcomm/workflows/PR%20Validation/badge.svg)](https://github.com/nyx-chat/navia-didcomm/actions)
[![Tests](https://img.shields.io/badge/tests-221%20passing-green.svg)](https://github.com/nyx-chat/navia-didcomm/actions)

**Production-ready DIDComm v2 implementation for secure peer-to-peer messaging**

Navia-DIDComm is a complete, modern implementation of the [DIDComm v2 specification](https://identity.foundation/didcomm-messaging/spec/) built for production use in the [Nyx](https://github.com/Nyx-Chat) ecosystem.

## ✨ Features

- 🔒 **Complete DIDComm v2 Support** - Full specification implementation
- 🚀 **Production Ready** - Comprehensive testing, security audits, modern dependencies
- 🔐 **Modern Cryptography** - X25519, P-256, P-384 ✅, P-521, Ed25519, Secp256k1
- 📨 **Secure Messaging** - Encrypted (anoncrypt/authcrypt) and signed messages
- 👥 **Multi-Recipient Support** - Efficient encryption for multiple recipients with shared CEK
- 🔄 **Message Routing** - Forward protocol, mediation support, and routing optimization
- 🔑 **DID Rotation** - Full `fromPrior` field support
- ⚡ **High Performance** - Optimized for speed and low memory usage

## 🔮 Future Roadmap

- **Post-Quantum Cryptography** - Kyber integration planned for quantum-resistant key exchange

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
  - Verification materials are expected in JWK, Base58 and Multibase (internally Base58 only) formats.
    - In Base58 and Multibase formats, keys using only X25519 and Ed25519 curves are supported.
    - For private keys in Base58 and Multibase formats, the verification material value contains both private and public parts (concatenated bytes).
    - In Multibase format, bytes of the verification material value is prefixed with the corresponding Multicodec code.
  - Key IDs (kids) used in `SecretsResolver` must match the corresponding key IDs from DID Doc verification methods.
  - Key IDs (kids) in DID Doc verification methods and secrets must be a full [DID Fragment](https://www.w3.org/TR/did-core/#fragment), that is `did#key-id`.
  - Verification methods referencing another DID Document are not supported (see [Referring to Verification Methods](https://www.w3.org/TR/did-core/#referring-to-verification-methods)).
- The following curves and algorithms are supported:
  - Encryption:
     - Curves: X25519, P-256, P-384
     - Content encryption algorithms: 
       - XC20P (to be used with ECDH-ES only, default for anoncrypt),
       - A256GCM (to be used with ECDH-ES only),
       - A256CBC-HS512 (default for authcrypt)
     - Key wrapping algorithms: ECDH-ES+A256KW, ECDH-1PU+A256KW
  - Signing:
    - Curves: Ed25519, Secp256k1, P-256, P-384
    - Algorithms: EdDSA (with crv=Ed25519), ES256, ES384, ES256K
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
        &[BOB_DID],
        Some(ALICE_DID),
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted")
    .into_iter()
    .next()
    .unwrap();

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
        &[BOB_DID],
        None, // Keep sender as None here
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted")
    .into_iter()
    .next()
    .unwrap();
```

**Encryption with non-repudiation** example:

```rust
let (msg, metadata) = msg
    .pack_encrypted(
        &[BOB_DID],
        Some(ALICE_DID),
        Some(ALICE_DID), // Provide information about signer here
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted")
    .into_iter()
    .next()
    .unwrap();
```

**Multi-recipient encryption** example:

```rust
// Send to multiple recipients with shared encryption
let results = msg
    .pack_encrypted(
        &[BOB_DID, CHARLIE_DID],
        Some(ALICE_DID),
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");

// Results contain one encrypted message per routing destination
for (packed_msg, metadata) in results {
    println!("Send to: {}", metadata.messaging_service.unwrap().service_endpoint);
    // Send packed_msg to the service endpoint
}
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

## Contribution
PRs are welcome!

The following CI checks are run against every PR:
- No warnings from `cargo check --all-targets`
- All tests must pass with `cargo test`
- Code must be formatted by `cargo fmt --all`
