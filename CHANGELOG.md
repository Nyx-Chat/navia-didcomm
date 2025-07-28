# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- P-384 curve support for enhanced cryptographic operations
- P-521 curve support for maximum security scenarios
- External key resolution mechanism
- DID resolution caching for improved performance
- Comprehensive API documentation
- Production-ready error handling and diagnostics

### Changed
- Package name from `didcomm` to `navia-didcomm`
- Rust edition upgraded from 2018 to 2021
- Minimum supported Rust version set to 1.70
- Enhanced error messages for better developer experience

## [1.0.0] - TBD

### Added
- Complete DIDComm v2 specification implementation
- Support for X25519, P-256, Ed25519, and Secp256k1 curves
- Encrypted messaging (anoncrypt and authcrypt)
- Signed messaging with multiple signature algorithms
- Forward protocol implementation
- DID rotation support via `fromPrior` field
- Message routing and mediation
- Comprehensive test suite with 167+ passing tests

### Security
- Modern cryptographic dependencies (askar-crypto 0.3.6)
- Secure base64 handling (base64 0.22)
- Latest curve25519-dalek and ed25519-dalek implementations
- Production-ready clippy linting configuration

## [0.4.1] - 2024-07-28 (Legacy - Original Fork Point)

### Security
- **BREAKING**: Upgraded askar-crypto from 0.2 to 0.3.6
- **BREAKING**: Upgraded base64 from 0.13 to 0.22
- Added curve25519-dalek 4.1.3 and ed25519-dalek 2.2.0
- Updated sha2, uuid, and other dependencies

### Fixed
- Fixed base64 API compatibility across all modules
- Fixed K256 key format issues (missing crv field)
- Fixed test cases for stricter validation
- Resolved 4 critical test failures from dependency upgrades

### Changed
- Migrated from git-pinned askar-crypto to stable release
- Updated error message assertions for new base64 library
- Enhanced test robustness for upgraded cryptographic libraries

---

## Migration Guide

### From `didcomm` 0.4.x to `navia-didcomm` 1.0.0

#### Package Update
```toml
# Before
[dependencies]
didcomm = "0.4"

# After  
[dependencies]
navia-didcomm = "1.0"
```

#### Import Changes
```rust
// Before
use didcomm::{Message, PackEncryptedOptions};

// After - same API, just new crate name
use navia_didcomm::{Message, PackEncryptedOptions};
```

#### No Breaking API Changes
The public API remains the same - only the crate name has changed. All existing code should work with minimal changes.

#### New Features Available
- P-384/P-521 curve support
- Enhanced error handling
- Improved performance with DID caching
- Better documentation and examples

### Upgrading from Original `didcomm` (pre-fork)

If upgrading from the original sicpa-dlab/didcomm-rust:

1. **Security**: This version includes critical security updates
2. **Dependencies**: All dependencies are updated to latest secure versions
3. **API**: Core API is compatible, but check deprecated features
4. **Testing**: Run your test suite - error messages may have changed

For detailed upgrade assistance, see the [Migration Guide](./docs/MIGRATION.md).