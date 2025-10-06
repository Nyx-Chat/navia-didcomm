## [1.2.0](https://github.com/Nyx-Chat/navia-didcomm/compare/v1.1.1...v1.2.0) (2025-10-06)

### ✨ Features

* add message ID tracking in pack_encrypted and unpack metadata ([137eaf2](https://github.com/Nyx-Chat/navia-didcomm/commit/137eaf2a03da27339712848c6fb3546ac7cb1653))

## [1.1.1](https://github.com/Nyx-Chat/navia-didcomm/compare/v1.1.0...v1.1.1) (2025-09-15)

### 🐛 Bug Fixes

* update tracing-subscriber to fix RUSTSEC-2025-0055 vulnerability ([d0abaa9](https://github.com/Nyx-Chat/navia-didcomm/commit/d0abaa9678bc6957654917d164dccbf0eb1e424e))

## [1.1.0](https://github.com/Nyx-Chat/navia-didcomm/compare/v1.0.3...v1.1.0) (2025-08-24)

### ✨ Features

* Add no_forward() constructor for PackEncryptedOptions ([173e39a](https://github.com/Nyx-Chat/navia-didcomm/commit/173e39aa789d935f252b5f1c518557ea02d1bca5))

### 🐛 Bug Fixes

* handle both single and double quotes in version extraction ([a1cb0af](https://github.com/Nyx-Chat/navia-didcomm/commit/a1cb0af5eb29ce1ac6952bec2978374f650486ea))
* replace cargo set-version with sed to avoid semver downgrade error ([2c08e56](https://github.com/Nyx-Chat/navia-didcomm/commit/2c08e56bdd3f9abe54c7c7b88d197a0d3c8ae293))
* Replace unnecessary unwrap with if-let pattern in unpack module ([1dd95aa](https://github.com/Nyx-Chat/navia-didcomm/commit/1dd95aa72d26692299c878a579ee4bfcbdec2b92))
* simplify PR preview package workflow ([1ac3086](https://github.com/Nyx-Chat/navia-didcomm/commit/1ac30869adddd0f8d8385046efed310c0c466ded))
* update sed to only modify first version line in Cargo.toml ([e2d544c](https://github.com/Nyx-Chat/navia-didcomm/commit/e2d544c82fd62d8fd61030912fb08e11ee5a4d23))
* update workflows for private Rust package handling ([a8de03b](https://github.com/Nyx-Chat/navia-didcomm/commit/a8de03bad377194e952d49270779286a98698ce9))

### 📝 Documentation

* add GITHUB_TOKEN usage instructions for CI/CD ([ffde22d](https://github.com/Nyx-Chat/navia-didcomm/commit/ffde22da486465291118f7a1ec4c40eed1f61d87))
* add instructions for using preview packages with private repositories ([f53a40f](https://github.com/Nyx-Chat/navia-didcomm/commit/f53a40fb36f452d9b4caa1c544928be41f31a6fc))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - TBD

### Added
- P-384 curve support for enhanced cryptographic operations
- P-521 curve support for maximum security scenarios (prepared)
- External key resolution mechanism
- Thread-safe DID resolution caching with `CachingDIDResolver`
- Comprehensive API documentation and integration guides
- Production-ready error handling with 19 structured error categories
- Integration testing suite with 11 end-to-end test scenarios
- Performance benchmarking across cryptographic algorithms
- Optional tracing/logging integration for diagnostics
- GitHub Actions CI/CD with automated release publishing
- Cross-platform testing (Linux, macOS, Windows)
- Private GitHub Packages publishing for enterprise use

### Security
- **CRITICAL**: Fixed timing attack vulnerabilities in key ID comparisons
- Implemented constant-time string comparison using `subtle` crate
- Enhanced memory safety with `RwLock` for thread-safe operations
- Validated all cryptographic implementations for production use
- Security auditing with `cargo audit` in CI pipeline

### Performance
- X25519 key agreement: ~103-178µs (fastest, recommended for mobile)  
- P-256 key agreement: 659-1,228µs (good compatibility)
- K-256 key agreement: 303-986µs (blockchain integration) 
- P-384 key agreement: Similar to P-256 (enterprise security)
- Ed25519 signatures: High-performance digital signatures

### Testing
- 190 total tests passing:
  - 172 unit tests covering core functionality
  - 11 integration tests for end-to-end message flows
  - 7 error diagnostics tests for structured error handling
- Multi-party conversation threading validation
- Cross-curve cryptographic compatibility testing
- Error handling and edge case coverage

### Changed
- Package name from `didcomm` to `navia-didcomm`
- Rust edition upgraded from 2018 to 2021
- Minimum supported Rust version set to 1.70
- Enhanced error messages for better developer experience
- Systematic error message format improvements across test suite

### Infrastructure
- Automated release workflow triggered by Cargo.toml version bumps
- Cross-platform CI validation for pull requests
- Dependency management with Dependabot
- Documentation generation and publishing

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
