## [1.3.0](https://github.com/Nyx-Chat/navia-didcomm/compare/v1.2.0...v1.3.0) (2025-11-14)

### ⚠ BREAKING CHANGES

* pack_encrypted signature changed from `to: &str` to `to: &[String]`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>

### ✨ Features

* add multi-recipient DIDComm v2 encryption support ([8c89d89](https://github.com/Nyx-Chat/navia-didcomm/commit/8c89d897307f631e43af794304c940b63414012e))
* add multi-recipient encryption and routing-multi protocol ([0b3f6b2](https://github.com/Nyx-Chat/navia-didcomm/commit/0b3f6b260441fd18cdef2273d9fffaefc7ce9362))

### 🐛 Bug Fixes

* resolve clippy warnings ([a26824c](https://github.com/Nyx-Chat/navia-didcomm/commit/a26824c363408fb1ea9e2cfb4a31d0fbada5dc51))
* restore advanced parameters in examples/advanced_params.rs ([6bfa56b](https://github.com/Nyx-Chat/navia-didcomm/commit/6bfa56b13f29261969ab937f3a2df7d2e75a292e))

### 📝 Documentation

* document multi-recipient and routing optimizations ([a5b958a](https://github.com/Nyx-Chat/navia-didcomm/commit/a5b958a438177d56fcdac9ceefce6c3aa7f79f60))
* update documentation to reflect current API ([42dbbbc](https://github.com/Nyx-Chat/navia-didcomm/commit/42dbbbca081bf91c1fd41a692e095c643cfac57d))

### ♻️ Refactoring

* change pack_encrypted to accept &[&str] instead of &[String] ([c2d5edf](https://github.com/Nyx-Chat/navia-didcomm/commit/c2d5edfb0e3fa3ed1d4d5f14c9854d9c18134c68))
* optimize pack_encrypted internal API to accept &[&str] ([7bf6397](https://github.com/Nyx-Chat/navia-didcomm/commit/7bf6397c9f4d8052e93e0837017f8ccd9fbe5b86))

## [Unreleased]

### ✨ Features

* **Multi-recipient encryption**: `pack_encrypted` now supports encrypting for multiple recipients in a single operation
  - Single Content Encryption Key (CEK) shared across all recipients
  - Automatic recipient deduplication
  - Each recipient receives their own encrypted key in the JWE recipients array
  - All recipients must have compatible key types

* **Routing-mod/1.0 protocol support**: Advanced routing optimization protocol
  - Implements [routing-multi/1.0](https://identity.foundation/didcomm-messaging/spec/#routing-multi) extension
  - Enables single message delivery to multiple next-hop mediators via attachments
  - Recursive divergent path handling for complex multi-hop routing scenarios
  - Automatic fallback to standard DIDComm 2.0 forward protocol when needed
  - Example: David, Eve, Frank through shared mediators = 1 optimized message instead of 3

* **Complex multi-hop routing**: Full support for 3+ hop mediator chains
  - Recursive routing structure creation when paths diverge at any level
  - Verified end-to-end delivery through complex mediator topologies
  - Efficient message grouping when recipients share partial routing paths
  - Example: Recipients with paths like `[med1, med2, med3]` and `[med1, med2, med4]` optimally routed

* **Routing optimization**: Intelligent message routing minimizes network overhead
  - Analyzes mediator chains to find common routing paths
  - Groups recipients sharing mediators to reduce message count
  - Example: 10 recipients through same 2 mediators = 1 message instead of 10
  - Automatic detection of direct vs. mediated delivery
  - Prefix-based and suffix-based routing optimizations

* **API improvements**: Enhanced ergonomics and performance
  - `pack_encrypted` accepts `&[&str]` for zero-copy recipient list
  - Returns `Vec<(String, PackEncryptedMetadata)>` for optimal routing
  - Internal API optimized to use string slices throughout the call chain
  - Eliminates unnecessary String allocations in hot paths

### 🔄 Breaking Changes

* `pack_encrypted` signature changed:
  - **Before**: `to: &str` → **After**: `to: &[&str]`
  - **Before**: `Result<(String, PackEncryptedMetadata)>` → **After**: `Result<Vec<(String, PackEncryptedMetadata)>>`
  - Migration: Single recipient `&bob_did` → `&[bob_did]`, extract first result with `.into_iter().next().unwrap()`

### 🐛 Bug Fixes

* **Routing**: Fixed divergent path handling when recipients share initial mediators but then diverge
  - Now correctly creates routing-multi messages at divergence points
  - Properly encrypts for next hop mediator instead of first mediator in fallback code
  - Forward messages now point to correct destination after mediator decrypts
* **Code quality**: Removed unused `build_forward_message_multi` function
* **Clippy**: Fixed `cloned_ref_to_slice_refs` warning by using `std::slice::from_ref`

### 📝 Documentation

* Updated README.md with current API examples and routing-multi/1.0 protocol information
* Updated docs/API.md with accurate function signatures, metadata types, and routing protocol details
* Added comprehensive examples for single and multi-recipient scenarios
* Added routing-multi protocol reference and constants

### 🧪 Testing

* Increased test coverage from 190 to 228 tests
* Added multi-recipient test suite (16 tests including complex 3-hop routing)
  - All recipients can unpack same message (shared CEK verification)
  - Mixed direct and routed recipients
  - Varying routing depths (1-3 hops)
  - Mediator security (cannot decrypt content)
  - No common paths optimization
* Added routing optimization tests (11 tests)
* End-to-end verification of 3-hop routing with divergent paths

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
