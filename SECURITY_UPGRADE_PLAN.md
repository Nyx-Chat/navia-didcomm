# Security Upgrade & Quantum Resistance Plan

## Overview

This document outlines the security upgrades and quantum resistance improvements for the navia-didcomm library, which serves as the core DIDComm helper library for the main Navia Android messaging framework.

## Current Security Issues

### 1. Outdated Dependencies (CRITICAL)

Current vulnerable dependencies identified in `Cargo.toml`:

- **askar-crypto**: `0.2` (pinned to specific git commit) → Update to latest stable
- **Missing curve25519-dalek**: Not directly used, but likely through askar-crypto
- **Missing ed25519-dalek**: Not directly used, but likely through askar-crypto
- **sha2**: `0.9` → Update to latest (likely 0.10+)
- **base64**: `0.13` → Update to latest
- **uuid**: `0.8` → Update to latest

### 2. Quantum Vulnerability

Current cryptographic primitives are vulnerable to quantum attacks:
- Elliptic curve cryptography (P-256, P-384, P-521)
- RSA signatures
- Ed25519 signatures
- ECDH key exchange

## Upgrade Strategy

### Phase 1: Dependency Security Updates

#### 1.1 Critical Dependencies
- [ ] **askar-crypto**: Update from `0.2` to latest stable version
  - Remove git dependency, use published crate
  - Verify compatibility with existing encryption/decryption flows
  - Test with current JWE/JWS implementations

#### 1.2 Supporting Dependencies  
- [ ] **sha2**: Update from `0.9` to latest
- [ ] **base64**: Update from `0.13` to latest  
- [ ] **uuid**: Update from `0.8` to latest
- [ ] **serde_json**: Update from `1.0` to latest patch
- [ ] **tokio**: Update dev dependency to latest stable

#### 1.3 New Cryptographic Dependencies
- [ ] Add **curve25519-dalek** `4.1.3+` for explicit curve operations
- [ ] Add **ed25519-dalek** `2.1.1+` for signature verification
- [ ] Research and add quantum-resistant library: **pqcrypto-kyber** vs **oqs**

### Phase 2: Quantum Resistance Integration

#### 2.1 Kyber Integration Research
**Option A: pqcrypto-kyber**
- Pure Rust implementation
- Smaller dependency footprint
- NIST standardized Kyber algorithms
- Better for embedded/mobile use

**Option B: liboqs (oqs crate)**
- More comprehensive post-quantum suite
- Includes signatures (Dilithium) and KEMs (Kyber)
- Larger binary size
- More future-proof for algorithm diversity

**Recommendation**: Start with **pqcrypto-kyber** for KEM, evaluate signatures separately.

#### 2.2 Implementation Areas

**Key Exchange (Priority: HIGH)**
- Location: `src/jwe/encrypt.rs`, `src/jwe/decrypt.rs`
- Current: ECDH-ES, ECDH-1PU
- Add: Kyber KEM for key encapsulation
- Maintain backward compatibility with hybrid approach

**Digital Signatures (Priority: MEDIUM)**  
- Location: `src/jws/sign.rs`, `src/jws/verify.rs`
- Current: Ed25519, ES256, ES384, ES512
- Add: Dilithium signatures (if using liboqs)
- Hybrid signatures for transition period

**Key Management (Priority: HIGH)**
- Location: `src/secrets/mod.rs`
- Add support for Kyber key pairs
- Update DID document key representations
- Ensure Aries Askar storage compatibility

#### 2.3 Algorithm Integration Strategy

**Hybrid Cryptography Approach:**
1. **Phase 2a**: Add Kyber alongside existing ECDH
   - Dual key exchange: Classical + Quantum-resistant
   - Combined entropy from both algorithms
   - Graceful fallback to classical for compatibility

2. **Phase 2b**: Quantum-resistant by default
   - Kyber-first with classical fallback
   - New message format versions
   - Migration path for existing keys

### Phase 3: DIDComm Protocol Updates

#### 3.1 Message Format Extensions
- [ ] Define new JWE algorithms: `KYBER768-AEAD`, `KYBER1024-AEAD`
- [ ] Define new JWS algorithms: `DILITHIUM2`, `DILITHIUM3` (if signatures added)
- [ ] Update `src/algorithms.rs` with new algorithm identifiers
- [ ] Maintain backward compatibility with existing formats

#### 3.2 DID Document Updates  
- [ ] Add Kyber public key formats to `src/did/did_doc.rs`
- [ ] Support new key agreement key types
- [ ] Update DID resolution for quantum-resistant keys

#### 3.3 Testing & Validation
- [ ] Add test vectors for Kyber operations
- [ ] Performance benchmarks for hybrid vs. quantum-only
- [ ] Interoperability tests with existing DIDComm implementations
- [ ] Security audit of hybrid implementations

## Implementation Timeline

### Week 1-2: Security Updates
- [ ] Update all vulnerable dependencies
- [ ] Ensure all tests pass with new versions
- [ ] Performance regression testing

### Week 3-4: Kyber Research & Integration
- [ ] Finalize Kyber library choice (pqcrypto-kyber vs oqs)
- [ ] Implement basic Kyber KEM operations
- [ ] Add hybrid key exchange support

### Week 5-6: DIDComm Integration
- [ ] Update JWE/JWS algorithms
- [ ] Add new message format support
- [ ] Comprehensive testing

### Week 7: Validation & Documentation
- [ ] Security review
- [ ] Performance optimization
- [ ] Update API documentation
- [ ] Migration guide for Navia integration

## Risk Mitigation

### Compatibility Risks
- **Risk**: Breaking changes in dependency updates
- **Mitigation**: Comprehensive test suite, staged rollout

### Performance Risks  
- **Risk**: Kyber operations slower than classical crypto
- **Mitigation**: Performance benchmarking, selective use in critical paths

### Security Risks
- **Risk**: Implementation vulnerabilities in quantum crypto
- **Mitigation**: Use well-audited libraries, security review

## Success Criteria

1. ✅ All critical security vulnerabilities resolved
2. ✅ Quantum-resistant key exchange implemented
3. ✅ Backward compatibility maintained
4. ✅ Performance within 20% of current implementation
5. ✅ Full test coverage for new cryptographic operations
6. ✅ Integration tested with main Navia library

## Dependencies Analysis

### Current Architecture
```
navia-didcomm (this repo)
├── JWE/JWS encryption/signing
├── DID document handling  
├── Key management
└── Message routing

navia (main Android lib)
├── UniFFI bindings
├── Android-specific storage
├── Kotlin/Java API
└── Uses navia-didcomm as core
```

### Integration Points
- Update Navia's Cargo.toml to use new navia-didcomm version
- Ensure UniFFI compatibility with new API surface
- Test Android builds with updated dependencies
- Validate Aries Askar integration still works

---

*This plan will be updated as implementation progresses and new security requirements are identified.*