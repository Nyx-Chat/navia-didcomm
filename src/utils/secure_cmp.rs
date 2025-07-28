//! Secure comparison utilities to prevent timing attacks

use subtle::ConstantTimeEq;

/// Compare two strings in constant time to prevent timing attacks on key IDs.
///
/// This is critical for security when comparing DID key identifiers, as timing
/// differences could leak information about valid key IDs to attackers.
pub(crate) fn secure_string_eq(a: &str, b: &str) -> bool {
    // First check lengths in constant time
    let len_match = a.len().ct_eq(&b.len());

    // If lengths don't match, still compare bytes to maintain constant time
    let max_len = a.len().max(b.len());
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut bytes_match = 1u8;
    for i in 0..max_len {
        let a_byte = a_bytes.get(i).copied().unwrap_or(0);
        let b_byte = b_bytes.get(i).copied().unwrap_or(0);
        bytes_match &= a_byte.ct_eq(&b_byte).unwrap_u8();
    }

    // Both length and bytes must match
    len_match.unwrap_u8() & bytes_match == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_eq() {
        // Same strings should match
        assert!(secure_string_eq(
            "did:example:alice#key-1",
            "did:example:alice#key-1"
        ));

        // Different strings should not match
        assert!(!secure_string_eq(
            "did:example:alice#key-1",
            "did:example:alice#key-2"
        ));
        assert!(!secure_string_eq(
            "did:example:alice#key-1",
            "did:example:bob#key-1"
        ));

        // Different lengths should not match
        assert!(!secure_string_eq("short", "much-longer-string"));
        assert!(!secure_string_eq("much-longer-string", "short"));

        // Empty strings
        assert!(secure_string_eq("", ""));
        assert!(!secure_string_eq("", "non-empty"));
    }

    #[test]
    fn test_secure_string_eq_constant_time() {
        // This test verifies the function works correctly but cannot
        // easily verify constant-time behavior without specialized timing tools
        let key1 = "did:example:alice#key-1";
        let key2 = "did:example:alice#key-2"; // Same prefix, different suffix
        let key3 = "eid:example:alice#key-1"; // Different prefix, same suffix

        assert!(secure_string_eq(key1, key1));
        assert!(!secure_string_eq(key1, key2));
        assert!(!secure_string_eq(key1, key3));
    }
}
