// Temporary file to test PQC API availability

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

pub fn test_dilithium_api() {
    // Generate a key pair to understand the format
    let (pk, sk) = dilithium3::keypair();

    println!("Dilithium3 public key size: {}", pk.as_bytes().len());
    println!("Dilithium3 secret key size: {}", sk.as_bytes().len());

    // Check if there are functions to derive public key from secret key
    // This will compile-fail if the function doesn't exist, helping us understand the API

    // Try to see what methods are available on SecretKey
    let sk_bytes = sk.as_bytes();
    let _pk_attempt = dilithium3::PublicKey::from_bytes(sk_bytes);

    // Let's also test libcrux-ml-kem
    let randomness = [0u8; 64];
    let keypair = libcrux_ml_kem::mlkem768::generate_key_pair(randomness);

    println!(
        "ML-KEM-768 public key size: {}",
        keypair.public_key().as_slice().len()
    );
    println!(
        "ML-KEM-768 private key size: {}",
        keypair.private_key().as_slice().len()
    );
}
