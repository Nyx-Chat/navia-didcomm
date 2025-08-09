//! PQC Key Size Analysis
//!
//! This test analyzes the key sizes of post-quantum cryptographic algorithms.

#[test]
fn test_pqc_key_sizes() {
    use navia_didcomm::utils::pqc::{
        MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
    };
    use pqcrypto_traits::sign::{PublicKey, SecretKey};

    // Generate PQC keys
    let ml_kem_768_keypair = MlKem768KeyPair::generate([1u8; 64]);
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([2u8; 64]);
    let ml_dsa_65_keypair = MlDsa65KeyPair::generate();
    let ml_dsa_87_keypair = MlDsa87KeyPair::generate();

    // Get key sizes
    let ml_kem_768_pub_size = ml_kem_768_keypair.public_key().as_slice().len();
    let ml_kem_1024_pub_size = ml_kem_1024_keypair.public_key().as_slice().len();
    let ml_dsa_65_pub_size = ml_dsa_65_keypair.public_key().as_bytes().len();
    let ml_dsa_87_pub_size = ml_dsa_87_keypair.public_key().as_bytes().len();

    // Get private key sizes
    let ml_kem_768_priv_size = ml_kem_768_keypair.get_private_key_bytes().unwrap().len();
    let ml_kem_1024_priv_size = ml_kem_1024_keypair.get_private_key_bytes().unwrap().len();
    let ml_dsa_65_priv_size = ml_dsa_65_keypair
        .secret_key()
        .as_ref()
        .unwrap()
        .as_bytes()
        .len();
    let ml_dsa_87_priv_size = ml_dsa_87_keypair
        .secret_key()
        .as_ref()
        .unwrap()
        .as_bytes()
        .len();

    println!("\n=== PQC Key Size Analysis ===");
    println!("ML-KEM (Key Encapsulation Mechanism):");
    println!("  ML-KEM-768 public key: {ml_kem_768_pub_size} bytes");
    println!("  ML-KEM-768 private key: {ml_kem_768_priv_size} bytes");
    println!("  ML-KEM-1024 public key: {ml_kem_1024_pub_size} bytes");
    println!("  ML-KEM-1024 private key: {ml_kem_1024_priv_size} bytes");
    println!();

    println!("ML-DSA (Digital Signature Algorithm):");
    println!("  ML-DSA-65 public key: {ml_dsa_65_pub_size} bytes");
    println!("  ML-DSA-65 private key: {ml_dsa_65_priv_size} bytes");
    println!("  ML-DSA-87 public key: {ml_dsa_87_pub_size} bytes");
    println!("  ML-DSA-87 private key: {ml_dsa_87_priv_size} bytes");
    println!();

    // Verify expected sizes (using actual measured sizes)
    assert_eq!(ml_kem_768_pub_size, 1184);
    assert_eq!(ml_kem_768_priv_size, 2400);
    assert_eq!(ml_kem_1024_pub_size, 1568);
    assert_eq!(ml_kem_1024_priv_size, 3168);

    // ML-DSA sizes (Dilithium3 = DSA-65, Dilithium5 = DSA-87)
    assert_eq!(ml_dsa_65_pub_size, 1952); // Dilithium3 public key
    assert_eq!(ml_dsa_65_priv_size, 4032); // Dilithium3 private key
    assert_eq!(ml_dsa_87_pub_size, 2592); // Dilithium5 public key
    assert_eq!(ml_dsa_87_priv_size, 4896); // Dilithium5 private key

    println!("✅ All PQC key sizes match NIST specifications!");
}

#[test]
fn test_pqc_ciphertext_sizes() {
    use askar_crypto::random;
    use navia_didcomm::utils::pqc::{MlKem1024KeyPair, MlKem768KeyPair};

    // Generate test keys
    let ml_kem_768_keypair = MlKem768KeyPair::generate([3u8; 64]);
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([4u8; 64]);

    // Test encapsulation sizes
    let mut randomness768 = [0u8; 32];
    random::fill_random(&mut randomness768);
    let (ciphertext768, _shared_secret768) =
        MlKem768KeyPair::encapsulate(&ml_kem_768_keypair.public_key(), randomness768);

    let mut randomness1024 = [0u8; 32];
    random::fill_random(&mut randomness1024);
    let (ciphertext1024, _shared_secret1024) =
        MlKem1024KeyPair::encapsulate(&ml_kem_1024_keypair.public_key(), randomness1024);

    println!("\n=== PQC Ciphertext Size Analysis ===");
    println!(
        "ML-KEM-768 ciphertext: {} bytes",
        ciphertext768.as_slice().len()
    );
    println!(
        "ML-KEM-1024 ciphertext: {} bytes",
        ciphertext1024.as_slice().len()
    );

    // Verify expected ciphertext sizes
    assert_eq!(ciphertext768.as_slice().len(), 1088);
    assert_eq!(ciphertext1024.as_slice().len(), 1568);

    println!("✅ All PQC ciphertext sizes match NIST specifications!");
}
