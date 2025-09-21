#![cfg(feature = "advanced-tests")]

use ecdsa_verify::{verify, EcdsaSignature, Point3D, secp256k1, secp256r1};
use num_bigint::BigInt;
use num_traits::Zero;
use rand::Rng;
use sha2::{Digest, Sha256};

use k256::{
    ecdsa::{signature::Signer, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey},
    ecdsa::Signature as K256Signature,
    SecretKey as K256SecretKey,
};

use p256::{
    ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey},
    ecdsa::Signature as P256Signature,
    SecretKey as P256SecretKey,
};

/// Flip a random bit in a BigInt
fn flip_random_bit_in_bigint(value: &BigInt, rng: &mut impl Rng) -> BigInt {
    let bytes = value.to_bytes_be();
    let (sign, mut bytes) = bytes;

    if bytes.is_empty() {
        return BigInt::from(1); // If value is 0, return 1
    }

    // Pick a random byte and bit position
    let byte_idx = rng.gen_range(0..bytes.len());
    let bit_idx = rng.gen_range(0..8);

    // Flip the bit
    bytes[byte_idx] ^= 1 << bit_idx;

    BigInt::from_bytes_be(sign, &bytes)
}

/// Flip a random bit in a byte array
fn flip_random_bit_in_bytes(bytes: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut result = bytes.to_vec();

    if result.is_empty() {
        return vec![1]; // If empty, return a single byte
    }

    // Pick a random byte and bit position
    let byte_idx = rng.gen_range(0..result.len());
    let bit_idx = rng.gen_range(0..8);

    // Flip the bit
    result[byte_idx] ^= 1 << bit_idx;

    result
}

#[test]
fn test_secp256k1_with_real_keys() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a random private key
        let secret_key = K256SecretKey::random(&mut rng);
        let signing_key = K256SigningKey::from(secret_key.clone());
        let verifying_key = K256VerifyingKey::from(&signing_key);

        // Create a random message
        let message = b"Test message for ECDSA signature verification";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        // Sign the message
        let signature: K256Signature = signing_key.sign(message);

        // Extract public key coordinates
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let x_bytes = public_key_bytes.x().unwrap();
        let y_bytes = public_key_bytes.y().unwrap();

        // Convert to our format
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, y_bytes),
            z: BigInt::zero(),
        };

        // Extract signature components
        let sig_bytes = signature.to_bytes();
        let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]);
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]);

        let ecdsa_sig = EcdsaSignature { r, s };

        // Verify with our implementation
        let curve = secp256k1();
        assert!(
            verify(&message_hash, &ecdsa_sig, &public_key, &curve),
            "Valid signature should verify successfully"
        );
    }
}

#[test]
fn test_secp256r1_with_real_keys() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a random private key
        let secret_key = P256SecretKey::random(&mut rng);
        let signing_key = P256SigningKey::from(secret_key.clone());
        let verifying_key = P256VerifyingKey::from(&signing_key);

        // Create a random message
        let message = b"Test message for ECDSA P-256 signature verification";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        // Sign the message
        let signature: P256Signature = signing_key.sign(message);

        // Extract public key coordinates
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let x_bytes = public_key_bytes.x().unwrap();
        let y_bytes = public_key_bytes.y().unwrap();

        // Convert to our format
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, y_bytes),
            z: BigInt::zero(),
        };

        // Extract signature components
        let sig_bytes = signature.to_bytes();
        let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]);
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]);

        let ecdsa_sig = EcdsaSignature { r, s };

        // Verify with our implementation
        let curve = secp256r1();
        assert!(
            verify(&message_hash, &ecdsa_sig, &public_key, &curve),
            "Valid signature should verify successfully"
        );
    }
}

#[test]
fn test_bit_flip_in_message_hash_secp256k1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = K256SecretKey::random(&mut rng);
        let signing_key = K256SigningKey::from(secret_key);
        let verifying_key = K256VerifyingKey::from(&signing_key);

        let message = b"Test message for bit flip testing";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: K256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let ecdsa_sig = EcdsaSignature {
            r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
            s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
        };

        let curve = secp256k1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in message hash and verify it fails
        for _ in 0..10 {
            let flipped_hash = flip_random_bit_in_bytes(&message_hash, &mut rng);
            assert!(
                !verify(&flipped_hash, &ecdsa_sig, &public_key, &curve),
                "Signature should fail with flipped bit in message hash"
            );
        }
    }
}

#[test]
fn test_bit_flip_in_public_key_secp256k1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = K256SecretKey::random(&mut rng);
        let signing_key = K256SigningKey::from(secret_key);
        let verifying_key = K256VerifyingKey::from(&signing_key);

        let message = b"Test message for public key bit flip";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: K256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let pub_x = BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap());
        let pub_y = BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap());

        let public_key = Point3D {
            x: pub_x.clone(),
            y: pub_y.clone(),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let ecdsa_sig = EcdsaSignature {
            r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
            s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
        };

        let curve = secp256k1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in public key X coordinate
        for _ in 0..5 {
            let flipped_pub_key = Point3D {
                x: flip_random_bit_in_bigint(&pub_x, &mut rng),
                y: pub_y.clone(),
                z: BigInt::zero(),
            };
            assert!(
                !verify(&message_hash, &ecdsa_sig, &flipped_pub_key, &curve),
                "Signature should fail with flipped bit in public key X"
            );
        }

        // Flip bits in public key Y coordinate
        for _ in 0..5 {
            let flipped_pub_key = Point3D {
                x: pub_x.clone(),
                y: flip_random_bit_in_bigint(&pub_y, &mut rng),
                z: BigInt::zero(),
            };
            assert!(
                !verify(&message_hash, &ecdsa_sig, &flipped_pub_key, &curve),
                "Signature should fail with flipped bit in public key Y"
            );
        }
    }
}

#[test]
fn test_bit_flip_in_signature_secp256k1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = K256SecretKey::random(&mut rng);
        let signing_key = K256SigningKey::from(secret_key);
        let verifying_key = K256VerifyingKey::from(&signing_key);

        let message = b"Test message for signature bit flip";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: K256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let sig_r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]);
        let sig_s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]);

        let ecdsa_sig = EcdsaSignature {
            r: sig_r.clone(),
            s: sig_s.clone(),
        };

        let curve = secp256k1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in signature R component
        for _ in 0..5 {
            let flipped_sig = EcdsaSignature {
                r: flip_random_bit_in_bigint(&sig_r, &mut rng),
                s: sig_s.clone(),
            };
            assert!(
                !verify(&message_hash, &flipped_sig, &public_key, &curve),
                "Signature should fail with flipped bit in R component"
            );
        }

        // Flip bits in signature S component
        for _ in 0..5 {
            let flipped_sig = EcdsaSignature {
                r: sig_r.clone(),
                s: flip_random_bit_in_bigint(&sig_s, &mut rng),
            };
            assert!(
                !verify(&message_hash, &flipped_sig, &public_key, &curve),
                "Signature should fail with flipped bit in S component"
            );
        }
    }
}

#[test]
fn test_bit_flip_in_message_hash_secp256r1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = P256SecretKey::random(&mut rng);
        let signing_key = P256SigningKey::from(secret_key);
        let verifying_key = P256VerifyingKey::from(&signing_key);

        let message = b"Test message for P-256 bit flip testing";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: P256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let ecdsa_sig = EcdsaSignature {
            r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
            s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
        };

        let curve = secp256r1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in message hash and verify it fails
        for _ in 0..10 {
            let flipped_hash = flip_random_bit_in_bytes(&message_hash, &mut rng);
            assert!(
                !verify(&flipped_hash, &ecdsa_sig, &public_key, &curve),
                "Signature should fail with flipped bit in message hash"
            );
        }
    }
}

#[test]
fn test_bit_flip_in_public_key_secp256r1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = P256SecretKey::random(&mut rng);
        let signing_key = P256SigningKey::from(secret_key);
        let verifying_key = P256VerifyingKey::from(&signing_key);

        let message = b"Test message for P-256 public key bit flip";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: P256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let pub_x = BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap());
        let pub_y = BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap());

        let public_key = Point3D {
            x: pub_x.clone(),
            y: pub_y.clone(),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let ecdsa_sig = EcdsaSignature {
            r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
            s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
        };

        let curve = secp256r1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in public key X coordinate
        for _ in 0..5 {
            let flipped_pub_key = Point3D {
                x: flip_random_bit_in_bigint(&pub_x, &mut rng),
                y: pub_y.clone(),
                z: BigInt::zero(),
            };
            assert!(
                !verify(&message_hash, &ecdsa_sig, &flipped_pub_key, &curve),
                "Signature should fail with flipped bit in public key X"
            );
        }

        // Flip bits in public key Y coordinate
        for _ in 0..5 {
            let flipped_pub_key = Point3D {
                x: pub_x.clone(),
                y: flip_random_bit_in_bigint(&pub_y, &mut rng),
                z: BigInt::zero(),
            };
            assert!(
                !verify(&message_hash, &ecdsa_sig, &flipped_pub_key, &curve),
                "Signature should fail with flipped bit in public key Y"
            );
        }
    }
}

#[test]
fn test_bit_flip_in_signature_secp256r1() {
    let mut rng = rand::thread_rng();

    // Test multiple iterations
    for _ in 0..100 {
        // Generate a valid signature first
        let secret_key = P256SecretKey::random(&mut rng);
        let signing_key = P256SigningKey::from(secret_key);
        let verifying_key = P256VerifyingKey::from(&signing_key);

        let message = b"Test message for P-256 signature bit flip";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().to_vec();

        let signature: P256Signature = signing_key.sign(message);

        // Convert to our format
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
            z: BigInt::zero(),
        };

        let sig_bytes = signature.to_bytes();
        let sig_r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]);
        let sig_s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]);

        let ecdsa_sig = EcdsaSignature {
            r: sig_r.clone(),
            s: sig_s.clone(),
        };

        let curve = secp256r1();

        // Verify original signature works
        assert!(verify(&message_hash, &ecdsa_sig, &public_key, &curve));

        // Flip bits in signature R component
        for _ in 0..5 {
            let flipped_sig = EcdsaSignature {
                r: flip_random_bit_in_bigint(&sig_r, &mut rng),
                s: sig_s.clone(),
            };
            assert!(
                !verify(&message_hash, &flipped_sig, &public_key, &curve),
                "Signature should fail with flipped bit in R component"
            );
        }

        // Flip bits in signature S component
        for _ in 0..5 {
            let flipped_sig = EcdsaSignature {
                r: sig_r.clone(),
                s: flip_random_bit_in_bigint(&sig_s, &mut rng),
            };
            assert!(
                !verify(&message_hash, &flipped_sig, &public_key, &curve),
                "Signature should fail with flipped bit in S component"
            );
        }
    }
}

#[test]
fn test_edge_cases_secp256k1() {
    let mut rng = rand::thread_rng();
    let curve = secp256k1();

    // Test multiple iterations
    for _ in 0..100 {
        // Test with maximum values near curve order
        let secret_key = K256SecretKey::random(&mut rng);
        let signing_key = K256SigningKey::from(secret_key);
        let verifying_key = K256VerifyingKey::from(&signing_key);

        // Test with different message sizes
        let test_messages: Vec<Vec<u8>> = vec![
            b"".to_vec(),                      // Empty message
            b"a".to_vec(),                      // Single byte
            vec![0xff; 32],                     // All 1s
            vec![0x00; 32],                     // All 0s
            "x".repeat(1000).into_bytes(),     // Large message
        ];

        for message in test_messages {
            let mut hasher = Sha256::new();
            hasher.update(&message);
            let message_hash = hasher.finalize().to_vec();

            let signature: K256Signature = signing_key.sign(&message);

            // Convert to our format
            let public_key_bytes = verifying_key.to_encoded_point(false);
            let public_key = Point3D {
                x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
                y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
                z: BigInt::zero(),
            };

            let sig_bytes = signature.to_bytes();
            let ecdsa_sig = EcdsaSignature {
                r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
                s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
            };

            assert!(
                verify(&message_hash, &ecdsa_sig, &public_key, &curve),
                "Edge case message should verify correctly"
            );
        }
    }
}

#[test]
fn test_edge_cases_secp256r1() {
    let mut rng = rand::thread_rng();
    let curve = secp256r1();

    // Test multiple iterations
    for _ in 0..100 {
        // Test with maximum values near curve order
        let secret_key = P256SecretKey::random(&mut rng);
        let signing_key = P256SigningKey::from(secret_key);
        let verifying_key = P256VerifyingKey::from(&signing_key);

        // Test with different message sizes
        let test_messages: Vec<Vec<u8>> = vec![
            b"".to_vec(),                      // Empty message
            b"a".to_vec(),                      // Single byte
            vec![0xff; 32],                     // All 1s
            vec![0x00; 32],                     // All 0s
            "x".repeat(1000).into_bytes(),     // Large message
        ];

        for message in test_messages {
            let mut hasher = Sha256::new();
            hasher.update(&message);
            let message_hash = hasher.finalize().to_vec();

            let signature: P256Signature = signing_key.sign(&message);

            // Convert to our format
            let public_key_bytes = verifying_key.to_encoded_point(false);
            let public_key = Point3D {
                x: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.x().unwrap()),
                y: BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key_bytes.y().unwrap()),
                z: BigInt::zero(),
            };

            let sig_bytes = signature.to_bytes();
            let ecdsa_sig = EcdsaSignature {
                r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[..32]),
                s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &sig_bytes[32..]),
            };

            assert!(
                verify(&message_hash, &ecdsa_sig, &public_key, &curve),
                "Edge case message should verify correctly"
            );
        }
    }
}