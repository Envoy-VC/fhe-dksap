//! # FHE-DKSAP: Fully Homomorphic Encryption Dual-Key Stealth Address Protocol
//!
//! This library implements a privacy-preserving stealth address protocol for Ethereum using
//! Fully Homomorphic Encryption (FHE). The protocol allows senders to create stealth addresses
//! that only the intended receiver can spend from, while maintaining privacy of both parties.
//!
//! ## Overview
//!
//! The FHE-DKSAP protocol combines:
//! - **Dual-Key Stealth Address Protocol (DKSAP)**: A privacy-preserving address generation scheme
//! - **Fully Homomorphic Encryption (FHE)**: Enables computation on encrypted data without decryption
//! - **secp256k1**: The elliptic curve used by Ethereum for key generation and signing
//!
//! ## Dependencies
//!
//! - `tfhe`: Fully Homomorphic Encryption library
//! - `secp256k1`: Elliptic curve cryptography for Ethereum compatibility
//! - `sha3`: Cryptographic hash functions for address generation
//!
//! ## Performance Considerations
//!
//! FHE operations are computationally expensive. The library is designed for privacy-critical
//! applications where the computational overhead is acceptable for enhanced privacy guarantees.
//!
//! ## Security Notes
//!
//! - FHE keys should be generated with appropriate security parameters
//! - New Stealth Addresses should be generated for each transaction basis

use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use std::error::Error;
use std::fmt;

use tfhe::{generate_keys, prelude::*, set_server_key, ClientKey, Config, FheUint256, ServerKey};

pub mod utils;

/// Errors that can occur during FHE-DKSAP operations.
///
/// This enum provides detailed error information for debugging and error handling
/// in production environments.
#[derive(Debug)]
pub enum FheDKSAPError {
    /// Error during key generation operations
    ///
    /// This error occurs when there are issues generating cryptographic keys,
    /// such as insufficient entropy or invalid key parameters.
    KeyGenerationError(String),
    /// Error during public key combination operations
    ///
    /// This error occurs when attempting to combine secp256k1 public keys,
    /// typically due to invalid key formats or cryptographic constraints.
    KeyCombinationError(String),
}

impl fmt::Display for FheDKSAPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FheDKSAPError::KeyGenerationError(msg) => write!(f, "Key generation error: {}", msg),
            FheDKSAPError::KeyCombinationError(msg) => write!(f, "Key combination error: {}", msg),
        }
    }
}

impl Error for FheDKSAPError {}

/// Result type for FHE-DKSAP operations.
///
/// Provides a convenient type alias for operations that can fail with
/// `FheDKSAPError`.
pub type FheDKSAPResult<T> = Result<T, FheDKSAPError>;

/// A pair of secp256k1 keys for Ethereum operations.
///
/// This struct holds both the secret and public keys needed for Ethereum
/// transactions and stealth address operations. The secret key is used for
/// signing transactions, while the public key is used for address generation
/// and key combination operations.
#[derive(Debug, Clone)]
pub struct EthereumKeyPair {
    /// The secret key used for signing transactions
    pub secret_key: SecretKey,
    /// The public key derived from the secret key
    pub public_key: PublicKey,
}

/// A pair of FHE keys for encrypted operations.
///
/// This struct holds the client and server keys needed for FHE operations.
/// The client key is used for encryption and decryption, while the server key
/// is used for performing computations on encrypted data.
#[derive(Clone)]
pub struct FheKeyPair {
    /// The client key used for encryption and decryption
    pub public_key: ClientKey,
    /// The server key used for FHE computations
    pub secret_key: ServerKey,
}

/// A stealth address with associated encrypted data.
///
/// This struct contains all the information needed to create and recover
/// a stealth address. The stealth address is the public address that can
/// receive funds, while the encrypted secret key contains the information
/// needed to recover the private key for spending.
#[derive(Clone)]
pub struct StealthAddress {
    /// The Ethereum stealth address in hex format (0x-prefixed)
    pub stealth_address: String,
    /// The ephemeral secret key encrypted with the receiver's FHE public key
    pub encrypted_secret_key: FheUint256,
    /// The ephemeral key pair used to generate this stealth address
    pub ephemeral_key_pair: EthereumKeyPair,
}

/// Generates a new secp256k1 key pair for Ethereum operations.
///
/// This function creates a cryptographically secure key pair using the secp256k1
/// curve, which is the same curve used by Ethereum. The generated keys can be
/// used for creating stealth addresses and signing transactions.
///
/// # Arguments
///
/// * `secp` - A secp256k1 context with all capabilities enabled
///
/// # Returns
///
/// Returns a `FheDKSAPResult<EthereumKeyPair>` containing the generated key pair
/// or an error if key generation fails.
///
/// # Example
///
/// ```rust
/// use secp256k1::Secp256k1;
/// use fhe_dksap::generate_ethereum_key_pair;
///
/// let secp = Secp256k1::new();
/// let keypair = generate_ethereum_key_pair(&secp).unwrap();
/// println!("Public key: {:?}", keypair.public_key);
/// ```
///
/// # Errors
///
/// Returns `FheDKSAPError::KeyGenerationError` if the key generation process fails.
pub fn generate_ethereum_key_pair(
    secp: &Secp256k1<secp256k1::All>,
) -> FheDKSAPResult<EthereumKeyPair> {
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());

    Ok(EthereumKeyPair {
        secret_key,
        public_key,
    })
}

/// Generates a new FHE key pair for encrypted operations.
///
/// This function creates a client-server key pair for FHE operations. The client
/// key is used for encryption and decryption, while the server key enables
/// computations on encrypted data without revealing the underlying values.
///
/// # Arguments
///
/// * `config` - The FHE configuration specifying security parameters and performance settings
///
/// # Returns
///
/// Returns a `FheDKSAPResult<FheKeyPair>` containing the generated FHE key pair
/// or an error if key generation fails.
///
/// # Example
///
/// ```rust
/// use tfhe::ConfigBuilder;
/// use fhe_dksap::generate_fhe_key_pair;
///
/// let config = ConfigBuilder::default().build();
/// let fhe_keypair = generate_fhe_key_pair(config).unwrap();
/// ```
///
/// # Errors
///
/// Returns `FheDKSAPError::KeyGenerationError` if the FHE key generation process fails.
pub fn generate_fhe_key_pair(config: Config) -> FheDKSAPResult<FheKeyPair> {
    let (client_key, server_key) = generate_keys(config);

    Ok(FheKeyPair {
        public_key: client_key,
        secret_key: server_key,
    })
}

/// Encrypts a secp256k1 secret key using FHE.
///
/// This function converts a secp256k1 secret key to a U256 representation and
/// encrypts it using the provided FHE client key. The encrypted key can be used
/// in FHE computations without revealing the original secret key.
///
/// # Arguments
///
/// * `secret_key` - The secp256k1 secret key to encrypt
/// * `fhe_client_key` - The FHE client key used for encryption
///
/// # Returns
///
/// Returns an `FheUint256` containing the encrypted secret key.
///
/// # Example
///
/// ```rust
/// use fhe_dksap::{generate_ethereum_key_pair, generate_fhe_key_pair, encrypt_secret_key};
/// use secp256k1::Secp256k1;
/// use tfhe::ConfigBuilder;
///
/// let secp = Secp256k1::new();
/// let config = ConfigBuilder::default().build();
///
/// let eth_keypair = generate_ethereum_key_pair(&secp).unwrap();
/// let fhe_keypair = generate_fhe_key_pair(config).unwrap();
///
/// let encrypted_sk = encrypt_secret_key(
///     eth_keypair.secret_key,
///     &fhe_keypair.public_key,
/// );
/// ```
pub fn encrypt_secret_key(secret_key: SecretKey, fhe_client_key: &ClientKey) -> FheUint256 {
    let sk_u256 = utils::bytes_be_to_u256(&secret_key.secret_bytes());
    FheUint256::encrypt(sk_u256, fhe_client_key)
}

/// Combines two secp256k1 public keys using elliptic curve point addition.
///
/// This function performs point addition on the secp256k1 curve to combine two
/// public keys. This operation is used in the stealth address generation process
/// to create the final stealth address public key.
///
/// # Arguments
///
/// * `pk1` - The first public key to combine
/// * `pk2` - The second public key to combine
///
/// # Returns
///
/// Returns a `FheDKSAPResult<PublicKey>` containing the combined public key
/// or an error if the combination fails.
///
/// # Example
///
/// ```rust
/// use fhe_dksap::{generate_ethereum_key_pair, combine_public_keys};
/// use secp256k1::Secp256k1;
///
/// let secp = Secp256k1::new();
/// let keypair1 = generate_ethereum_key_pair(&secp).unwrap();
/// let keypair2 = generate_ethereum_key_pair(&secp).unwrap();
///
/// let combined_pk = combine_public_keys(
///     &keypair1.public_key,
///     &keypair2.public_key,
/// ).unwrap();
/// ```
///
/// # Errors
///
/// Returns `FheDKSAPError::KeyCombinationError` if the public key combination
/// fails due to invalid keys or cryptographic constraints.
///
/// # Mathematical Background
///
/// The combination is performed using elliptic curve point addition:
/// `P_combined = P1 + P2` where `+` represents point addition on the secp256k1 curve.
pub fn combine_public_keys(pk1: &PublicKey, pk2: &PublicKey) -> FheDKSAPResult<PublicKey> {
    pk1.combine(pk2).map_err(|e| {
        FheDKSAPError::KeyCombinationError(format!("Failed to combine public keys: {}", e))
    })
}

/// Generates a stealth address for a receiver using their public keys.
///
/// This function implements the core stealth address generation algorithm. It creates
/// a new ephemeral key pair, combines it with the receiver's public key to generate
/// a stealth address, and encrypts the ephemeral secret key for later recovery.
///
/// # Arguments
///
/// * `secp` - A secp256k1 context with all capabilities enabled
/// * `receiver_eth_public_key` - The receiver's secp256k1 public key
/// * `receiver_fhe_public_key` - The receiver's FHE client key for encryption
///
/// # Returns
///
/// Returns a `FheDKSAPResult<StealthAddress>` containing the generated stealth address
/// and associated encrypted data, or an error if generation fails.
///
/// # Example
///
/// ```rust
/// use fhe_dksap::{generate_ethereum_key_pair, generate_fhe_key_pair, generate_stealth_address};
/// use secp256k1::Secp256k1;
/// use tfhe::ConfigBuilder;
///
/// let secp = Secp256k1::new();
/// let config = ConfigBuilder::default().build();
///
/// // Receiver setup
/// let receiver_eth_keypair = generate_ethereum_key_pair(&secp).unwrap();
/// let receiver_fhe_keypair = generate_fhe_key_pair(config).unwrap();
///
/// // Generate stealth address
/// let stealth_address = generate_stealth_address(
///     &secp,
///     &receiver_eth_keypair.public_key,
///     &receiver_fhe_keypair.public_key,
/// ).unwrap();
///
/// println!("Stealth address: {}", stealth_address.stealth_address);
/// ```
///
/// # Errors
///
/// Returns `FheDKSAPError::KeyGenerationError` if ephemeral key generation fails,
/// or `FheDKSAPError::KeyCombinationError` if public key combination fails.
///
/// # Protocol Details
///
/// The stealth address generation follows these steps:
/// 1. Generate ephemeral key pair (sk₁, pk₁)
/// 2. Combine public keys: pk_z = pk₁ + pk_receiver
/// 3. Generate stealth address from pk_z
/// 4. Encrypt sk₁ with receiver's FHE public key
pub fn generate_stealth_address(
    secp: &Secp256k1<secp256k1::All>,
    receiver_eth_public_key: &PublicKey,
    receiver_fhe_public_key: &ClientKey,
) -> FheDKSAPResult<StealthAddress> {
    // Generate ephemeral key pair for this transaction
    let ephemeral_key_pair = generate_ethereum_key_pair(secp).map_err(|e| {
        FheDKSAPError::KeyGenerationError(format!("Failed to generate ephemeral key pair: {}", e))
    })?;

    // Combine public keys: pk_z = pk_1 + pk_2
    let pk_z = ephemeral_key_pair
        .public_key
        .combine(receiver_eth_public_key)
        .map_err(|e| {
            FheDKSAPError::KeyCombinationError(format!("Failed to combine public keys: {}", e))
        })?;

    // Generate stealth address from combined public key
    let stealth_address = utils::pk_to_eth_address(&pk_z);

    // Encrypt the ephemeral private key using receiver's FHE public key
    let sk1_u256 = utils::bytes_be_to_u256(&ephemeral_key_pair.secret_key.secret_bytes());
    let encrypted_secret_key = FheUint256::encrypt(sk1_u256, receiver_fhe_public_key);

    Ok(StealthAddress {
        stealth_address,
        encrypted_secret_key,
        ephemeral_key_pair,
    })
}

/// Recovers the private key for a stealth address using FHE operations.
///
/// This function implements the stealth address recovery algorithm. It uses FHE
/// operations to compute the private key for a stealth address without revealing
/// the intermediate values during computation.
///
/// # Arguments
///
/// * `secp` - A secp256k1 context with all capabilities enabled
/// * `fhe_keypair` - The receiver's FHE key pair for decryption and computation
/// * `enc_receiver_secret_key` - The receiver's secret key encrypted with their FHE public key
/// * `enc_sender_secret_key` - The ephemeral secret key encrypted with the receiver's FHE public key
///
/// # Returns
///
/// Returns a `FheDKSAPResult<EthereumKeyPair>` containing the recovered key pair
/// for the stealth address, or an error if recovery fails.
///
/// # Example
///
/// ```rust
/// use fhe_dksap::{
///     generate_ethereum_key_pair, generate_fhe_key_pair, generate_stealth_address,
///     recover_secret_key, encrypt_secret_key
/// };
/// use secp256k1::Secp256k1;
/// use tfhe::ConfigBuilder;
///
/// let secp = Secp256k1::new();
/// let config = ConfigBuilder::default().build();
///
/// // Receiver setup
/// let receiver_eth_keypair = generate_ethereum_key_pair(&secp).unwrap();
/// let receiver_fhe_keypair = generate_fhe_key_pair(config).unwrap();
/// let receiver_enc_secret_key = encrypt_secret_key(
///     receiver_eth_keypair.secret_key,
///     &receiver_fhe_keypair.public_key,
/// );
///
/// // Generate stealth address
/// let stealth_address = generate_stealth_address(
///     &secp,
///     &receiver_eth_keypair.public_key,
///     &receiver_fhe_keypair.public_key,
/// ).unwrap();
///
/// // Recover stealth address private key
/// let recovered_keypair = recover_secret_key(
///     &secp,
///     &receiver_fhe_keypair,
///     &receiver_enc_secret_key,
///     &stealth_address.encrypted_secret_key,
/// ).unwrap();
/// ```
///
/// # Errors
///
/// Returns `FheDKSAPError::KeyGenerationError` if the recovered private key
/// is invalid or if key creation fails.
///
/// # Protocol Details
///
/// The recovery process follows these steps:
/// 1. Set the FHE server key for computations
/// 2. Perform modulo operation: C = (C₁ + C₂) mod n
/// 3. Decrypt the result to get the stealth address private key
/// 4. Convert the result back to a secp256k1 secret key
pub fn recover_secret_key(
    secp: &Secp256k1<secp256k1::All>,
    fhe_keypair: &FheKeyPair,
    enc_receiver_secret_key: &FheUint256,
    enc_sender_secret_key: &FheUint256,
) -> FheDKSAPResult<EthereumKeyPair> {
    // Set the server key for FHE operations
    set_server_key(fhe_keypair.secret_key.clone());

    // Get the secp256k1 order for modulo operation
    let n = FheUint256::encrypt(utils::secp256k1_order(), &fhe_keypair.public_key);

    // Perform modulo operation: C = (C_1 + C_2) % n
    let x = n - enc_sender_secret_key;
    let c = enc_receiver_secret_key.ge(x.clone()).if_then_else(
        &(enc_receiver_secret_key - x),
        &(enc_sender_secret_key + enc_receiver_secret_key),
    );

    // Decrypt the result to get the stealth address private key
    let sk_z_u256 = c.decrypt(&fhe_keypair.public_key);

    // Convert U256 back to SecretKey
    let sk_z_bytes = utils::u256_to_bytes_be(sk_z_u256);
    let sk_z = SecretKey::from_byte_array(sk_z_bytes).map_err(|e| {
        FheDKSAPError::KeyGenerationError(format!("Failed to create SecretKey from bytes: {}", e))
    })?;

    Ok(EthereumKeyPair {
        secret_key: sk_z,
        public_key: sk_z.public_key(secp),
    })
}
