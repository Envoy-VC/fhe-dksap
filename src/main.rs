use secp256k1::rand;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::error::Error;
use std::fmt;
use tfhe::{
    ClientKey, ConfigBuilder, FheUint256, ServerKey, generate_keys, prelude::*, set_server_key,
};

pub mod utils;

/// Custom error types for FHE-DKSAP operations
#[derive(Debug)]
pub enum FheDksapError {
    /// Error during key generation
    KeyGenerationError(String),
    /// Error during encryption operations
    EncryptionError(String),
    /// Error during decryption operations
    DecryptionError(String),
    /// Error during address generation
    AddressGenerationError(String),
    /// Error during key combination
    KeyCombinationError(String),
    /// Error during modulo operation
    ModuloOperationError(String),
}

impl fmt::Display for FheDksapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FheDksapError::KeyGenerationError(msg) => write!(f, "Key generation error: {}", msg),
            FheDksapError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            FheDksapError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            FheDksapError::AddressGenerationError(msg) => {
                write!(f, "Address generation error: {}", msg)
            }
            FheDksapError::KeyCombinationError(msg) => write!(f, "Key combination error: {}", msg),
            FheDksapError::ModuloOperationError(msg) => {
                write!(f, "Modulo operation error: {}", msg)
            }
        }
    }
}

impl Error for FheDksapError {}

/// Result type for FHE-DKSAP operations
pub type FheDksapResult<T> = Result<T, FheDksapError>;

/// Represents a complete Ethereum key pair
#[derive(Debug, Clone)]
pub struct EthereumKeyPair {
    /// The private key
    pub secret_key: SecretKey,
    /// The public key
    pub public_key: PublicKey,
}

/// Represents FHE keys for encryption/decryption
#[derive(Clone)]
pub struct FheKeyPair {
    /// FHE client key for encryption
    pub public_key: ClientKey,
    /// FHE server key for decryption
    pub secret_key: ServerKey,
}

/// Represents the receiver's setup data
#[derive(Clone)]
pub struct ReceiverSetup {
    /// Ethereum wallet key pair for stealth address spending
    pub eth_key_pair: EthereumKeyPair,
    /// FHE key pair for encryption/decryption
    pub fhe_key_pair: FheKeyPair,
    /// Encrypted spending private key
    pub encrypted_sk2: FheUint256,
}

/// Represents a stealth address transaction
#[derive(Clone)]
pub struct StealthAddressTransaction {
    /// The generated stealth address
    pub stealth_address: String,
    /// Encrypted ephemeral private key
    pub encrypted_sk1: FheUint256,
    /// Ephemeral key pair used for this transaction
    pub ephemeral_key_pair: EthereumKeyPair,
}

/// Core FHE-DKSAP protocol functions
pub mod protocol {
    use tfhe::Config;

    use super::*;

    /// Generates a new Ethereum key pair using secp256k1
    ///
    /// # Arguments
    /// * `secp` - The secp256k1 context
    ///
    /// # Returns
    /// * `FheDksapResult<EthereumKeyPair>` - The generated key pair or an error
    pub fn generate_ethereum_key_pair(
        secp: &Secp256k1<secp256k1::All>,
    ) -> FheDksapResult<EthereumKeyPair> {
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());

        Ok(EthereumKeyPair {
            secret_key,
            public_key,
        })
    }

    /// Generates FHE keys for encryption and decryption
    ///
    /// # Arguments
    /// * `config` - The TFHE configuration
    ///
    /// # Returns
    /// * `FheDksapResult<FheKeyPair>` - The generated FHE key pair or an error
    pub fn generate_fhe_key_pair(config: Config) -> FheDksapResult<FheKeyPair> {
        let (client_key, server_key) = generate_keys(config);

        Ok(FheKeyPair {
            public_key: client_key,
            secret_key: server_key,
        })
    }

    /// Sets up the receiver (Bob) with all necessary keys and encrypted data
    ///
    /// This function implements Phase 1 of the FHE-DKSAP protocol:
    /// 1. Generates Ethereum wallet key pair for stealth address spending
    /// 2. Generates FHE key pair for encryption/decryption
    /// 3. Encrypts the spending private key using FHE
    ///
    /// # Arguments
    /// * `secp` - The secp256k1 context
    /// * `config` - The TFHE configuration
    ///
    /// # Returns
    /// * `FheDksapResult<ReceiverSetup>` - The complete receiver setup or an error
    ///
    /// # Example
    /// ```rust
    /// use secp256k1::Secp256k1;
    /// use ConfigBuilder;
    ///
    /// let secp = Secp256k1::new();
    /// let config = ConfigBuilder::default().build();
    /// let receiver_setup = setup_receiver(&secp, config)?;
    /// ```
    pub fn setup_receiver(
        secp: &Secp256k1<secp256k1::All>,
        config: Config,
    ) -> FheDksapResult<ReceiverSetup> {
        // Generate Ethereum wallet key pair for stealth address spending
        let eth_key_pair = generate_ethereum_key_pair(secp).map_err(|e| {
            FheDksapError::KeyGenerationError(format!(
                "Failed to generate Ethereum key pair: {}",
                e
            ))
        })?;

        // Generate FHE key pair for encryption/decryption
        let fhe_key_pair = generate_fhe_key_pair(config).map_err(|e| {
            FheDksapError::KeyGenerationError(format!("Failed to generate FHE key pair: {}", e))
        })?;

        // Encrypt the spending private key using FHE
        let sk2_u256 = utils::bytes_be_to_u256(&eth_key_pair.secret_key.secret_bytes());
        let encrypted_sk2 = FheUint256::encrypt(sk2_u256, &fhe_key_pair.public_key);

        Ok(ReceiverSetup {
            eth_key_pair,
            fhe_key_pair,
            encrypted_sk2,
        })
    }

    /// Generates a stealth address for a transaction
    ///
    /// This function implements Phase 2 of the FHE-DKSAP protocol:
    /// 1. Generates ephemeral key pair for this transaction
    /// 2. Combines public keys to create stealth address
    /// 3. Encrypts the ephemeral private key
    ///
    /// # Arguments
    /// * `secp` - The secp256k1 context
    /// * `receiver_setup` - The receiver's setup data containing public keys
    ///
    /// # Returns
    /// * `FheDksapResult<StealthAddressTransaction>` - The stealth address transaction or an error
    ///
    /// # Example
    /// ```rust
    /// let transaction = generate_stealth_address(&secp, &receiver_setup)?;
    /// println!("Stealth Address: {}", transaction.stealth_address);
    /// ```
    pub fn generate_stealth_address(
        secp: &Secp256k1<secp256k1::All>,
        receiver_setup: &ReceiverSetup,
    ) -> FheDksapResult<StealthAddressTransaction> {
        // Generate ephemeral key pair for this transaction
        let ephemeral_key_pair = generate_ethereum_key_pair(secp).map_err(|e| {
            FheDksapError::KeyGenerationError(format!(
                "Failed to generate ephemeral key pair: {}",
                e
            ))
        })?;

        // Combine public keys: pk_z = pk_1 + pk_2
        let pk_z = ephemeral_key_pair
            .public_key
            .combine(&receiver_setup.eth_key_pair.public_key)
            .map_err(|e| {
                FheDksapError::KeyCombinationError(format!("Failed to combine public keys: {}", e))
            })?;

        // Generate stealth address from combined public key
        let stealth_address = utils::pk_to_eth_address(&pk_z);

        // Encrypt the ephemeral private key using receiver's FHE public key
        let sk1_u256 = utils::bytes_be_to_u256(&ephemeral_key_pair.secret_key.secret_bytes());
        let encrypted_sk1 = FheUint256::encrypt(sk1_u256, &receiver_setup.fhe_key_pair.public_key);

        Ok(StealthAddressTransaction {
            stealth_address,
            encrypted_sk1,
            ephemeral_key_pair,
        })
    }

    /// Recovers the stealth address private key using FHE operations
    ///
    /// This function implements Phase 3 of the FHE-DKSAP protocol:
    /// 1. Adds the two encrypted private keys using FHE
    /// 2. Performs modulo operation with secp256k1 order
    /// 3. Decrypts the result to obtain the stealth address private key
    ///
    /// # Arguments
    /// * `receiver_setup` - The receiver's setup data containing FHE keys
    /// * `encrypted_sk1` - The encrypted ephemeral private key from the sender
    ///
    /// # Returns
    /// * `FheDksapResult<SecretKey>` - The recovered stealth address private key or an error
    ///
    /// # Example
    /// ```rust
    /// let stealth_private_key = recover_stealth_key(&receiver_setup, &transaction.encrypted_sk1)?;
    /// ```
    pub fn recover_stealth_key(
        receiver_setup: &ReceiverSetup,
        encrypted_sk1: &FheUint256,
    ) -> FheDksapResult<SecretKey> {
        // Set the server key for FHE operations
        set_server_key(receiver_setup.fhe_key_pair.secret_key.clone());

        // Get the secp256k1 order for modulo operation
        let n = FheUint256::encrypt(
            utils::secp256k1_order(),
            &receiver_setup.fhe_key_pair.public_key,
        );

        // Perform modulo operation: C = (C_1 + C_2) % n
        let x = n - encrypted_sk1.clone();
        let c = receiver_setup.encrypted_sk2.ge(x.clone()).if_then_else(
            &(receiver_setup.encrypted_sk2.clone() - x),
            &(encrypted_sk1 + &receiver_setup.encrypted_sk2),
        );

        // Decrypt the result to get the stealth address private key
        let sk_z_u256 = c.decrypt(&receiver_setup.fhe_key_pair.public_key);

        // Convert U256 back to SecretKey
        let sk_z_bytes = utils::u256_to_bytes_be(sk_z_u256);
        let sk_z = SecretKey::from_byte_array(sk_z_bytes).map_err(|e| {
            FheDksapError::KeyGenerationError(format!(
                "Failed to create SecretKey from bytes: {}",
                e
            ))
        })?;

        Ok(sk_z)
    }

    /// Verifies that the recovered stealth address matches the generated one
    ///
    /// # Arguments
    /// * `secp` - The secp256k1 context
    /// * `stealth_private_key` - The recovered stealth address private key
    /// * `expected_stealth_address` - The expected stealth address
    ///
    /// # Returns
    /// * `FheDksapResult<bool>` - True if addresses match, false otherwise, or an error
    pub fn verify_stealth_address(
        secp: &Secp256k1<secp256k1::All>,
        stealth_private_key: &SecretKey,
        expected_stealth_address: &str,
    ) -> FheDksapResult<bool> {
        let recovered_public_key = stealth_private_key.public_key(secp);
        let recovered_address = utils::pk_to_eth_address(&recovered_public_key);

        Ok(recovered_address == expected_stealth_address)
    }
}

/// Main function demonstrating the complete FHE-DKSAP protocol
fn main() -> FheDksapResult<()> {
    println!("🚀 Starting FHE-DKSAP Protocol Demonstration");
    println!("=============================================");

    // Initialize cryptographic contexts
    let secp = Secp256k1::new();
    let config = ConfigBuilder::default().build();

    println!("✅ Cryptographic contexts initialized");

    // Phase 1: Bob (Receiver) Setup
    println!("\n📋 Phase 1: Bob (Receiver) Setup");
    println!("--------------------------------");
    let receiver_setup = protocol::setup_receiver(&secp, config)?;
    println!("✅ Receiver setup completed");
    println!(
        "   Ethereum Address: {}",
        utils::pk_to_eth_address(&receiver_setup.eth_key_pair.public_key)
    );

    // Phase 2: Alice (Sender) Creates Stealth Address
    println!("\n📋 Phase 2: Alice (Sender) Creates Stealth Address");
    println!("------------------------------------------------");
    let stealth_transaction = protocol::generate_stealth_address(&secp, &receiver_setup)?;
    println!("✅ Stealth address generated");
    println!(
        "   Stealth Address: {}",
        stealth_transaction.stealth_address
    );

    // Phase 3: Bob (Receiver) Recovers Stealth Address
    println!("\n📋 Phase 3: Bob (Receiver) Recovers Stealth Address");
    println!("--------------------------------------------------");
    let stealth_private_key =
        protocol::recover_stealth_key(&receiver_setup, &stealth_transaction.encrypted_sk1)?;
    println!("✅ Stealth address private key recovered");

    // Verification
    println!("\n🔍 Verification");
    println!("---------------");
    let is_valid = protocol::verify_stealth_address(
        &secp,
        &stealth_private_key,
        &stealth_transaction.stealth_address,
    )?;

    if is_valid {
        println!("✅ SUCCESS: Recovered stealth address matches generated address!");
        let recovered_public_key = stealth_private_key.public_key(&secp);
        let recovered_address = utils::pk_to_eth_address(&recovered_public_key);
        println!("   Recovered Address: {}", recovered_address);
    } else {
        println!("❌ ERROR: Address verification failed!");
        return Err(FheDksapError::AddressGenerationError(
            "Address verification failed".to_string(),
        ));
    }

    println!("\n🎉 FHE-DKSAP Protocol demonstration completed successfully!");
    Ok(())
}
