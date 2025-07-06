use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};
use tfhe::integer::U256;

/// Converts a byte array in big-endian format to U256
///
/// # Arguments
/// * `bytes` - 32-byte array in big-endian format
///
/// # Returns
/// * `U256` - The converted value
///
/// # Panics
/// Panics if the byte array is not exactly 32 bytes
pub fn bytes_be_to_u256(bytes: &[u8]) -> U256 {
    if bytes.len() != 32 {
        panic!("Expected 32 bytes, got {}", bytes.len());
    }

    let high = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    let low = u128::from_be_bytes(bytes[16..32].try_into().unwrap());
    U256::from((low, high))
}

/// Converts a U256 value to a byte array in big-endian format
///
/// # Arguments
/// * `u` - The U256 value to convert
///
/// # Returns
/// * `[u8; 32]` - The byte array in big-endian format
pub fn u256_to_bytes_be(u: U256) -> [u8; 32] {
    let (low, high) = u.to_low_high_u128();
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&high.to_be_bytes()); // high 128 bits first
    bytes[16..32].copy_from_slice(&low.to_be_bytes()); // then low 128 bits
    bytes
}

/// Converts a secp256k1 public key to an Ethereum address
///
/// # Arguments
/// * `pk` - The secp256k1 public key
///
/// # Returns
/// * `String` - The Ethereum address in hex format with 0x prefix
pub fn pk_to_eth_address(pk: &PublicKey) -> String {
    let serialized = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&serialized[1..]);
    let address = &hash[12..];
    format!("0x{}", hex::encode(address))
}

/// Returns the secp256k1 curve order as U256
///
/// # Returns
/// * `U256` - The secp256k1 curve order
pub fn secp256k1_order() -> U256 {
    let low = 0xBAAEDCE6AF48A03BBFD25E8CD0364141;
    let high = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE;
    U256::from((low, high))
}
