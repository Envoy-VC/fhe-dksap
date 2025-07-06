use secp256k1::rand;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use sha3::{Digest, Keccak256};
use tfhe::{ConfigBuilder, FheUint256, generate_keys, integer::U256, prelude::*, set_server_key};

fn bytes_be_to_u256(bytes: &[u8]) -> U256 {
    let high = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    let low = u128::from_be_bytes(bytes[16..32].try_into().unwrap());
    U256::from((low, high))
}

fn u256_to_bytes_be(u: U256) -> [u8; 32] {
    let (low, high) = u.to_low_high_u128();
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&high.to_be_bytes()); // high 128 bits first
    bytes[16..32].copy_from_slice(&low.to_be_bytes()); // then low 128 bits
    bytes
}

fn pk_to_eth_address(pk: &PublicKey) -> String {
    let serialized = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&serialized[1..]);
    let address = &hash[12..];
    format!("0x{}", hex::encode(address))
}

fn secp256k1_order() -> U256 {
    let low = 0xBAAEDCE6AF48A03BBFD25E8CD0364141;
    let high = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE;
    U256::from((low, high))
}

fn main() {
    let secp = Secp256k1::new();
    let config = ConfigBuilder::default().build();
    // Receiver (Bob) part

    // Receiver (Bob) generates a ethereum key pair (sk_2, pk_2)
    let (sk_2, pk_2) = secp.generate_keypair(&mut rand::rng());

    // Receiver (Bob) generates a FHE key pair (pk_b, sk_b)
    let (pk_b, sk_b) = generate_keys(config);

    // Receiver (Bob) encrypts sk_2 with pk_b to get c_2 and publishes it
    let sk_2_u256 = bytes_be_to_u256(&sk_2.secret_bytes());
    let c_2 = FheUint256::encrypt(sk_2_u256, &pk_b);

    // Sender (Alice) part

    // Sender (Alice) generates a ethereum key pair (sk_1, pk_1) for each SA Transaction
    let (sk_1, pk_1) = secp.generate_keypair(&mut rand::rng());

    // Sender (Alice) Combines Public Keys: pk_z = pk_1 + pk_2
    let pk_z = pk_1.combine(&pk_2).unwrap();

    // Get Stealth Address (SA) from PK_z
    let sa = pk_to_eth_address(&pk_z);
    println!("Stealth Address: {:?}", sa);

    // Sender (Alice) encrypts sk_1 with pk_b to get c_1 and publishes it
    let sk_1_u256 = bytes_be_to_u256(&sk_1.secret_bytes());
    let c_1 = FheUint256::encrypt(sk_1_u256, &pk_b);

    // Helper SECP256k1 order for modulo operation
    let n = FheUint256::encrypt(secp256k1_order(), &pk_b);

    // Now sender does not know SA's private key, but knows where to send the transaction to Stealth Address.

    // Receiver(Bob) receives c_1 from Sender (Alice), and already has c_2.
    // He computes C = (C_1 + C_2) % n
    // where n is the SECP256k1 order
    set_server_key(sk_b);
    let x = n - c_1.clone();
    let c = c_2
        .ge(x.clone())
        .if_then_else(&(c_2.clone() - x), &(c_1 + c_2));

    // Receiver(Bob) decrypts C to get sk_z
    let sk_z_uint256: U256 = c.decrypt(&pk_b);
    let sk_z = SecretKey::from_byte_array(u256_to_bytes_be(sk_z_uint256)).unwrap();

    let recovered_pk = sk_z.public_key(&secp);
    let recovered_address = pk_to_eth_address(&recovered_pk);
    println!("Recovered Address: {:?}", recovered_address);
}
