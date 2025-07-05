use secp256k1::rand;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use sha3::{Digest, Keccak256};

use tfhe::integer::U256;
use tfhe::prelude::{FheDecrypt, FheEncrypt};
use tfhe::{
    ClientKey, Config, ConfigBuilder, FheUint256, ServerKey, generate_keys, set_server_key,
};

pub fn generate_secp256k1_keypair(secp: &Secp256k1<secp256k1::All>) -> (SecretKey, PublicKey) {
    secp.generate_keypair(&mut rand::rng())
}

pub fn generate_fhe_keypair(config: Config) -> (ClientKey, ServerKey) {
    generate_keys(config)
}

fn split_sk_bytes(sk_bytes: [u8; 32]) -> (u128, u128) {
    let high = u128::from_be_bytes(sk_bytes[0..16].try_into().unwrap());
    let low = u128::from_be_bytes(sk_bytes[16..32].try_into().unwrap());
    (high, low)
}

pub fn encrypt_sk(client_key: &ClientKey, sk: &SecretKey) -> FheUint256 {
    let sk_u256 = U256::from(split_sk_bytes(sk.secret_bytes()));
    FheUint256::encrypt(sk_u256, client_key)
}

pub fn decrypt_sk(ct: &FheUint256, client_key: &ClientKey) -> U256 {
    ct.decrypt(client_key)
}

pub fn eth_address(public_key: &PublicKey) -> String {
    let serialized = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&serialized[1..]); // drop 0x04
    let address = &hash[12..]; // last 20 bytes
    format!("0x{}", hex::encode(address))
}

pub fn derive_ec_pk(secp: &Secp256k1<secp256k1::All>, sk_u256: U256) -> PublicKey {
    let (high, low) = sk_u256.to_low_high_u128();
    let mut sk_bytes = [0u8; 32];

    // Big-endian: high is most-significant 16 bytes
    sk_bytes[0..16].copy_from_slice(&high.to_be_bytes());
    sk_bytes[16..32].copy_from_slice(&low.to_be_bytes());

    // Create a SecretKey from the full 32-byte array
    let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
    sk.public_key(secp)
}

fn main() {
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let fhe_config = ConfigBuilder::default().build();

    // Receiver (Bob) part

    // Receiver (Bob) generates a key pair for (sk_2, pk_2)
    let (sk_2, pk_2) = generate_secp256k1_keypair(&secp);

    // Receiver (Bob) generates a FHE key pair (sk_b, pk_b)
    let (pk_b, sk_b) = generate_keys(fhe_config);

    // C_2 = Enc(sk_2, pk_b)
    let c_2 = encrypt_sk(&pk_b, &sk_2);

    // Sender (Alice) part

    // 1. Alice (sender) generates a key pair (sk_1, pk_1) randomly for each SA
    let (sk_1, pk_1) = generate_secp256k1_keypair(&secp);

    // 2. Combine Public Keys: pk_z = pk_1 + pk_2
    let pk_z = pk_1.combine(&pk_2).unwrap();

    // 3. Convert Public Key to Ethereum Address
    let sa = eth_address(&pk_z);
    println!("Stealth Address: {:?}", sa);

    // 4. C_1 = Enc(sk_1, pk_b)
    let c_1 = encrypt_sk(&pk_b, &sk_1);

    // 5. Alice broadcasts C_1 to Bob

    // 6. Bob receives C_1 and computes C_2 = C_1 + C_bob
    set_server_key(sk_b);
    let c = c_1 + c_2;

    // 7. Bob decrypts C to get sk_z
    let sk_z_uint256 = decrypt_sk(&c, &pk_b);

    let recovered_pk = derive_ec_pk(&secp, sk_z_uint256);

    let recovered_eth_address = eth_address(&recovered_pk);
    println!("Recovered Address: {:?}", recovered_eth_address);
}
