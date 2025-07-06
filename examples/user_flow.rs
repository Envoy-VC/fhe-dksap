use std::time::Instant;

use secp256k1::Secp256k1;
use tfhe::ConfigBuilder;
extern crate fhe_dksap;
use fhe_dksap::{
    encrypt_secret_key, generate_ethereum_key_pair, generate_fhe_key_pair,
    generate_stealth_address, recover_secret_key, utils,
};
fn main() {
    println!("🚀 Starting FHE-DKSAP Protocol Demonstration");
    println!("=============================================");

    // Initialize cryptographic contexts
    let secp = Secp256k1::new();
    let config = ConfigBuilder::default().build();

    println!("✅ Cryptographic contexts initialized");

    // Phase 1: Bob (Receiver) Setup
    println!("\n📋 Phase 1: Bob (Receiver) Setup");
    println!("--------------------------------");

    // Generate Ethereum wallet key pair for stealth address spending
    let receiver_eth_keypair = generate_ethereum_key_pair(&secp).unwrap();
    // Generate FHE key pair for encryption/decryption
    let receiver_fhe_keypair = generate_fhe_key_pair(config).unwrap();

    // Compute the encrypted secret key
    let receiver_enc_secret_key = encrypt_secret_key(
        receiver_eth_keypair.secret_key,
        &receiver_fhe_keypair.public_key,
    );

    println!("✅ Receiver setup completed");

    // Phase 2: Alice (Sender) Creates Stealth Address
    println!("\n📋 Phase 2: Alice (Sender) Creates New Stealth Address");
    println!("------------------------------------------------");
    let phase2_start = Instant::now();
    let res = generate_stealth_address(
        &secp,
        &receiver_eth_keypair.public_key,
        &receiver_fhe_keypair.public_key,
    )
    .unwrap();
    let phase2_end = phase2_start.elapsed();

    println!("✅ Stealth address generated");
    println!("Stealth Address: {:?}", res.stealth_address);
    println!(
        "Stealth Address Creation Time: {:?}ms",
        phase2_end.as_micros() as f64 / 1000000.0
    );

    // Phase 3: Bob (Receiver) Recovers Stealth Address
    println!("\n📋 Phase 3: Bob (Receiver) Recovers Stealth Address Secret Key");
    println!("--------------------------------------------------");
    let phase3_start = Instant::now();
    let recovered = recover_secret_key(
        &secp,
        &receiver_fhe_keypair,
        &receiver_enc_secret_key,
        &res.encrypted_secret_key,
    )
    .unwrap();
    let phase3_end = phase3_start.elapsed();
    println!(
        "Private Key for Stealth Address: {:?}",
        format!("0x{}", hex::encode(recovered.secret_key.secret_bytes()))
    );
    println!(
        "Stealth Address Private Key Recovery in: {:?}s",
        phase3_end.as_micros() as f64 / 1000000.0
    );

    let recovered_address = utils::pk_to_eth_address(&recovered.public_key);
    println!("✅ Stealth address private key recovered");

    // Verification
    println!("\n🔍 Verification");
    println!("---------------");
    let is_valid = res.stealth_address == recovered_address;

    if is_valid {
        println!("✅ SUCCESS: Recovered stealth address matches generated address!");
    } else {
        println!("❌ ERROR: Address verification failed!");
    }

    println!("\n🎉 FHE-DKSAP Protocol demonstration completed successfully!");
}
