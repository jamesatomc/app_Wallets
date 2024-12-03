use std::{collections::HashMap, str::FromStr, thread, time::Duration};

use bip39::Mnemonic;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPrivKey}, secp256k1::{Secp256k1, SecretKey}, Address, Network, PrivateKey, PublicKey
};
use rand::Rng;
use serde::Deserialize;

fn generate_mnemonic() -> Mnemonic {
    // Generate 16 bytes of entropy (for 12 words)
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 16];
    rng.fill(&mut entropy);
    
    Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic")
}

#[derive(Deserialize)]
struct AddressBalance {
    final_balance: u64,
}

#[derive(Deserialize)]
struct BalanceResponse {
    #[serde(flatten)]
    addresses: HashMap<String, AddressBalance>,
}

fn main() {
    let mut batch = 1;
    loop {
        println!("\nBatch #{}", batch);
        let mnemonic = generate_mnemonic();
        println!("Mnemonic: {}\n", mnemonic);
        println!("Bitcoin Wallets:");
        
        for i in 0..10 {
            let path = DerivationPath::from_str(&format!("m/44'/0'/0'/0/{}", i))
                .expect("Failed to parse derivation path");
                
            let secp = Secp256k1::new();
            let seed = mnemonic.to_seed("");
            let master_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
                .expect("Failed to create master key");
                
            let child_key = master_key.derive_priv(&secp, &path)
                .expect("Failed to derive child key");
                
            let secret_key = SecretKey::from_slice(&child_key.private_key[..])
                .expect("Failed to create secret key");

            let priv_key = PrivateKey::new(secret_key, Network::Bitcoin);
                
            let public_key = PublicKey::new(secret_key.public_key(&secp));
            let address = Address::p2pkh(&public_key, Network::Bitcoin);
            
            println!("{:2}. Address: {}", i + 1, address);
            println!("    View on BlockExplorer: https://blockexplorer.one/bitcoin/mainnet/address/{}", address);
            println!("    Private key (WIF): {}", priv_key.to_wif());
            
            // Add delay between requests to avoid rate limiting
            thread::sleep(Duration::from_millis(100));

            // Fetch and check balance
            let url = format!("https://blockchain.info/balance?active={}", address);
            let balance_btc = match reqwest::blocking::get(&url) {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.text() {
                            Ok(text) => {
                                match serde_json::from_str::<BalanceResponse>(&text) {
                                    Ok(balance_info) => {
                                        match balance_info.addresses.get(&address.to_string()) {
                                            Some(addr_info) => addr_info.final_balance as f64 / 100_000_000.0,
                                            None => 0.0,
                                        }
                                    },
                                    Err(_) => {
                                        println!("    Error: Failed to parse balance response");
                                        0.0
                                    }
                                }
                            },
                            Err(_) => {
                                println!("    Error: Failed to read response");
                                0.0
                            }
                        }
                    } else {
                        println!("    Error: API request failed with status {}", resp.status());
                        0.0
                    }
                },
                Err(_) => {
                    println!("    Error: Failed to connect to API");
                    0.0
                }
            };

            println!("    Balance: {:.8} BTC", balance_btc);
            println!();
        }
        
        batch += 1;
        println!("\nPress Enter to generate next batch...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
    }
}