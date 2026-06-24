//! Mnemonic (BIP-39) vanity search — all chains, each at its standard account
//! (BIP-44/BIP-84 for secp256k1; SLIP-0010 for ed25519; see `mnemonic_path_str`).
//!
//! This searches the other direction: random BIP-39 mnemonic -> seed -> HD key
//! -> address. The found mnemonic genuinely restores to the address in any
//! standard wallet (unlike encoding a raw key as words). It is far slower than
//! the raw-key search (PBKDF2 2048 rounds per attempt, no incremental/GPU).

use k256::ProjectivePoint;
use wasm_bindgen::prelude::*;

use crate::chain::Chain;
use crate::ed25519::{sui_address_bytes, sui_privkey};
use crate::hashes::{eip55, hex_0x, hex_no_prefix, matches, push_hex, starts_and_ends_with};
use crate::hd::{
    derive_ed25519_seed, derive_secp_scalar, ed25519_path, mnemonic_path_str, secp_bip44_path,
};
use crate::secp::{eth_address_hex, secp_address, wif_compressed};

/// A mnemonic-mode match.
#[wasm_bindgen]
pub struct MnemonicFound {
    address: String,
    private_key: String,
    mnemonic: String,
    path: String,
}

#[wasm_bindgen]
impl MnemonicFound {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String { self.address.clone() }
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> String { self.private_key.clone() }
    #[wasm_bindgen(getter)]
    pub fn mnemonic(&self) -> String { self.mnemonic.clone() }
    #[wasm_bindgen(getter)]
    pub fn path(&self) -> String { self.path.clone() }
}

/// BIP-39 mnemonic vanity searcher. Draws a random BIP-39 mnemonic, derives the
/// chain's standard account (see [`mnemonic_path_str`]) and checks the address
/// against the pattern. The found mnemonic genuinely restores to the address in
/// any standard wallet. `words` is 12 or 24.
#[wasm_bindgen]
pub struct MnemonicSearcher {
    chain: Chain,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    checksum: bool,
    entropy_len: usize,
}

#[wasm_bindgen]
impl MnemonicSearcher {
    #[wasm_bindgen(constructor)]
    pub fn new(chain: &str, prefix: &str, suffix: &str, checksum: bool, words: u32) -> MnemonicSearcher {
        let chain = Chain::parse(chain);
        // Same casing rules as the raw-key searcher: EVM-without-checksum and
        // Sui (both hex) match case-insensitively; base58/bech32 and EVM-with-
        // checksum match exactly as typed.
        let normalize = |s: &str| -> Vec<u8> {
            if (chain == Chain::Evm && !checksum) || chain == Chain::Sui {
                s.to_ascii_lowercase().into_bytes()
            } else {
                s.as_bytes().to_vec()
            }
        };
        MnemonicSearcher {
            chain,
            prefix: normalize(prefix),
            suffix: normalize(suffix),
            checksum,
            entropy_len: if words == 24 { 32 } else { 16 },
        }
    }

    pub fn run(&mut self, iters: u32) -> Option<MnemonicFound> {
        let mut entropy = [0u8; 32];
        for _ in 0..iters {
            let ent = &mut entropy[..self.entropy_len];
            getrandom::getrandom(ent).expect("CSPRNG unavailable");
            let mnemonic = bip39::Mnemonic::from_entropy(ent).expect("valid entropy");
            let seed = mnemonic.to_seed("");
            if let Some((address, private_key)) = self.check(&seed) {
                return Some(MnemonicFound {
                    address,
                    private_key,
                    mnemonic: mnemonic.to_string(),
                    path: mnemonic_path_str(self.chain).to_string(),
                });
            }
        }
        None
    }
}

impl MnemonicSearcher {
    /// Derive the chain's account from `seed` and, if its address matches the
    /// pattern, return `(address, private_key_display)`.
    fn check(&self, seed: &[u8; 64]) -> Option<(String, String)> {
        match self.chain {
            Chain::Solana => {
                use ed25519_dalek::SigningKey;
                let edseed = derive_ed25519_seed(seed, ed25519_path(Chain::Solana).unwrap());
                let sk = SigningKey::from_bytes(&edseed);
                let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();
                if matches(addr.as_bytes(), 0, &self.prefix, &self.suffix) {
                    let private_key = bs58::encode(sk.to_keypair_bytes()).into_string();
                    return Some((addr, private_key));
                }
                None
            }
            Chain::Sui => {
                use ed25519_dalek::SigningKey;
                let edseed = derive_ed25519_seed(seed, ed25519_path(Chain::Sui).unwrap());
                let sk = SigningKey::from_bytes(&edseed);
                let addr_bytes = sui_address_bytes(&sk.verifying_key().to_bytes());
                let mut hex = String::with_capacity(64);
                push_hex(&mut hex, &addr_bytes);
                if matches(hex.as_bytes(), 0, &self.prefix, &self.suffix) {
                    let mut address = String::with_capacity(66);
                    address.push_str("0x");
                    address.push_str(&hex);
                    return Some((address, sui_privkey(&edseed)));
                }
                None
            }
            _ => {
                let scalar = derive_secp_scalar(seed, &secp_bip44_path(self.chain).unwrap());
                let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
                let key_bytes = scalar.to_bytes();
                if self.chain == Chain::Evm {
                    let mut hex = [0u8; 40];
                    eth_address_hex(&point, &mut hex);
                    let hit = if self.checksum {
                        starts_and_ends_with(&eip55(&hex), &self.prefix, &self.suffix)
                    } else {
                        starts_and_ends_with(&hex, &self.prefix, &self.suffix)
                    };
                    if hit {
                        let display = eip55(&hex);
                        let mut address = String::with_capacity(42);
                        address.push_str("0x");
                        address.push_str(core::str::from_utf8(&display).unwrap());
                        return Some((address, hex_0x(&key_bytes)));
                    }
                    None
                } else {
                    let addr = secp_address(self.chain, &point);
                    if matches(addr.as_bytes(), self.chain.lead(), &self.prefix, &self.suffix) {
                        let private_key = match self.chain {
                            Chain::Tron | Chain::Xrp => hex_no_prefix(&key_bytes),
                            Chain::BtcP2pkh | Chain::BtcBech32 => wif_compressed(&key_bytes),
                            _ => unreachable!(),
                        };
                        return Some((addr, private_key));
                    }
                    None
                }
            }
        }
    }
}
