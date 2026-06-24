//! Free-function wasm-bindgen exports: re-derive/verify a key's address (used
//! by the trusted CPU re-check of GPU candidates), format a private key for
//! display, and the difficulty/reachability sampler.

use k256::{ProjectivePoint, Scalar};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;
use crate::ed25519::sui_address_bytes;
use crate::hashes::{eip55, hex_0x, hex_no_prefix, push_hex};
use crate::searcher::Searcher;
use crate::secp::{
    btc_bech32_address, btc_p2pkh_address, eth_address_hex, tron_address, wif_compressed,
    xrp_address,
};

/// Derive the EIP-55 checksummed Ethereum address (`0x…`) for a 32-byte
/// private key given as hex (with or without `0x`). Returns an empty string if
/// the key is invalid. Used to re-derive and verify candidates found by the
/// WebGPU kernel on the trusted CPU path before they are ever shown.
#[wasm_bindgen]
pub fn eth_address(priv_hex: &str) -> String {
    use k256::elliptic_curve::PrimeField;
    let s = priv_hex.strip_prefix("0x").unwrap_or(priv_hex);
    if s.len() != 64 {
        return String::new();
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        match u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
            Ok(b) => bytes[i] = b,
            Err(_) => return String::new(),
        }
    }
    let repr = k256::FieldBytes::from(bytes);
    let scalar = match Option::<Scalar>::from(Scalar::from_repr(repr)) {
        Some(sc) if sc != Scalar::ZERO => sc,
        _ => return String::new(),
    };
    let point = ProjectivePoint::GENERATOR * scalar;
    let mut hex = [0u8; 40];
    eth_address_hex(&point.to_affine(), &mut hex);
    let cased = eip55(&hex);
    let mut address = String::with_capacity(42);
    address.push_str("0x");
    address.push_str(core::str::from_utf8(&cased).unwrap());
    address
}

/// Derive the address for `chain` from a private key hex (with or without
/// `0x`). For secp256k1 chains the hex is the scalar; for Solana/Sui it is the
/// 32-byte seed. Returns "" on an invalid key. Used to re-derive and verify
/// GPU-found candidates on the trusted CPU path.
#[wasm_bindgen]
pub fn address_of(chain: &str, priv_hex: &str) -> String {
    let chain = Chain::parse(chain);
    let s = priv_hex.strip_prefix("0x").unwrap_or(priv_hex);
    if s.len() != 64 {
        return String::new();
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        match u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
            Ok(b) => bytes[i] = b,
            Err(_) => return String::new(),
        }
    }

    match chain {
        Chain::Solana => {
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(&bytes);
            bs58::encode(sk.verifying_key().to_bytes()).into_string()
        }
        Chain::Sui => {
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(&bytes);
            let addr = sui_address_bytes(&sk.verifying_key().to_bytes());
            let mut out = String::with_capacity(66);
            out.push_str("0x");
            push_hex(&mut out, &addr);
            out
        }
        _ => {
            use k256::elliptic_curve::PrimeField;
            let repr = k256::FieldBytes::from(bytes);
            let scalar = match Option::<Scalar>::from(Scalar::from_repr(repr)) {
                Some(sc) if sc != Scalar::ZERO => sc,
                _ => return String::new(),
            };
            let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
            match chain {
                Chain::Tron => tron_address(&point),
                Chain::BtcP2pkh => btc_p2pkh_address(&point),
                Chain::BtcBech32 => btc_bech32_address(&point),
                Chain::Xrp => xrp_address(&point),
                _ => {
                    let mut hex = [0u8; 40];
                    eth_address_hex(&point, &mut hex);
                    let cased = eip55(&hex);
                    let mut a = String::with_capacity(42);
                    a.push_str("0x");
                    a.push_str(core::str::from_utf8(&cased).unwrap());
                    a
                }
            }
        }
    }
}

/// Format a secp256k1 private key (32-byte hex) in the chain's usual import
/// format, for displaying a GPU-found key. EVM -> 0x-hex, Tron/XRP -> hex,
/// Bitcoin -> WIF (compressed).
#[wasm_bindgen]
pub fn privkey_display(chain: &str, priv_hex: &str) -> String {
    let chain = Chain::parse(chain);
    let s = priv_hex.strip_prefix("0x").unwrap_or(priv_hex);
    if s.len() != 64 {
        return String::new();
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        match u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
            Ok(b) => bytes[i] = b,
            Err(_) => return String::new(),
        }
    }
    match chain {
        Chain::BtcP2pkh | Chain::BtcBech32 => wif_compressed(&bytes),
        Chain::Tron | Chain::Xrp => hex_no_prefix(&bytes),
        _ => hex_0x(&bytes),
    }
}

/// Sample `samples` random addresses for `chain` and count, for each requested
/// prefix/suffix position, how many samples have the requested character there.
/// Returns JSON `{"p":[...],"s":[...],"n":N}`. A position whose count is 0 is
/// effectively unreachable on this chain (e.g. an out-of-range character right
/// after the fixed lead on Tron/Bitcoin), which lets the UI estimate the real
/// difficulty and flag impossible patterns instead of searching forever.
#[wasm_bindgen]
pub fn estimate(chain: &str, prefix: &str, suffix: &str, samples: u32) -> String {
    let mut s = Searcher::new(chain, "", "", false);
    let lead = s.chain.lead();

    let p: Vec<u8> = if s.chain == Chain::Evm {
        prefix.to_ascii_lowercase().into_bytes()
    } else {
        prefix.as_bytes().to_vec()
    };
    let suf: Vec<u8> = if s.chain == Chain::Evm {
        suffix.to_ascii_lowercase().into_bytes()
    } else {
        suffix.as_bytes().to_vec()
    };

    let mut pc = vec![0u32; p.len()];
    let mut sc = vec![0u32; suf.len()];

    for _ in 0..samples {
        let addr = s.match_string();
        let b = addr.as_bytes();
        for i in 0..p.len() {
            if lead + i < b.len() && b[lead + i] == p[i] {
                pc[i] += 1;
            }
        }
        let bl = b.len();
        for i in 0..suf.len() {
            if suf.len() <= bl && b[bl - suf.len() + i] == suf[i] {
                sc[i] += 1;
            }
        }
        s.advance();
    }

    let join = |v: &[u32]| v.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    format!("{{\"p\":[{}],\"s\":[{}],\"n\":{}}}", join(&pc), join(&sc), samples)
}
