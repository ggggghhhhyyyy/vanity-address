//! HD-wallet derivation for the mnemonic tool: BIP-44/BIP-84 paths for
//! secp256k1 chains and SLIP-0010 (hardened-only) for ed25519 chains.

use k256::{ProjectivePoint, Scalar};

use crate::chain::Chain;
use crate::hashes::hmac_sha512;
use crate::secp::pubkey_compressed;

pub(crate) fn scalar_reduce(bytes: &[u8]) -> Scalar {
    use k256::elliptic_curve::ops::Reduce;
    let mut fb = k256::FieldBytes::default();
    fb.copy_from_slice(bytes);
    <Scalar as Reduce<k256::U256>>::reduce_bytes(&fb)
}

/// The standard BIP-44/BIP-84 derivation path for a chain's first receiving
/// account (`m/{purpose}'/{coin}'/0'/0/0` for secp256k1 chains). Returns the
/// indices as `(value, hardened)` pairs, or `None` for ed25519 chains (which
/// use SLIP-0010, see [`ed25519_path`]).
pub(crate) fn secp_bip44_path(chain: Chain) -> Option<[(u32, bool); 5]> {
    // SLIP-0044 coin types. BTC SegWit uses BIP-84 (purpose 84) so wallets
    // restore a native-segwit (`bc1q…`) account; everything else uses BIP-44.
    let (purpose, coin) = match chain {
        Chain::Evm => (44, 60),
        Chain::Tron => (44, 195),
        Chain::Xrp => (44, 144),
        Chain::BtcP2pkh => (44, 0),
        Chain::BtcBech32 => (84, 0),
        Chain::Solana | Chain::Sui => return None,
    };
    Some([(purpose, true), (coin, true), (0, true), (0, false), (0, false)])
}

/// SLIP-0010 ed25519 child indices (all hardened) for Solana / Sui. `None` for
/// secp256k1 chains.
pub(crate) fn ed25519_path(chain: Chain) -> Option<&'static [u32]> {
    match chain {
        Chain::Solana => Some(&[44, 501, 0, 0]),    // m/44'/501'/0'/0' (Phantom)
        Chain::Sui => Some(&[44, 784, 0, 0, 0]),    // m/44'/784'/0'/0'/0' (Sui Wallet)
        _ => None,
    }
}

/// Human-readable derivation path shown alongside a mnemonic match.
pub(crate) fn mnemonic_path_str(chain: Chain) -> &'static str {
    match chain {
        Chain::Evm => "m/44'/60'/0'/0/0",
        Chain::Tron => "m/44'/195'/0'/0/0",
        Chain::Xrp => "m/44'/144'/0'/0/0",
        Chain::BtcP2pkh => "m/44'/0'/0'/0/0",
        Chain::BtcBech32 => "m/84'/0'/0'/0/0",
        Chain::Solana => "m/44'/501'/0'/0'",
        Chain::Sui => "m/44'/784'/0'/0'/0'",
    }
}

/// Derive a secp256k1 private scalar from a BIP-32 seed along `path`
/// (`(index, hardened)` pairs). Used for the EVM/Tron/BTC/XRP mnemonic tool.
pub(crate) fn derive_secp_scalar(seed: &[u8], path: &[(u32, bool)]) -> Scalar {
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let mut kpar = scalar_reduce(&i[0..32]);
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..64]);

    for &(idx, hardened) in path {
        let index = if hardened { idx + 0x8000_0000 } else { idx };
        let mut data = Vec::with_capacity(37);
        if hardened {
            data.push(0x00);
            data.extend_from_slice(&kpar.to_bytes());
        } else {
            let point = ProjectivePoint::GENERATOR * kpar;
            data.extend_from_slice(&pubkey_compressed(&point.to_affine()));
        }
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(&chain, &data);
        kpar = scalar_reduce(&i[0..32]) + kpar;
        chain.copy_from_slice(&i[32..64]);
    }
    kpar
}

/// Derive an ed25519 32-byte private seed from a BIP-32/39 seed using
/// SLIP-0010. Every level is hardened; `path` lists the child indices without
/// the hardened offset (e.g. `[44, 501, 0, 0]` → `m/44'/501'/0'/0'`).
pub(crate) fn derive_ed25519_seed(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let i = hmac_sha512(b"ed25519 seed", seed);
    let mut key = [0u8; 32];
    key.copy_from_slice(&i[0..32]);
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..64]);

    for &idx in path {
        let index = idx + 0x8000_0000; // SLIP-0010 ed25519 is hardened-only
        let mut data = Vec::with_capacity(37);
        data.push(0x00);
        data.extend_from_slice(&key);
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(&chain, &data);
        key.copy_from_slice(&i[0..32]);
        chain.copy_from_slice(&i[32..64]);
    }
    key
}
