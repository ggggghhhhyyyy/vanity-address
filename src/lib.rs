//! Offline vanity address generator core, compiled to WebAssembly.
//!
//! Supported chains:
//!   - EVM (Ethereum / Base / BNB Smart Chain / any EVM): secp256k1 + keccak256,
//!     hex address, optional EIP-55 case-sensitive matching.
//!   - Tron: secp256k1 + keccak256, base58check with 0x41 version ("T…").
//!   - Bitcoin P2PKH: secp256k1, RIPEMD160(SHA256(pubkey)), base58check ("1…").
//!   - Bitcoin SegWit (bech32 v0): same hash160, bech32 ("bc1q…").
//!   - Solana: ed25519, base58 of the 32-byte public key.
//!
//! secp256k1 chains use the incremental point-addition trick (`P += G`,
//! `k += 1`) so each candidate costs one point addition instead of a full
//! scalar multiplication. Solana derives a fresh ed25519 keypair per candidate
//! (no incremental shortcut), which is inherently slower.
//!
//! Everything runs locally: keys are generated and tested in the browser and
//! never touch a network.
//!
//! The crate is split into focused modules; this root wires them together and
//! re-exports the public (wasm-bindgen + rlib) API:
//!   - [`chain`]    — the `Chain` taxonomy.
//!   - [`hashes`]   — keccak/sha/ripemd/hmac, hex, EIP-55, matching, RNG.
//!   - [`secp`]     — secp256k1 plumbing + EVM/Tron/BTC/XRP encoders + prefilter.
//!   - [`ed25519`]  — Sui address + suiprivkey encoding.
//!   - [`hd`]       — BIP-39/BIP-32/SLIP-0010 derivation for the mnemonic tool.
//!   - [`searcher`] — the raw-key `Searcher` (full-affine hot loop) + `Found`.
//!   - [`mnemonic`] — `MnemonicSearcher` + `MnemonicFound`.
//!   - [`api`]      — the standalone exported functions.

mod api;
mod chain;
mod ed25519;
mod hashes;
mod hd;
mod mnemonic;
mod searcher;
mod secp;

#[cfg(test)]
mod tests;

pub use api::{address_of, estimate, eth_address, privkey_display};
pub use mnemonic::{MnemonicFound, MnemonicSearcher};
pub use searcher::{Found, Searcher};
