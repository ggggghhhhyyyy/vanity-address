//! ed25519 (Solana / Sui) address and private-key encoders. (Solana's address
//! is just `bs58::encode(pubkey)`, inlined at its call sites.)

/// Sui address bytes: BLAKE2b-256(0x00 flag || ed25519 pubkey).
pub(crate) fn sui_address_bytes(pubkey: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let mut input = [0u8; 33];
    input[0] = 0x00; // Ed25519 scheme flag
    input[1..].copy_from_slice(pubkey);
    let digest = Blake2b::<U32>::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Sui private key in the `suiprivkey1…` bech32 format (flag || 32-byte seed).
pub(crate) fn sui_privkey(seed: &[u8; 32]) -> String {
    let mut data = [0u8; 33];
    data[0] = 0x00;
    data[1..].copy_from_slice(seed);
    let hrp = bech32::Hrp::parse_unchecked("suiprivkey");
    bech32::encode::<bech32::Bech32>(hrp, &data).expect("bech32 encode")
}
