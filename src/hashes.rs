//! Chain-agnostic primitives: hashes, hex encoding, the candidate counter,
//! pattern matching, the EIP-55 checksum, and the CSPRNG scalar draw.

use hmac::{Hmac, Mac};
use k256::Scalar;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use tiny_keccak::{Hasher, Keccak};

pub(crate) const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut digest = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut digest);
    digest
}

/// RIPEMD160(SHA256(data)).
pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

pub(crate) fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512>>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

pub(crate) fn hex_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    push_hex(&mut s, bytes);
    s
}

pub(crate) fn hex_no_prefix(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    push_hex(&mut s, bytes);
    s
}

pub(crate) fn push_hex(s: &mut String, bytes: &[u8]) {
    for byte in bytes {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

/// Increment a 32-byte big-endian counter in place.
pub(crate) fn increment(seed: &mut [u8; 32]) {
    for byte in seed.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            break;
        }
    }
}

/// Fixed-size EVM matcher over the 40-char hex buffer.
#[inline]
pub(crate) fn starts_and_ends_with(hex: &[u8; 40], prefix: &[u8], suffix: &[u8]) -> bool {
    matches(hex, 0, prefix, suffix)
}

/// Does `addr` have `prefix` immediately after `lead` leading chars, and end
/// with `suffix`?
#[inline]
pub(crate) fn matches(addr: &[u8], lead: usize, prefix: &[u8], suffix: &[u8]) -> bool {
    if lead + prefix.len() > addr.len() || suffix.len() > addr.len() {
        return false;
    }
    if &addr[lead..lead + prefix.len()] != prefix {
        return false;
    }
    &addr[addr.len() - suffix.len()..] == suffix
}

/// Apply the EIP-55 mixed-case checksum to a 40-char lowercase hex address.
pub(crate) fn eip55(hex: &[u8; 40]) -> [u8; 40] {
    let digest = keccak256(hex);
    let mut out = *hex;
    for (i, c) in out.iter_mut().enumerate() {
        if c.is_ascii_alphabetic() {
            let nibble = if i % 2 == 0 {
                digest[i / 2] >> 4
            } else {
                digest[i / 2] & 0x0f
            };
            if nibble >= 8 {
                *c = c.to_ascii_uppercase();
            }
        }
    }
    out
}

/// Draw a uniformly random non-zero secp256k1 scalar from the platform CSPRNG.
pub(crate) fn random_scalar() -> Scalar {
    use k256::elliptic_curve::PrimeField;
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("CSPRNG unavailable");
        let repr = k256::FieldBytes::from(bytes);
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_repr(repr)) {
            if scalar != Scalar::ZERO {
                return scalar;
            }
        }
    }
}
