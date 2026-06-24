//! secp256k1 public-key plumbing and the EVM/Tron/BTC/XRP address encoders.
//!
//! The address encoders work from raw affine coordinates (`*_xy`) so the
//! full-affine search can call them without ever materializing an `AffinePoint`
//! (k256 doesn't let us build one from coordinates). The `AffinePoint`-taking
//! wrappers below keep the non-hot-loop callers (estimate, `match_string`,
//! tests) unchanged.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldElement};
use tiny_keccak::{Hasher, Keccak};

use crate::chain::Chain;
use crate::hashes::{hash160, HEX};

pub(crate) const XRPL_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// The standard Bitcoin/Tron base58 alphabet (used by `bs58`'s default).
pub(crate) const BTC_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// --- secp256k1 public-key encodings -----------------------------------------

/// Compressed SEC1 public key (33 bytes) of the public point.
pub(crate) fn pubkey_compressed(point: &AffinePoint) -> [u8; 33] {
    let encoded = point.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Raw affine X and Y (32 bytes each) of the public point.
pub(crate) fn affine_xy_bytes(point: &AffinePoint) -> ([u8; 32], [u8; 32]) {
    let encoded = point.to_encoded_point(false);
    let b = encoded.as_bytes();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&b[1..33]);
    y.copy_from_slice(&b[33..65]);
    (x, y)
}

/// Affine X and Y as field elements (for the full-affine incremental search).
pub(crate) fn affine_xy(point: &AffinePoint) -> (FieldElement, FieldElement) {
    let (x, y) = affine_xy_bytes(point);
    (fe_from_bytes(&x), fe_from_bytes(&y))
}

/// A secp256k1 base-field element from its 32-byte big-endian encoding. The
/// inputs here are always valid curve coordinates, so the decode never fails.
pub(crate) fn fe_from_bytes(bytes: &[u8; 32]) -> FieldElement {
    FieldElement::from_bytes(&k256::FieldBytes::from(*bytes)).expect("valid field element")
}

/// Compressed SEC1 public key (33 bytes) from raw affine coordinates: the
/// `0x02`/`0x03` parity tag (from Y's low bit) followed by X.
pub(crate) fn compressed_xy(x: &[u8; 32], y: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02 | (y[31] & 1);
    out[1..].copy_from_slice(x);
    out
}

// --- per-chain address derivation -------------------------------------------

/// Address string for a secp256k1 base58/bech32 chain from raw affine
/// coordinates. Dispatches to the per-chain encoders.
pub(crate) fn secp_address_xy(chain: Chain, x: &[u8; 32], y: &[u8; 32]) -> String {
    match chain {
        Chain::Tron => {
            let digest = keccak_xy(x, y);
            let mut payload = [0u8; 21];
            payload[0] = 0x41;
            payload[1..].copy_from_slice(&digest[12..32]);
            base58check_string(&payload, BTC_ALPHABET)
        }
        Chain::BtcP2pkh => {
            let mut payload = [0u8; 21];
            payload[1..].copy_from_slice(&hash160(&compressed_xy(x, y)));
            base58check_string(&payload, BTC_ALPHABET)
        }
        Chain::Xrp => {
            let mut payload = [0u8; 21];
            payload[1..].copy_from_slice(&hash160(&compressed_xy(x, y)));
            base58check_string(&payload, XRPL_ALPHABET)
        }
        Chain::BtcBech32 => {
            let h160 = hash160(&compressed_xy(x, y));
            let hrp = bech32::Hrp::parse_unchecked("bc");
            bech32::segwit::encode_v0(hrp, &h160).expect("valid 20-byte program")
        }
        _ => unreachable!(),
    }
}

/// base58check (version-prefixed payload + double-SHA256 checksum) over a given
/// alphabet (Bitcoin/Tron default, or XRPL for XRP).
pub(crate) fn base58check_string(payload: &[u8; 21], alphabet: &[u8; 58]) -> String {
    let ab = bs58::Alphabet::new(alphabet).expect("valid alphabet");
    bs58::encode(payload).with_alphabet(&ab).with_check().into_string()
}

/// Lowercase hex Ethereum address (40 chars, no `0x`) from raw affine coords.
pub(crate) fn eth_address_hex_xy(x: &[u8; 32], y: &[u8; 32], out: &mut [u8; 40]) {
    let digest = keccak_xy(x, y);
    for (i, byte) in digest[12..32].iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
}

/// keccak256(X || Y) of the uncompressed public key.
pub(crate) fn keccak_xy(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut digest = [0u8; 32];
    keccak.update(x);
    keccak.update(y);
    keccak.finalize(&mut digest);
    digest
}

// --- AffinePoint wrappers (non-hot-loop callers) ----------------------------

pub(crate) fn secp_address(chain: Chain, point: &AffinePoint) -> String {
    let (x, y) = affine_xy_bytes(point);
    secp_address_xy(chain, &x, &y)
}

pub(crate) fn eth_address_hex(point: &AffinePoint, out: &mut [u8; 40]) {
    let (x, y) = affine_xy_bytes(point);
    eth_address_hex_xy(&x, &y, out);
}

pub(crate) fn tron_address(point: &AffinePoint) -> String {
    secp_address(Chain::Tron, point)
}

pub(crate) fn btc_p2pkh_address(point: &AffinePoint) -> String {
    secp_address(Chain::BtcP2pkh, point)
}

pub(crate) fn btc_bech32_address(point: &AffinePoint) -> String {
    secp_address(Chain::BtcBech32, point)
}

pub(crate) fn xrp_address(point: &AffinePoint) -> String {
    secp_address(Chain::Xrp, point)
}

// --- base58check prefix pre-filter ------------------------------------------

/// 21-byte base58check payload (1-byte version || 20-byte hash), *without* the
/// trailing 4-byte checksum, for the base58check secp chains. Returns `None`
/// for chains that aren't base58check (EVM hex, SegWit bech32, ed25519).
pub(crate) fn secp_payload21_xy(chain: Chain, x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 21]> {
    let mut payload = [0u8; 21];
    match chain {
        Chain::Tron => {
            let digest = keccak_xy(x, y);
            payload[0] = 0x41;
            payload[1..].copy_from_slice(&digest[12..32]);
        }
        Chain::BtcP2pkh | Chain::Xrp => {
            payload[0] = 0x00;
            payload[1..].copy_from_slice(&hash160(&compressed_xy(x, y)));
        }
        _ => return None,
    }
    Some(payload)
}

/// The leading, *checksum-independent* base58 characters of a base58check
/// address, computed without the 4-byte checksum and without any heap
/// allocation. Writes the full leading run into `out` and returns the number of
/// those characters that are guaranteed correct for the *real* address (with
/// **no false negatives**).
///
/// We encode `payload || 00 00 00 00`. The real address's number is
/// `lo + c` for some checksum `c ∈ [0, 2^32)`, so it only differs in the 4 low
/// bytes. Since `2^32 < 58^6`, adding `c` can change the 6 least-significant
/// base58 digits directly, and the carry out of digit 6 is at most 1; that
/// carry then ripples up only through a run of maximal (`alphabet[57]`) digits.
/// Every digit above where the carry stops is therefore identical to the real
/// address's, so the count we return is provably safe to compare as a prefix.
/// (A prefix hit is still re-encoded with the real checksum via `secp_address`
/// and re-checked before being returned — same belt-and-suspenders model as the
/// GPU path — so the untrusted tail can never surface a wrong address either.)
pub(crate) fn base58_safe_prefix(payload: &[u8; 21], alphabet: &[u8; 58], out: &mut [u8; 40]) -> usize {
    let mut num = [0u8; 25]; // payload (21) || zero checksum (4)
    num[..21].copy_from_slice(payload);
    let zeros = num.iter().take_while(|&&b| b == 0).count();

    // Repeated big-endian long division by 58; remainders are the base58 digit
    // *indices*, produced least-significant first.
    let mut idx = [0u8; 40];
    let mut dlen = 0usize;
    let mut begin = zeros;
    while begin < num.len() {
        let mut rem = 0u32;
        for byte in num[begin..].iter_mut() {
            let acc = (rem << 8) | (*byte as u32);
            *byte = (acc / 58) as u8;
            rem = acc % 58;
        }
        idx[dlen] = rem as u8;
        dlen += 1;
        if num[begin] == 0 {
            begin += 1;
        }
    }

    // Carry from adding the (≤ 2^32) checksum reaches at most digit 6, then
    // ripples through a run of maximal digits. Find where it provably stops.
    let mut p = 6.min(dlen); // digits [0, p) are not trusted
    while p < dlen && idx[p] == 57 {
        p += 1;
    }
    if p < dlen {
        p += 1; // the digit that absorbs the carry can also change
    }
    let trusted_digits = dlen.saturating_sub(p); // high digits, all safe

    // Emit MSD-first: structural leading zeros (always safe) then the trusted
    // high digits.
    let total_trusted = zeros + trusted_digits;
    for slot in out.iter_mut().take(zeros) {
        *slot = alphabet[0];
    }
    for j in 0..trusted_digits {
        out[zeros + j] = alphabet[idx[dlen - 1 - j] as usize];
    }
    total_trusted
}

/// WIF for a compressed-pubkey key: base58check(0x80 || key || 0x01).
pub(crate) fn wif_compressed(key: &[u8]) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0x80);
    payload.extend_from_slice(key);
    payload.push(0x01);
    bs58::encode(payload).with_check().into_string()
}
