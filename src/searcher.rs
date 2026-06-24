//! The raw-key vanity searcher: a fixed base point plus a precomputed `1G…NG`
//! table, advanced entirely in affine coordinates with one batched inversion
//! per window (the CPU hot loop). ed25519 chains derive a fresh key per attempt.

use k256::{FieldElement, ProjectivePoint, Scalar};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;
use crate::ed25519::{sui_address_bytes, sui_privkey};
use crate::hashes::{
    eip55, hex_0x, hex_no_prefix, increment, matches, push_hex, random_scalar,
    starts_and_ends_with, HEX,
};
use crate::secp::{
    affine_xy, base58_safe_prefix, btc_bech32_address, btc_p2pkh_address, eth_address_hex,
    eth_address_hex_xy, secp_address_xy, secp_payload21_xy, tron_address, wif_compressed,
    xrp_address, BTC_ALPHABET, XRPL_ALPHABET,
};

/// How many incremental candidates to normalize from projective to affine in
/// one shot. The dominant per-candidate cost used to be the field *inversion*
/// hidden inside `ProjectivePoint::to_affine` (one modular inverse each). With
/// Montgomery's batch-inversion trick (`BatchNormalize`) a whole window of
/// points shares a *single* inversion, so the per-candidate cost drops to a
/// few field multiplications. 128 captures essentially all of the saving while
/// keeping the on-stack scratch (`[ProjectivePoint; N]` + `[AffinePoint; N]`)
/// modest for the WASM stack.
const AFFINE_BATCH: usize = 128;

/// A successful match, handed back to JavaScript.
#[wasm_bindgen]
pub struct Found {
    address: String,
    private_key: String,
}

#[wasm_bindgen]
impl Found {
    /// The full address (EIP-55 checksummed and `0x`-prefixed for EVM).
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// The private key in the chain's usual import format:
    ///   EVM  -> 0x-prefixed hex
    ///   Tron -> 64-char hex
    ///   BTC  -> WIF (compressed)
    ///   Sol  -> base58 of the 64-byte secret key (seed || pubkey)
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> String {
        self.private_key.clone()
    }
}

/// Stateful vanity searcher. Construct once per worker, then call
/// [`Searcher::run`] in a loop, yielding to the event loop between batches.
#[wasm_bindgen]
pub struct Searcher {
    pub(crate) chain: Chain,
    checksum: bool,
    prefix: Vec<u8>,
    suffix: Vec<u8>,

    // secp256k1 state (EVM / Tron / BTC).
    pub(crate) point: ProjectivePoint,
    pub(crate) scalar: Scalar,
    // Precomputed affine coordinates of k·G for k = 1..=AFFINE_BATCH, used by
    // the full-affine search; empty for ed25519 chains.
    tbl_x: Vec<FieldElement>,
    tbl_y: Vec<FieldElement>,

    // ed25519 / Solana state.
    seed: [u8; 32],
}

#[wasm_bindgen]
impl Searcher {
    /// Create a searcher. `chain` is one of `evm`, `tron`, `btc`, `btc-bech32`,
    /// `sol`. `prefix`/`suffix` are validated by the caller for the chain's
    /// alphabet. `checksum` only affects EVM (EIP-55 case-sensitive matching);
    /// base58/bech32 chains are always matched case-sensitively.
    #[wasm_bindgen(constructor)]
    pub fn new(chain: &str, prefix: &str, suffix: &str, checksum: bool) -> Searcher {
        let chain = Chain::parse(chain);

        // EVM in non-checksum mode is case-insensitive; everything else is
        // matched exactly as typed.
        // Hex chains (EVM without checksum, Sui) match case-insensitively.
        let normalize = |s: &str| -> Vec<u8> {
            if (chain == Chain::Evm && !checksum) || chain == Chain::Sui {
                s.to_ascii_lowercase().into_bytes()
            } else {
                s.as_bytes().to_vec()
            }
        };

        let scalar = random_scalar();
        let point = ProjectivePoint::GENERATOR * scalar;

        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("CSPRNG unavailable");

        // Precompute 1G..NG for the full-affine search (secp chains only).
        let is_secp = matches!(
            chain,
            Chain::Evm | Chain::Tron | Chain::BtcP2pkh | Chain::BtcBech32 | Chain::Xrp
        );
        let (tbl_x, tbl_y) = if is_secp {
            let mut tx = Vec::with_capacity(AFFINE_BATCH);
            let mut ty = Vec::with_capacity(AFFINE_BATCH);
            let mut p = ProjectivePoint::GENERATOR;
            for _ in 0..AFFINE_BATCH {
                let (x, y) = affine_xy(&p.to_affine());
                tx.push(x);
                ty.push(y);
                p += ProjectivePoint::GENERATOR;
            }
            (tx, ty)
        } else {
            (Vec::new(), Vec::new())
        };

        Searcher {
            chain,
            checksum,
            prefix: normalize(prefix),
            suffix: normalize(suffix),
            point,
            scalar,
            tbl_x,
            tbl_y,
            seed,
        }
    }

    /// Try up to `iters` candidates. Returns the first match (state is left
    /// just past it) or `None`.
    pub fn run(&mut self, iters: u32) -> Option<Found> {
        match self.chain {
            Chain::Evm
            | Chain::Tron
            | Chain::BtcP2pkh
            | Chain::BtcBech32
            | Chain::Xrp => self.run_secp(iters),
            Chain::Solana => self.run_solana(iters),
            Chain::Sui => self.run_sui(iters),
        }
    }
}

impl Searcher {
    /// Unified secp256k1 search for every secp chain (EVM / Tron / BTC / SegWit
    /// / XRP). Candidates `kG, (k+1)G, …` are formed by **full-affine** point
    /// addition (profanity-style): a fixed base point `P` plus a precomputed
    /// table of `1G…NG`, so the `N` addition denominators `x_{kG} − x_P` are
    /// independent for a round and one batched inversion (Montgomery's trick)
    /// covers them all. Each candidate then costs ~3 field muls instead of the
    /// projective mixed-add (~8) + per-window `BatchNormalize`, and the last
    /// candidate `P + NG` rolls over to the next base for free. ~1.45× the
    /// addresses/sec of the old projective path on native (see
    /// `cargo run --example bench`); candidate order — and therefore results —
    /// is byte-for-byte identical (the bench asserts it).
    fn run_secp(&mut self, iters: u32) -> Option<Found> {
        let n_total = iters as usize;
        if n_total == 0 {
            return None;
        }
        let chain = self.chain;
        let alphabet = if chain == Chain::Xrp { XRPL_ALPHABET } else { BTC_ALPHABET };
        // The base58check prefix pre-filter (see `base58_safe_prefix`) only
        // applies to prefix-only searches on the base58check chains.
        let prefilter = self.suffix.is_empty()
            && !self.prefix.is_empty()
            && matches!(chain, Chain::Tron | Chain::BtcP2pkh | Chain::Xrp);

        let mut hex = [0u8; 40];
        let mut b58 = [0u8; 40];

        // Base point P (= self.scalar · G), in affine field coordinates.
        let base_aff = self.point.to_affine();
        let (mut bx, mut by) = affine_xy(&base_aff);
        let mut base_scalar = self.scalar;

        // Candidate 0 is the base itself (scalar = base_scalar).
        let (xb, yb): ([u8; 32], [u8; 32]) = (bx.to_bytes().into(), by.to_bytes().into());
        if let Some(found) =
            self.eval_xy(&xb, &yb, &base_scalar, &mut hex, &mut b58, prefilter, alphabet)
        {
            self.scalar = base_scalar;
            self.point = base_aff.into();
            return Some(found);
        }

        let zero = FieldElement::from_u64(0);
        let mut den = vec![zero; AFFINE_BATCH];
        let mut prods = vec![zero; AFFINE_BATCH];
        let mut invs = vec![zero; AFFINE_BATCH];

        let mut done = 1usize;
        while done < n_total {
            let n = (n_total - done).min(AFFINE_BATCH);

            // Addition denominators x_{kG} − x_P (independent for a fixed P).
            let mut degenerate = false;
            for k in 0..n {
                let d = (self.tbl_x[k] - bx).normalize_weak();
                if bool::from(d.normalizes_to_zero()) {
                    degenerate = true; // P = ±kG: the affine slope is undefined
                    break;
                }
                den[k] = d;
            }

            if degenerate {
                // Vanishingly rare (≈ N / 2^256). Fall back to the library for
                // this round so a zero denominator can never reach `invert`.
                for k in 0..n {
                    let s = base_scalar + Scalar::from((k + 1) as u64);
                    let aff = (ProjectivePoint::GENERATOR * s).to_affine();
                    let (fx, fy) = affine_xy(&aff);
                    let (xb, yb): ([u8; 32], [u8; 32]) = (fx.to_bytes().into(), fy.to_bytes().into());
                    if let Some(found) =
                        self.eval_xy(&xb, &yb, &s, &mut hex, &mut b58, prefilter, alphabet)
                    {
                        self.scalar = s;
                        self.point = aff.into();
                        return Some(found);
                    }
                    if k == n - 1 {
                        bx = fx;
                        by = fy;
                    }
                }
                base_scalar += Scalar::from(n as u64);
                done += n;
                continue;
            }

            // Montgomery batch inversion of den[0..n].
            let mut run = den[0];
            prods[0] = run;
            for k in 1..n {
                run = run * &den[k];
                prods[k] = run;
            }
            let mut inv = run.invert().expect("nonzero product (denominators checked)");
            for k in (1..n).rev() {
                invs[k] = inv * &prods[k - 1];
                inv = inv * &den[k];
            }
            invs[0] = inv;

            // Affine additions P + kG, all against the fixed round base (bx, by);
            // the last candidate (P + nG) becomes the next base.
            let (mut last_x, mut last_y) = (bx, by);
            for k in 0..n {
                let num = (self.tbl_y[k] - by).normalize_weak();
                let lambda = num * &invs[k];
                let xc = (lambda.square() - self.tbl_x[k] - bx).normalize();
                let yc = (lambda * &(bx - xc).normalize_weak() - by).normalize();

                let s = base_scalar + Scalar::from((k + 1) as u64);
                let (xb, yb): ([u8; 32], [u8; 32]) = (xc.to_bytes().into(), yc.to_bytes().into());
                if let Some(found) =
                    self.eval_xy(&xb, &yb, &s, &mut hex, &mut b58, prefilter, alphabet)
                {
                    self.scalar = s;
                    self.point = ProjectivePoint::GENERATOR * s;
                    return Some(found);
                }
                last_x = xc;
                last_y = yc;
            }
            bx = last_x;
            by = last_y;
            base_scalar += Scalar::from(n as u64);
            done += n;
        }

        // No hit: leave state pointing at the next, not-yet-tried candidate.
        self.scalar = base_scalar + Scalar::ONE;
        self.point = ProjectivePoint::GENERATOR * self.scalar;
        None
    }

    /// Evaluate one secp candidate given its public-point coordinates and the
    /// scalar that produced it. Returns `Some(Found)` on a pattern match.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn eval_xy(
        &self,
        x: &[u8; 32],
        y: &[u8; 32],
        scalar: &Scalar,
        hex: &mut [u8; 40],
        b58: &mut [u8; 40],
        prefilter: bool,
        alphabet: &[u8; 58],
    ) -> Option<Found> {
        if self.chain == Chain::Evm {
            eth_address_hex_xy(x, y, hex);
            let hit = if self.checksum {
                let cased = eip55(hex);
                starts_and_ends_with(&cased, &self.prefix, &self.suffix)
            } else {
                starts_and_ends_with(hex, &self.prefix, &self.suffix)
            };
            if hit {
                let display = eip55(hex);
                let mut address = String::with_capacity(42);
                address.push_str("0x");
                address.push_str(core::str::from_utf8(&display).unwrap());
                return Some(Found {
                    address,
                    private_key: hex_0x(&scalar.to_bytes()),
                });
            }
            return None;
        }

        let chain = self.chain;
        let lead = chain.lead();
        if prefilter {
            let payload = secp_payload21_xy(chain, x, y).expect("base58check chain");
            let safe = base58_safe_prefix(&payload, alphabet, b58);
            // Trust the comparison only when the whole prefix lies inside the
            // checksum-independent region; otherwise fall through to the full,
            // always-correct check rather than risk a false negative.
            if lead + self.prefix.len() <= safe && b58[lead..lead + self.prefix.len()] != self.prefix[..]
            {
                return None;
            }
        }
        let addr = secp_address_xy(chain, x, y);
        if matches(addr.as_bytes(), lead, &self.prefix, &self.suffix) {
            let key_bytes = scalar.to_bytes();
            let private_key = match chain {
                Chain::Tron | Chain::Xrp => hex_no_prefix(&key_bytes),
                Chain::BtcP2pkh | Chain::BtcBech32 => wif_compressed(&key_bytes),
                _ => unreachable!(),
            };
            return Some(Found { address: addr, private_key });
        }
        None
    }

    fn run_solana(&mut self, iters: u32) -> Option<Found> {
        use ed25519_dalek::SigningKey;
        for _ in 0..iters {
            let signing = SigningKey::from_bytes(&self.seed);
            let pubkey = signing.verifying_key().to_bytes();
            let addr = bs58::encode(pubkey).into_string();

            if matches(addr.as_bytes(), 0, &self.prefix, &self.suffix) {
                let secret = signing.to_keypair_bytes(); // seed || pubkey
                let private_key = bs58::encode(secret).into_string();
                return Some(Found { address: addr, private_key });
            }
            increment(&mut self.seed);
        }
        None
    }

    fn run_sui(&mut self, iters: u32) -> Option<Found> {
        use ed25519_dalek::SigningKey;
        let mut hex = [0u8; 64];
        for _ in 0..iters {
            let signing = SigningKey::from_bytes(&self.seed);
            let pubkey = signing.verifying_key().to_bytes();
            let addr = sui_address_bytes(&pubkey);
            for (i, byte) in addr.iter().enumerate() {
                hex[i * 2] = HEX[(byte >> 4) as usize];
                hex[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
            }

            if matches(&hex, 0, &self.prefix, &self.suffix) {
                let mut address = String::with_capacity(66);
                address.push_str("0x");
                address.push_str(core::str::from_utf8(&hex).unwrap());
                return Some(Found {
                    address,
                    private_key: sui_privkey(&self.seed),
                });
            }
            increment(&mut self.seed);
        }
        None
    }

    #[inline]
    fn advance_secp(&mut self) {
        self.point += ProjectivePoint::GENERATOR;
        self.scalar += Scalar::ONE;
    }

    /// The current candidate's matchable address string (lowercase hex without
    /// `0x` for EVM; the full encoded address otherwise).
    pub(crate) fn match_string(&self) -> String {
        match self.chain {
            Chain::Evm => {
                let mut hex = [0u8; 40];
                eth_address_hex(&self.point.to_affine(), &mut hex);
                String::from_utf8(hex.to_vec()).unwrap()
            }
            Chain::Tron => tron_address(&self.point.to_affine()),
            Chain::BtcP2pkh => btc_p2pkh_address(&self.point.to_affine()),
            Chain::BtcBech32 => btc_bech32_address(&self.point.to_affine()),
            Chain::Xrp => xrp_address(&self.point.to_affine()),
            Chain::Solana => {
                use ed25519_dalek::SigningKey;
                let s = SigningKey::from_bytes(&self.seed);
                bs58::encode(s.verifying_key().to_bytes()).into_string()
            }
            Chain::Sui => {
                use ed25519_dalek::SigningKey;
                let s = SigningKey::from_bytes(&self.seed);
                let addr = sui_address_bytes(&s.verifying_key().to_bytes());
                let mut out = String::with_capacity(64);
                push_hex(&mut out, &addr);
                out
            }
        }
    }

    pub(crate) fn advance(&mut self) {
        match self.chain {
            Chain::Solana | Chain::Sui => increment(&mut self.seed),
            _ => self.advance_secp(),
        }
    }
}
