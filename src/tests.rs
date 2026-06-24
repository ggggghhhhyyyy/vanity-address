use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::chain::Chain;
use crate::ed25519::{sui_address_bytes, sui_privkey};
use crate::hashes::{eip55, hex_no_prefix, matches};
use crate::hd::{derive_ed25519_seed, derive_secp_scalar, mnemonic_path_str, secp_bip44_path};
use crate::secp::{
    affine_xy_bytes, base58_safe_prefix, btc_bech32_address, btc_p2pkh_address, eth_address_hex,
    secp_address, secp_payload21_xy, tron_address, xrp_address, BTC_ALPHABET, XRPL_ALPHABET,
};
use crate::{address_of, estimate, eth_address, privkey_display, MnemonicSearcher, Searcher};

fn point_for(scalar: Scalar) -> AffinePoint {
    (ProjectivePoint::GENERATOR * scalar).to_affine()
}

#[test]
fn eth_known_vector() {
    let mut hex = [0u8; 40];
    eth_address_hex(&point_for(Scalar::ONE), &mut hex);
    let cased = eip55(&hex);
    assert_eq!(
        core::str::from_utf8(&cased).unwrap(),
        "7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
}

#[test]
fn btc_p2pkh_known_vector() {
    // Compressed P2PKH for private key = 1 (the generator point).
    let addr = btc_p2pkh_address(&point_for(Scalar::ONE));
    assert_eq!(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
}

#[test]
fn tron_decodes_to_eth_payload() {
    // Tron payload (after 0x41) equals the raw ETH address bytes, which we
    // already trust from eth_known_vector.
    let addr = tron_address(&point_for(Scalar::ONE));
    assert!(addr.starts_with('T'));
    let decoded = bs58::decode(&addr).with_check(None).into_vec().unwrap();
    assert_eq!(decoded[0], 0x41);
    let eth_bytes =
        hex_literal("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    assert_eq!(&decoded[1..], &eth_bytes[..]);
}

#[test]
fn xrp_decodes_to_btc_hash160() {
    // The XRP payload (after version 0x00) is the same hash160 as the
    // Bitcoin P2PKH address for the same key, which we already trust.
    let point = point_for(Scalar::ONE);
    let addr = xrp_address(&point);
    assert!(addr.starts_with('r'), "got {addr}");
    let alphabet = bs58::Alphabet::new(XRPL_ALPHABET).unwrap();
    let xrp = bs58::decode(&addr).with_alphabet(&alphabet).with_check(None).into_vec().unwrap();
    let btc = bs58::decode(btc_p2pkh_address(&point)).with_check(None).into_vec().unwrap();
    assert_eq!(xrp[0], 0x00);
    assert_eq!(&xrp[1..], &btc[1..]); // same hash160
}

#[test]
fn base58_prefilter_is_a_true_prefix_of_the_real_address() {
    // The checksum-free pre-filter must always agree with the real
    // base58check address on the characters it claims are safe (no false
    // negatives), for every base58check chain and many keys.
    for k in [1u64, 2, 3, 7, 42, 255, 12_345, 7_000_003, 999_999_999] {
        let aff = point_for(Scalar::from(k));
        let (ax, ay) = affine_xy_bytes(&aff);
        for chain in [Chain::Tron, Chain::BtcP2pkh, Chain::Xrp] {
            let alphabet = if chain == Chain::Xrp { XRPL_ALPHABET } else { BTC_ALPHABET };
            let payload = secp_payload21_xy(chain, &ax, &ay).unwrap();
            let mut buf = [0u8; 40];
            let n = base58_safe_prefix(&payload, alphabet, &mut buf);
            let real = secp_address(chain, &aff);
            // It is a genuine, non-trivial prefix (we drop ~6 tail chars to
            // the checksum, so a ~34-char address keeps well over 20).
            assert!(n >= 20, "trusted prefix too short ({n}) for {real}");
            assert!(
                real.as_bytes().starts_with(&buf[..n]),
                "prefilter {:?} is not a prefix of {real}",
                core::str::from_utf8(&buf[..n]).unwrap()
            );
        }
    }
}

#[test]
fn prefiltered_search_still_finds_known_matches() {
    // End-to-end: the prefilter fast path must not skip a real match. Search
    // for the exact prefix of the priv=1 address and confirm it is found at
    // the very first candidate (scalar = 1).
    for (chain_id, lead, real) in [
        ("tron", 1usize, tron_address(&point_for(Scalar::ONE))),
        ("btc", 1, btc_p2pkh_address(&point_for(Scalar::ONE))),
        ("xrp", 1, xrp_address(&point_for(Scalar::ONE))),
    ] {
        // 4 chars right after the fixed lead.
        let prefix = &real[lead..lead + 4];
        let mut s = Searcher::new(chain_id, prefix, "", false);
        // Pin the search to start at scalar = 1 so the known vector is first.
        s.scalar = Scalar::ONE;
        s.point = ProjectivePoint::GENERATOR;
        let found = s.run(64).expect("prefiltered search found the known match");
        assert_eq!(found.address(), real);
    }
}

#[test]
fn blake2b256_empty_vector() {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let d = Blake2b::<U32>::digest([]);
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
}

#[test]
fn sui_address_shape() {
    // RFC 8032 pubkey -> a 32-byte Sui address; private key is suiprivkey1…
    let seed = rfc8032_seed();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let addr = sui_address_bytes(&signing.verifying_key().to_bytes());
    assert_eq!(addr.len(), 32);
    assert!(sui_privkey(&seed).starts_with("suiprivkey1"));
}

#[test]
fn btc_bech32_starts_with_bc1q() {
    let addr = btc_bech32_address(&point_for(Scalar::ONE));
    assert!(addr.starts_with("bc1q"), "got {addr}");
    assert_eq!(addr.len(), 42); // P2WPKH addresses are 42 chars
}

#[test]
fn solana_ed25519_rfc8032_vector() {
    // RFC 8032 test vector 1.
    let seed = rfc8032_seed();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();
    let expected =
        hex_literal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(&pubkey[..], &expected[..]);
    // And base58 of it is a valid Solana-style address.
    let addr = bs58::encode(pubkey).into_string();
    assert!(addr.len() >= 32 && addr.len() <= 44);
}

#[test]
fn matching_respects_lead_and_suffix() {
    let addr = b"T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
    assert!(matches(addr, 1, b"9y", b"wb"));
    assert!(!matches(addr, 1, b"T9", b"wb")); // prefix is after the lead
}

#[test]
fn incremental_search_finds_prefix_consistently() {
    let mut s = Searcher::new("evm", "a", "", false);
    let f = loop {
        if let Some(f) = s.run(100_000) {
            break f;
        }
    };
    assert!(f.address().to_ascii_lowercase().starts_with("0xa"));
    assert_eq!(f.private_key().len(), 66);
}

#[test]
fn mnemonic_bip44_eth_known_vector() {
    // The canonical all-zero-entropy mnemonic and its m/44'/60'/0'/0/0 account.
    let m = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    assert!(m.to_string().starts_with("abandon abandon abandon"));
    let seed = m.to_seed("");
    let scalar = derive_secp_scalar(&seed, &secp_bip44_path(Chain::Evm).unwrap());
    let point = ProjectivePoint::GENERATOR * scalar;
    let mut hex = [0u8; 40];
    eth_address_hex(&point.to_affine(), &mut hex);
    let cased = eip55(&hex);
    assert_eq!(
        format!("0x{}", core::str::from_utf8(&cased).unwrap()),
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
}

#[test]
fn slip10_ed25519_test_vector_1() {
    // Official SLIP-0010 ed25519 test vector 1 (seed 000102…0f). Anchors the
    // hardened-only derivation used for Solana/Sui mnemonic mode.
    let seed = hex_literal("000102030405060708090a0b0c0d0e0f");
    let hx = |k: [u8; 32]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hx(derive_ed25519_seed(&seed, &[])), // master
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
    );
    assert_eq!(
        hx(derive_ed25519_seed(&seed, &[0])), // m/0'
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
    );
    assert_eq!(
        hx(derive_ed25519_seed(&seed, &[0, 1, 2, 2, 1_000_000_000])), // m/0'/1'/2'/2'/1000000000'
        "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
    );
}

#[test]
fn mnemonic_bip84_btc_segwit_known_vector() {
    // BIP-84 reference: "abandon…about" m/84'/0'/0'/0/0 first receive address.
    let m = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let seed = m.to_seed("");
    let scalar = derive_secp_scalar(&seed, &secp_bip44_path(Chain::BtcBech32).unwrap());
    let addr = btc_bech32_address(&(ProjectivePoint::GENERATOR * scalar).to_affine());
    assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

#[test]
fn mnemonic_bip44_btc_p2pkh_known_vector() {
    // "abandon…about" m/44'/0'/0'/0/0 first receive address.
    let m = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let seed = m.to_seed("");
    let scalar = derive_secp_scalar(&seed, &secp_bip44_path(Chain::BtcP2pkh).unwrap());
    let addr = btc_p2pkh_address(&(ProjectivePoint::GENERATOR * scalar).to_affine());
    assert_eq!(addr, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
}

#[test]
fn mnemonic_searcher_all_chains_shape() {
    // Empty pattern matches the first attempt; check every chain yields a
    // well-formed result (correct lead, valid 12-word phrase, real key, path).
    for (engine, lead) in [
        ("evm", "0x"),
        ("tron", "T"),
        ("btc", "1"),
        ("btc-bech32", "bc1q"),
        ("xrp", "r"),
        ("sol", ""),
        ("sui", "0x"),
    ] {
        let mut s = MnemonicSearcher::new(engine, "", "", false, 12);
        let f = s.run(1).expect("empty pattern matches immediately");
        assert!(f.address().starts_with(lead), "chain {engine}: {}", f.address());
        assert_eq!(f.mnemonic().split_whitespace().count(), 12, "chain {engine}");
        assert!(!f.private_key().is_empty(), "chain {engine}");
        assert_eq!(f.path(), mnemonic_path_str(Chain::parse(engine)), "chain {engine}");
    }
}

#[test]
fn fuzz_public_api_no_panic() {
    // Throw random/garbage inputs at every public entry point: the only
    // assertion is that nothing panics (and the test process survives).
    let mut seed = 0x1234_5678_90ab_cdefu64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let chains = ["evm", "tron", "btc", "btc-bech32", "sol", "sui", "xrp", "garbage", ""];
    let alpha = b"0123456789abcdefABCDEFxyzXYZ!T1r ";
    for _ in 0..3000 {
        let chain = chains[(next() as usize) % chains.len()];
        let mk = |n: &mut dyn FnMut() -> u64, max: usize| -> String {
            let len = (n() as usize) % max;
            (0..len).map(|_| alpha[(n() as usize) % alpha.len()] as char).collect()
        };
        let key = mk(&mut next, 80);
        let _ = address_of(chain, &key);
        let _ = privkey_display(chain, &key);
        let _ = eth_address(&key);
        let pre = mk(&mut next, 8);
        let suf = mk(&mut next, 8);
        let _ = estimate(chain, &pre, &suf, 30);
        let mut s = Searcher::new(chain, &pre, &suf, next() % 2 == 0);
        let _ = s.run(50);
    }
}

#[test]
fn fuzz_searcher_matches_address_of() {
    // For chains whose private-key display is a raw hex scalar, the address
    // a Searcher finds must re-derive identically via address_of.
    for engine in ["evm", "tron", "xrp"] {
        for _ in 0..50 {
            let mut s = Searcher::new(engine, "", "", false);
            let f = s.run(1).expect("empty pattern matches immediately");
            assert_eq!(address_of(engine, &f.private_key()), f.address(), "chain {engine}");
        }
    }
}

#[test]
fn affine_batch_loop_re_derives_for_hex_chains() {
    // Drive the *batched* full-affine loop (not just candidate 0) and confirm
    // every found address re-derives from its private key via address_of, for
    // each secp chain whose key displays as raw hex. The target prefix is
    // taken from a real address 5 steps ahead of the pinned start, so it is
    // guaranteed reachable and the loop must iterate to reach it.
    for engine in ["evm", "tron", "xrp"] {
        let start = Scalar::from(1_000_000u64);
        let target = start + Scalar::from(5u64);
        let target_addr = address_of(engine, &hex_no_prefix(&target.to_bytes()));
        // Matching is against the address body: skip "0x" (EVM) or the fixed
        // lead char ('T'/'r'). The prefix comes from a real reachable address.
        let off = if engine == "evm" { 2 } else { 1 };
        let prefix = &target_addr[off..off + 4];

        let mut s = Searcher::new(engine, prefix, "", false);
        s.scalar = start;
        s.point = ProjectivePoint::GENERATOR * start;

        let f = s.run(64).expect("match within the window");
        // The found key must re-derive to the found address through the
        // independent address_of path — proving the affine engine's
        // scalar→point→address mapping across the batched loop.
        assert_eq!(address_of(engine, &f.private_key()), f.address(), "{engine}");
        assert!(
            f.address()[off..]
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase()),
            "{engine}: {} !~ {prefix}",
            f.address()
        );
    }
}

// --- tiny hex helper for tests ---
fn hex_literal(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn rfc8032_seed() -> [u8; 32] {
    let v = hex_literal(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}
