//! Chain taxonomy: the set of supported chains and their fixed-prefix shape.

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Chain {
    Evm,
    Tron,
    BtcP2pkh,
    BtcBech32,
    Solana,
    Sui,
    Xrp,
}

impl Chain {
    pub(crate) fn parse(s: &str) -> Chain {
        match s {
            "tron" => Chain::Tron,
            "btc" => Chain::BtcP2pkh,
            "btc-bech32" => Chain::BtcBech32,
            "sol" => Chain::Solana,
            "sui" => Chain::Sui,
            "xrp" => Chain::Xrp,
            _ => Chain::Evm,
        }
    }

    /// Number of leading characters that are fixed for every address on this
    /// chain (a user prefix is matched right after them).
    pub(crate) fn lead(self) -> usize {
        match self {
            Chain::Evm | Chain::Solana | Chain::Sui => 0,
            Chain::Tron | Chain::BtcP2pkh | Chain::Xrp => 1, // 'T' / '1' / 'r'
            Chain::BtcBech32 => 4,                           // 'bc1q'
        }
    }
}
