//! Test query structs

use super::{L, QUERY_IDENTIFIER_NFT};
use ethers::types::{Address, U256};
use std::str::FromStr;

/// The query struct used to check with the plonky2 public inputs in Solidity.
#[derive(Debug)]
pub(crate) struct TestQuery {
    pub(crate) contract_address: Address,
    pub(crate) user_address: Address,
    pub(crate) client_address: Address,
    pub(crate) min_block_number: u32,
    pub(crate) max_block_number: u32,
    pub(crate) block_hash: U256,
    pub(crate) rewards_rate: U256,
    pub(crate) identifier: u8,
}

impl TestQuery {
    /// Create the test Query data.
    pub(crate) fn new() -> Self {
        Self {
            contract_address: Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd")
                .unwrap(),
            user_address: Address::from_str("0x21471c9771c39149b1e42483a785a49f3873d0a5").unwrap(),
            client_address: Address::from_str("0x21471c9771c39149b1e42483a785a49f3873d0a5")
                .unwrap(),
            min_block_number: 5594942,
            max_block_number: 5594951,
            block_hash: U256::from_little_endian(&[
                59, 29, 137, 127, 105, 222, 146, 7, 197, 154, 29, 147, 160, 158, 243, 163, 194,
                164, 70, 74, 21, 84, 190, 107, 170, 77, 180, 48, 171, 56, 194, 78,
            ]),
            rewards_rate: 2.into(),
            identifier: QUERY_IDENTIFIER_NFT,
        }
    }
}

/// Test query result
#[derive(Debug)]
pub(crate) enum TestQueryResult {
    NftIds([u32; L]),
    Erc20(U256),
}

impl TestQueryResult {
    /// Enforce the query result as expected.
    pub(crate) fn enforce_equal(&self, expected_result: &[U256]) {
        let self_result = match self {
            Self::NftIds(ids) => ids.iter().cloned().map(Into::into).collect(),
            Self::Erc20(u) => vec![*u],
        };

        assert_eq!(self_result, expected_result);
    }
}
