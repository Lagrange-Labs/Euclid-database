//! Utility structs and functions used for integration tests

mod block;
mod context;
mod erc20;
mod nft;
mod query;

pub(crate) use context::TestContext;
pub(crate) use query::{TestQuery, TestQueryResult};

// Test number of NFT IDs
pub(crate) const L: usize = 5;

pub(crate) const QUERY_IDENTIFIER_NFT: u8 = 67;
pub(crate) const QUERY_IDENTIFIER_ERC20: u8 = 88;
