//! Test the Groth16 proving process for the queries.

use common::{TestContext, TestQuery, TestQueryResult, L};
use ethers::{
    abi::{Contract, Token},
    types::U256,
};
use groth16_framework::{
    test_utils::test_groth16_proving_and_verification, utils::read_file, EVMVerifier,
};
use serial_test::serial;
use std::path::Path;

mod common;

/// Test block DB depth
const BLOCK_DB_DEPTH: usize = 2;

/// Test NFT IDs
const TEST_NFT_IDS: [u32; L] = [1, 2, 3, 4, 5];

/// Test ERC20 query result
const TEST_ERC20_RESULT: U256 = U256::one();

/// Test proving for the query circuit.
#[ignore] // Ignore for long running time in CI.
#[serial]
#[test]
fn test_groth16_proving_for_queries() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_queries";

    // Create the test query and context.
    let query = TestQuery::new();
    let ctx = TestContext::<BLOCK_DB_DEPTH>::new();

    // Generate the Groth16 asset files.
    ctx.generate_assets(ASSET_DIR);

    // Generate a fake block db proof.
    let block_db_proof = ctx.generate_block_db_proof(&query);

    // Generate the NFT query proof and do verification.
    let proof = ctx.generate_nft_query_proof(ASSET_DIR, &query, &block_db_proof, &TEST_NFT_IDS);
    test_groth16_proving_and_verification(ASSET_DIR, &proof);
    verify_query2_solidity_fun(ASSET_DIR, &query, TestQueryResult::NftIds(TEST_NFT_IDS));

    // Generate the ERC20 query proof and do verification.
    let proof =
        ctx.generate_erc20_query_proof(ASSET_DIR, &query, &block_db_proof, TEST_ERC20_RESULT);
    test_groth16_proving_and_verification(ASSET_DIR, &proof);
    verify_query2_solidity_fun(ASSET_DIR, &query, TestQueryResult::Erc20(TEST_ERC20_RESULT));
}

/// Verify the Query2 Solidity function.
fn verify_query2_solidity_fun(asset_dir: &str, query: &TestQuery, query_result: TestQueryResult) {
    let solidity_file_path = Path::new("test_data")
        .join("TestGroth16Verifier.sol")
        .to_string_lossy()
        .to_string();

    let contract = Contract::load(
        read_file(Path::new("test_data").join("TestGroth16Verifier.abi"))
            .unwrap()
            .as_slice(),
    )
    .expect("Failed to load the Solidity verifier contract from ABI");

    // Read the combined bytes of the full proof.
    let proof_bytes = read_file(Path::new(asset_dir).join("full_proof.bin")).unwrap();

    // Encode to a bytes32 array.
    let data = Token::Array(
        proof_bytes
            .chunks(32)
            .map(|b| {
                let u = U256::from_little_endian(b);
                println!("0x{:x}", u);
                Token::FixedBytes(b.to_vec())
            })
            .collect(),
    );

    let mut block_hash_bytes = vec![0; 32];
    query.block_hash.to_little_endian(&mut block_hash_bytes);

    let query = Token::Tuple(vec![
        Token::Address(query.contract_address),
        Token::Address(query.user_address),
        Token::Address(query.client_address),
        Token::Uint(query.min_block_number.into()),
        Token::Uint(query.max_block_number.into()),
        Token::FixedBytes(block_hash_bytes),
        Token::Uint(query.rewards_rate),
    ]);

    // Build the ABI encoded data.
    let args = vec![data, query];
    let fun = &contract.functions["processQuery"][0];
    let calldata = fun
        .encode_input(&args)
        .expect("Failed to encode the inputs of Solidity respond function");

    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    // Verify in Solidity.
    let output = verifier
        .verify(calldata)
        .expect("Failed to verify in Solidity")
        .1;

    // Parse the Solidity output.
    let output = fun
        .decode_output(&output)
        .expect("Failed to decode the Solidity output");
    let real_result = match output.as_slice() {
        [Token::Array(arr)] => arr
            .into_iter()
            .map(|token| match token {
                Token::Uint(u) => *u,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>(),
        _ => unreachable!(),
    };

    // Check the returned query result.
    query_result.enforce_equal(&real_result);
}
