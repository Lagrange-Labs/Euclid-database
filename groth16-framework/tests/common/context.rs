//! Test context used in the test cases

use super::L;
use groth16_framework::{compile_and_generate_assets, utils::clone_circuit_data, C, D, F};
use mr_plonky2_circuits::{
    api::WrapCircuitParams,
    block::NUM_IVC_PUBLIC_INPUTS as BLOCK_DB_NUM_IO,
    query2::{block::NUM_IO as NFT_NUM_IO, revelation::Parameters as NftParameters},
    query_erc20::{block::NUM_IO as ERC_NUM_IO, revelation::Parameters as ErcParameters},
};
use plonky2::plonk::circuit_data::CircuitData;
use recursion_framework::{
    framework::RecursiveCircuits, framework_testing::TestingRecursiveCircuits,
};

/// Test context
pub(crate) struct TestContext<const BLOCK_DB_DEPTH: usize> {
    pub(crate) block_db_circuits: TestingRecursiveCircuits<F, C, D, BLOCK_DB_NUM_IO>,
    pub(crate) erc_circuits: TestingRecursiveCircuits<F, C, D, ERC_NUM_IO>,
    pub(crate) nft_circuits: TestingRecursiveCircuits<F, C, D, NFT_NUM_IO>,
    pub(crate) erc_params: ErcParameters<BLOCK_DB_DEPTH, L>,
    pub(crate) nft_params: NftParameters<BLOCK_DB_DEPTH, L>,
    pub(crate) wrap_circuit: WrapCircuitParams<L>,
    pub(crate) circuit_set: RecursiveCircuits<F, C, D>,
}

impl<const BLOCK_DB_DEPTH: usize> TestContext<BLOCK_DB_DEPTH> {
    /// Create the test context.
    pub(crate) fn new() -> Self {
        // Generate a fake block verification key.
        let block_db_circuits = TestingRecursiveCircuits::<F, C, D, BLOCK_DB_NUM_IO>::default();
        let block_db_circuit_set = block_db_circuits.get_recursive_circuit_set();
        let block_db_vk = block_db_circuits.verifier_data_for_input_proofs::<1>()[0];

        // Generate a fake ERC20 circuit set.
        let erc_circuits = TestingRecursiveCircuits::<F, C, D, ERC_NUM_IO>::default();
        let erc_circuit_set = erc_circuits.get_recursive_circuit_set();

        // Generate a fake NFT circuit set.
        let nft_circuits = TestingRecursiveCircuits::<F, C, D, NFT_NUM_IO>::default();
        let nft_circuit_set = nft_circuits.get_recursive_circuit_set();

        // Build the parameters.
        let erc_params = ErcParameters::<BLOCK_DB_DEPTH, L>::build(
            erc_circuit_set,
            block_db_circuit_set,
            block_db_vk,
        );
        let nft_params = NftParameters::<BLOCK_DB_DEPTH, L>::build(
            nft_circuit_set,
            block_db_circuit_set,
            block_db_vk,
        );

        // Build the wrap circuit.
        let digests = vec![
            erc_params.circuit_data().verifier_only.circuit_digest,
            nft_params.circuit_data().verifier_only.circuit_digest,
        ];
        let circuit_set = RecursiveCircuits::new_from_circuit_digests(digests);
        let wrap_circuit = WrapCircuitParams::<L>::build(&circuit_set);

        Self {
            block_db_circuits,
            erc_circuits,
            nft_circuits,
            erc_params,
            nft_params,
            wrap_circuit,
            circuit_set,
        }
    }

    /// Generate the Groth16 asset files.
    pub fn generate_assets(&self, asset_dir: &str) {
        let circuit_data = clone_circuit_data(self.wrap_circuit.circuit_data()).unwrap();
        compile_and_generate_assets(circuit_data, asset_dir)
            .expect("Failed to generate the Groth16 asset files");
    }
}
