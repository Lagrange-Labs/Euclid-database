//! Test utilities for ERC20 query

use super::{TestContext, TestQuery, L};
use ethers::prelude::U256;
use groth16_framework::{test_utils::save_plonky2_proof_pis, C, D, F};
use mr_plonky2_circuits::{
    api::{deserialize_proof, serialize_proof, ProofWithVK},
    block::PublicInputs as BlockDbPublicInputs,
    query_erc20::{
        block::BlockPublicInputs, revelation::RevelationRecursiveInput, RevelationErcInput,
    },
    utils::{Packer, ToFields},
};
use mrp2_utils::utils::convert_u256_to_u32_fields;
use plonky2::{
    field::types::{Field, PrimeField64, Sample},
    hash::hash_types::HashOut,
    plonk::proof::ProofWithPublicInputs,
};

impl<const BLOCK_DB_DEPTH: usize> TestContext<BLOCK_DB_DEPTH> {
    /// Generate a fake ERC20 query proof.
    pub(crate) fn generate_erc20_query_proof(
        &self,
        output_dir: &str,
        query: &TestQuery,
        block_db_proof: &ProofWithPublicInputs<F, C, D>,
        query_result: U256,
    ) -> Vec<u8> {
        // Generate a fake ERC20 query proof.
        let block_db_pi = BlockDbPublicInputs::<F>::from(&block_db_proof.public_inputs);
        let query_max_number = block_db_pi.block_number_data() - F::ONE;
        let query_range = F::from_canonical_usize(10);
        let query_min_number = query_max_number - query_range + F::ONE;
        let query_root = HashOut {
            elements: block_db_pi.root_data().try_into().unwrap(),
        };
        let contract_address = query.contract_address;
        let user_address = query.user_address;
        let mapping_slot = F::rand();
        let length_slot = F::rand();
        let pi = BlockPublicInputs::from_parts(
            query_max_number,
            query_range,
            query_root,
            &contract_address
                .as_fixed_bytes()
                .pack()
                .to_fields()
                .try_into()
                .unwrap(),
            &user_address
                .as_fixed_bytes()
                .pack()
                .to_fields()
                .try_into()
                .unwrap(),
            mapping_slot,
            length_slot,
            &convert_u256_to_u32_fields(query_result),
            &convert_u256_to_u32_fields(query.rewards_rate),
        );
        let query_proof = self.erc_circuits.generate_input_proofs([pi]).unwrap();
        let query_vk = self.erc_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof[0].clone(), query_vk[0].clone()))
            .serialize()
            .unwrap();

        // Generate the revelation proof.
        let input = RevelationRecursiveInput::<L>::new(
            RevelationErcInput::new(
                query_min_number.to_canonical_u64() as usize,
                query_max_number.to_canonical_u64() as usize,
                query_proof,
                serialize_proof(&block_db_proof).unwrap(),
            )
            .unwrap(),
            self.erc_circuits.get_recursive_circuit_set().clone(),
        )
        .unwrap();
        let proof = self
            .erc_params
            .generate_proof(&self.circuit_set, input)
            .unwrap();
        self.erc_params.verify_proof(proof.clone()).unwrap();

        // Generate the final wrapped proof.
        let proof = ProofWithVK::deserialize(&proof).unwrap();
        let proof = self
            .wrap_circuit
            .generate_proof(&self.circuit_set, &proof)
            .unwrap();

        // Save the public inputs to a file.
        save_plonky2_proof_pis(output_dir, &deserialize_proof(&proof).unwrap());

        proof
    }
}
