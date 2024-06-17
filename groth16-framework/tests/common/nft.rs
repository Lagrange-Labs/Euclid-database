//! Test utilities for NFT query

use super::{TestContext, TestQuery, L};
use groth16_framework::{test_utils::save_plonky2_proof_pis, C, D, F};
use mr_plonky2_circuits::{
    api::{deserialize_proof, serialize_proof, ProofWithVK},
    block::PublicInputs as BlockDbPublicInputs,
    query2::{
        block::{BlockPublicInputs, NUM_IO as NFT_NUM_IO},
        revelation::{circuit::RevelationRecursiveInput, RevelationInput},
    },
    utils::{Packer, ToFields},
};
use mrp2_utils::{
    eth::{left_pad, left_pad32},
    group_hashing,
    types::MAPPING_KEY_LEN,
};
use plonky2::{
    field::types::{Field, PrimeField64, Sample},
    hash::hash_types::HashOut,
    plonk::proof::ProofWithPublicInputs,
};

impl<const BLOCK_DB_DEPTH: usize> TestContext<BLOCK_DB_DEPTH> {
    /// Generate a fake NFT query proof.
    pub(crate) fn generate_nft_query_proof(
        &self,
        output_dir: &str,
        query: &TestQuery,
        block_db_proof: &ProofWithPublicInputs<F, C, D>,
        nft_ids: &[u32],
    ) -> Vec<u8> {
        // Generate a fake NFT query proof.
        let block_db_pi = BlockDbPublicInputs::<F>::from(&block_db_proof.public_inputs);
        let query_max_number = F::from_canonical_u32(query.max_block_number);
        let query_min_number = F::from_canonical_u32(query.min_block_number);
        let query_range =
            F::from_canonical_u32(query.max_block_number - query.min_block_number + 1);
        let query_root = HashOut {
            elements: block_db_pi.root_data().try_into().unwrap(),
        };
        let contract_address = query.contract_address;
        let user_address = query.user_address;
        let mapping_slot = F::rand();
        let length_slot = F::rand();
        let mapping_keys = test_mapping_keys(nft_ids);
        let packed_field_mks = mapping_keys
            .iter()
            .map(|x| x.pack().to_fields())
            .collect::<Vec<_>>();
        log::info!("NFT IDs to set before proving: {packed_field_mks:?}");
        let digests = packed_field_mks
            .iter()
            .map(|i| group_hashing::map_to_curve_point(i))
            .collect::<Vec<_>>();
        let single_digest = group_hashing::add_curve_point(&digests);
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
            &left_pad32(user_address.as_fixed_bytes())
                .pack()
                .to_fields()
                .try_into()
                .unwrap(),
            mapping_slot,
            length_slot,
            single_digest.to_weierstrass(),
        );
        let query_proof = self.nft_circuits.generate_input_proofs([pi]).unwrap();
        let query_vk = self.nft_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof[0].clone(), query_vk[0].clone()))
            .serialize()
            .unwrap();

        // Generate the revelation proof.
        let input = RevelationRecursiveInput::<L>::new(
            RevelationInput::new(
                mapping_keys.into_iter().map(|x| x.to_vec()).collect(),
                query_min_number.to_canonical_u64() as usize,
                query_max_number.to_canonical_u64() as usize,
                query_proof,
                serialize_proof(&block_db_proof).unwrap(),
            )
            .unwrap(),
            self.nft_circuits.get_recursive_circuit_set().clone(),
        )
        .unwrap();
        let proof = self
            .nft_params
            .generate_proof(&self.circuit_set, input)
            .unwrap();
        self.nft_params.verify_proof(proof.clone()).unwrap();

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

/// Generate the test mapping keys.
fn test_mapping_keys(nft_ids: &[u32]) -> Vec<[u8; MAPPING_KEY_LEN]> {
    (0..L)
        .map(|i| left_pad::<MAPPING_KEY_LEN>(&nft_ids[i].to_le_bytes()))
        .collect()
}
