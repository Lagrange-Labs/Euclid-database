//! Test utilities for generating the fake block DB proof

use super::{TestContext, TestQuery};
use groth16_framework::{C, D, F};
use itertools::Itertools;
use mr_plonky2_circuits::block::{empty_merkle_root, PublicInputs, NUM_IVC_PUBLIC_INPUTS};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitData, proof::ProofWithPublicInputs,
    },
};
use std::iter::once;

impl<const BLOCK_DB_DEPTH: usize> TestContext<BLOCK_DB_DEPTH> {
    /// Generate a fake block DB proof.
    pub(crate) fn generate_block_db_proof(
        &self,
        query: &TestQuery,
    ) -> ProofWithPublicInputs<F, C, D> {
        let init_root = empty_merkle_root::<F, D, BLOCK_DB_DEPTH>();
        let last_root = HashOut {
            elements: F::rand_vec(NUM_HASH_OUT_ELTS).try_into().unwrap(),
        };
        let init_block_number = F::ONE;
        let last_block_number = F::from_canonical_u32(query.max_block_number + 1);
        let last_block_hash = query
            .block_hash
            .0
            .iter()
            .flat_map(|u| [*u as u32, (u >> 32) as u32].map(F::from_canonical_u32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let block_db_inputs: [F; NUM_IVC_PUBLIC_INPUTS] = PublicInputs::from_parts(
            &init_root.elements,
            &last_root.elements,
            init_block_number,
            last_block_number,
            &last_block_hash,
        )
        .into_iter()
        .chain(once(F::ONE))
        .collect_vec()
        .try_into()
        .unwrap();
        self.block_db_circuits
            .generate_input_proofs::<1>([block_db_inputs.clone()])
            .unwrap()[0]
            .clone()
    }
}
