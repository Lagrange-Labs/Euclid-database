use itertools::Itertools;
use mrp2_utils::u256::CircuitBuilderU256;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::array::Array;

use super::BlockPublicInputs;

#[derive(Serialize, Deserialize)]
pub struct FullNodeWires {}

#[derive(Clone, Debug)]
pub struct FullNodeCircuit {}
impl FullNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [BlockPublicInputs<Target>; 2],
    ) -> FullNodeWires {
        let to_hash = Array::<Target, { 2 * NUM_HASH_OUT_ELTS }>::try_from(
            inputs[0]
                .root()
                .elements
                .iter()
                .copied()
                .chain(inputs[1].root().elements.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        // X[0] == X[1]
        inputs[0]
            .user_address()
            .enforce_equal(b, &inputs[1].user_address());
        // M[0] == M[1]
        b.connect(inputs[0].mapping_slot(), inputs[1].mapping_slot());
        // A[0] == A[1]
        inputs[0]
            .smart_contract_address()
            .enforce_equal(b, &inputs[1].smart_contract_address());
        // S[0] == S[1]
        b.connect(
            inputs[0].mapping_slot_length(),
            inputs[1].mapping_slot_length(),
        );

        // block_number[0] == block_number[1] - range
        let right_min = b.sub(inputs[1].block_number(), inputs[1].range());
        let left_max = inputs[0].block_number();
        b.connect(left_max, right_min);

        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));
        let new_upper_block = inputs[1].block_number();
        let new_range_length = b.add(inputs[0].range(), inputs[1].range());
        let (new_result, overflow) =
            b.add_u256(&inputs[0].query_results(), &inputs[1].query_results());
        // ensure the prover is not trying to obtain invalid results by overflowing the mul
        let _false = b._false();
        b.connect(overflow.0, _false.target);
        b.enforce_equal_u256(&inputs[0].rewards_rate(), &inputs[1].rewards_rate());

        BlockPublicInputs::<Target>::register(
            b,
            new_upper_block,
            new_range_length,
            &root,
            &inputs[0].smart_contract_address(),
            &inputs[0].user_address(),
            inputs[0].mapping_slot(),
            inputs[0].mapping_slot_length(),
            new_result,
            inputs[0].rewards_rate(),
        );

        FullNodeWires {}
    }

    pub fn assign(&self, _pw: &mut PartialWitness<GoldilocksField>, _wires: &FullNodeWires) {}
}

type F = crate::api::F;
const D: usize = crate::api::D;
const NUM_IO: usize = BlockPublicInputs::<Target>::total_len();

impl CircuitLogicWires<F, D, 2> for FullNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = FullNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 2],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let children_pi = verified_proofs
            .into_iter()
            .map(|proof| BlockPublicInputs::from(Self::public_input_targets(proof)))
            .collect_vec()
            .try_into()
            .unwrap();
        FullNodeCircuit::build(builder, children_pi)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
