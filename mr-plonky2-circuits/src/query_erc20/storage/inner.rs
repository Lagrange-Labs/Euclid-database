//! Mechanism for intermediate node, i.e. only one child proof needs to be recomputed

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};

use crate::poseidon::hash_maybe_swap;

use super::public_inputs::PublicInputs;

#[derive(Serialize, Deserialize)]
pub struct InnerNodeWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    proved_is_right: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    unproved_hash: HashOutTarget,
}

/// This circuit prove the root of the subtree made of:
///   - a child whose hash has not changes on the side defined by unproved_is_left
///   - another child whose hash has been updated.
#[derive(Clone, Debug)]
pub struct InnerNodeCircuit {
    pub proved_is_right: bool,
    pub unproved_hash: HashOut<GoldilocksField>,
}

impl InnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &PublicInputs<Target>,
    ) -> InnerNodeWires {
        let unproved_hash = b.add_virtual_hash();
        let proved_is_right = b.add_virtual_bool_target_unsafe();

        // C = if position = 0 ? poseidon(sibling_hash || p[C]) else poseidon(p[C] || sibling_hash)
        let c = hash_maybe_swap(
            b,
            &[proved.root_hash().elements, unproved_hash.elements],
            proved_is_right,
        );

        PublicInputs::<Target>::register(
            b,
            &c,
            &proved.query_user_address(),
            &proved.query_results(),
            &proved.query_rewards_rate(),
        );

        InnerNodeWires {
            unproved_hash,
            proved_is_right,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &InnerNodeWires) {
        pw.set_bool_target(wires.proved_is_right, self.proved_is_right);
        pw.set_hash_target(wires.unproved_hash, self.unproved_hash);
    }
}

impl CircuitLogicWires<GoldilocksField, 2, 1> for InnerNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = InnerNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::from_slice(Self::public_input_targets(verified_proofs[0]));
        InnerNodeCircuit::build(builder, &inputs)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
