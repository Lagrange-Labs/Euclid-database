use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use serde::{Deserialize, Serialize};

use crate::{
    block::{empty_merkle_root, public_inputs::PublicInputs as BlockDBPublicInputs},
    query_erc20::block::BlockPublicInputs as BlockQueryPublicInputs,
    utils::less_than,
};

use super::RevelationPublicInputs;

#[derive(Serialize, Deserialize)]
pub(crate) struct RevelationWires {
    pub min_block_number: Target,
    pub max_block_number: Target,
}

#[derive(Clone, Debug)]
pub struct RevelationCircuit<const L: usize> {
    // parameters of the query
    pub(crate) query_min_block_number: usize,
    pub(crate) query_max_block_number: usize,
}
impl<const L: usize> RevelationCircuit<L> {
    pub fn build<const MAX_DEPTH: usize>(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockDBPublicInputs<Target>,
        root_proof: BlockQueryPublicInputs<Target>,
    ) -> RevelationWires {
        // Create the empty root constant matching the given MAX_DEPTH of the Poseidon storage tree
        let empty_root = HashOutTarget::from_vec(
            empty_merkle_root::<GoldilocksField, 2, MAX_DEPTH>()
                .elements
                .into_iter()
                .map(|x| b.constant(x))
                .collect_vec(),
        );

        let query_min_block_number = b.add_virtual_target();
        let query_max_block_number = b.add_virtual_target();

        // Assert the roots of the query and the block db are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_hashes(db_proof.init_root(), empty_root);

        let computed_min_block = b.sub(root_proof.block_number(), root_proof.range());
        let min_block_in_db = db_proof.first_block_number();
        let max_block_in_db = db_proof.block_number();

        // if B_MIN < min_block_in_db -> assert min_bound == B_0
        // else -> 	assert min_bound == B_MIN
        // where B_MIN is the query paramter, B_0 is the first block inserted in db, and min_bound is
        // range looked over for our db.
        let too_small_min = less_than(b, query_min_block_number, min_block_in_db.0, 32);
        let right_side = b.select(too_small_min, min_block_in_db.0, query_min_block_number);
        b.connect(computed_min_block, right_side);

        // if B_MAX > B_i: 	assert root_proof.public_inputs[B] == B_i
        // else : assert root_proof.public_inputs[B] == B_MAX
        // where B_i is the latest block inserted in our db and B_MAX is the block parameter of the query
        let too_large_max = less_than(b, max_block_in_db.0, query_max_block_number, 32);
        let right_side = b.select(too_large_max, max_block_in_db.0, query_max_block_number);
        b.connect(root_proof.block_number(), right_side);

        RevelationPublicInputs::<Target, L>::register(
            b,
            root_proof.block_number(),
            root_proof.range(),
            query_min_block_number,
            query_max_block_number,
            &root_proof.smart_contract_address(),
            &root_proof.user_address(),
            root_proof.mapping_slot(),
            root_proof.mapping_slot_length(),
            db_proof.original_block_header(),
            root_proof.query_results(),
            root_proof.rewards_rate(),
        );

        RevelationWires {
            min_block_number: query_min_block_number,
            max_block_number: query_max_block_number,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &RevelationWires) {
        pw.set_target(
            wires.min_block_number,
            GoldilocksField::from_canonical_usize(self.query_min_block_number),
        );
        pw.set_target(
            wires.max_block_number,
            GoldilocksField::from_canonical_usize(self.query_max_block_number),
        );
    }
}
