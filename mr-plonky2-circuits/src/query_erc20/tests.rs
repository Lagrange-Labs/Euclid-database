use super::{
    block::{
        full_node::{FullNodeCircuit, FullNodeWires},
        partial_node::{PartialNodeCircuit, PartialNodeWires},
        BlockPublicInputs as BlockQueryPublicInputs,
    },
    revelation::{
        circuit::{RevelationCircuit, RevelationWires},
        RevelationPublicInputs,
    },
    state::tests::run_state_circuit_with_slot_and_addresses,
};
use crate::{
    block::{empty_merkle_root, public_inputs::PublicInputs as BlockDBPublicInputs},
    keccak::PACKED_HASH_LEN,
    types::MAPPING_KEY_LEN,
    utils::convert_u8_to_u32_slice,
};
use ethers::types::Address;
use itertools::Itertools;
use mrp2_test_utils::circuit::{run_circuit, UserCircuit};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Debug, Clone)]
struct FullNodeCircuitValidator<'a> {
    validated: FullNodeCircuit,
    children: &'a [BlockQueryPublicInputs<'a, F>; 2],
}

impl UserCircuit<GoldilocksField, D> for FullNodeCircuitValidator<'_> {
    type Wires = (FullNodeWires, [Vec<Target>; 2]);

    fn build(c: &mut CircuitBuilder<GoldilocksField, D>) -> Self::Wires {
        let child_inputs = [
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len()),
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len()),
        ];
        let children_io = std::array::from_fn(|i| {
            BlockQueryPublicInputs::<Target>::from(child_inputs[i].as_slice())
        });
        let wires = FullNodeCircuit::build(c, children_io);
        (wires, child_inputs)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1[0], self.children[0].inputs);
        pw.set_target_arr(&wires.1[1], self.children[1].inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct PartialNodeCircuitValidator<'a> {
    validated: PartialNodeCircuit,
    child_proof: BlockQueryPublicInputs<'a, F>,
}
impl UserCircuit<F, D> for PartialNodeCircuitValidator<'_> {
    type Wires = (PartialNodeWires, Vec<Target>);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_to_prove_pi =
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len());
        let child_to_prove_io =
            BlockQueryPublicInputs::<Target>::from(child_to_prove_pi.as_slice());
        let wires = PartialNodeCircuit::build(c, &child_to_prove_io);

        (wires, child_to_prove_pi.try_into().unwrap())
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.child_proof.inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct RevelationCircuitValidator<'a, const MAX_DEPTH: usize, const L: usize> {
    validated: RevelationCircuit<L>,
    db_proof: BlockDBPublicInputs<'a, F>,
    root_proof: BlockQueryPublicInputs<'a, F>,
}
impl<const MAX_DEPTH: usize, const L: usize> UserCircuit<F, D>
    for RevelationCircuitValidator<'_, MAX_DEPTH, L>
{
    type Wires = (RevelationWires, Vec<Target>, Vec<Target>);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let db_proof_io = c.add_virtual_targets(BlockDBPublicInputs::<Target>::TOTAL_LEN);
        let db_proof_pi = BlockDBPublicInputs::<Target>::from(db_proof_io.as_slice());

        let root_proof_io = c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len());
        let root_proof_pi = BlockQueryPublicInputs::<Target>::from(root_proof_io.as_slice());

        let wires = RevelationCircuit::<L>::build::<MAX_DEPTH>(c, db_proof_pi, root_proof_pi);
        (wires, db_proof_io, root_proof_io)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.db_proof.proof_inputs);
        pw.set_target_arr(&wires.2, self.root_proof.inputs);
        self.validated.assign(pw, &wires.0);
    }
}

const EMPTY_NFT_ID: [u8; MAPPING_KEY_LEN] = [0u8; MAPPING_KEY_LEN];

/// Builds & proves the following tree
///
/// Top-level - PartialInnerCircuit
/// ├── Middle sub-tree - FullInnerNodeCircuit
/// │   ├── LeafCircuit -
/// │   └── LeafCircuit -
/// └── Untouched sub-tree - hash == Poseidon("ernesto")
#[test]
fn test_query_erc20_main_api() {
    const L: usize = 5;
    const SLOT_LENGTH: u32 = 9;
    const MAX_DEPTH: usize = 12;
    const MAPPING_SLOT: u32 = 48372;
    const BLOCK_NUMBER: u32 = 123456;
    let smart_contract_address = Address::random();
    let user_address = Address::random();

    let left_leaf_proof_io = run_state_circuit_with_slot_and_addresses(
        BLOCK_NUMBER,
        SLOT_LENGTH,
        MAPPING_SLOT,
        smart_contract_address,
        user_address,
    );
    let right_leaf_proof_io = run_state_circuit_with_slot_and_addresses(
        BLOCK_NUMBER + 1,
        SLOT_LENGTH,
        MAPPING_SLOT,
        smart_contract_address,
        user_address,
    );

    let left_leaf_pi = BlockQueryPublicInputs::<'_, F>::from(left_leaf_proof_io.as_slice());
    let right_leaf_pi = BlockQueryPublicInputs::<'_, F>::from(right_leaf_proof_io.as_slice());

    let middle_proof = run_circuit::<F, D, C, _>(FullNodeCircuitValidator {
        validated: FullNodeCircuit {},
        children: &[left_leaf_pi.clone(), right_leaf_pi.clone()],
    });

    let proved = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"ernesto"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    );

    let top_proof = run_circuit::<F, D, C, _>(PartialNodeCircuitValidator {
        validated: PartialNodeCircuit::new(proved, false),
        child_proof: BlockQueryPublicInputs::<F>::from(middle_proof.public_inputs.as_slice()),
    });

    let root_proof =
        BlockQueryPublicInputs::<GoldilocksField>::from(top_proof.public_inputs.as_slice());

    let prev_root = empty_merkle_root::<GoldilocksField, 2, MAX_DEPTH>();
    let new_root = root_proof.root().elements;

    // we say we ran the query up to the last block generated in the block db
    let last_block = root_proof.block_number();
    // we say the first block number generated is the last block - the range - some constant
    // i.e. the database have been running for a while before
    let first_block = root_proof.block_number() - root_proof.range() - F::from_canonical_u8(34);
    // A random value for the block header
    let block_header: [F; PACKED_HASH_LEN] = std::array::from_fn(F::from_canonical_usize);

    let block_data = BlockDBPublicInputs::from_parts(
        &prev_root.elements,
        &new_root,
        first_block,
        last_block,
        &block_header,
    );
    let db_proof = BlockDBPublicInputs::<F>::from(block_data.as_slice());

    let query_min_block_number = root_proof.block_number() - root_proof.range();
    let query_max_block_number = root_proof.block_number();

    let revelation_circuit = RevelationCircuit {
        query_min_block_number: query_min_block_number.to_canonical_u64() as usize,
        query_max_block_number: query_max_block_number.to_canonical_u64() as usize,
    };

    let final_proof = run_circuit::<F, D, C, _>(RevelationCircuitValidator::<MAX_DEPTH, L> {
        validated: revelation_circuit,
        db_proof: db_proof.clone(),
        root_proof: root_proof.clone(),
    });
    let pi = RevelationPublicInputs::<_, L> {
        inputs: final_proof.public_inputs.as_slice(),
    };

    // Check the revelation public inputs.
    assert_eq!(pi.block_number(), last_block);
    assert_eq!(pi.range(), root_proof.range());
    assert_eq!(pi.min_block_number(), query_min_block_number);
    assert_eq!(pi.max_block_number(), query_max_block_number);
    assert_eq!(
        pi.smart_contract_address(),
        root_proof.smart_contract_address(),
    );
    assert_eq!(pi.user_address(), root_proof.user_address(),);
    assert_eq!(pi.mapping_slot(), root_proof.mapping_slot());
    assert_eq!(pi.mapping_slot_length(), root_proof.mapping_slot_length());
    assert_eq!(pi.block_header(), db_proof.block_header_data());
    assert_eq!(pi.rewards_rate(), root_proof.rewards_rate());
    // Check the final query result is the addition of leaves.
    assert_eq!(
        pi.query_results(),
        left_leaf_pi.query_results() + right_leaf_pi.query_results()
    );
}
