use super::StateWires;
use crate::utils::{Packer, ToFields};
use crate::{
    array::Array,
    query_erc20::{
        block::BlockPublicInputs, storage::public_inputs::PublicInputs as StorageInputs,
    },
};
use crate::{query_erc20::state::CircuitInputsInternal, types::MAPPING_KEY_LEN};
use ethers::types::{Address, U256};
use mrp2_test_utils::circuit::{run_circuit, UserCircuit};
use mrp2_utils::eth::left_pad32;
use mrp2_utils::types::{PackedSCAddress, PACKED_ADDRESS_LEN};
use mrp2_utils::utils::convert_u8_to_u32_slice;
use plonky2::field::types::Sample;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use rand::{thread_rng, Rng, RngCore};
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use serial_test::serial;
use std::array::from_fn as create_array;
use std::iter;

type StateParameters = super::Parameters;
type StateCircuit<const MAX_DEPTH: usize> = super::StateCircuit<MAX_DEPTH, GoldilocksField>;

type C = crate::api::C;
type F = crate::api::F;
const D: usize = crate::api::D;

const MAX_DEPTH: usize = 3;
const NUM_STORAGE_INPUTS: usize = StorageInputs::<Target>::TOTAL_LEN;

#[test]
fn test_query_erc20_state_circuit() {
    let mut rng = thread_rng();
    run_state_circuit_with_slot_and_addresses(
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        Address::random(),
        Address::random(),
    );
}

#[test]
#[serial]
fn test_query_erc20_state_parameters() {
    let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_STORAGE_INPUTS>::default();

    let params = StateParameters::build(testing_framework.get_recursive_circuit_set());

    let inputs =
        generate_inputs_for_state_circuit(&testing_framework, None, None, None, None, None);

    let proof = params
        .generate_proof(testing_framework.get_recursive_circuit_set(), inputs)
        .unwrap();

    params.verify_proof(&proof).unwrap();
}

pub(crate) fn run_state_circuit_with_slot_and_addresses(
    block_number: u32,
    slot_length: u32,
    mapping_slot: u32,
    sc_address: Address,
    user_address: Address,
) -> Vec<GoldilocksField> {
    let root = create_array(|_| GoldilocksField::rand());
    let value = U256::from_dec_str("145648").unwrap();
    let rewards_rate = U256::from_dec_str("34").unwrap();
    let user_address = convert_u8_to_u32_slice(&left_pad32(user_address.as_fixed_bytes()));
    let user_address_fields: [GoldilocksField; PACKED_ADDRESS_LEN] =
        create_array(|i| GoldilocksField::from_canonical_u32(user_address[i]));

    let inputs = StorageInputs::from_parts(&root, &user_address_fields, value, rewards_rate);
    let storage_pi = StorageInputs::from_slice(&inputs);

    let circuit = TestStateCircuit::<MAX_DEPTH>::new(
        block_number,
        slot_length,
        mapping_slot,
        sc_address,
        &storage_pi,
    );
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit.clone());
    let pi = BlockPublicInputs::<'_, GoldilocksField>::from(proof.public_inputs.as_slice());
    assert_eq!(pi.block_number(), circuit.block_number);
    assert_eq!(pi.range(), GoldilocksField::ONE);
    assert_eq!(pi.root(), circuit.root);
    assert_eq!(
        pi.smart_contract_address(),
        &circuit.smart_contract_address.arr
    );
    assert_eq!(pi.user_address(), user_address_fields);
    assert_eq!(pi.mapping_slot(), circuit.mapping_slot);
    assert_eq!(pi.mapping_slot_length(), circuit.length_slot);

    proof.public_inputs.to_owned()
}

#[derive(Debug, Clone)]
pub struct TestProvenanceWires {
    storage: Vec<Target>,
    provenance: StateWires<MAX_DEPTH>,
}

#[derive(Clone, Debug)]
pub struct TestStateCircuit<const MAX_DEPTH: usize> {
    storage_values: Vec<GoldilocksField>,
    c: StateCircuit<MAX_DEPTH>,
    block_number: GoldilocksField,
    root: HashOut<GoldilocksField>,
    smart_contract_address: PackedSCAddress<GoldilocksField>,
    mapping_slot: GoldilocksField,
    length_slot: GoldilocksField,
}

impl<const MAX_DEPTH: usize> TestStateCircuit<MAX_DEPTH> {
    pub fn new(
        block_number: u32,
        length_slot: u32,
        mapping_slot: u32,
        smart_contract_address: Address,
        storage: &StorageInputs<GoldilocksField>,
    ) -> Self {
        let mut rng = thread_rng();

        let smart_contract_address =
            PackedSCAddress::try_from(smart_contract_address.as_bytes().pack().to_fields())
                .unwrap();

        let mapping_slot = GoldilocksField::from_canonical_u32(mapping_slot);
        let length_slot = GoldilocksField::from_canonical_u32(length_slot);
        let block_number = GoldilocksField::from_canonical_u32(block_number);
        let depth = GoldilocksField::from_canonical_u32(MAX_DEPTH as u32);

        let siblings: Vec<_> = (0..MAX_DEPTH)
            .map(|_| {
                let mut s = HashOut::default();
                s.elements
                    .iter_mut()
                    .for_each(|l| *l = GoldilocksField::from_canonical_u32(rng.next_u32()));
                s
            })
            .collect();

        let positions: Vec<_> = (0..MAX_DEPTH).map(|_| rng.next_u32() & 1 == 1).collect();

        let preimage: Vec<_> = smart_contract_address
            .arr
            .iter()
            .chain(iter::once(&mapping_slot))
            .chain(iter::once(&length_slot))
            .chain(storage.root_hash_raw().iter())
            .copied()
            .collect();

        let mut state_root = hash_n_to_hash_no_pad::<
            GoldilocksField,
            PoseidonPermutation<GoldilocksField>,
        >(preimage.as_slice());

        for i in 0..MAX_DEPTH {
            let (left, right) = if positions[i] {
                (siblings[i].clone(), state_root.clone())
            } else {
                (state_root.clone(), siblings[i].clone())
            };

            let mut preimage = left.elements.to_vec();
            preimage.extend_from_slice(&right.elements);

            state_root = hash_n_to_hash_no_pad::<
                GoldilocksField,
                PoseidonPermutation<GoldilocksField>,
            >(preimage.as_slice());
        }

        let mut block_hash = Array::<GoldilocksField, 8>::default();

        block_hash
            .arr
            .iter_mut()
            .for_each(|h| *h = GoldilocksField::from_canonical_u32(rng.next_u32()));

        let mut preimage = vec![block_number];
        preimage.extend_from_slice(&block_hash.arr);
        preimage.extend_from_slice(&state_root.elements);

        let block_leaf_hash = hash_n_to_hash_no_pad::<
            GoldilocksField,
            PoseidonPermutation<GoldilocksField>,
        >(preimage.as_slice());

        let c = StateCircuit::new(
            smart_contract_address.clone(),
            mapping_slot,
            length_slot,
            block_number,
            depth,
            siblings,
            positions,
            block_hash,
        );

        Self {
            storage_values: storage.inputs.to_vec(),
            c,
            block_number,
            root: block_leaf_hash,
            smart_contract_address,
            mapping_slot,
            length_slot,
        }
    }
}

impl UserCircuit<GoldilocksField, 2> for TestStateCircuit<MAX_DEPTH> {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(StorageInputs::<()>::TOTAL_LEN);
        let storage = StorageInputs::from_slice(&targets);
        let provenance = StateCircuit::<MAX_DEPTH>::build(b, &storage);

        TestProvenanceWires {
            storage: targets,
            provenance,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        wires
            .storage
            .iter()
            .zip(self.storage_values.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        self.c.assign(pw, &wires.provenance);
    }
}

pub(crate) fn generate_inputs_for_state_circuit(
    testing_framework: &TestingRecursiveCircuits<F, C, D, NUM_STORAGE_INPUTS>,
    block_number: Option<u32>,
    length_slot: Option<u32>,
    mapping_slot: Option<u32>,
    smart_contract_address: Option<Address>,
    user_address: Option<Address>,
) -> CircuitInputsInternal {
    let mut rng = thread_rng();

    let block_number = if let Some(block_number) = block_number {
        block_number
    } else {
        rng.next_u32()
    };
    let length_slot = if let Some(slot) = length_slot {
        slot
    } else {
        rng.next_u32()
    };
    let mapping_slot = if let Some(slot) = mapping_slot {
        slot
    } else {
        rng.next_u32()
    };
    let smart_contract_address = if let Some(address) = smart_contract_address {
        address
    } else {
        Address::random()
    };
    let user_address = if let Some(address) = user_address {
        address
    } else {
        Address::random()
    };
    let root = create_array(|_| GoldilocksField::rand());
    let value = U256::from_dec_str("145648").unwrap();
    let rewards_rate = U256::from_dec_str("34").unwrap();
    let user_address = convert_u8_to_u32_slice(&left_pad32(user_address.as_fixed_bytes()));
    let user_address_fields: [GoldilocksField; PACKED_ADDRESS_LEN] =
        create_array(|i| GoldilocksField::from_canonical_u32(user_address[i]));

    let storage_pi = StorageInputs::from_parts(&root, &user_address_fields, value, rewards_rate);

    let storage_proof = (
        testing_framework
            .generate_input_proofs([storage_pi.clone()])
            .unwrap()[0]
            .clone(),
        testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
    )
        .into();

    let state_circuit = TestStateCircuit::new(
        block_number,
        length_slot,
        mapping_slot,
        smart_contract_address,
        &StorageInputs::from(storage_pi.as_slice()),
    )
    .c;

    CircuitInputsInternal::new(
        state_circuit,
        storage_proof,
        testing_framework.get_recursive_circuit_set(),
    )
}
