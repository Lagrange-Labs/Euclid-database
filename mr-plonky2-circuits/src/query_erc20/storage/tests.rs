use std::array;

use super::{
    inner::{InnerNodeCircuit, InnerNodeWires},
    leaf::{LeafCircuit, LeafWires, HASH_PREFIX},
    public_inputs::PublicInputs,
    CircuitInput, Parameters,
};
use crate::{
    api::ProofWithVK,
    utils::{convert_u8_slice_to_u32_fields, ToFields},
};
use ethers::prelude::{Address, U256};
use itertools::Itertools;
use mrp2_test_utils::circuit::{run_circuit, UserCircuit};
use mrp2_utils::{
    eth::left_pad32,
    types::{MAPPING_KEY_LEN, PACKED_MAPPING_KEY_LEN, PACKED_VALUE_LEN},
    utils::convert_u8_to_u32_slice,
};
use plonky2::field::types::Sample;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::{rngs::StdRng, thread_rng, Rng, RngCore, SeedableRng};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Debug)]
struct TestLeafCircuit {
    c: LeafCircuit,
}

impl UserCircuit<GoldilocksField, 2> for TestLeafCircuit {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        LeafCircuit::build(b)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.c.assign(pw, wires);
    }
}

#[derive(Clone, Debug)]
struct TestInnerNodeCircuit<'a> {
    c: InnerNodeCircuit,
    child_pi_slice: &'a [F],
}

impl<'a> UserCircuit<F, D> for TestInnerNodeCircuit<'a> {
    // Branch node wires + child public inputs
    type Wires = (InnerNodeWires, Vec<Target>);

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let inner_node_wires = InnerNodeCircuit::build(b, &PublicInputs::from_slice(&child_pi));

        (inner_node_wires, child_pi)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        self.c.assign(pw, &wires.0);

        assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
        pw.set_target_arr(&wires.1, self.child_pi_slice);
    }
}

#[test]
fn test_query_erc20_storage_leaf_circuit() {
    let mut rng = thread_rng();
    let address = Address::random();

    // Generate the base values to calculate rewards.
    // Leave the first 16-bits for the rewards rate.
    let max_total_supply = U256::MAX >> 16;
    let [value, total_supply] = [0; 2].map(|_| U256(rng.gen::<[u64; 4]>()));
    let total_supply = total_supply & max_total_supply;
    // Ensure value <= total_supply.
    let value = value & total_supply;
    assert!(value <= total_supply);
    let rewards_rate = U256::from(rng.gen::<u16>());
    // Calculate the expected result.
    let exp_query_results = rewards_rate * value / total_supply;

    let test_circuit = TestLeafCircuit {
        c: LeafCircuit {
            query_address: address,
            address,
            value,
            total_supply,
            rewards_rate,
        },
    };

    let proof = run_circuit::<_, D, C, _>(test_circuit);
    let pi = PublicInputs::<GoldilocksField>::from_slice(&proof.public_inputs);

    // Calculate the expected hash:
    // C = poseidon("LEAF" || pack_u32(address) || pack_u32(value))
    let prefix: Vec<_> = HASH_PREFIX
        .iter()
        .map(|v| GoldilocksField::from_canonical_u8(*v))
        .collect();
    let packed_address = convert_u8_slice_to_u32_fields(&address.0);
    let mut bytes = [0; 32];
    value.to_little_endian(&mut bytes);
    let packed_value = convert_u8_slice_to_u32_fields(&bytes);
    let inputs: Vec<_> = prefix
        .into_iter()
        .chain(packed_address)
        .chain(packed_value)
        .collect();
    let exp_c = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&inputs);

    assert_eq!(pi.root_hash(), exp_c);
    assert_eq!(pi.query_user_address(), address);
    assert_eq!(pi.query_results(), exp_query_results);
    assert_eq!(pi.query_rewards_rate(), rewards_rate);

    // check that the circuit fails if there is an overflow
    let value = U256::max_value();
    let rewards_rate = U256::max_value();
    let test_circuit = TestLeafCircuit {
        c: LeafCircuit {
            query_address: address,
            address,
            value,
            total_supply,
            rewards_rate,
        },
    };

    assert!(
            std::panic::catch_unwind(|| 
            run_circuit::<_, D, C, _>(test_circuit)
        ).is_err(), "leaf storage circuit didnn't catch overflow"
    );

    // check that the circuit fails if there is a division by zero
    let value = U256::one();
    let rewards_rate = U256::one();
    let total_supply = U256::zero();
    let test_circuit = TestLeafCircuit {
        c: LeafCircuit {
            query_address: address,
            address,
            value,
            total_supply,
            rewards_rate,
        },
    };

    assert!(
            std::panic::catch_unwind(|| 
            run_circuit::<_, D, C, _>(test_circuit)
        ).is_err(), "leaf storage circuit didnn't catch division by zero"
    );
}

#[test]
fn test_query_erc20_storage_inner_node_circuit() {
    let mut rng = thread_rng();
    let child_pi_slice = &rng
        .gen::<[u32; PublicInputs::<Target>::TOTAL_LEN]>()
        .to_fields();
    let unproved_hash = HashOut::from_vec(rng.gen::<[u8; NUM_HASH_OUT_ELTS]>().to_fields());
    let test_circuit = TestInnerNodeCircuit {
        c: InnerNodeCircuit {
            proved_is_right: true,
            unproved_hash,
        },
        child_pi_slice,
    };

    let proof = run_circuit::<_, D, C, _>(test_circuit);
    let [pi, child_pi] = [&proof.public_inputs, child_pi_slice]
        .map(|pi| PublicInputs::<GoldilocksField>::from_slice(pi));
    let inputs: Vec<_> = unproved_hash
        .elements
        .into_iter()
        .chain(child_pi.root_hash().elements)
        .collect();
    let exp_c = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&inputs);
    assert_eq!(pi.root_hash(), exp_c);
    assert_eq!(pi.query_user_address(), child_pi.query_user_address());
    assert_eq!(pi.query_results(), child_pi.query_results());
    assert_eq!(pi.query_rewards_rate(), child_pi.query_rewards_rate());

    let test_circuit = TestInnerNodeCircuit {
        c: InnerNodeCircuit {
            proved_is_right: false,
            unproved_hash,
        },
        child_pi_slice,
    };

    let proof = run_circuit::<_, D, C, _>(test_circuit);
    let [pi, child_pi] = [&proof.public_inputs, child_pi_slice]
        .map(|pi| PublicInputs::<GoldilocksField>::from_slice(pi));
    let inputs: Vec<_> = child_pi
        .root_hash()
        .elements
        .into_iter()
        .chain(unproved_hash.elements)
        .collect();
    let exp_c = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&inputs);
    assert_eq!(pi.root_hash(), exp_c);
    assert_eq!(pi.query_user_address(), child_pi.query_user_address());
    assert_eq!(pi.query_results(), child_pi.query_results());
    assert_eq!(pi.query_rewards_rate(), child_pi.query_rewards_rate());
}

#[test]
fn test_query_erc20_storage_api() {
    let params = Parameters::build();

    let mut rng = thread_rng();
    let address = Address::random();
    // generate U256 from u128 to be sure to avoid overflows when multiplying
    let [value, total_supply, rewards_rate] = [0; 3].map(|_| U256::from(rng.gen::<u128>()));
    let leaf = params
        .generate_proof(CircuitInput::new_leaf(
            address,
            address,
            value,
            total_supply,
            rewards_rate,
        ))
        .unwrap();
    params
        .leaf_circuit
        .circuit_data()
        .verify(ProofWithVK::deserialize(&leaf).unwrap().proof)
        .unwrap();

    let unproved_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &rng.gen::<[u8; 16]>().map(F::from_canonical_u8),
    )
    .to_bytes();
    let inner = params
        .generate_proof(CircuitInput::new_inner_node(&leaf, &unproved_hash, false))
        .unwrap();
    params
        .inner_node_circuit
        .circuit_data()
        .verify(ProofWithVK::deserialize(&inner).unwrap().proof)
        .unwrap();
}
