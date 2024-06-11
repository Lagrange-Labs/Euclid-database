use super::{
    inner::{InnerNodeCircuit, InnerNodeWires},
    leaf::{LeafCircuit, LeafWires, HASH_PREFIX},
    public_inputs::PublicInputs,
    CircuitInput, Parameters,
};
use crate::{
    api::ProofWithVK,
    eth::left_pad32,
    group_hashing::map_to_curve_point,
    storage::lpn::{intermediate_node_hash, leaf_hash_for_mapping},
    types::{MAPPING_KEY_LEN, PACKED_MAPPING_KEY_LEN, PACKED_VALUE_LEN},
    utils::{convert_u8_slice_to_u32_fields, convert_u8_to_u32_slice},
};
use ethers::prelude::{Address, U256};
use itertools::Itertools;
use mrp2_test_utils::circuit::{run_circuit, UserCircuit};
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
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rand::{thread_rng, Rng};
use std::{array::from_fn, ops::Add};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        LeafCircuit::build(b)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}

#[derive(Clone, Debug)]
struct TestInnerNodeCircuit<'a> {
    c: InnerNodeCircuit,
    child_pi: &'a [F],
}

impl<'a> UserCircuit<F, D> for TestInnerNodeCircuit<'a> {
    // Branch node wires + child public inputs
    type Wires = (InnerNodeWires, Vec<Target>);

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let inner_node_wires = InnerNodeCircuit::build(b, PublicInputs::from_slice(&child_pi));

        (inner_node_wires, child_pi)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        self.c.assign(pw, &wires.0);

        assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
        pw.set_target_arr(&wires.1, self.child_pi);
    }
}

#[test]
fn test_storage_leaf_circuit() {
    let mut rng = thread_rng();
    let address = Address::random();
    let [value, total_supply, reward] = [0; 3].map(|_| U256(rng.gen::<[u64; 4]>()));

    let circuit = LeafCircuit {
        address,
        value,
        total_supply,
        reward,
    };

    let proof = run_circuit::<_, D, C, _>(circuit);
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

    assert_eq!(pi.c(), exp_c);
    assert_eq!(pi.x(), address);
    // TODO
    // assert_eq!(pi.v(), reward * value / total_supply);
    assert_eq!(pi.r(), reward);
}

/*
#[test]
fn test_storage_inner_node_circuit() {
    let test_circuit = TestInnerNodeCircuit {
        c: InnerNodeCircuit {},
        children: &[
            PublicInputs::from(left.proof.public_inputs.as_slice()),
        ],
    };
    let middle_proof = run_circuit::<F, D, C, _>(inner);
    let middle_ios = PublicInputs::<F>::from(middle_proof.public_inputs.as_slice());
}

#[test]
fn test_storage_api() {
    let some_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"coucou"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    )
    .to_bytes();

    let params = Parameters::build();

    let leaf1 = params
        .generate_proof(CircuitInput::new_leaf(b"jean", b"michel"))
        .unwrap();
    params
        .leaf_circuit
        .circuit_data()
        .verify(ProofWithVK::deserialize(&leaf1).unwrap().proof)
        .unwrap();
    let leaf2 = params
        .generate_proof(CircuitInput::new_leaf(b"juan", b"michel"))
        .unwrap();
    params
        .leaf_circuit
        .circuit_data()
        .verify(ProofWithVK::deserialize(&leaf1).unwrap().proof)
        .unwrap();

    let partial_inner = params
        .generate_proof(CircuitInput::new_partial_node(&leaf1, &some_hash, false))
        .unwrap();
    params
        .partial_node_circuit
        .circuit_data()
        .verify(ProofWithVK::deserialize(&partial_inner).unwrap().proof)
        .unwrap();
}

fn test_leaf(k: &[u8], v: &[u8]) {
}

#[derive(Clone, Debug)]
struct PartialInnerNodeCircuitValidator<'a> {
    validated: PartialInnerNodeCircuit,
    proved_child: &'a PublicInputs<'a, F>,
}
impl<'a> UserCircuit<GoldilocksField, 2> for PartialInnerNodeCircuitValidator<'a> {
    type Wires = (PartialInnerNodeWires, Vec<Target>);

    fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let leaf_child_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let leaf_child_io = PublicInputs::from(leaf_child_pi.as_slice());

        let wires = PartialInnerNodeCircuit::build(c, &leaf_child_io);
        (wires, leaf_child_pi.try_into().unwrap())
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.validated.assign(pw, &wires.0);
        pw.set_target_arr(&wires.1, self.proved_child.inputs);
    }
}
*/
