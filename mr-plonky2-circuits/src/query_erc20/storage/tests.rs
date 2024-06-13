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
use rand::{thread_rng, Rng};

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
fn test_storage_leaf_circuit() {
    let mut rng = thread_rng();
    let address = Address::random();
    let [value, total_supply, reward] = [0; 3].map(|_| U256(rng.gen::<[u64; 4]>()));

    let test_circuit = TestLeafCircuit {
        c: LeafCircuit {
            address,
            value,
            total_supply,
            reward,
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

    assert_eq!(pi.c(), exp_c);
    assert_eq!(pi.x(), address);
    // TODO
    // assert_eq!(pi.v(), reward * value / total_supply);
    assert_eq!(pi.r(), reward);
}

#[test]
fn test_storage_inner_node_circuit() {
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
        .chain(child_pi.c().elements)
        .collect();
    let exp_c = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&inputs);
    assert_eq!(pi.c(), exp_c);
    assert_eq!(pi.x(), child_pi.x());
    assert_eq!(pi.v(), child_pi.v());
    assert_eq!(pi.r(), child_pi.r());

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
        .c()
        .elements
        .into_iter()
        .chain(unproved_hash.elements)
        .collect();
    let exp_c = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&inputs);
    assert_eq!(pi.c(), exp_c);
    assert_eq!(pi.x(), child_pi.x());
    assert_eq!(pi.v(), child_pi.v());
    assert_eq!(pi.r(), child_pi.r());
}

#[test]
fn test_storage_api() {
    let params = Parameters::build();

    let mut rng = thread_rng();
    let address = Address::random();
    let [value, total_supply, reward] = [0; 3].map(|_| U256(rng.gen::<[u64; 4]>()));
    let leaf = params
        .generate_proof(CircuitInput::new_leaf(address, value, total_supply, reward))
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
