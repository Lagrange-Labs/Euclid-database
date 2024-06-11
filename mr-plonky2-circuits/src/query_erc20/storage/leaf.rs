use crate::{
    array::Targetable,
    query_erc20::storage::public_inputs::PublicInputs,
    types::{PackedAddressTarget, PackedU256Target},
    utils::Packer,
};
use ethers::prelude::{Address, U256};
use plonky2::field::types::Field;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

pub(crate) const HASH_PREFIX: &[u8] = b"LEAF";

#[derive(Serialize, Deserialize)]
pub struct LeafWires {
    address: PackedAddressTarget,
    value: PackedU256Target,
    total_supply: PackedU256Target,
    reward: PackedU256Target,
}

#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub address: Address,
    pub value: U256,
    pub total_supply: U256,
    pub reward: U256,
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        let address = (&self.address.0).pack().try_into().unwrap();
        wires.address.assign_from_data(pw, &address);

        let mut bytes = [0; 32];
        [
            (self.value, &wires.value),
            (self.total_supply, &wires.total_supply),
            (self.reward, &wires.reward),
        ]
        .iter()
        .for_each(|(v, w)| {
            v.to_little_endian(&mut bytes);
            let v = bytes.pack().try_into().unwrap();

            w.assign_from_data(pw, &v);
        });
    }

    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let address = PackedAddressTarget::new(b);
        let [value, total_supply, reward] = [0; 3].map(|_| PackedU256Target::new(b));

        // C = poseidon("LEAF" || pack_u32(address) || pack_u32(value))
        let prefix: Vec<_> = HASH_PREFIX
            .iter()
            .map(|v| GoldilocksField::from_canonical_u8(*v))
            .collect();
        let prefix = b.constants(&prefix);
        let inputs = prefix
            .into_iter()
            .chain(address.arr.map(|v| v.to_target()))
            .chain(value.arr.map(|v| v.to_target()))
            .collect();
        let c = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        // V = R * value / totalSupply
        // TODO: U256 operations
        let v = PackedU256Target::new(b);

        PublicInputs::<GoldilocksField>::register(b, &c, &address, &v, &reward);

        LeafWires {
            address,
            value,
            total_supply,
            reward,
        }
    }
}

impl CircuitLogicWires<GoldilocksField, 2, 0> for LeafWires {
    type CircuitBuilderParams = ();
    type Inputs = LeafCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafCircuit::build(builder)
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
