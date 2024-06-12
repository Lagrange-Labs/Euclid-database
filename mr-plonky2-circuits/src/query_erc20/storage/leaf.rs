use std::array::from_fn as create_array;

use crate::{
    array::Targetable,
    query_erc20::storage::public_inputs::PublicInputs,
    types::{PackedAddressTarget, PackedU256Target, PACKED_U256_LEN},
    utils::Packer,
};
use ethers::prelude::{Address, U256};
use plonky2::field::types::Field;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

pub(crate) const HASH_PREFIX: &[u8] = b"LEAF";

#[derive(Serialize, Deserialize)]
pub struct LeafWires {
    // Note this is a fix because we can't prove non membership yet in v0
    address: PackedAddressTarget,
    query_address: PackedAddressTarget,
    value: PackedU256Target,
    total_supply: PackedU256Target,
    reward: PackedU256Target,
}

#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub address: Address,
    pub query_address: Address,
    pub value: U256,
    pub total_supply: U256,
    pub reward: U256,
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        let address = (&self.address.0).pack().try_into().unwrap();
        wires.address.assign_from_data(pw, &address);
        let query_address = (&self.query_address.0).pack().try_into().unwrap();
        wires.query_address.assign_from_data(pw,&query_address);

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
        // address of the user stored at the leaf
        let address = PackedAddressTarget::new(b);
        // address of the query we expose as public input
        let query_address = PackedAddressTarget::new(b);
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
        let zero = b.zero();
        let fake_v = b.constants(&[GoldilocksField::ZERO; PACKED_U256_LEN]);
        let v = PackedU256Target::from(create_array(|i| U32Target(fake_v[i])));
        let null_result = PackedU256Target::from_array(create_array(|_| U32Target(zero)));
        let are_addresses_equal = address.equals(b, &query_address);
        // only output real value if user address == query address.
        // That's a hack to allow to still have a proof when a user is not included in a block since non membership
        // proofs will be supported only in v1.
        let final_output = v.select(b, are_addresses_equal, &null_result);
        PublicInputs::<GoldilocksField>::register(b, &c, &address, &final_output, &reward);

        LeafWires {
            address,
            query_address,
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
