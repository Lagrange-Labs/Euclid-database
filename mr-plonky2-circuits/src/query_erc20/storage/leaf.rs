use mrp2_utils::u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256};

use crate::{
    array::Targetable, query_erc20::storage::public_inputs::PublicInputs,
    types::PackedAddressTarget, utils::Packer,
};
use ethers::prelude::{Address, U256};
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder,
};
use plonky2::{field::types::Field, iop::target::Target};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

pub(crate) const HASH_PREFIX: &[u8] = b"LEAF";

#[derive(Serialize, Deserialize)]
pub struct LeafWires {
    // Note this is a fix because we can't prove non membership yet in v0
    address: PackedAddressTarget,
    query_address: PackedAddressTarget,
    value: UInt256Target,
    total_supply: UInt256Target,
    rewards_rate: UInt256Target,
}

#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub address: Address,
    pub query_address: Address,
    pub value: U256,
    pub total_supply: U256,
    pub rewards_rate: U256,
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        let address = (&self.address.0).pack().try_into().unwrap();
        wires.address.assign_from_data(pw, &address);
        let query_address = (&self.query_address.0).pack().try_into().unwrap();
        wires.query_address.assign_from_data(pw, &query_address);

        [
            (self.value, &wires.value),
            (self.total_supply, &wires.total_supply),
            (self.rewards_rate, &wires.rewards_rate),
        ]
        .iter()
        .for_each(|(v, w)| pw.set_u256_target(w, *v));
    }

    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        // address of the user stored at the leaf
        let address = PackedAddressTarget::new(b);
        // address of the query we expose as public input
        let query_address = PackedAddressTarget::new(b);
        let [value, total_supply, rewards_rate] = [0; 3].map(|_| b.add_virtual_u256());

        // C = poseidon("LEAF" || pack_u32(address) || pack_u32(value))
        let prefix: Vec<_> = HASH_PREFIX
            .iter()
            .map(|v| GoldilocksField::from_canonical_u8(*v))
            .collect();
        let prefix = b.constants(&prefix);
        let inputs = prefix
            .into_iter()
            .chain(address.arr.map(|v| v.to_target()))
            .chain(<&UInt256Target as Into<Vec<Target>>>::into(&value))
            .collect();
        let c = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        // V = R * value / totalSupply
        // do multiplication first then division
        // We can't handle overflow in v0 yet so we ignore it
        let zero_u256 = b.zero_u256();
        let (op1, _) = b.mul_u256(&value, &rewards_rate);
        let (res, _, _) = b.div_u256(&op1, &total_supply);
        let are_addresses_equal = address.equals(b, &query_address);
        // only output real value if user address == query address.
        // That's a hack to allow to still have a proof when a user is not included in a block since non membership
        // proofs will be supported only in v1.
        let final_output = b.select_u256(are_addresses_equal, &res, &zero_u256);
        PublicInputs::<GoldilocksField>::register(b, &c, &address, &final_output, &rewards_rate);

        LeafWires {
            address,
            query_address,
            value,
            total_supply,
            rewards_rate,
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
