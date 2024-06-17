use mrp2_utils::array::Array;
use mrp2_utils::types::{PackedMappingKeyTarget, MAPPING_KEY_LEN, VALUE_LEN};
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
    value_bytes_be: Array<Target, VALUE_LEN>,
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
        let address = self.address.0.pack().try_into().unwrap();
        wires.address.assign_from_data(pw, &address);
        let query_address = self.query_address.0.pack().try_into().unwrap();
        wires.query_address.assign_from_data(pw, &query_address);

        let mut value_buff = [0u8; 32];
        self.value.to_big_endian(&mut value_buff[..]);
        wires.value_bytes_be.assign_bytes(pw, &value_buff);
        [
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
        let value_big_endian = Array::<Target, VALUE_LEN>::new(b);
        value_big_endian.assert_bytes(b);
        // this is what goes into the hashing structure since that's how we extract it
        let packed_be = value_big_endian.convert_u8_to_u32(b);
        // this is what goes into the u256 computation since it expects LE format
        let packed_le = value_big_endian.reverse().convert_u8_to_u32(b);
        // unwrap is safe because we exactly give 32 bytes  in packed format
        let value_u256 = UInt256Target::new_from_limbs(&packed_le.arr).unwrap();
        let [total_supply, rewards_rate] = [0; 2].map(|_| b.add_virtual_u256());

        // we left_pad the address to 8 (packed 32bytes ) as it is the
        // hashing structure expected: 32 byte for mapping key packed = 8 fields
        let zero = b.zero();
        let mut packed_key_mapping = [zero; 8];
        packed_key_mapping[3..].copy_from_slice(&address.arr.map(|v| v.to_target()));
        // C = poseidon(pack_u32(left_pad32(address)) || pack_u32(left_pad32(value)))
        let inputs = packed_key_mapping
            .into_iter()
            //.chain(<&UInt256Target as Into<Vec<Target>>>::into(&value))
            .chain(packed_be.to_targets().arr)
            .collect();
        let c = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        // V = R * value / totalSupply
        // do multiplication first then division
        let zero_u256 = b.zero_u256();
        let (op1, overflow) = b.mul_u256(&value_u256, &rewards_rate);
        // ensure the prover is not trying to obtain invalid results by overflowing the mul
        let _false = b._false();
        b.connect(overflow.target, _false.target);
        let (res, _, div_by_zero) = b.div_u256(&op1, &total_supply);
        // ensure the prover is not trying to obtain invalid results by dividing by zero
        b.connect(div_by_zero.target, _false.target);
        let are_addresses_equal = address.equals(b, &query_address);
        // only output real value if user address == query address.
        // That's a hack to allow to still have a proof when a user is not included in a block since non membership
        // proofs will be supported only in v1.
        let final_output = b.select_u256(are_addresses_equal, &res, &zero_u256);
        PublicInputs::<GoldilocksField>::register(b, &c, &address, &final_output, &rewards_rate);

        LeafWires {
            address,
            query_address,
            value_bytes_be: value_big_endian,
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
