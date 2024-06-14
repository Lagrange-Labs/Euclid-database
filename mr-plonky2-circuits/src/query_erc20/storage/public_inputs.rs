use crate::types::{PackedAddressTarget, PACKED_ADDRESS_LEN, PACKED_U256_LEN};
use crate::utils::convert_u32_fields_to_u8_vec;
use ethers::prelude::{Address, U256};
use mrp2_utils::u256::{CircuitBuilderU256, UInt256Target};
use mrp2_utils::utils::convert_u32_fields_to_u256;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array::from_fn;

/// The public inputs required for the storage proof of query ERC20
///   - C ([4]F): hash of the subtree (NUM_HASH_OUT_ELTS)
///   - X ([5]F): address of the query (H160)
///   - V ([8]F): balance / total supply (U256)
///   - R ([8]F): reward (U256)
#[derive(Debug)]
pub struct PublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}
impl<'a, T: Clone + Copy> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::TOTAL_LEN);
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> PublicInputs<'a, T> {
    pub(crate) const C_OFFSET: usize = 0;
    pub(crate) const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub(crate) const QUERY_ADDRESS_OFFSET: usize = Self::C_OFFSET + Self::C_LEN;
    pub(crate) const QUERY_ADDRESS_LEN: usize = PACKED_ADDRESS_LEN;
    pub(crate) const QUERY_RESULT_OFFSET: usize =
        Self::QUERY_ADDRESS_OFFSET + Self::QUERY_ADDRESS_LEN;
    pub(crate) const QUERY_RESULT_LEN: usize = PACKED_U256_LEN;
    pub(crate) const QUERY_REWARDS_RATE_OFFSET: usize =
        Self::QUERY_RESULT_OFFSET + Self::QUERY_RESULT_LEN;
    pub(crate) const QUERY_REWARDS_RATE_LEN: usize = PACKED_U256_LEN;

    pub const TOTAL_LEN: usize = Self::QUERY_REWARDS_RATE_OFFSET + Self::QUERY_REWARDS_RATE_LEN;

    /// Creates a representation of the public inputs from the provided slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the length of the provided slice is smaller than
    /// [Self::TOTAL_LEN].
    pub fn from_slice(arr: &'a [T]) -> Self {
        assert!(
            Self::TOTAL_LEN <= arr.len(),
            "The public inputs slice length must be equal or greater than the expected length."
        );

        Self { inputs: arr }
    }

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        c: &HashOutTarget,
        x: &PackedAddressTarget,
        value: &UInt256Target,
        reward_rate: &UInt256Target,
    ) {
        b.register_public_inputs(&c.elements);
        x.register_as_public_input(b);
        b.register_public_input_u256(value);
        b.register_public_input_u256(reward_rate);
    }

    pub(crate) fn root_hash_raw(&self) -> &[T] {
        &self.inputs[Self::C_OFFSET..Self::C_OFFSET + Self::C_LEN]
    }
    pub(crate) fn query_user_address_raw(&self) -> &[T] {
        &self.inputs
            [Self::QUERY_ADDRESS_OFFSET..Self::QUERY_ADDRESS_OFFSET + Self::QUERY_ADDRESS_LEN]
    }
    pub(crate) fn query_results_raw(&self) -> &[T] {
        &self.inputs[Self::QUERY_RESULT_OFFSET..Self::QUERY_RESULT_OFFSET + Self::QUERY_RESULT_LEN]
    }
    pub(crate) fn query_rewards_rate_raw(&self) -> &[T] {
        &self.inputs[Self::QUERY_REWARDS_RATE_OFFSET
            ..Self::QUERY_REWARDS_RATE_OFFSET + Self::QUERY_REWARDS_RATE_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn root_hash(&self) -> HashOutTarget {
        HashOutTarget::from(from_fn(|i| self.inputs[Self::C_OFFSET + i]))
    }
    pub fn query_user_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::from_array(from_fn(|i| {
            U32Target(self.inputs[Self::QUERY_ADDRESS_OFFSET + i])
        }))
    }
    pub fn query_results(&self) -> UInt256Target {
        UInt256Target::new_from_target_limbs(
            &self.inputs
                [Self::QUERY_RESULT_OFFSET..Self::QUERY_RESULT_OFFSET + Self::QUERY_RESULT_LEN],
        )
        .expect("invalid length of slice inputs")
    }
    pub fn query_rewards_rate(&self) -> UInt256Target {
        UInt256Target::new_from_target_limbs(
            &self.inputs[Self::QUERY_REWARDS_RATE_OFFSET
                ..Self::QUERY_REWARDS_RATE_OFFSET + Self::QUERY_REWARDS_RATE_LEN],
        )
        .expect("invalid length of slice inputs")
    }
}

impl<'a> PublicInputs<'a, GoldilocksField> {
    pub fn root_hash(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.root_hash_raw().to_owned())
    }
    pub fn query_user_address(&self) -> Address {
        Address::from_slice(&convert_u32_fields_to_u8_vec(self.query_user_address_raw()))
    }
    pub fn query_results(&self) -> U256 {
        convert_u32_fields_to_u256(self.query_results_raw())
    }
    pub fn query_rewards_rate(&self) -> U256 {
        convert_u32_fields_to_u256(self.query_rewards_rate_raw())
    }
}

#[cfg(test)]
mod test {
    use mrp2_utils::utils::convert_u8_slice_to_u32_fields;
    use plonky2::field::types::Field;

    use super::*;
    impl<'a> PublicInputs<'a, GoldilocksField> {
        /// Writes the parts of the public inputs into the provided target array.
        pub fn from_parts(
            root_hash: &[GoldilocksField; PublicInputs::<()>::C_LEN],
            owner: &[GoldilocksField; PublicInputs::<()>::QUERY_ADDRESS_LEN],
            value: U256,
            reward_rate: U256,
        ) -> [GoldilocksField; Self::TOTAL_LEN] {
            let mut values = [GoldilocksField::ZERO; Self::TOTAL_LEN];
            values[Self::C_OFFSET..Self::C_OFFSET + Self::C_LEN].copy_from_slice(root_hash);
            values
                [Self::QUERY_ADDRESS_OFFSET..Self::QUERY_ADDRESS_OFFSET + Self::QUERY_ADDRESS_LEN]
                .copy_from_slice(owner);
            let u256_to_fields = |a: U256| -> Vec<GoldilocksField> {
                let mut b = [0u8; 32];
                a.to_little_endian(&mut b[..]);
                convert_u8_slice_to_u32_fields(&b)
            };
            values[Self::QUERY_RESULT_OFFSET..Self::QUERY_RESULT_OFFSET + Self::QUERY_RESULT_LEN]
                .copy_from_slice(&u256_to_fields(value));
            values[Self::QUERY_REWARDS_RATE_OFFSET
                ..Self::QUERY_REWARDS_RATE_OFFSET + Self::QUERY_REWARDS_RATE_LEN]
                .copy_from_slice(&u256_to_fields(reward_rate));
            values
        }
    }
}
