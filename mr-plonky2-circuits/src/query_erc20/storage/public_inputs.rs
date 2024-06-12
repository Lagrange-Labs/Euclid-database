use crate::types::{PackedAddressTarget, PackedU256Target, PACKED_ADDRESS_LEN, PACKED_U256_LEN};
use crate::utils::convert_u32_fields_to_u8_vec;
use ethers::prelude::{Address, U256};
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
    pub(crate) const X_OFFSET: usize = Self::C_OFFSET + Self::C_LEN;
    pub(crate) const X_LEN: usize = PACKED_ADDRESS_LEN;
    pub(crate) const V_OFFSET: usize = Self::X_OFFSET + Self::X_LEN;
    pub(crate) const V_LEN: usize = PACKED_U256_LEN;
    pub(crate) const R_OFFSET: usize = Self::V_OFFSET + Self::V_LEN;
    pub(crate) const R_LEN: usize = PACKED_U256_LEN;

    pub const TOTAL_LEN: usize = Self::R_OFFSET + Self::R_LEN;

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
        v: &PackedU256Target,
        r: &PackedU256Target,
    ) {
        b.register_public_inputs(&c.elements);
        x.register_as_public_input(b);
        v.register_as_public_input(b);
        r.register_as_public_input(b);
    }

    pub(crate) fn c_raw(&self) -> &[T] {
        &self.inputs[Self::C_OFFSET..Self::C_OFFSET + Self::C_LEN]
    }
    pub(crate) fn x_raw(&self) -> &[T] {
        &self.inputs[Self::X_OFFSET..Self::X_OFFSET + Self::X_LEN]
    }
    pub(crate) fn v_raw(&self) -> &[T] {
        &self.inputs[Self::V_OFFSET..Self::V_OFFSET + Self::V_LEN]
    }
    pub(crate) fn r_raw(&self) -> &[T] {
        &self.inputs[Self::R_OFFSET..Self::R_OFFSET + Self::R_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn c(&self) -> HashOutTarget {
        HashOutTarget::from(from_fn(|i| self.inputs[Self::C_OFFSET + i]))
    }
    pub fn x(&self) -> PackedAddressTarget {
        PackedAddressTarget::from_array(from_fn(|i| U32Target(self.inputs[Self::X_OFFSET + i])))
    }
    pub fn v(&self) -> PackedU256Target {
        PackedU256Target::from_array(from_fn(|i| U32Target(self.inputs[Self::V_OFFSET + i])))
    }
    pub fn r(&self) -> PackedU256Target {
        PackedU256Target::from_array(from_fn(|i| U32Target(self.inputs[Self::R_OFFSET + i])))
    }
}

impl<'a> PublicInputs<'a, GoldilocksField> {
    pub fn c(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.c_raw().to_owned())
    }
    pub fn x(&self) -> Address {
        Address::from_slice(&convert_u32_fields_to_u8_vec(self.x_raw()))
    }
    pub fn v(&self) -> U256 {
        U256::from_little_endian(&convert_u32_fields_to_u8_vec(self.v_raw()))
    }
    pub fn r(&self) -> U256 {
        U256::from_little_endian(&convert_u32_fields_to_u8_vec(self.r_raw()))
    }
}
