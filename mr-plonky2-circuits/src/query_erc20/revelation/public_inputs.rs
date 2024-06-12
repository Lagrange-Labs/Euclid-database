use crate::types::PackedU256Target;
use std::array::from_fn as create_array;

use mrp2_utils::u256::{CircuitBuilderU256, UInt256Target};
use plonky2::{
    field::goldilocks_field::GoldilocksField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{keccak::OutputHash, types::PackedAddressTarget};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Inputs {
    BlockNumber,
    Range,
    MinBlockNumber,
    MaxBlockNumber,
    SmartContractAddress,
    UserAddress,
    MappingSlot,
    MappingSlotLength,
    BlockHeader,
    RewardsRate,
    QueryResult,
}
impl Inputs {
    const SIZES: [usize; 11] = [
        // Block number
        1,
        // Range
        1,
        // Min block number
        1,
        // Max block number
        1,
        // Smart contract address
        PackedAddressTarget::LEN,
        // User address
        PackedAddressTarget::LEN,
        // Mapping Slot
        1,
        // Mapping slot length
        1,
        // Block Header
        OutputHash::LEN,
        // result - uint256
        8,
        // reward rate - uint256
        8,
    ];

    const fn total_len() -> usize {
        Self::SIZES[0]
            + Self::SIZES[1]
            + Self::SIZES[2]
            + Self::SIZES[3]
            + Self::SIZES[4]
            + Self::SIZES[5]
            + Self::SIZES[6]
            + Self::SIZES[7]
            + Self::SIZES[8]
            + Self::SIZES[9]
            + Self::SIZES[10]
    }

    fn range(&self) -> std::ops::Range<usize> {
        let mut offset = 0;
        let me = *self as u8;
        for i in 0..me {
            offset += Self::SIZES[i as usize];
        }

        offset..offset + Self::SIZES[me as usize]
    }
}

#[derive(Clone)]
pub struct RevelationPublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}

impl<'a, T: Clone + Copy> From<&'a [T]> for RevelationPublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::total_len());
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> RevelationPublicInputs<'a, T> {
    fn block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::BlockNumber.range()]
    }
    fn range_raw(&self) -> &[T] {
        &self.inputs[Inputs::Range.range()]
    }
    fn min_block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::MinBlockNumber.range()]
    }
    fn max_block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::MaxBlockNumber.range()]
    }
    fn smart_contract_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::SmartContractAddress.range()]
    }
    fn user_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::UserAddress.range()]
    }
    fn mapping_slot_raw(&self) -> &[T] {
        &self.inputs[Inputs::MappingSlot.range()]
    }
    fn mapping_slot_length_raw(&self) -> &[T] {
        &self.inputs[Inputs::MappingSlotLength.range()]
    }
    fn block_header_raw(&self) -> &[T] {
        &self.inputs[Inputs::BlockHeader.range()]
    }
    fn query_results_raw(&self) -> &[T] {
        &self.inputs[Inputs::QueryResult.range()]
    }
    fn query_rewards_rate_raw(&self) -> &[T] {
        &self.inputs[Inputs::RewardsRate.range()]
    }
    pub const fn total_len() -> usize {
        Inputs::total_len()
    }
}

impl<'a> RevelationPublicInputs<'a, Target> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        query_block_number: Target,
        query_range: Target,
        query_min_block: Target,
        query_max_block: Target,
        query_contract_address: &PackedAddressTarget,
        query_user_address: &PackedAddressTarget,
        query_mapping_slot: Target,
        mapping_slot_length: Target,
        // the block hash of the latest block inserted at time of building the circuit
        // i.e. the one who corresponds to the block db proof being verified here.
        lpn_latest_block: OutputHash,
        query_result: UInt256Target,
        rewards_rate: UInt256Target,
    ) {
        b.register_public_input(query_block_number);
        b.register_public_input(query_range);
        b.register_public_input(query_min_block);
        b.register_public_input(query_max_block);
        query_contract_address.register_as_public_input(b);
        query_user_address.register_as_public_input(b);
        b.register_public_input(query_mapping_slot);
        b.register_public_input(mapping_slot_length);
        b.register_public_inputs(&lpn_latest_block.to_targets().arr);
        b.register_public_input_u256(&rewards_rate);
        b.register_public_input_u256(&query_result);
    }

    fn block_number(&self) -> Target {
        self.block_number_raw()[0]
    }

    pub(crate) fn range(&self) -> Target {
        self.range_raw()[0]
    }

    fn min_block_number(&self) -> Target {
        self.min_block_number_raw()[0]
    }

    fn max_block_number(&self) -> Target {
        self.max_block_number_raw()[0]
    }

    pub(crate) fn smart_contract_address(&self) -> PackedAddressTarget {
        let arr = self.smart_contract_address_raw();
        PackedAddressTarget {
            arr: create_array(|i| U32Target(arr[i])),
        }
    }

    pub(crate) fn user_address(&self) -> PackedAddressTarget {
        let arr = self.user_address_raw();
        PackedAddressTarget {
            arr: create_array(|i| U32Target(arr[i])),
        }
    }

    fn mapping_slot(&self) -> Target {
        self.mapping_slot_raw()[0]
    }

    fn mapping_slot_length(&self) -> Target {
        self.mapping_slot_length_raw()[0]
    }

    fn query_results(&self) -> &[Target] {
        self.query_results_raw()
    }
    fn query_rewards_rate(&self) -> &[Target] {
        self.query_rewards_rate_raw()
    }

    fn block_header(&self) -> OutputHash {
        OutputHash::from_array(
            self.block_header_raw()
                .iter()
                .map(|x| U32Target(*x))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<'a> RevelationPublicInputs<'a, GoldilocksField> {
    fn block_number(&self) -> GoldilocksField {
        self.block_number_raw()[0]
    }

    pub(crate) fn range(&self) -> GoldilocksField {
        self.range_raw()[0]
    }

    pub(crate) fn min_block_number(&self) -> GoldilocksField {
        self.min_block_number_raw()[0]
    }

    pub(crate) fn max_block_number(&self) -> GoldilocksField {
        self.max_block_number_raw()[0]
    }

    pub(crate) fn smart_contract_address(&self) -> &[GoldilocksField] {
        self.smart_contract_address_raw()
    }

    pub(crate) fn user_address(&self) -> &[GoldilocksField] {
        self.user_address_raw()
    }

    pub(crate) fn mapping_slot(&self) -> GoldilocksField {
        self.mapping_slot_raw()[0]
    }

    pub(crate) fn mapping_slot_length(&self) -> GoldilocksField {
        self.mapping_slot_length_raw()[0]
    }

    pub(crate) fn query_results(&self) -> &[GoldilocksField] {
        self.query_results()
    }

    pub(crate) fn rewards_rate(&self) -> &[GoldilocksField] {
        self.rewards_rate()
    }

    pub(crate) fn block_header(&self) -> &[GoldilocksField] {
        self.block_header_raw()
    }
}
