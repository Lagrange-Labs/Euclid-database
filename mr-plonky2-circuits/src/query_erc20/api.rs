use super::{
    block,
    revelation::{self, circuit::RevelationRecursiveInput, num_io},
    state::{self, CircuitInputsInternal},
    storage,
};
use crate::api::{BlockDBCircuitInfo, C, D, F};
use plonky2::{
    hash::poseidon::PoseidonHash,
    plonk::{circuit_data::CircuitData, config::Hasher},
};
use recursion_framework::framework::RecursiveCircuits;
use serde::{Deserialize, Serialize};

use anyhow::Result;

/// L is the number of elements we allow to expose in the result
pub enum CircuitInput<const L: usize> {
    /// Input to be provided to generate a proof for the storage tree circuit of query-erc20
    Storage(storage::CircuitInput),
    /// Input to be provided to generate a proof for the sttate tree circuit of query-erc20
    State(state::CircuitInput),
    /// Input to be provided to generate a proof for the block DB circuit of query-erc20
    Block(block::CircuitInput),
    /// Input to be provided to generate a proof for the revelation circuit of query-erc20
    Revelation(revelation::RevelationErcInput<L>),
}

#[derive(Serialize, Deserialize)]
/// Parameters representing the circuits employed to prove query2
pub(crate) struct PublicParameters<const BLOCK_DB_DEPTH: usize, const L: usize> {
    storage: storage::Parameters,
    state: state::Parameters,
    block: block::Parameters,
    revelation: revelation::Parameters<BLOCK_DB_DEPTH, L>,
}

impl<const BLOCK_DB_DEPTH: usize, const L: usize> PublicParameters<BLOCK_DB_DEPTH, L>
where
    [(); num_io::<L>()]:,
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    /// Instantiate the circuits employed for query2, returning their corresponding parameters
    pub(crate) fn build(block_db_circuit_info: &[u8]) -> Result<Self> {
        let storage = storage::Parameters::build();
        let state = state::Parameters::build(storage.get_storage_circuit_set());
        let block = block::Parameters::build(&state);
        let block_db_info =
            BlockDBCircuitInfo::<BLOCK_DB_DEPTH>::deserialize(block_db_circuit_info)?;
        let revelation = revelation::Parameters::build(
            block.get_block_circuit_set(),
            block_db_info.get_block_db_circuit_set(),
            block_db_info.get_block_db_vk(),
        );
        Ok(Self {
            storage,
            state,
            block,
            revelation,
        })
    }
    /// Generate a proof for the circuit related to query2 specified by `input`,
    /// employing the corresponding parameters in `self`; the inputs necessary to
    /// generate the proof must be provided in the `input` data structure.
    /// The method returns the proof and a flag specifying whether the generated
    /// proof is for the revelation circuit
    pub(crate) fn generate_proof(
        &self,
        input: CircuitInput<L>,
        query_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<(Vec<u8>, bool)> {
        match input {
            CircuitInput::Storage(input) => Ok((self.storage.generate_proof(input)?, false)),
            CircuitInput::State(input) => Ok((
                self.state.generate_proof(
                    self.block.get_block_circuit_set(),
                    CircuitInputsInternal::from_circuit_input(
                        input,
                        self.storage.get_storage_circuit_set(),
                    ),
                )?,
                false,
            )),
            CircuitInput::Block(input) => Ok((self.block.generate_proof(input)?, false)),
            CircuitInput::Revelation(inputs) => Ok((
                self.revelation.generate_proof(
                    query_circuit_set,
                    RevelationRecursiveInput::new(
                        inputs,
                        self.block.get_block_circuit_set().clone(),
                    )?,
                )?,
                true,
            )),
        }
    }
    /// Circuit data for the final revelation circuit
    pub fn final_proof_circuit_data(&self) -> &CircuitData<F, C, D> {
        self.revelation.circuit_data()
    }
}
