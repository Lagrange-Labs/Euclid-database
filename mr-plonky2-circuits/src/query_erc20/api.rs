use super::{
    block, revelation,
    state::{self, CircuitInputsInternal},
    storage,
};
use crate::api::{BlockDBCircuitInfo, C, D, F};
use recursion_framework::framework::RecursiveCircuits;
use serde::{Deserialize, Serialize};

use anyhow::Result;
use plonky2::plonk::circuit_data::CircuitData;

/// L is the number of elements we allow to expose in the result
pub enum CircuitInput<const L: usize> {
    /// Input to be provided to generate a proof for the storage tree circuit of query2-erc20
    Storage(storage::CircuitInput),
    /// Input to be provided to generate a proof for the sttate tree circuit of query2-erc20
    State(state::CircuitInput),
    /// Input to be provided to generate a proof for the block DB circuit of query2-erc20
    Block(block::CircuitInput),
}

#[derive(Serialize, Deserialize)]
/// Parameters representing the circuits employed to prove query2
pub struct PublicParameters<const BLOCK_DB_DEPTH: usize, const L: usize> {
    storage: storage::Parameters,
    state: state::Parameters,
    block: block::Parameters,
    //revelation: revelation::Parameters<BLOCK_DB_DEPTH, L>,
}

impl<const BLOCK_DB_DEPTH: usize, const L: usize> PublicParameters<BLOCK_DB_DEPTH, L> 
{
    /// Instantiate the circuits employed for query2, returning their corresponding parameters
    pub fn build() -> Result<Self> {
        let storage = storage::Parameters::build();
        let state = state::Parameters::build(storage.get_storage_circuit_set());
        let block = block::Parameters::build(&state);
        Ok(Self {
            storage,
            state,
            block,
        })
    }
    /// Generate a proof for the circuit related to query2 specified by `input`,
    /// employing the corresponding parameters in `self`; the inputs necessary to
    /// generate the proof must be provided in the `input` data structure
    pub fn generate_proof(&self, input: CircuitInput<L>) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Storage(input) => self.storage.generate_proof(input),
            CircuitInput::State(input) => self.state.generate_proof(
                self.block.get_block_circuit_set(),
                CircuitInputsInternal::from_circuit_input(
                    input,
                    self.storage.get_storage_circuit_set(),
                ),
            ),
            CircuitInput::Block(input) => self.block.generate_proof(input),
        }
    }

    pub fn get_query_block_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        self.block.get_block_circuit_set()
    }
}
