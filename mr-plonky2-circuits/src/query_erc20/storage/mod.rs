//! The module implementing the required mechanisms for Query ERC20
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#5776936f0833485ab9c7e27dcd277c91

use anyhow::Result;
use ethers::prelude::{Address, U256};
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::api::{default_config, ProofWithVK, C, D, F};

use self::{
    inner::{InnerNodeCircuit, InnerNodeWires},
    leaf::{LeafCircuit, LeafWires},
    public_inputs::PublicInputs,
};

mod inner;
mod leaf;
pub mod public_inputs;
#[cfg(test)]
mod tests;

pub enum CircuitInput {
    Leaf(LeafCircuit),
    Inner(InnerNodeCircuit, ProofWithVK),
}

impl CircuitInput {
    pub fn new_leaf(
        address: Address,
        query_address: Address,
        value: U256,
        total_supply: U256,
        reward: U256,
    ) -> Self {
        CircuitInput::Leaf(LeafCircuit {
            query_address,
            address,
            value,
            total_supply,
            reward,
        })
    }

    pub fn new_inner_node(left: &[u8], right: &[u8], proved_is_right: bool) -> Self {
        let proof = ProofWithVK::deserialize(if proved_is_right { right } else { left })
            .expect("unable to deserialize proof");
        let unproved_hash = HashOut::from_bytes(if proved_is_right { left } else { right });

        CircuitInput::Inner(
            InnerNodeCircuit {
                proved_is_right,
                unproved_hash,
            },
            proof,
        )
    }
}

const STORAGE_CIRCUIT_SET_SIZE: usize = 2;
const NUM_IO: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    inner_node_circuit: CircuitWithUniversalVerifier<F, C, D, 1, InnerNodeWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl Parameters {
    pub fn build() -> Self {
        let config = default_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            STORAGE_CIRCUIT_SET_SIZE,
        );
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires>(());
        let inner_node_circuit = circuit_builder.build_circuit::<C, 1, InnerNodeWires>(());

        let circuit_set = vec![
            leaf_circuit.get_verifier_data().circuit_digest,
            inner_node_circuit.get_verifier_data().circuit_digest,
        ];

        Self {
            leaf_circuit,
            inner_node_circuit,
            set: RecursiveCircuits::new_from_circuit_digests(circuit_set),
        }
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf(leaf) => {
                let proof = self.set.generate_proof(&self.leaf_circuit, [], [], leaf)?;
                ProofWithVK {
                    proof,
                    vk: self.leaf_circuit.get_verifier_data().clone(),
                }
            }
            CircuitInput::Inner(inner, child) => {
                let proof = self.set.generate_proof(
                    &self.inner_node_circuit,
                    [child.proof],
                    [&child.vk],
                    inner,
                )?;

                ProofWithVK {
                    proof,
                    vk: self.inner_node_circuit.get_verifier_data().clone(),
                }
            }
        }
        .serialize()
    }

    pub(crate) fn get_storage_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }
}
