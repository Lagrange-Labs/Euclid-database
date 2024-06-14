use itertools::Itertools;
use mrp2_utils::{
    serialization::{deserialize, serialize},
    utils::keccak256,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierOnlyCircuitData,
        config::Hasher,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, deserialize_proof, ProofWithVK, C, D, F},
    block::{
        empty_merkle_root, public_inputs::PublicInputs as BlockDBPublicInputs,
        Parameters as BlockDbParameters,
    },
    query_erc20::{
        block::BlockPublicInputs as BlockQueryPublicInputs,
        revelation::{BLOCK_DB_NUM_IO, QUERY_ERC_BLOCK_NUM_IO},
    },
    utils::less_than,
};

use super::{num_io, RevelationErcInput, RevelationPublicInputs};

#[derive(Serialize, Deserialize)]
pub(crate) struct RevelationWires {
    pub min_block_number: Target,
    pub max_block_number: Target,
}

#[derive(Clone, Debug)]
pub struct RevelationCircuit<const L: usize> {
    // parameters of the query
    pub(crate) query_min_block_number: usize,
    pub(crate) query_max_block_number: usize,
}
impl<const L: usize> RevelationCircuit<L> {
    pub fn build<const MAX_DEPTH: usize>(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockDBPublicInputs<Target>,
        root_proof: BlockQueryPublicInputs<Target>,
    ) -> RevelationWires {
        // Create the empty root constant matching the given MAX_DEPTH of the Poseidon storage tree
        let empty_root = HashOutTarget::from_vec(
            empty_merkle_root::<GoldilocksField, 2, MAX_DEPTH>()
                .elements
                .into_iter()
                .map(|x| b.constant(x))
                .collect_vec(),
        );

        let query_min_block_number = b.add_virtual_target();
        let query_max_block_number = b.add_virtual_target();

        // Assert the roots of the query and the block db are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_hashes(db_proof.init_root(), empty_root);

        let one = b.one();
        let computed_min_block = b.sub(root_proof.block_number(), root_proof.range());
        let computed_min_block = b.add(computed_min_block, one);
        let min_block_in_db = db_proof.first_block_number();
        let max_block_in_db = db_proof.block_number();

        // if B_MIN < min_block_in_db -> assert min_bound == B_0
        // else -> 	assert min_bound == B_MIN
        // where B_MIN is the query paramter, B_0 is the first block inserted in db, and min_bound is
        // range looked over for our db.
        let too_small_min = less_than(b, query_min_block_number, min_block_in_db.0, 32);
        let right_side = b.select(too_small_min, min_block_in_db.0, query_min_block_number);
        b.connect(computed_min_block, right_side);

        // if B_MAX > B_i: 	assert root_proof.public_inputs[B] == B_i
        // else : assert root_proof.public_inputs[B] == B_MAX
        // where B_i is the latest block inserted in our db and B_MAX is the block parameter of the query
        let too_large_max = less_than(b, max_block_in_db.0, query_max_block_number, 32);
        let right_side = b.select(too_large_max, max_block_in_db.0, query_max_block_number);
        b.connect(root_proof.block_number(), right_side);

        RevelationPublicInputs::<Target, L>::register(
            b,
            root_proof.block_number(),
            root_proof.range(),
            query_min_block_number,
            query_max_block_number,
            &root_proof.smart_contract_address(),
            &root_proof.user_address(),
            root_proof.mapping_slot(),
            root_proof.mapping_slot_length(),
            db_proof.original_block_header(),
            root_proof.query_results(),
            root_proof.rewards_rate(),
        );

        RevelationWires {
            min_block_number: query_min_block_number,
            max_block_number: query_max_block_number,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &RevelationWires) {
        pw.set_target(
            wires.min_block_number,
            GoldilocksField::from_canonical_usize(self.query_min_block_number),
        );
        pw.set_target(
            wires.max_block_number,
            GoldilocksField::from_canonical_usize(self.query_max_block_number),
        );
    }
}

pub struct BuilderParams {
    query_circuits: RecursiveCircuits<F, C, D>,
    block_db_circuits: RecursiveCircuits<F, C, D>,
    block_db_verifier_data: VerifierOnlyCircuitData<C, D>,
}

impl BuilderParams {
    pub(crate) fn new(
        query_circuits: RecursiveCircuits<F, C, D>,
        block_db_circuits: RecursiveCircuits<F, C, D>,
        block_db_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        Self {
            query_circuits,
            block_db_circuits,
            block_db_verifier_data,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct RevelationRecursiveWires<const BLOCK_DB_DEPTH: usize, const L: usize> {
    revelation_wires: RevelationWires,
    query_block_wires: RecursiveCircuitsVerifierTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    block_db_wires: ProofWithPublicInputsTarget<D>,
}

/// Circuit inputs for the revelation step which contains the
/// raw witnesses and the proof to verify in circuit.
/// The proof is any of the proofs contained in the `query2/block/` module.
pub struct RevelationRecursiveInput<const L: usize> {
    inputs: RevelationErcInput<L>,
    /// Set of circuits for query block proofs
    query_block_circuit_set: RecursiveCircuits<F, C, D>,
}

impl<const L: usize> RevelationRecursiveInput<L> {
    pub(crate) fn new(
        inputs: RevelationErcInput<L>,
        query_block_circuit_set: RecursiveCircuits<F, C, D>,
    ) -> anyhow::Result<RevelationRecursiveInput<L>> {
        Ok(RevelationRecursiveInput {
            inputs,
            query_block_circuit_set,
        })
    }
}

pub(crate) const fn revelation_num_io<const L: usize>() -> usize {
    RevelationPublicInputs::<Target, L>::total_len()
}

impl<const BLOCK_DB_DEPTH: usize, const L: usize> CircuitLogicWires<F, D, 0>
    for RevelationRecursiveWires<BLOCK_DB_DEPTH, L>
where
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    type CircuitBuilderParams = BuilderParams;

    type Inputs = RevelationRecursiveInput<L>;

    const NUM_PUBLIC_INPUTS: usize = num_io::<L>();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // instantiate the wires to verify a query2/block proof which can be in a circuit set
        let query_block_verifier_gadget =
            RecursiveCircuitsVerifierGagdet::<F, C, D, QUERY_ERC_BLOCK_NUM_IO>::new(
                default_config(),
                &builder_parameters.query_circuits,
            );
        let query_block_verifier_wires =
            query_block_verifier_gadget.verify_proof_in_circuit_set(builder);
        let query_block_pi = BlockQueryPublicInputs::<Target>::from(
            query_block_verifier_wires.get_public_input_targets::<F, QUERY_ERC_BLOCK_NUM_IO>(),
        );

        assert_eq!(query_block_pi.inputs.len(), QUERY_ERC_BLOCK_NUM_IO);
        // instantiate the wires to verify a block db proof
        let block_db_verifier_gadget =
            RecursiveCircuitsVerifierGagdet::<F, C, D, BLOCK_DB_NUM_IO>::new(
                default_config(),
                &builder_parameters.block_db_circuits,
            );
        // we enforce that the db proof is generated with the IVC circuit, not the dummy one
        let block_db_wires = block_db_verifier_gadget.verify_proof_fixed_circuit_in_circuit_set(
            builder,
            &builder_parameters.block_db_verifier_data,
        );
        let block_db_pi = BlockDBPublicInputs::from(
            BlockDbParameters::<BLOCK_DB_DEPTH>::block_tree_public_input_targets(&block_db_wires),
        );

        let revelation_wires =
            RevelationCircuit::<L>::build::<BLOCK_DB_DEPTH>(builder, block_db_pi, query_block_pi);

        // register additional public input to identify the query circuits
        let identifier =
            builder.constant(F::from_canonical_u8(keccak256("QueryERC20".as_bytes())[0]));
        builder.register_public_input(identifier);

        RevelationRecursiveWires {
            revelation_wires,
            query_block_wires: query_block_verifier_wires,
            block_db_wires,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        let (query_proof, query_vd) = (&inputs.inputs.query_block_proof).into();
        self.query_block_wires.set_target(
            pw,
            &inputs.query_block_circuit_set,
            query_proof,
            query_vd,
        )?;
        pw.set_proof_with_pis_target(&self.block_db_wires, &inputs.inputs.block_db_proof);
        inputs
            .inputs
            .logic_inputs
            .assign(pw, &self.revelation_wires);

        Ok(())
    }
}
