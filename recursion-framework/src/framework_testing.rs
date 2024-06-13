use plonky2::{
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};
use serialization::{
    circuit_data_serialization::SerializableRichField, deserialize_array, serialize_array,
};

use crate::{
    circuit_builder::{
        CircuitLogicWires, CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder,
    },
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};

use anyhow::Result;
#[derive(Serialize, Deserialize, Eq, PartialEq)]
/// Wirs of a circuit employing for testing purposes, which imply exposes
/// `NUM_PUBLIC_INPUTS` unconstrained public inputs in the generated proofs
pub struct DummyCircuitWires<const NUM_PUBLIC_INPUTS: usize>(
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    [Target; NUM_PUBLIC_INPUTS],
);

impl<F: SerializableRichField<D>, const D: usize, const NUM_PUBLIC_INPUTS: usize>
    CircuitLogicWires<F, D, 0> for DummyCircuitWires<NUM_PUBLIC_INPUTS>
{
    type CircuitBuilderParams = ();

    type Inputs = [F; NUM_PUBLIC_INPUTS];

    const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let input_targets = builder.add_virtual_public_input_arr::<NUM_PUBLIC_INPUTS>();

        Self(input_targets)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        pw.set_target_arr(self.0.as_ref(), inputs.as_slice());

        Ok(())
    }
}
/// `TestingRecursiveCircuits` is a variant of the `RecursiveCircuits` framework that must be employed only for
/// testing and benchmarking purposes. It allows to employ dummy proofs with customizable public inputs to test
/// circuits with the universal verifier, instead of the proofs generated from the actual circuits belonging to
/// a `RecursiveCircuits` set, which might be hard to generate in a unit testing/benchmarking scenario in
/// case there are many recursion layers
#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
pub struct TestingRecursiveCircuits<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Set of circuits whose proofs can be recursively verified by the universal verifier
    recursive_circuits: RecursiveCircuits<F, C, D>,
    dummy_circuit: CircuitWithUniversalVerifier<F, C, D, 0, DummyCircuitWires<NUM_PUBLIC_INPUTS>>,
}

/// This function must be employed to generate an instance of `CircuitWithUniversalVerifierBuilder`
/// for circuits that will belong to the set of circuits tested with an instance of
/// `TestingRecursiveCircuits`; the instance generated by this function is also employed to
/// instantiate a `TestingRecursiveCircuits`
pub fn new_universal_circuit_builder_for_testing<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
>(
    config: CircuitConfig,
    circuit_set_size: usize,
) -> CircuitWithUniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<C>(
        config,
        circuit_set_size + 1,
    )
}

impl<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const NUM_PUBLIC_INPUTS: usize,
    > Default for TestingRecursiveCircuits<F, C, D, NUM_PUBLIC_INPUTS>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// Build a `TestingRecursiveCircuits` for an empty set of circuits and employing
    /// `standard_recursion_config` as the circuit configuration
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let circuit_builder =
            new_universal_circuit_builder_for_testing::<F, C, D, NUM_PUBLIC_INPUTS>(config, 0);
        // we create an instance of `TestingRecursiveCircuits` where the set of circuits comprises only the dummy circuit
        TestingRecursiveCircuits::<F, C, D, NUM_PUBLIC_INPUTS>::new(&circuit_builder, vec![])
    }
}
impl<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const NUM_PUBLIC_INPUTS: usize,
    > TestingRecursiveCircuits<F, C, D, NUM_PUBLIC_INPUTS>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// Instantiate a `TestingRecursiveCircuits` for the set of circuits given by `circuits`; `builder` must be instantiated
    /// by employing the `new_universal_circuit_builder_for_testing` utility function
    pub fn new(
        builder: &CircuitWithUniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>,
        circuits: Vec<Box<dyn RecursiveCircuitInfo<F, C, D> + '_>>,
    ) -> Self {
        let circuit_digests = circuits
            .into_iter()
            .map(|circuit| circuit.as_ref().get_verifier_data().circuit_digest)
            .collect::<Vec<_>>();

        Self::new_from_circuit_digests(builder, circuit_digests)
    }

    /// Instantiate a `TestingRecursiveCircuits` for the set of circuits given by `circuit_digests`;
    /// `builder` must be instantiated
    pub fn new_from_circuit_digests(
        builder: &CircuitWithUniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>,
        mut circuit_digests: Vec<HashOut<F>>,
    ) -> Self {
        assert_eq!(circuit_digests.len(), builder.get_circuit_set_size() - 1);
        let dummy_circuit = builder.build_circuit::<C, 0, DummyCircuitWires<NUM_PUBLIC_INPUTS>>(());

        circuit_digests.push(dummy_circuit.get_verifier_data().circuit_digest);
        let recursive_circuits = RecursiveCircuits::new_from_circuit_digests(circuit_digests);

        Self {
            recursive_circuits,
            dummy_circuit,
        }
    }

    /// Returns the set of recursive circuits bounded to `self` instance of `TestingRecursivCircuits`
    pub fn get_recursive_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.recursive_circuits
    }

    /// Generate a proof for the circuit with universal verifier `circuit`, employing the provided `pulic_inputs` as public
    /// inputs of the `NUM_VERIFIERS` proof being verified in `circuit`
    pub fn generate_proof_from_public_inputs<
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        circuit: &CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>,
        public_inputs: [[F; NUM_PUBLIC_INPUTS]; NUM_VERIFIERS],
        custom_inputs: CLW::Inputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let input_proofs = self.generate_input_proofs(public_inputs)?;

        self.generate_proof(circuit, input_proofs, custom_inputs)
    }

    /// Generate `NUM_VERIFIERS` proofs having the provided `public_inputs' values as public inputs;
    /// these proofs can be recursively verified by any recursive circuit included in the set of circuits
    /// bounded to `self`
    pub fn generate_input_proofs<const NUM_VERIFIERS: usize>(
        &self,
        public_inputs: [[F; NUM_PUBLIC_INPUTS]; NUM_VERIFIERS],
    ) -> Result<[ProofWithPublicInputs<F, C, D>; NUM_VERIFIERS]> {
        let input_proofs = public_inputs
            .into_iter()
            .map(|inputs| {
                self.recursive_circuits
                    .generate_proof(&self.dummy_circuit, [], [], inputs)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(input_proofs.try_into().unwrap())
    }

    /// Utility function to get the verifier data for the circuit being employed to generate the input proofs
    /// computed by the `generate_input_proofs` method
    pub fn verifier_data_for_input_proofs<const NUM_VERIFIERS: usize>(
        &self,
    ) -> [&VerifierOnlyCircuitData<C, D>; NUM_VERIFIERS] {
        [self.dummy_circuit.get_verifier_data(); NUM_VERIFIERS]
    }

    /// Generates a proof for the circuit `circuit`, verfying the set of `NUM_VERIFIERS` proofs provided as input,
    /// which are expected to be generated with `generate_inputs_proofs` method.
    /// The method `generate_proof_with_public_inputs` is the preferred way to generate proofs with the
    /// `TestingRecursiveCircuits` framework, as it already performs both the generation of the input proofs
    /// and the generation of the proof for circuit `circuit`; instead, generate_proof` method is meant
    /// to be publicly exposed mostly to benchmark the proof generation time of the input `circuit`, as it allows
    /// to isolate the proof generation for the circuit being benchmarked from the generation of the input proofs;
    pub fn generate_proof<
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        circuit: &CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>,
        input_proofs: [ProofWithPublicInputs<F, C, D>; NUM_VERIFIERS],
        custom_inputs: CLW::Inputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.recursive_circuits.generate_proof(
            circuit,
            input_proofs,
            self.verifier_data_for_input_proofs(),
            custom_inputs,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use plonky2::field::types::Sample;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use crate::{
        circuit_builder::tests::{RecursiveCircuitWires, NUM_PUBLIC_INPUTS_TEST_CIRCUITS},
        framework::{
            prepare_recursive_circuit_for_circuit_set,
            tests::{VerifierCircuitFixedWires, VerifierCircuitWires},
            RecursiveCircuitsVerifierGagdet,
        },
    };

    use super::*;

    use serial_test::serial;

    fn test_recursive_circuit_with_testing_framework<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const NUM_VERIFIERS: usize,
    >()
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        const INPUT_SIZE: usize = 8;
        let config = CircuitConfig::standard_recursion_config();
        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
        let circuit_builder =
            new_universal_circuit_builder_for_testing::<F, C, D, NUM_PUBLIC_INPUTS>(config, 1);
        let recursive_circuit = circuit_builder
            .build_circuit::<C, NUM_VERIFIERS, RecursiveCircuitWires<INPUT_SIZE>>(());

        let circuits = vec![prepare_recursive_circuit_for_circuit_set(
            &recursive_circuit,
        )];

        let testing_framework = TestingRecursiveCircuits::new(&circuit_builder, circuits);

        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let public_inputs_for_verified_proofs = array::from_fn(|_| array::from_fn(|_| F::rand()));
        let proof = testing_framework
            .generate_proof_from_public_inputs(
                &recursive_circuit,
                public_inputs_for_verified_proofs,
                recursive_circuits_input,
            )
            .unwrap();

        assert_eq!(
            &proof.public_inputs[NUM_PUBLIC_INPUTS..],
            testing_framework
                .recursive_circuits
                .get_circuit_set_digest()
                .flatten()
                .as_slice()
        );

        recursive_circuit.circuit_data().verify(proof).unwrap();
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    #[serial]
    fn test_circuit_with_testing_framework_one_universal_verifier() {
        test_recursive_circuit_with_testing_framework::<F, C, D, 1>();
    }

    #[test]
    #[serial]
    fn test_circuit_with_testing_framework_two_universal_verifier() {
        test_recursive_circuit_with_testing_framework::<F, C, D, 2>();
    }

    #[test]
    #[serial]
    fn test_circuit_with_testing_framework_three_universal_verifier() {
        test_recursive_circuit_with_testing_framework::<F, C, D, 3>();
    }

    #[test]
    #[serial]
    fn test_verifier_circuit_with_dummy_proofs() {
        // This test shows how to employ th `TestingRecursiveCircuits` framework to test circuits that employ the `RecursiveCircuitsVerifierGadget`
        let config = CircuitConfig::standard_recursion_config();
        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
        // we create an instance of `TestingRecursiveCircuits` where the set of circuits comprises only the dummy circuit
        let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_PUBLIC_INPUTS>::default();

        // we build 2 circuits employing the `RecursiveCircuitsVerifierGadget`
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<
            C,
        >(config.clone(), 2);

        let verifier_gadget = RecursiveCircuitsVerifierGagdet::new(
            config.clone(),
            &testing_framework.get_recursive_circuit_set(),
        );
        let verifier_circuit = circuit_builder
            .build_circuit::<C, 0, VerifierCircuitWires<C, D, NUM_PUBLIC_INPUTS>>(verifier_gadget);

        let verifier_gadget = RecursiveCircuitsVerifierGagdet::new(
            config.clone(),
            &testing_framework.get_recursive_circuit_set(),
        );
        let verifier_circuit_fixed = circuit_builder
            .build_circuit::<C, 0, VerifierCircuitFixedWires<C, D, NUM_PUBLIC_INPUTS>>((
                verifier_gadget,
                testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
            ));

        let verifier_circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&verifier_circuit),
            prepare_recursive_circuit_for_circuit_set(&verifier_circuit_fixed),
        ];
        // We create an instance of `RecursiveCircuits` for the set of circuits employing the `RecursiveVerifierGadget`
        let recursive_framework_verifier_circuits = RecursiveCircuits::new(verifier_circuits);

        // Generate and verify proof for `VerifierCircuit` employing a dummy proof (generated by the testing framework) as input proof
        let public_inputs = [array::from_fn(|_| F::rand())];
        let proof = recursive_framework_verifier_circuits
            .generate_proof(
                &verifier_circuit,
                [],
                [],
                (
                    testing_framework.get_recursive_circuit_set().clone(),
                    testing_framework
                        .generate_input_proofs::<1>(public_inputs)
                        .unwrap()[0]
                        .clone(),
                    testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
                ),
            )
            .unwrap();
        verifier_circuit.circuit_data().verify(proof).unwrap();

        // Generate and verify proof for `VerifierCircuitFixed` employing a dummy proof (generated by the testing framework) as input proof
        let public_inputs = [array::from_fn(|_| F::rand())];
        let proof = recursive_framework_verifier_circuits
            .generate_proof(
                &verifier_circuit_fixed,
                [],
                [],
                testing_framework
                    .generate_input_proofs::<1>(public_inputs)
                    .unwrap()[0]
                    .clone(),
            )
            .unwrap();

        verifier_circuit_fixed.circuit_data().verify(proof).unwrap();
    }
}
