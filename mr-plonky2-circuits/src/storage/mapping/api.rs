use super::extension::ExtensionNodeCircuit;
use super::extension::ExtensionWires;
use super::leaf::LeafCircuit;
use super::leaf::LeafWires;
use super::leaf::StorageLeafWire;
use super::PublicInputs;
use crate::api::default_config;
use crate::api::ProofWithVK;
use crate::mpt_sequential::PAD_LEN;
use crate::storage::key::MappingSlot;
use crate::storage::mapping::branch::BranchCircuit;
use crate::storage::mapping::branch::BranchWires;
use crate::storage::MAX_BRANCH_NODE_LEN;
use crate::storage::MAX_LEAF_NODE_LEN;
use anyhow::bail;
use anyhow::Result;
use log::debug;
use paste::paste;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;
use recursion_framework::framework::RecursiveCircuitInfo;
use recursion_framework::framework::RecursiveCircuits;

#[cfg(test)]
use recursion_framework::framework_testing::{
    new_universal_circuit_builder_for_testing, TestingRecursiveCircuits,
};
use serde::Deserialize;
use serde::Serialize;
use std::array::from_fn as create_array;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Serialize, Deserialize)]
/// CircuitType is a wrapper around the different specialized circuits that can be used to prove a MPT node recursively
/// NOTE: Right now these circuits are specialized to prove inclusion of a single mapping slot.
pub enum CircuitInput {
    Leaf(LeafCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionInput),
    Branch(BranchInput),
}

impl CircuitInput {
    /// Returns a circuit input for proving a leaf MPT node
    pub fn new_leaf(node: Vec<u8>, slot: usize, mapping_key: Vec<u8>) -> Self {
        CircuitInput::Leaf(LeafCircuit {
            node,
            slot: MappingSlot::new(slot as u8, mapping_key),
        })
    }
    /// Returns a circuit input for proving an extension MPT node
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }
    /// Returns a circuit input for proving an branch MPT node
    pub fn new_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>) -> Self {
        CircuitInput::Branch(ProofInputSerialized {
            input: InputNode { node },
            serialized_child_proofs: child_proofs,
        })
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
/// Main struct holding the different circuit parameters for each of the MPT circuits defined here.
/// Most notably, it holds them in a way to use the recursion framework allowing us to specialize
/// circuits according to the situation.
pub struct PublicParameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, StorageLeafWire>,
    ext_circuit: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    #[cfg(not(test))]
    branchs: BranchCircuits,
    #[cfg(test)]
    branchs: TestBranchCircuits,
    #[cfg(not(test))]
    set: RecursiveCircuits<F, C, D>,
    #[cfg(test)]
    set: TestingRecursiveCircuits<F, C, D, NUM_IO>,
}
/// Public API employed to build the MPT circuits, which are returned in serialized form
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

/// Public API employed to generate a proof for the circuit specified by `CircuitType`,
/// employing the `circuit_params` generated with the `build_circuits_params` API
pub fn generate_proof(
    circuit_params: &PublicParameters,
    circuit_type: CircuitInput,
) -> Result<Vec<u8>> {
    circuit_params.generate_proof(circuit_type)?.serialize()
}
#[derive(Serialize, Deserialize)]
/// This data structure allows to specify the inputs for a circuit that needs to recursively verify
/// proofs; the generic type `T` allows to specify the specific inputs of each circuits besides the
/// proofs that need to be recursively verified, while the proofs are serialized in byte format
struct ProofInputSerialized<T> {
    input: T,
    serialized_child_proofs: Vec<Vec<u8>>,
}

impl<T> ProofInputSerialized<T> {
    /// Deserialize child proofs and return the set of deserialized 'MTPProof`s
    fn get_child_proofs(&self) -> Result<Vec<ProofWithVK>> {
        self.serialized_child_proofs
            .iter()
            .map(|proof| ProofWithVK::deserialize(proof))
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Struct containing the expected input MPT Extension/Branch node.
struct InputNode {
    node: Vec<u8>,
}

type ExtensionInput = ProofInputSerialized<InputNode>;

type BranchInput = ProofInputSerialized<InputNode>;

pub(crate) const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;
/// generate a macro filling the BranchCircuit structs manually
macro_rules! impl_branch_circuits {
    ($struct_name:ty, $($i:expr),*) => {
        paste! {
        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        pub struct [< $struct_name GenericNodeLen>]<const NODE_LEN: usize>
        where
            [(); PAD_LEN(NODE_LEN)]:,
        {
            $(
                [< b $i >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<NODE_LEN>>,
            )+
        }
        #[doc = stringify!($struct_name)]
        #[doc = "holds the logic to create the different circuits for handling a branch node.
        In particular, it generates specific circuits for each number of child proofs, as well as
        in combination with the node input length."]
        pub type $struct_name =  [< $struct_name GenericNodeLen>]<MAX_BRANCH_NODE_LEN>;

        impl $struct_name {
            fn new(builder: &CircuitWithUniversalVerifierBuilder<F, D, NUM_IO>) -> Self {
                $struct_name {
                    $(
                        // generate one circuit with full node len
                        [< b $i >]:  builder.build_circuit::<C, $i, BranchWires<MAX_BRANCH_NODE_LEN>>(()),
                    )+
                }
            }
            /// Returns the set of circuits to be fed to the recursive framework
            fn circuit_set(&self) -> Vec<HashOut<F>> {
                let mut arr = Vec::new();
                $(
                    arr.push(self.[< b $i >].circuit_data().verifier_only.circuit_digest);
                )+
                arr
            }

            /// generates a proof from the inputs stored in `branch`. Depending on the size of the node,
            /// and the number of children proofs, it selects the right specialized circuit to generate the proof.
            fn generate_proof(
                &self,
                set: &RecursiveCircuits<F, C, D>,
                branch_node: InputNode,
                child_proofs: Vec<ProofWithVK>,
            ) -> Result<ProofWithVK> {
                // first, determine manually the common prefix, the ptr and the mapping slot
                // from the public inputs of the children proofs.
                // Note this is done outside circuits, more as a sanity check. The circuits is enforcing
                // this condition.
                let valid_inputs = child_proofs
                    .windows(2)
                    .all(|arr| {
                        if arr.len() == 1 {
                            true
                        } else {
                            let pi1 = PublicInputs::<F>::from(&arr[0].proof().public_inputs);
                            let (k1, p1) = pi1.mpt_key_info();
                            let pi2 = PublicInputs::<F>::from(&arr[1].proof().public_inputs);
                            let (k2, p2) = pi2.mpt_key_info();
                            let up1 = p1.to_canonical_u64() as usize;
                            let up2 = p2.to_canonical_u64() as usize;
                            up1 < k1.len() && up2 < k2.len() && p1 == p2 && k1[..up1] == k2[..up2]
                        }
                    });
                if !valid_inputs {
                    bail!("proofs don't match on the key and/or pointers");
                }
                if child_proofs.is_empty() || child_proofs.len() > 16 {
                    bail!("No child proofs or too many child proofs");
                }
                if branch_node.node.len() > MAX_BRANCH_NODE_LEN {
                    bail!("Branch node too long");
                }

                // we just take the first one,it doesn't matter which one we take as long
                // as all prefixes and pointers are equal.
                let pi = PublicInputs::<F>::from(&child_proofs[0].proof().public_inputs);
                let (key, ptr) = pi.mpt_key_info();
                let mapping_slot = pi.mapping_slot().to_canonical_u64() as usize;
                let common_prefix = key
                    .iter()
                    .map(|nib| nib.to_canonical_u64() as u8)
                    .collect::<Vec<_>>();
                let pointer = ptr.to_canonical_u64() as usize;
                let (mut proofs, vks): (Vec<_>, Vec<_>) = child_proofs
                    .iter()
                    // TODO: didn't find a way to get rid of the useless clone - it's either on the vk or on the proof
                    .map(|p| {
                        let (proof, vk) = p.into();
                        (proof.clone(), vk)
                    })
                    .unzip();
                 match child_proofs.len() {
                     $(_ if $i == child_proofs.len() => {
                         set.generate_proof(
                             &self.[< b $i >],
                             proofs.try_into().unwrap(),
                             create_array(|i| vks[i]),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 mapping_slot,
                                 nb_proofs: $i,
                             }
                         ).map(|p| (p, self.[< b $i >].get_verifier_data().clone()).into())
                     },
                        _ if $i > child_proofs.len()  => {
type C = crate::api::C;
                           // this should match for number of real proofs between the previous $i passed to
                            // the macro and current $i, since `match` greedily matches arms
                            let num_real_proofs = child_proofs.len();
                            // we pad the number of proofs to $i by repeating the
                            // first proof
                            for _ in 0..($i - num_real_proofs) {
                                proofs.push(proofs.first().unwrap().clone());
                            }
                            println!("Generating proof with {} proofs over branch circuit {}", proofs.len(), $i);
                         set.generate_proof(
                             &self.[< b $i>],
                             proofs.try_into().unwrap(),
                             create_array(|i| if i < num_real_proofs { vks[i] } else { vks[0] }),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 mapping_slot,
                                 nb_proofs: num_real_proofs,
                             }
                         ).map(|p| (p, self.[< b $i>].get_verifier_data().clone()).into())
                     }
                 )+
                     _ => bail!("invalid child proof len"),
                 }
                }
            }
}
    }
}

impl_branch_circuits!(BranchCircuits, 2, 9, 16);
#[cfg(test)]
impl_branch_circuits!(TestBranchCircuits, 1, 4, 9);

/// number of circuits in the set
#[cfg(not(test))]
const MAPPING_CIRCUIT_SET_SIZE: usize = 3 + 2; // 3 branch circuits + 1 ext + 1 leaf
#[cfg(test)]
const MAPPING_CIRCUIT_SET_SIZE: usize = 3 + 2; // 3 branch + 1 ext + 1 leaf

impl PublicParameters {
    /// Generates the circuit parameters for the MPT circuits.
    fn build() -> Self {
        let config = default_config();
        #[cfg(not(test))]
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );
        #[cfg(test)]
        let circuit_builder = new_universal_circuit_builder_for_testing::<F, C, D, NUM_IO>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );

        debug!("Building leaf circuit");
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires<MAX_LEAF_NODE_LEN>>(());

        debug!("Building extension circuit");
        let ext_circuit = circuit_builder.build_circuit::<C, 1, ExtensionWires>(());

        debug!("Building branch circuits");
        #[cfg(not(test))]
        let branch_circuits = BranchCircuits::new(&circuit_builder);
        #[cfg(test)]
        let branch_circuits = TestBranchCircuits::new(&circuit_builder);
        let mut circuits_set = vec![
            leaf_circuit.get_verifier_data().circuit_digest,
            ext_circuit.get_verifier_data().circuit_digest,
        ];
        circuits_set.extend(branch_circuits.circuit_set());
        assert_eq!(circuits_set.len(), MAPPING_CIRCUIT_SET_SIZE);

        PublicParameters {
            leaf_circuit,
            ext_circuit,
            branchs: branch_circuits,
            #[cfg(not(test))]
            set: RecursiveCircuits::new_from_circuit_digests(circuits_set),
            #[cfg(test)]
            set: TestingRecursiveCircuits::new_from_circuit_digests(&circuit_builder, circuits_set),
        }
    }

    fn generate_proof(&self, circuit_type: CircuitInput) -> Result<ProofWithVK> {
        #[cfg(not(test))]
        let set = &self.set;
        #[cfg(test)]
        let set = &self.set.get_recursive_circuit_set();
        match circuit_type {
            CircuitInput::Leaf(leaf) => set
                .generate_proof(&self.leaf_circuit, [], [], leaf)
                .map(|p| (p, self.leaf_circuit.get_verifier_data().clone()).into()),
            CircuitInput::Extension(ext) => {
                let mut child_proofs = ext.get_child_proofs()?;
                let (child_proof, child_vk) = child_proofs
                    .pop()
                    .ok_or(anyhow::Error::msg(
                        "No proof found in input for extension node",
                    ))?
                    .into();
                set.generate_proof(
                    &self.ext_circuit,
                    [child_proof],
                    [&child_vk],
                    ExtensionNodeCircuit {
                        node: ext.input.node,
                    },
                )
                .map(|p| (p, self.ext_circuit.get_verifier_data().clone()).into())
            }
            CircuitInput::Branch(branch) => {
                let child_proofs = branch.get_child_proofs()?;
                self.branchs.generate_proof(set, branch.input, child_proofs)
            }
        }
    }

    pub(crate) fn get_mapping_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        #[cfg(not(test))]
        let set = &self.set;
        #[cfg(test)]
        let set = self.set.get_recursive_circuit_set();

        set
    }
}

#[cfg(test)]
mod test {
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use mrp2_test_utils::{mpt_sequential::generate_random_storage_mpt, utils::random_vector};
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use plonky2_ecgfp5::curve::curve::Point;
    use serial_test::serial;
    use std::sync::Arc;

    use super::*;
    use crate::{
        api::lpn_storage::leaf_digest_for_mapping, eth::StorageSlot,
        mpt_sequential::utils::bytes_to_nibbles, storage::key::MappingSlot, types::ADDRESS_LEN,
    };

    struct TestData {
        trie: EthTrie<MemoryDB>,
        key: Vec<u8>,
        mpt_keys: Vec<Vec<u8>>,
    }

    fn generate_storage_trie_and_keys(slot: usize, num_children: usize) -> TestData {
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        // insert `num_children` keys that share the same prefix
        let key = random_vector(20); // like address
        let mut mpt = StorageSlot::Mapping(key.clone(), slot).mpt_key_vec();
        let mpt_len = mpt.len();
        let last_byte = mpt[mpt_len - 1];
        let first_nibble = last_byte & 0xF0;
        let second_nibble = last_byte & 0x0F;
        println!(
            "key: {}, last: {}, first: {}, second: {}",
            hex::encode(&mpt),
            last_byte,
            first_nibble,
            second_nibble
        );
        let mut mpt_keys = Vec::new();
        // only change the last nibble
        for i in 0..num_children {
            mpt[mpt_len - 1] = first_nibble + ((second_nibble + i as u8) & 0x0F);
            mpt_keys.push(mpt.clone());
        }
        println!(
            "key1: {:?}, key2: {:?}",
            hex::encode(&mpt_keys[0]),
            hex::encode(&mpt_keys[1])
        );
        let v: Vec<u8> = rlp::encode(&random_vector(32)).to_vec();
        mpt_keys
            .iter()
            .for_each(|mpt| trie.insert(&mpt, &v).unwrap());
        trie.root_hash().unwrap();

        TestData {
            trie,
            key,
            mpt_keys,
        }
    }

    #[test]
    #[serial]
    fn test_serialization() {
        let params = PublicParameters::build();

        let encoded = bincode::serialize(&params).unwrap();
        let decoded_params: PublicParameters = bincode::deserialize(&encoded).unwrap();

        assert!(decoded_params == params);

        let slot = 3;
        let mut test_data = generate_storage_trie_and_keys(slot, 2);
        let p1 = test_data.trie.get_proof(&test_data.mpt_keys[0]).unwrap();
        let l1 = CircuitInput::Leaf(LeafCircuit {
            node: p1.last().unwrap().to_vec(),
            slot: MappingSlot::new(slot as u8, test_data.key.clone()),
        });

        let encoded = bincode::serialize(&l1).unwrap();
        let decoded_input: CircuitInput = bincode::deserialize(&encoded).unwrap();

        // we test serialization of `CircuitType::Leaf` by employing the deserialized input to
        // generate the proof
        let leaf_proof = params.generate_proof(decoded_input).unwrap();
        let encoded = bincode::serialize(&leaf_proof).unwrap();
        let decoded_proof: ProofWithVK = bincode::deserialize(&encoded).unwrap();

        assert_eq!(leaf_proof, decoded_proof);

        let branch_node = p1[p1.len() - 2].to_vec();
        let branch_inputs = CircuitInput::Branch(BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs: vec![encoded],
        });

        let encoded = bincode::serialize(&branch_inputs).unwrap();
        let decoded_input: CircuitInput = bincode::deserialize(&encoded).unwrap();

        // we test serialization of `CircuitType::Branch` by employing the deserialized input to
        // generate the proof
        let proof = params.generate_proof(decoded_input).unwrap();

        let encoded = bincode::serialize(&proof).unwrap();
        let decoded_proof: ProofWithVK = bincode::deserialize(&encoded).unwrap();

        assert_eq!(proof, decoded_proof);
    }

    /// test if the selection of the circuits is correct
    #[test]
    #[serial]
    fn test_branch_logic() {
        let params = PublicParameters::build();
        let slot = 0;
        let num_children = 6;
        let mut test_data = generate_storage_trie_and_keys(slot, num_children);
        let trie = &mut test_data.trie;
        let key = &test_data.key;
        let mpt1 = test_data.mpt_keys[0].as_slice();
        let mpt2 = test_data.mpt_keys[1].as_slice();
        let p1 = trie.get_proof(&mpt1).unwrap();
        let p2 = trie.get_proof(&mpt2).unwrap();
        // they should share the same branch node
        assert_eq!(p1.len(), p2.len());
        assert_eq!(p1[p1.len() - 2], p2[p2.len() - 2]);
        let l1_inputs = CircuitInput::new_leaf(p1.last().unwrap().to_vec(), slot, key.clone());
        // generate a leaf then a branch proof with only this leaf
        println!("[+] Generating leaf proof 1...");
        let leaf1_proof_buff = generate_proof(&params, l1_inputs).unwrap();
        // some testing on the public inputs of the proof
        let leaf1_proof = ProofWithVK::deserialize(&leaf1_proof_buff).unwrap();
        let pub1 = leaf1_proof.proof.public_inputs[..NUM_IO].to_vec();
        let pi1 = PublicInputs::from(&pub1);
        assert_eq!(pi1.proof_inputs.len(), NUM_IO);
        let (_, comp_ptr) = pi1.mpt_key_info();
        assert_eq!(comp_ptr, F::from_canonical_usize(63));

        let branch_node = p1[p1.len() - 2].to_vec();
        println!("[+] Generating branch proof 1...");
        let branch_inputs = CircuitInput::new_branch(branch_node.clone(), vec![leaf1_proof_buff]);
        let branch1_buff = generate_proof(&params, branch_inputs).unwrap();
        let branch1 = ProofWithVK::deserialize(&branch1_buff).unwrap();
        let exp_vk = params.branchs.b1.get_verifier_data().clone();
        assert_eq!(branch1.verifier_data(), &exp_vk);

        let gen_fake_proof = |mpt| {
            let mut pub2 = pub1.clone();
            assert_eq!(pub2.len(), NUM_IO);
            pub2[PublicInputs::<F>::KEY_IDX..PublicInputs::<F>::T_IDX].copy_from_slice(
                &bytes_to_nibbles(mpt)
                    .into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(pub2.len(), pub1.len());

            let pi2 = PublicInputs::from(&pub2);
            {
                let (k1, p1) = pi1.mpt_key_info();
                let (k2, p2) = pi2.mpt_key_info();
                let (pt1, pt2) = (
                    p1.to_canonical_u64() as usize,
                    p2.to_canonical_u64() as usize,
                );
                assert!(pt1 < k1.len() && pt2 < k2.len());
                assert!(p1 == p2);
                assert!(k1[..pt1] == k2[..pt2]);
            }
            let fake_proof = params
                .set
                .generate_input_proofs([pub2.clone().try_into().unwrap()])
                .unwrap();
            let vk = params.set.verifier_data_for_input_proofs::<1>()[0].clone();
            ProofWithVK::from((fake_proof[0].clone(), vk))
        };

        // generate  a branch proof with two leafs inputs now but using the testing framework
        // we simulate another leaf at the right key, so we just modify the nibble at the pointer
        // generate fake dummy proofs but with expected public inputs
        println!("[+] Generating leaf proof 2...");
        let leaf2_proof_vk = gen_fake_proof(mpt2);

        println!("[+] Generating branch proof 2...");
        let branch_inputs = CircuitInput::Branch(BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs: vec![
                bincode::serialize(&leaf1_proof).unwrap(),
                bincode::serialize(&leaf2_proof_vk).unwrap(),
            ],
        });
        let branch2 = params.generate_proof(branch_inputs).unwrap();
        let exp_vk = params.branchs.b4.get_verifier_data().clone();
        assert_eq!(branch2.verifier_data(), &exp_vk);
        // check validity of public input of `branch2` proof
        let check_public_input = |num_children, proof: &ProofWithVK| {
            let value1: Vec<u8> = rlp::decode(&trie.get(mpt1).unwrap().unwrap()).unwrap();
            let p1_acc = leaf_digest_for_mapping(&test_data.key, &value1);
            //let value2: Vec<u8> = rlp::decode(&trie.get(&test_data.mpt_key2).unwrap().unwrap()).unwrap();
            //let p2_acc = leaf_digest_for_mapping(&test_data.key, &value2);
            let exp_accumulator = (0..num_children).fold(Point::NEUTRAL, |acc, _| acc + p1_acc);
            let branch_pub = PublicInputs::from(&proof.proof().public_inputs[..NUM_IO]);
            assert_eq!(exp_accumulator.to_weierstrass(), branch_pub.accumulator());
            assert_eq!(F::from_canonical_usize(num_children), branch_pub.n());
            let (k1, p1) = pi1.mpt_key_info();
            let (kb, pb) = branch_pub.mpt_key_info();
            let p1 = p1.to_canonical_u64() as usize;
            let pb = pb.to_canonical_u64() as usize;
            assert_eq!(p1 - 1, pb);
            assert_eq!(k1[..pb], kb[..pb]);
            assert_eq!(pi1.mapping_slot(), branch_pub.mapping_slot());
        };
        check_public_input(2, &branch2);
        // generate num_children-2 fake proofs to tesr branch circuit with num_children proofs
        let mut serialized_child_proofs = vec![
            bincode::serialize(&leaf1_proof).unwrap(),
            bincode::serialize(&leaf2_proof_vk).unwrap(),
        ];
        for i in 2..num_children {
            serialized_child_proofs.push(
                bincode::serialize(&gen_fake_proof(test_data.mpt_keys[i].as_slice())).unwrap(),
            )
        }
        println!("[+] Generating branch proof {}...", num_children);
        let branch_inputs = CircuitInput::Branch(BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs,
        });
        let branch_proof = params.generate_proof(branch_inputs).unwrap();
        let exp_vk = params.branchs.b9.get_verifier_data().clone();
        assert_eq!(branch_proof.verifier_data(), &exp_vk);
        check_public_input(num_children, &branch_proof);
    }

    #[test]
    fn test_mapping_api() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key1 = [1u8; 4];
        let val1 = [2u8; ADDRESS_LEN];
        let slot1 = StorageSlot::Mapping(key1.to_vec(), 0);
        let mpt_key1 = slot1.mpt_key();

        let key2 = [3u8; 4];
        let val2 = [4u8; ADDRESS_LEN];
        let slot2 = StorageSlot::Mapping(key2.to_vec(), 0);
        let mpt_key2 = slot2.mpt_key();

        trie.insert(&mpt_key1, &rlp::encode(&val1.as_slice()))
            .unwrap();
        trie.insert(&mpt_key2, &rlp::encode(&val2.as_slice()))
            .unwrap();
        trie.root_hash().unwrap();

        let proof1 = trie.get_proof(&mpt_key1).unwrap();
        let proof2 = trie.get_proof(&mpt_key2).unwrap();

        assert_eq!(proof1[0], proof2[0]);
        // only need to make sure node above is really a branch node
        assert!(rlp::decode_list::<Vec<u8>>(&proof1[0]).len() == 17);
        use crate::storage::mapping::{self};
        println!("Generating params...");
        let params = mapping::api::build_circuits_params();
        println!("Proving leaf 1...");

        let leaf_input1 = mapping::CircuitInput::new_leaf(proof1[1].clone(), 0, key1.to_vec());
        let leaf_proof1 = mapping::api::generate_proof(&params, leaf_input1).unwrap();
        {
            let lp = ProofWithVK::deserialize(&leaf_proof1).unwrap();
            let pub1 = mapping::PublicInputs::from(&lp.proof.public_inputs);
            let (_, ptr) = pub1.mpt_key_info();
            assert_eq!(ptr, GoldilocksField::ZERO);
        }

        println!("Proving leaf 2...");

        let leaf_input2 = mapping::CircuitInput::new_leaf(proof2[1].clone(), 0, key2.to_vec());

        let leaf_proof2 = mapping::api::generate_proof(&params, leaf_input2).unwrap();

        println!("Proving branch...");

        let branch_input = mapping::api::CircuitInput::new_branch(
            proof1[0].clone(),
            vec![leaf_proof1, leaf_proof2],
        );

        mapping::api::generate_proof(&params, branch_input).unwrap();
    }
}
