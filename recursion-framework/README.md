# Universal Recursion Framework for Plonky2

This code is an adaptation of Horizen Labs [https://github.com/HorizenLabs/plonky2/tree/generic_recursion_crate](code) to support 
our specific use case.
Namely, this crate now allows to define multiple independent circuits and create a circuit set of all the verification keys.
From then, one can compose (i.e. recurse over) proofs generically (i.e. no specific verification key hardcoding) with the guarantee
that the proof being verified in circuit is in the circuit set defined in the first step.

This allows to specialize circuits for MPT proof verification using recursion in the most efficient manner for example, since we can
specialize circuits to handle leaf, extension, or branch node (with different number of childrens) while still composing them generically.