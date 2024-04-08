# Lagrange Database Codebase for Euclid testnet

This repository contains the code logic supporting the Euclid testnet. Specifically, it contains the code to extract information from the 
blockchain and map it into a zk-friendly database. This step is called the "preprocessing" phase, or indexing. 


## Entry point in the codebase

To get a deeper understanding of how the code works, we invite the reader to start with the `mapreduce-plonky2/src/api.rs` file. 
This file contains the entry point to the proofs Lagrange generates on its backend for the preprocessing step.

For more information, we refer the reader to the public information about Euclid testnet available here. 
Detailed developer documentation, including cryptographic documentation, will be published soon after the release of Euclid.

## License

The code is licensed under a Lagrange specific license file located in `LICENSE`.
