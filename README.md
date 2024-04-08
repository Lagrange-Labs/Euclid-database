# Lagrange Database Codebase for Euclid testnet

This repository contains the code logic supporting the Euclid testnet. Specifically it contains the code to extract the information from the 
blockchain and turn it into a zk friendly database. 

## Entry point in the codebase

To get a deeper understanding at how the code works, we invite the reader to start with the `mapreduce-plonky2/src/api.rs` file. 
This file contains the entry point to all the proofs Lagrange generates on its backend for the preprocessing part.

For more information, we refer the reader to the public information about Euclid testnet here. 
More in-depth documentation, including cryptographic documentation, will be published soon.

## License

The code is licensed under a Lagrange specific license file located in `LICENSE`.
