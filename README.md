# ZKBoo

Zero Knowledge Prover and Verifier for Boolean Circuits. Currently available is a prover and verifier for SHA-1 and SHA-256. They on OpenSSL for doing commits and randomness generation and use OpenMP for parallelization.

When starting either prover, it will prompt for an input to hash. After entering the input, the proof will be generated as a file in the folder the program resides in. The file is named out<NUM_ROUNDS>.bin where <NUM_ROUNDS> is the number of rounds of the algorithm run (Set to 136 by defauly, but can be changed in shared.h
