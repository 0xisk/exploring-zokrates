# Tutorial: A SNARK Powered RNG
> Source: https://zokrates.github.io/examples/rng_tutorial.html

## Description of the problem

Alice and Bob want to bet on the result of a series of coin tosses. To do so, they need to generate a series of random bits. They proceed as follows:

1. Each of them commits to a 512 bit value. Let’s call this value the preimage. They publish the hash of the preimage.
2. Each time they need a new random value, they reveal one bit from their preimage, and agree that the new random value is the result of XORing these two bits, so that neither of them can control the output.

Note that we are making a few assumptions here:

1. They make sure they do not use all 512 bits of their preimage, as the more they reveal, the easier it gets for the other to brute-force their preimage.
1. They need a way to be convinced that the bit the other revealed is indeed part of their preimage.

In this tutorial you learn how to use Zokrates and zero knowledge proofs to reveal a single bit from the preimage of a hash value.
