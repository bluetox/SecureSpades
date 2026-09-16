# Secure Spades

**Secure Spades** is a Rust cryptographic library providing the primitives required to build **trustless card games**.

The library implements cryptographic protocols developed and refined by **Pascale Lafourcade and collaborators**, based on the following research papers:

1. [Practical Construction for Secure Trick-Taking Games Even With Cards Set Aside (2023)](https://perso.limos.fr/~palafour/PAPERS/PDF/s08p2.pdf)
2. [Secure Trick-Taking Games (2019)](https://perso.limos.fr/~palafour/PAPERS/PDF/BL19.pdf)

The goal of the library is to provide reusable, low-level cryptographic primitives while leaving the game-specific logic to the application using it.

## Library Structure

### `cards`

Defines the traits and utility functions required to implement custom card decks.

* Supports custom card representations
* Provides utilities for encoding cards as group elements
* Supports decks containing up to `u16::MAX` distinct cards

### `elgamal`

Provides the structures and operations required for ElGamal encryption.

* Ciphertext representation
* Encryption and re-encryption
* Partial encryption and decryption utilities
* Card encryption helpers

### `group`

Provides basic cryptographic group utilities.

* Ristretto group generator `G`
* Random scalar generation
* Group-related helper functions

### `keys`

Defines key-related structures and utilities.

* `KeyPair` structure
* Secret and public key generation
* Generation of a shared/global public key from multiple participants

### `proof`

Provides zero-knowledge proofs used by the protocols.

* Schnorr proofs
* Partial decryption proofs
* Proof generation
* Proof verification

### `shuffle`

Provides the primitives required to securely shuffle encrypted cards.

* Encrypted deck shuffling
* Shuffle proof generation
* Shuffle proof verification
* Permutation validation

## Cryptographic Properties

This implementation is based on the **Ristretto group** provided by [`curve25519-dalek`](https://docs.rs/curve25519-dalek/).

The generator `G` is the [`RISTRETTO_BASEPOINT_POINT`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/constants/static.RISTRETTO_BASEPOINT_POINT.html) provided by the library.

Other cryptographic parameters and protocol details are based on the associated research papers.

### Security Disclaimer

This implementation has **not been externally audited** and may contain bugs or security vulnerabilities.

While the library is intended as an implementation and demonstration of the protocols described in the referenced papers, **no guarantee is made regarding its security or correctness**.

This library should therefore **not be used in security-critical or sensitive systems** without a thorough independent security review and audit.

## License

This project is licensed under the **MIT License**.

Copyright © 2026 Etienne Beard.

If you use or redistribute this project, please retain the original copyright notice and license.
