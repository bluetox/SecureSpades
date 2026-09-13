//! Implementation of the Secure Spades protocol
//! 
#![warn(missing_docs)]
#![allow(non_snake_case)]


pub mod cards;
pub mod elgamal;
pub mod group;
pub mod keys;
pub mod proof;
pub mod shuffle;

pub use cards::{decode_card, encode_card};
pub use elgamal::{
    Ciphertext, decrypt, decrypt_after_partials, encrypt, encrypt_card, encrypt_deck,
    encrypt_with_randomness, partial_decrypt, randomize, randomize_with_randomness,
    remove_partial_decryption,
};
pub use group::{generator, random_scalar};
pub use keys::{KeyPair, generate_keypair, global_public_key};
pub use proof::SchnorrProof;
pub use shuffle::{
    ShuffleProof, prove_shuffle, shuffle, shuffle_and_keep_witness, shuffle_with_parameters,
    verify_shuffle,
};
