use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

use crate::cards::{CardProvider, encode_card};
use crate::group::random_scalar;

/// An ElGamal ciphertext over the Ristretto group.
///
/// A ciphertext consists of two Ristretto points:
///
/// - `c1` is the ephemeral public component.
/// - `c2` contains the encoded plaintext combined with the
///   ephemeral shared secret.
///
/// For a plaintext encoded as a Ristretto point `m`, public key `pk`,
/// and encryption randomness `r`, the ciphertext is:
///
/// ```text
/// c1 = r * G
/// c2 = m + r * pk
/// ```
///
/// where `G` is the Ristretto base point.
///
/// The ciphertext can be decrypted using the corresponding private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// The ephemeral public component of the ciphertext.
    pub c1: RistrettoPoint,

    /// The encrypted plaintext component of the ciphertext.
    pub c2: RistrettoPoint,
}

/// Encrypts a message using the given public key.
///
/// This function generates a cryptographically secure random scalar
/// and uses it as the encryption randomness. It then delegates the
/// encryption to [`encrypt_with_randomness`].
///
/// Returns a [`Ciphertext`] containing the encrypted message.
///
/// # Arguments
///
/// * `message` - The message represented as a [`RistrettoPoint`].
/// * `pk` - The public key used for encryption.
///
/// # Security
///
/// A fresh random scalar is generated for each encryption, ensuring
/// that encrypting the same message multiple times produces different
/// ciphertexts.
pub fn encrypt<R: CryptoRng + RngCore + Default>(message: &RistrettoPoint, pk: &RistrettoPoint) -> Ciphertext {
    let r = random_scalar::<R>();
    encrypt_with_randomness(message, pk, &r)
}

/// Encrypts a message using the given public key and random scalar.
///
/// Given a message `m`, public key `pk`, and random scalar `r`, this
/// function computes the ciphertext components:
///
/// ```text
/// c1 = r * G
/// c2 = m + r * pk
/// ```
///
/// where `G` is the Ristretto base point.
///
/// Returns a [`Ciphertext`] containing the encrypted message.
///
/// # Arguments
///
/// * `message` - The message represented as a [`RistrettoPoint`].
/// * `pk` - The public key used for encryption.
/// * `r` - The scalar used as encryption randomness.
///
/// # Security
///
/// The caller is responsible for providing a suitable random scalar.
/// For normal use, prefer [`encrypt`], which generates the randomness
/// using a cryptographically secure random number generator.
pub fn encrypt_with_randomness(
    message: &RistrettoPoint,
    pk: &RistrettoPoint,
    r: &Scalar,
) -> Ciphertext {
    Ciphertext {
        c1: r * RISTRETTO_BASEPOINT_POINT,
        c2: message + r * pk,
    }
}
/// Decrypts an ElGamal ciphertext using the corresponding secret key.
///
/// Given a ciphertext `(c1, c2)` and secret key `sk`, computes the
/// plaintext as:
///
/// ```text
/// m = c2 - sk * c1
/// ```
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext to decrypt.
/// * `sk` - The secret key corresponding to the public key used for encryption.
///
/// Returns the plaintext as a [`RistrettoPoint`].
pub fn decrypt(ciphertext: &Ciphertext, sk: &Scalar) -> RistrettoPoint {
    ciphertext.c2 - sk * ciphertext.c1
}

/// Encrypts a card identifier using the given public key.
///
/// The card identifier is first encoded as a [`RistrettoPoint`].
/// The resulting plaintext is then encrypted using a fresh,
/// implicit encryption randomness.
///
/// # Arguments
///
/// * `card_id` - The identifier of the card to encrypt.
/// * `global_pk` - The public key used to encrypt the card.
///
/// Returns a [`Ciphertext`] containing the encrypted card.
pub fn encrypt_card(card_id: u16, global_pk: &RistrettoPoint) -> Ciphertext {
    let message = encode_card(card_id);
    Ciphertext {
        c1: RISTRETTO_BASEPOINT_POINT,
        c2: message + global_pk,
    }
}

/// Encrypts every card in the deck defined by `C`.
///
/// Each card returned by [`CardProvider::get_deck`] is encoded and
/// encrypted using the given global public key.
///
/// The resulting ciphertexts preserve the order of the cards returned
/// by [`CardProvider::get_deck`].
///
/// # Arguments
///
/// * `global_pk` - The public key used to encrypt the deck.
///
/// Returns a vector containing one ciphertext for each card in the deck.
pub fn encrypt_deck<C: CardProvider>(global_pk: &RistrettoPoint) -> Vec<Ciphertext> {
    C::get_deck()
        .into_iter()
        .map(|id| encrypt_card(id, global_pk))
        .collect()
}

/// Re-randomizes an ElGamal ciphertext.
///
/// Re-randomization adds fresh encryption randomness to an existing
/// ciphertext without changing the underlying plaintext.
///
/// A fresh random scalar is generated internally and used to
/// re-randomize the ciphertext.
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext to re-randomize.
/// * `global_pk` - The public key under which the ciphertext was encrypted.
///
/// Returns a re-randomized [`Ciphertext`] containing the same plaintext.
pub fn randomize<R: CryptoRng + RngCore + Default>(ciphertext: &Ciphertext, global_pk: &RistrettoPoint) -> Ciphertext {
    let r = random_scalar::<R>();
    randomize_with_randomness(ciphertext, global_pk, &r)
}

/// Re-randomizes an ElGamal ciphertext using the provided randomness.
///
/// Given a ciphertext `(c1, c2)` and random scalar `r`, computes:
///
/// ```text
/// c1' = c1 + r * G
/// c2' = c2 + r * pk
/// ```
///
/// The resulting ciphertext encrypts the same plaintext as the original
/// ciphertext while using different encryption randomness.
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext to re-randomize.
/// * `global_pk` - The public key under which the ciphertext was encrypted.
/// * `r` - The scalar used as re-randomization randomness.
///
/// # Security
///
/// The caller is responsible for providing a suitable random scalar.
/// For normal use, prefer [`randomize`], which generates fresh randomness
/// using a cryptographically secure random number generator.
pub fn randomize_with_randomness(
    ciphertext: &Ciphertext,
    global_pk: &RistrettoPoint,
    r: &Scalar,
) -> Ciphertext {
    Ciphertext {
        c1: ciphertext.c1 + r * RISTRETTO_BASEPOINT_POINT,
        c2: ciphertext.c2 + r * global_pk,
    }
}

/// Computes a partial ElGamal decryption.
///
/// Given a ciphertext with first component `c1` and secret key `sk`,
/// computes the secret-key contribution:
///
/// ```text
/// partial = sk * c1
/// ```
///
/// This value can be published or passed to another party, which can
/// remove it from the ciphertext without learning the secret key.
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext to partially decrypt.
/// * `sk` - The secret key used to compute the partial decryption.
///
/// Returns the partial decryption as a [`RistrettoPoint`].
pub fn partial_decrypt(ciphertext: &Ciphertext, sk: &Scalar) -> RistrettoPoint {
    sk * ciphertext.c1
}

/// Removes a partial decryption from a ciphertext.
///
/// Given a partial decryption `partial`, subtracts it from the second
/// ciphertext component:
///
/// ```text
/// c2' = c2 - partial
/// ```
///
/// The first ciphertext component is left unchanged.
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext from which the partial decryption is removed.
/// * `partial` - The partial decryption to remove.
///
/// Returns a [`Ciphertext`] with the partial decryption removed.
pub fn remove_partial_decryption(ciphertext: &Ciphertext, partial: &RistrettoPoint) -> Ciphertext {
    Ciphertext {
        c1: ciphertext.c1,
        c2: ciphertext.c2 - partial,
    }
}

/// Completes decryption after all partial decryptions have been removed.
///
/// Given a ciphertext whose partial decryptions have already been
/// removed, uses the owner's secret key to recover the plaintext:
///
/// ```text
/// m = c2 - owner_sk * c1
/// ```
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext after the required partial decryptions
///   have been removed.
/// * `owner_sk` - The owner's secret key.
///
/// Returns the plaintext as a [`RistrettoPoint`].
pub fn decrypt_after_partials(ciphertext: &Ciphertext, owner_sk: &Scalar) -> RistrettoPoint {
    ciphertext.c2 - owner_sk * ciphertext.c1
}
