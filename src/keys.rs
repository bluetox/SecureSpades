use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::group::{generator, random_scalar};

/// An ElGamal key pair.
///
/// A key pair consists of a secret scalar `sk` and its corresponding
/// public key `pk`.
///
/// The public key is computed as:
///
/// ```text
/// pk = sk * G
/// ```
///
/// where `G` is the Ristretto group generator.
pub struct KeyPair {
    /// The secret key.
    ///
    /// This value must be kept secret.
    pub sk: Scalar,

    /// The public key corresponding to [`Self::sk`].
    pub pk: RistrettoPoint,
}

/// Generates a new ElGamal key pair.
///
/// The secret key is generated using a cryptographically secure random
/// scalar, and the corresponding public key is derived by multiplying
/// the secret key by the Ristretto group generator.
///
/// Returns a [`KeyPair`] containing the generated secret and public keys.
pub fn generate_keypair<R: CryptoRng + RngCore + Default>() -> KeyPair {
    let sk = random_scalar::<R>();
    let pk = sk * generator();

    KeyPair { sk, pk }
}

/// Computes the global public key from a set of public keys.
///
/// The global public key is the sum of all individual public keys:
///
/// ```text
/// PK = pk₁ + pk₂ + ... + pkₙ
/// ```
///
/// If each public key is generated from a secret key `skᵢ` such that:
///
/// ```text
/// pkᵢ = skᵢ * G
/// ```
///
/// then the global public key corresponds to the sum of the secret keys:
///
/// ```text
/// PK = (sk₁ + sk₂ + ... + skₙ) * G
/// ```
///
/// # Arguments
///
/// * `public_keys` - The individual public keys to combine.
///
/// Returns the resulting global public key.
///
/// # Panics
///
/// This function does not panic for an empty slice; an empty input
/// produces the Ristretto identity element.
pub fn global_public_key(public_keys: &[RistrettoPoint]) -> RistrettoPoint {
    public_keys.iter().copied().sum()
}