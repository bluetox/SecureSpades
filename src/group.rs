use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

/// Returns the generator of the Ristretto group.
///
/// This is the standard Ristretto base point [`RISTRETTO_BASEPOINT_POINT`]
/// provided by `curve25519-dalek`.
pub fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// Generates a cryptographically secure random scalar.
///
/// The scalar is generated from 512 bits of randomness obtained from
/// the operating system's cryptographically secure random number
/// generator and reduced modulo the Ristretto group order.
///
/// # Panics
///
/// Panics if the operating system's random number generator cannot
/// provide the requested randomness.
pub fn random_scalar<R: CryptoRng + RngCore + Default>() -> Scalar {
    let mut bytes = [0u8; 64];
    let mut rng = R::default();
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}