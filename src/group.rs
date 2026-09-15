use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

pub fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}
