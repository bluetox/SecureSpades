use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};

pub fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes).expect("failed to obtain randomness");
    Scalar::from_bytes_mod_order_wide(&bytes)
}
