use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::group::{generator, random_scalar};

pub struct KeyPair {
    pub sk: Scalar,
    pub pk: RistrettoPoint,
}

pub fn generate_keypair() -> KeyPair {
    let sk = random_scalar();
    let pk = sk * generator();
    KeyPair { sk, pk }
}

pub fn global_public_key(public_keys: &[RistrettoPoint]) -> RistrettoPoint {
    public_keys.iter().copied().sum()
}
