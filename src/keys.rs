use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::group::{generator, random_scalar};

pub struct KeyPair {
    pub sk: Scalar,

    pub pk: RistrettoPoint,
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> KeyPair {
    let sk = random_scalar(rng);
    let pk = sk * generator();
    KeyPair { sk, pk }
}

pub fn global_public_key(public_keys: &[RistrettoPoint]) -> RistrettoPoint {
    public_keys.iter().copied().sum()
}
