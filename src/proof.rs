use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha2::{Digest, Sha512};

use crate::group::random_scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    pub commitment: RistrettoPoint,
    pub response: Scalar,
}

impl SchnorrProof {
    pub fn prove(sk: &Scalar, pk: &RistrettoPoint, generator_point: &RistrettoPoint) -> Self {
        let r = random_scalar();
        let commitment = r * generator_point;
        let challenge = compute_challenge(generator_point, pk, &commitment);
        let response = r + challenge * sk;

        Self {
            commitment,
            response,
        }
    }

    pub fn verify(&self, pk: &RistrettoPoint, generator_point: &RistrettoPoint) -> bool {
        let challenge = compute_challenge(generator_point, pk, &self.commitment);
        let lhs = self.response * generator_point;
        let rhs = self.commitment + challenge * pk;

        lhs == rhs
    }
}

fn compute_challenge(
    generator_point: &RistrettoPoint,
    pk: &RistrettoPoint,
    commitment: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"secureSpades/schnorr-proof/v1");
    hasher.update(generator_point.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(commitment.compress().as_bytes());
    let hash = hasher.finalize();

    Scalar::from_bytes_mod_order_wide(&hash.into())
}
