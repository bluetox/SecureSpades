use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::group::random_scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    pub commitment: RistrettoPoint,
    pub response: Scalar,
}

impl SchnorrProof {
    pub fn prove<R: CryptoRng + RngCore>(
        sk: &Scalar,
        pk: &RistrettoPoint,
        generator_point: &RistrettoPoint,
        rng: &mut R,
    ) -> Self {
        let r = random_scalar(rng);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialDecryptionProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub response: Scalar,
}

pub fn prove_partial_decryption<R: CryptoRng + RngCore>(
    c1: &RistrettoPoint,
    pk: &RistrettoPoint,
    sk: &Scalar,
    theta: &RistrettoPoint,
    rng: &mut R,
) -> PartialDecryptionProof {
    let r = random_scalar(rng);

    let t1 = r * RISTRETTO_BASEPOINT_POINT;
    let t2 = r * c1;

    let challenge = compute_partial_decryption_challenge(c1, pk, theta, &t1, &t2);

    let response = r + challenge * sk;

    PartialDecryptionProof { t1, t2, response }
}

pub fn verify_partial_decryption(
    c1: &RistrettoPoint,
    pk: &RistrettoPoint,
    theta: &RistrettoPoint,
    proof: &PartialDecryptionProof,
) -> bool {
    let challenge = compute_partial_decryption_challenge(c1, pk, theta, &proof.t1, &proof.t2);

    let lhs_1 = proof.response * RISTRETTO_BASEPOINT_POINT;
    let rhs_1 = proof.t1 + challenge * pk;

    if lhs_1 != rhs_1 {
        return false;
    }

    let lhs_2 = proof.response * c1;
    let rhs_2 = proof.t2 + challenge * theta;

    lhs_2 == rhs_2
}

fn compute_partial_decryption_challenge(
    c1: &RistrettoPoint,
    pk: &RistrettoPoint,
    theta: &RistrettoPoint,
    t1: &RistrettoPoint,
    t2: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();

    hasher.update(b"secureSpades/partial-decryption-proof/v1");

    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(c1.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(theta.compress().as_bytes());
    hasher.update(t1.compress().as_bytes());
    hasher.update(t2.compress().as_bytes());

    let hash = hasher.finalize();

    Scalar::from_bytes_mod_order_wide(&hash.into())
}
