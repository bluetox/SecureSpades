use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

use crate::cards::{CardProvider, encode_card};
use crate::group::random_scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

pub fn encrypt<R: CryptoRng + RngCore>(
    message: &RistrettoPoint,
    pk: &RistrettoPoint,
    rng: &mut R,
) -> Ciphertext {
    let r = random_scalar(rng);
    encrypt_with_randomness(message, pk, &r)
}

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

pub fn decrypt(ciphertext: &Ciphertext, sk: &Scalar) -> RistrettoPoint {
    ciphertext.c2 - sk * ciphertext.c1
}

pub fn encrypt_card<R: CryptoRng + RngCore>(
    card_id: u16,
    global_pk: &RistrettoPoint,
    rng: &mut R,
) -> Ciphertext {
    let message = encode_card(card_id);
    encrypt(&message, global_pk, rng)
}

pub fn encrypt_deck<C: CardProvider, R: CryptoRng + RngCore>(
    global_pk: &RistrettoPoint,
    rng: &mut R,
) -> Vec<Ciphertext> {
    C::get_deck()
        .into_iter()
        .map(|id| encrypt_card(id, global_pk, rng))
        .collect()
}

pub fn randomize<R: CryptoRng + RngCore>(
    ciphertext: &Ciphertext,
    global_pk: &RistrettoPoint,
    rng: &mut R,
) -> Ciphertext {
    let r = random_scalar(rng);
    randomize_with_randomness(ciphertext, global_pk, &r)
}

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

pub fn partial_decrypt(ciphertext: &Ciphertext, sk: &Scalar) -> RistrettoPoint {
    sk * ciphertext.c1
}

pub fn remove_partial_decryption(ciphertext: &Ciphertext, partial: &RistrettoPoint) -> Ciphertext {
    Ciphertext {
        c1: ciphertext.c1,
        c2: ciphertext.c2 - partial,
    }
}

pub fn decrypt_after_partials(ciphertext: &Ciphertext, owner_sk: &Scalar) -> RistrettoPoint {
    ciphertext.c2 - owner_sk * ciphertext.c1
}
