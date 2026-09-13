use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::cards::CardProvider;
use crate::elgamal::{Ciphertext, randomize_with_randomness};
use crate::group::random_scalar;

const SHUFFLE_PROOF_DOMAIN: &[u8] = b"secureSpades/shuffle-proof/v1";

pub fn validate_permutation(
    permutation: &[usize],
    expected_len: usize,
) -> Result<(), &'static str> {
    if permutation.len() != expected_len {
        return Err("Permutation length mismatch");
    }
    let mut seen = vec![false; expected_len];
    for &idx in permutation {
        if idx >= expected_len {
            return Err("Permutation index out of bounds");
        }
        if seen[idx] {
            return Err("Duplicate index in permutation");
        }
        seen[idx] = true;
    }
    Ok(())
}

pub fn random_permutation(len: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (0..len).collect();
    for i in (1..len).rev() {
        let j = random_bounded_usize(i + 1);
        p.swap(i, j);
    }
    p
}

fn random_bounded_usize(bound: usize) -> usize {
    let limit = 256 - (256 % bound);
    let mut byte = [0u8; 1];
    loop {
        getrandom::fill(&mut byte).expect("failed to obtain randomness");
        let val = byte[0] as usize;
        if val < limit {
            return val % bound;
        }
    }
}

pub fn shuffle_with_parameters<C: CardProvider>(
    deck: &[Ciphertext],
    permutation: &[usize],
    randomness: &[Scalar],
    global_pk: &RistrettoPoint,
) -> Vec<Ciphertext> {
    validate_permutation(permutation, C::DECK_SIZE as usize).expect("Invalid permutation");

    let mut shuffled = Vec::with_capacity(C::DECK_SIZE as usize);
    for j in 0..C::DECK_SIZE as usize {
        let input_idx = permutation[j];
        let card = &deck[input_idx];
        let rand_card = randomize_with_randomness(card, global_pk, &randomness[j]);
        shuffled.push(rand_card);
    }
    shuffled
}

pub fn shuffle<C: CardProvider, R: CryptoRng + RngCore + Default>(
    deck: &[Ciphertext],
    global_pk: &RistrettoPoint,
) -> Vec<Ciphertext> {
    let (shuffled, _, _) = shuffle_and_keep_witness::<C, R>(deck, global_pk);
    shuffled
}

pub fn shuffle_and_keep_witness<C: CardProvider, R: CryptoRng + RngCore + Default>(
    deck: &[Ciphertext],
    global_pk: &RistrettoPoint,
) -> (Vec<Ciphertext>, Vec<usize>, Vec<Scalar>) {
    let permutation = random_permutation(C::DECK_SIZE as usize);
    let randomness: Vec<Scalar> = (0..C::DECK_SIZE).map(|_| random_scalar::<R>()).collect();
    let shuffled = shuffle_with_parameters::<C>(deck, &permutation, &randomness, global_pk);
    (shuffled, permutation, randomness)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardShuffleProof {
    pub challenges: Vec<Scalar>,
    pub responses: Vec<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShuffleProof {
    pub card_proofs: Vec<CardShuffleProof>,
}

pub fn prove_shuffle<C: CardProvider, R: CryptoRng + RngCore + Default>(
    input: &[Ciphertext],
    output: &[Ciphertext],
    permutation: &[usize],
    randomness: &[Scalar],
    global_pk: &RistrettoPoint,
) -> ShuffleProof {
    let n = input.len();
    validate_permutation(permutation, C::DECK_SIZE as usize).expect("Invalid permutation");

    let mut card_proofs = Vec::with_capacity(n);

    for j in 0..n {
        let real_branch = permutation[j];
        let r_j = randomness[j];
        let out_j = &output[j];

        let mut challenges = vec![Scalar::ZERO; n];
        let mut responses = vec![Scalar::ZERO; n];
        let mut commitments = Vec::with_capacity(n);

        let mut nonce_w = Scalar::ZERO;

        for l in 0..n {
            let delta_c1 = out_j.c1 - input[l].c1;
            let delta_c2 = out_j.c2 - input[l].c2;

            if l == real_branch {
                nonce_w = random_scalar::<R>();
                let a_real = nonce_w * RISTRETTO_BASEPOINT_POINT;
                let b_real = nonce_w * global_pk;
                commitments.push((a_real, b_real));
            } else {
                let c_l = random_scalar::<R>();
                let s_l = random_scalar::<R>();
                challenges[l] = c_l;
                responses[l] = s_l;

                let a_l = s_l * RISTRETTO_BASEPOINT_POINT - c_l * delta_c1;
                let b_l = s_l * global_pk - c_l * delta_c2;
                commitments.push((a_l, b_l));
            }
        }

        let master_challenge = compute_shuffle_challenge(global_pk, input, out_j, j, &commitments);

        let mut sum_simulated = Scalar::ZERO;
        for (l, &ch) in challenges.iter().enumerate() {
            if l != real_branch {
                sum_simulated += ch;
            }
        }
        let real_c = master_challenge - sum_simulated;
        challenges[real_branch] = real_c;

        let real_s = nonce_w + real_c * r_j;
        responses[real_branch] = real_s;

        card_proofs.push(CardShuffleProof {
            challenges,
            responses,
        });
    }

    ShuffleProof { card_proofs }
}

pub fn verify_shuffle<C: CardProvider>(
    input: &[Ciphertext],
    output: &[Ciphertext],
    proof: &ShuffleProof,
    global_pk: &RistrettoPoint,
) -> bool {
    let n = input.len();
    if n != C::DECK_SIZE as usize
        || output.len() != C::DECK_SIZE as usize
        || proof.card_proofs.len() != C::DECK_SIZE as usize
    {
        return false;
    }

    for (j, (card_proof, out_j)) in proof.card_proofs.iter().zip(output.iter()).enumerate() {
        if card_proof.challenges.len() != n || card_proof.responses.len() != n {
            return false;
        }

        let mut commitments = Vec::with_capacity(n);

        for (l, in_l) in input.iter().enumerate() {
            let delta_c1 = out_j.c1 - in_l.c1;
            let delta_c2 = out_j.c2 - in_l.c2;

            let c_l = card_proof.challenges[l];
            let s_l = card_proof.responses[l];

            let a_l = s_l * RISTRETTO_BASEPOINT_POINT - c_l * delta_c1;
            let b_l = s_l * global_pk - c_l * delta_c2;
            commitments.push((a_l, b_l));
        }

        let master_challenge = compute_shuffle_challenge(global_pk, input, out_j, j, &commitments);

        let sum_challenges: Scalar = card_proof.challenges.iter().sum();
        if sum_challenges != master_challenge {
            return false;
        }
    }

    true
}

fn compute_shuffle_challenge(
    global_pk: &RistrettoPoint,
    input: &[Ciphertext],
    output_card: &Ciphertext,
    card_index: usize,
    commitments: &[(RistrettoPoint, RistrettoPoint)],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(SHUFFLE_PROOF_DOMAIN);
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(global_pk.compress().as_bytes());
    hasher.update((input.len() as u64).to_le_bytes());

    for c in input {
        hasher.update(c.c1.compress().as_bytes());
        hasher.update(c.c2.compress().as_bytes());
    }

    hasher.update(output_card.c1.compress().as_bytes());
    hasher.update(output_card.c2.compress().as_bytes());
    hasher.update((card_index as u64).to_le_bytes());

    for (a, b) in commitments {
        hasher.update(a.compress().as_bytes());
        hasher.update(b.compress().as_bytes());
    }

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
