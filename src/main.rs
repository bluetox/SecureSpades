#![allow(non_snake_case)]

use secureSpades::KeyPair;
use secureSpades::cards::{CardProvider, IpsoCardProvider, decode_card};
use secureSpades::elgamal::{
    decrypt_after_partials, encrypt_deck, partial_decrypt, remove_partial_decryption,
};
use secureSpades::group::generator;
use secureSpades::keys::{generate_keypair, global_public_key};
use secureSpades::proof::SchnorrProof;
use secureSpades::shuffle::{prove_shuffle, shuffle_and_keep_witness, verify_shuffle};

fn main() {
    println!("=== SecureSpades Core Cryptography Protocol Demo ===");
    let g = generator();

    println!("\n[1] Generating key pairs for 4 players...");
    let p1 = generate_keypair();
    let p2 = generate_keypair();
    let p3 = generate_keypair();
    let p4 = generate_keypair();

    println!("  Player 1 PK: {:?}", p1.pk.compress());
    println!("  Player 2 PK: {:?}", p2.pk.compress());
    println!("  Player 3 PK: {:?}", p3.pk.compress());
    println!("  Player 4 PK: {:?}", p4.pk.compress());

    println!("\n[3] Computing global public key (PK = PK1 + PK2 + PK3 + PK4)...");
    let global_pk = global_public_key(&[p1.pk, p2.pk, p3.pk, p4.pk]);
    println!("  Global PK: {:?}", global_pk.compress());

    println!("\n[4] Generating initial encrypted canonical deck (c_{{0,j}} = (G, M_j + PK))...");
    let deck0 = encrypt_deck::<IpsoCardProvider>(&global_pk);
    println!("  ✓ Generated {} initial ciphertexts", deck0.len());

    println!("\n[5] Sequential shuffling by 4 players with ZK shuffle proofs...");

    let (deck1, perm1, rand1) = shuffle_and_keep_witness::<IpsoCardProvider>(&deck0, &global_pk);

    let proof_shuffle1 =
        prove_shuffle::<IpsoCardProvider>(&deck0, &deck1, &perm1, &rand1, &global_pk);
    assert!(verify_shuffle::<IpsoCardProvider>(
        &deck0,
        &deck1,
        &proof_shuffle1,
        &global_pk
    ));
    println!("  ✓ Player 1 shuffle proof verified");

    let (deck2, perm2, rand2) = shuffle_and_keep_witness::<IpsoCardProvider>(&deck1, &global_pk);
    let proof_shuffle2 =
        prove_shuffle::<IpsoCardProvider>(&deck1, &deck2, &perm2, &rand2, &global_pk);
    assert!(verify_shuffle::<IpsoCardProvider>(
        &deck1,
        &deck2,
        &proof_shuffle2,
        &global_pk
    ));
    println!("  ✓ Player 2 shuffle proof verified");

    let (deck3, perm3, rand3) = shuffle_and_keep_witness::<IpsoCardProvider>(&deck2, &global_pk);
    let proof_shuffle3 =
        prove_shuffle::<IpsoCardProvider>(&deck2, &deck3, &perm3, &rand3, &global_pk);
    assert!(verify_shuffle::<IpsoCardProvider>(
        &deck2,
        &deck3,
        &proof_shuffle3,
        &global_pk
    ));
    println!("  ✓ Player 3 shuffle proof verified");

    let (deck4, perm4, rand4) = shuffle_and_keep_witness::<IpsoCardProvider>(&deck3, &global_pk);
    let proof_shuffle4 =
        prove_shuffle::<IpsoCardProvider>(&deck3, &deck4, &perm4, &rand4, &global_pk);
    assert!(verify_shuffle::<IpsoCardProvider>(
        &deck3,
        &deck4,
        &proof_shuffle4,
        &global_pk
    ));
    println!("  ✓ Player 4 shuffle proof verified");

    println!("\n[6] Dealing hands (13 cards each) and performing partial decryptions...");
    let players = [&p1, &p2, &p3, &p4];
    let mut total_recovered = 0;

    for (player_idx, owner) in players.iter().enumerate() {
        let start_idx = player_idx * (IpsoCardProvider::DECK_SIZE as usize / players.len());
        let end_idx = start_idx + (IpsoCardProvider::DECK_SIZE as usize / players.len());
        println!(
            "  Player {} cards (indices {}..{}):",
            player_idx + 1,
            start_idx,
            end_idx
        );

        for &card_ciphertext in &deck4[start_idx..end_idx] {
            let mut ciphertext = card_ciphertext;

            for (other_idx, other_player) in players.iter().enumerate() {
                if other_idx != player_idx {
                    let theta = partial_decrypt(&card_ciphertext, &other_player.sk);
                    ciphertext = remove_partial_decryption(&ciphertext, &theta);
                }
            }

            let plaintext_point = decrypt_after_partials(&ciphertext, &owner.sk);
            let card_id =
                decode_card::<IpsoCardProvider>(&plaintext_point).expect("decoding card ID");
            let card = card_id;
            total_recovered += 1;
            print!("    [{:?}] ", card);
        }
        println!();
    }

    println!(
        "\n✓ Protocol execution complete: {} cards successfully dealt and verified.",
        total_recovered
    );
}
