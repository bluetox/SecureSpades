use core::panic;
use std::sync::mpsc::{self, Receiver, Sender};
use std::{println, vec};

use curve25519_dalek::RistrettoPoint;
use rand::SeedableRng;
use rand::rngs::StdRng;

use secureSpades::cards::{CardProvider, decode_card};
use secureSpades::elgamal::{
    encrypt_deck, partial_decrypt, remove_partial_decryption,
};
use secureSpades::group::generator;
use secureSpades::keys::{generate_keypair, global_public_key};
use secureSpades::proof::{
    PartialDecryptionProof, prove_partial_decryption, verify_partial_decryption,
};
use secureSpades::shuffle::{prove_shuffle, shuffle_and_keep_witness, verify_shuffle};
use secureSpades::{Ciphertext, KeyPair, SchnorrProof, ShuffleProof, proof};

struct IpsoCardProvider;

impl CardProvider for IpsoCardProvider {
    type Deck = [u16; Self::DECK_SIZE as usize];

    const DECK_SIZE: u16 = 90;

    fn get_deck() -> Self::Deck {
        std::array::from_fn(|i| (i + 1) as u16)
    }
}

fn show_pyramid(pyramid: &[u16]) {
    let mut counter = 2;
    let mut index = 0;
    while index <= pyramid.len() - counter {
        println!("{:?}", &pyramid[index..index + counter]);
        index += counter;
        counter += 1;
    }
}

enum IpsoPacket {
    Join(JoinPacket),
    InitialDeck(Vec<Ciphertext>),
    Shuffle(ShufflePacket),
    DecryptionRequest(DecryptionRequestPacket),
    CardDecryptionAndProof(CardDecryptionAndProofPacket),
    DecryptedCard(DecryptedCardPacket),
    CommitMove(CommitMovePacket),
}

struct CommitMovePacket {
    middle_index: u8,
    pyramid_index: u8,
}

struct DecryptionRequestPacket {
    card: u16,
    ct: Ciphertext,
}

#[derive(Clone)]
struct DecryptedCardPacket {
    index: usize,
    card: u16,
    steps: Vec<DecryptStep>,
}

#[derive(Clone)]
struct DecryptStep {
    theta: RistrettoPoint,
    proof: PartialDecryptionProof,
    player_id: u16,
}

struct CardDecryptionAndProofPacket {
    proof: PartialDecryptionProof,
    theta: RistrettoPoint,
}

#[derive(Clone)]
struct JoinPacket {
    pk: RistrettoPoint,
    proof: SchnorrProof,
}

#[derive(Clone)]
struct ShufflePacket {
    n_deck: Vec<Ciphertext>,
    proof: ShuffleProof,
}

struct Player {
    id: usize,
    senders: Vec<Option<Sender<IpsoPacket>>>,
    receivers: Vec<Option<Receiver<IpsoPacket>>>,
}

impl Player {
    fn decrypt_card(
        &mut self,
        card_index: usize,
        decks: &[Vec<Ciphertext>],
        player_count: usize,
        players_keys: &[RistrettoPoint],
        keypair: &KeyPair,
        rng: &mut StdRng,
    ) -> (u16, Vec<DecryptStep>) {
        let ct = decks[player_count][card_index];
        let mut steps: Vec<DecryptStep> = Vec::with_capacity(player_count);

        for player_id in 0..player_count {
            if player_id == self.id {
                continue;
            }
            self.senders[player_id]
                .as_mut()
                .unwrap()
                .send(IpsoPacket::DecryptionRequest(DecryptionRequestPacket {
                    card: card_index as u16,
                    ct,
                }))
                .unwrap();

            let packet = self.receivers[player_id].as_mut().unwrap().recv().unwrap();

            let packet = match packet {
                IpsoPacket::CardDecryptionAndProof(p) => p,
                _ => panic!("Expected CardDecryptionAndProof"),
            };

            assert!(
                verify_partial_decryption(
                    &ct.c1,
                    &players_keys[player_id],
                    &packet.theta,
                    &packet.proof,
                ),
                "Invalid partial decryption from player {}",
                player_id
            );

            steps.push(DecryptStep {
                theta: packet.theta,
                proof: packet.proof,
                player_id: player_id as u16,
            });
        }

        let theta = partial_decrypt(&ct, &keypair.sk);

        let proof = prove_partial_decryption(&ct.c1, &keypair.pk, &keypair.sk, &theta, rng);

        assert!(
            verify_partial_decryption(&ct.c1, &keypair.pk, &theta, &proof,),
            "Our own partial decryption proof is invalid"
        );

        steps.push(DecryptStep {
            theta,
            proof,
            player_id: self.id as u16,
        });
        let mut decrypted_ct = ct;

        for step in &steps {
            decrypted_ct = remove_partial_decryption(&decrypted_ct, &step.theta);
        }

        let plaintext = decrypted_ct.c2;
        let value =
            decode_card::<IpsoCardProvider>(&plaintext).expect("Failed to decode decrypted card");
        return (value, steps);
    }
    pub fn run(&mut self) {
        let player_count = self.senders.len();
        let mut rng = StdRng::from_os_rng();
        let keypair = generate_keypair(&mut rng);
        let keypair_proof =
            proof::SchnorrProof::prove(&keypair.sk, &keypair.pk, &generator(), &mut rng);

        let join_message = JoinPacket {
            pk: keypair.pk,
            proof: keypair_proof,
        };

        for sender in self.senders.iter_mut() {
            if let Some(s) = sender {
                s.send(IpsoPacket::Join(join_message.clone())).unwrap();
            }
        }

        let mut players_keys: Vec<RistrettoPoint> = vec![RistrettoPoint::default(); 4];
        for (i, receiver) in self.receivers.iter_mut().enumerate() {
            if let Some(s) = receiver {
                let packet = s.recv().unwrap();
                let join = match packet {
                    IpsoPacket::Join(p) => p,
                    _ => panic!("First packet should be a join"),
                };

                if join.proof.verify(&join.pk, &generator()) {
                    players_keys[i] = join.pk;
                } else {
                    panic!("Unable to verify proof of player {}", i);
                }
            } else {
                players_keys[i] = keypair.pk;
            }
        }

        let global_pk = global_public_key(&players_keys);

        println!("global pk: {:?}", global_pk.compress());

        let deck0 = if self.id == 0 {
            let deck = encrypt_deck::<IpsoCardProvider, _>(&global_pk, &mut rng);

            for sender in self.senders.iter() {
                if let Some(sender) = sender {
                    sender.send(IpsoPacket::InitialDeck(deck.clone())).unwrap();
                }
            }

            deck
        } else {
            let receiver = self.receivers[0].as_mut().unwrap();

            match receiver.recv().unwrap() {
                IpsoPacket::InitialDeck(deck) => deck,
                _ => panic!("Expected initial deck"),
            }
        };
        let mut decks = vec![deck0];
        let mut shuffling_proof_turn = 0;

        while shuffling_proof_turn < player_count {
            if shuffling_proof_turn == self.id {
                let (n_deck, perm, r) = shuffle_and_keep_witness::<IpsoCardProvider, _>(
                    &decks[shuffling_proof_turn],
                    &global_pk,
                    &mut rng,
                );
                decks.push(n_deck.clone());
                let proof = prove_shuffle::<IpsoCardProvider, _>(
                    &decks[shuffling_proof_turn],
                    &n_deck,
                    &perm,
                    &r,
                    &global_pk,
                    &mut rng,
                );
                let packet = ShufflePacket { proof, n_deck };

                for sender in self.senders.iter_mut() {
                    if let Some(s) = sender {
                        s.send(IpsoPacket::Shuffle(packet.clone())).unwrap();
                    }
                }
            } else {
                let packet = self.receivers[shuffling_proof_turn]
                    .as_mut()
                    .unwrap()
                    .recv()
                    .unwrap();
                let shuffle = match packet {
                    IpsoPacket::Shuffle(s) => s,
                    _ => panic!("Should have received a shuffle"),
                };
                assert!(
                    verify_shuffle::<IpsoCardProvider>(
                        &decks[shuffling_proof_turn],
                        &shuffle.n_deck,
                        &shuffle.proof,
                        &global_pk
                    ) == true
                );
                decks.push(shuffle.n_deck);
            }
            shuffling_proof_turn += 1;
        }

        let mut middle_cards = [0u16; 2];

        if self.id == 0 {
            for card_index in 0..2 {
                let (value, steps) = self.decrypt_card(
                    card_index,
                    &decks,
                    player_count,
                    &players_keys,
                    &keypair,
                    &mut rng,
                );

                middle_cards[card_index] = value;

                let packet = DecryptedCardPacket {
                    index: card_index,
                    card: value,
                    steps,
                };

                for player_id in 1..player_count {
                    self.senders[player_id]
                        .as_mut()
                        .unwrap()
                        .send(IpsoPacket::DecryptedCard(packet.clone()))
                        .unwrap();
                }
            }

            println!("Both middle cards have been decrypted.");
        } else {
            let mut decrypted1 = false;
            let mut decrypted2 = false;
            loop {
                let packet = self.receivers[0].as_mut().unwrap().recv().unwrap();

                match packet {
                    IpsoPacket::DecryptionRequest(request) => {
                        let theta = partial_decrypt(&request.ct, &keypair.sk);
                        assert!(matches!(request.card, 0 | 1));
                        let proof = prove_partial_decryption(
                            &request.ct.c1,
                            &keypair.pk,
                            &keypair.sk,
                            &theta,
                            &mut rng,
                        );

                        self.senders[0]
                            .as_mut()
                            .unwrap()
                            .send(IpsoPacket::CardDecryptionAndProof(
                                CardDecryptionAndProofPacket { proof, theta },
                            ))
                            .unwrap();
                    }

                    IpsoPacket::DecryptedCard(result) => {
                        let original_ct = decks[player_count][result.index];
                        let mut ciphertext = original_ct;

                        assert_eq!(
                            result.steps.len(),
                            player_count,
                            "Missing decryption contribution"
                        );

                        let mut seen = vec![false; player_count];

                        for step in &result.steps {
                            let player_id = step.player_id as usize;
                            assert!(player_id < player_count, "Invalid player ID");
                            assert!(!seen[player_id], "Duplicate decryption contribution");

                            seen[player_id] = true;

                            let pk = &players_keys[player_id];

                            assert!(
                                verify_partial_decryption(
                                    &original_ct.c1,
                                    pk,
                                    &step.theta,
                                    &step.proof,
                                ),
                                "Invalid decryption proof from player {}",
                                player_id
                            );

                            ciphertext = remove_partial_decryption(&ciphertext, &step.theta);
                        }

                        assert!(
                            seen.iter().all(|seen| *seen),
                            "Not every player contributed"
                        );

                        let plaintext = ciphertext.c2;
                        let value = decode_card::<IpsoCardProvider>(&plaintext)
                            .expect("Failed to decode card");

                        assert_eq!(value, result.card, "Player 0 lied about the decrypted card");

                        if result.index == 0 {
                            decrypted1 = true;
                            middle_cards[0] = result.card;
                        } else {
                            decrypted2 = true;
                            middle_cards[1] = result.card;
                        }

                        if decrypted1 && decrypted2 {
                            break;
                        }
                    }

                    _ => {
                        panic!("Unexpected packet during decryption");
                    }
                }
            }
        }
        println!("player {} done", self.id);

        let pyramid_size = 14;
        let mut pyramids: Vec<Vec<u16>> = vec![
            vec![0u16; pyramid_size],
            vec![0u16; pyramid_size],
            vec![0u16; pyramid_size],
            vec![0u16; pyramid_size],
        ];

        // This is used because we do not manually chose a move we make them in order
        let mut personal_pyramid_index = 0;

        let mut total_recovered = 2;
        let mut current_player = 0;

        while total_recovered != pyramid_size * player_count {
            if current_player == self.id {
                for sender in self.senders.iter_mut() {
                    if let Some(s) = sender {
                        s.send(IpsoPacket::CommitMove(CommitMovePacket {
                            middle_index: 0,
                            pyramid_index: personal_pyramid_index,
                        }))
                        .unwrap();
                    }
                }
                pyramids[current_player][personal_pyramid_index as usize] = middle_cards[0];
                let (value, steps) = self.decrypt_card(
                    total_recovered as usize,
                    &decks,
                    player_count,
                    &players_keys,
                    &keypair,
                    &mut rng,
                );

                let packet = DecryptedCardPacket {
                    index: total_recovered as usize,
                    card: value,
                    steps,
                };

                for player_id in 0..player_count {
                    if player_id != self.id {
                        self.senders[player_id]
                            .as_mut()
                            .unwrap()
                            .send(IpsoPacket::DecryptedCard(packet.clone()))
                            .unwrap();
                    }
                }
                personal_pyramid_index += 1;
            } else {
                let mut commit = [0u8; 2];
                let mut is_commit = false;
                loop {
                    let packet = self.receivers[current_player]
                        .as_mut()
                        .unwrap()
                        .recv()
                        .unwrap();

                    match packet {
                        IpsoPacket::CommitMove(c) => {
                            if is_commit {
                                panic!("Player tried to commit twice");
                            }
                            assert!(c.middle_index < 2, "Invalid middle card index");

                            assert!(
                                (c.pyramid_index as usize) < pyramid_size,
                                "Invalid pyramid index"
                            );

                            assert_eq!(
                                pyramids[current_player][c.pyramid_index as usize], 0,
                                "Already played this move"
                            );
                            commit[0] = c.middle_index;
                            commit[1] = c.pyramid_index;
                            is_commit = true;
                        }
                        IpsoPacket::DecryptionRequest(request) => {
                            assert!(request.card == total_recovered as u16);
                            let theta = partial_decrypt(&request.ct, &keypair.sk);
                            let proof = prove_partial_decryption(
                                &request.ct.c1,
                                &keypair.pk,
                                &keypair.sk,
                                &theta,
                                &mut rng,
                            );

                            self.senders[current_player]
                                .as_mut()
                                .unwrap()
                                .send(IpsoPacket::CardDecryptionAndProof(
                                    CardDecryptionAndProofPacket { proof, theta },
                                ))
                                .unwrap();
                        }

                        IpsoPacket::DecryptedCard(result) => {
                            let original_ct = decks[player_count][result.index];
                            let mut ciphertext = original_ct;

                            assert_eq!(
                                result.steps.len(),
                                player_count,
                                "Missing decryption contribution"
                            );

                            let mut seen = vec![false; player_count];

                            for step in &result.steps {
                                let player_id = step.player_id as usize;
                                assert!(player_id < player_count, "Invalid player ID");
                                assert!(!seen[player_id], "Duplicate decryption contribution");

                                seen[player_id] = true;

                                let pk = &players_keys[player_id];

                                assert!(
                                    verify_partial_decryption(
                                        &original_ct.c1,
                                        pk,
                                        &step.theta,
                                        &step.proof,
                                    ),
                                    "Invalid decryption proof from player {}",
                                    player_id
                                );

                                ciphertext = remove_partial_decryption(&ciphertext, &step.theta);
                            }

                            assert!(
                                seen.iter().all(|seen| *seen),
                                "Not every player contributed"
                            );

                            let plaintext = ciphertext.c2;
                            let value = decode_card::<IpsoCardProvider>(&plaintext)
                                .expect("Failed to decode card");

                            assert_eq!(
                                value, result.card,
                                "Player 0 lied about the decrypted card"
                            );
                            pyramids[current_player][commit[1] as usize] =
                                middle_cards[commit[0] as usize];
                            middle_cards[commit[0] as usize] = result.card;
                            break;
                        }

                        _ => {
                            panic!("Unexpected packet during decryption");
                        }
                    }
                }
            }
            total_recovered += 1;
            current_player = (current_player + 1) % 4;
        }

        println!("Player {}'s pyramid", self.id);
        show_pyramid(&pyramids[self.id]);

        // Minimalist Implementation which explains the abscence of the star card and final play
    }
}

fn main() {
    const PLAYER_COUNT: usize = 4;

    let mut senders: Vec<Vec<Option<Sender<IpsoPacket>>>> = (0..PLAYER_COUNT)
        .map(|_| (0..PLAYER_COUNT).map(|_| None).collect())
        .collect();

    let mut receivers: Vec<Vec<Option<Receiver<IpsoPacket>>>> = (0..PLAYER_COUNT)
        .map(|_| (0..PLAYER_COUNT).map(|_| None).collect())
        .collect();

    // Create one channel for every direction.
    for from in 0..PLAYER_COUNT {
        for to in 0..PLAYER_COUNT {
            if from == to {
                continue;
            }

            let (sender, receiver) = mpsc::channel();

            senders[from][to] = Some(sender);
            receivers[to][from] = Some(receiver);
        }
    }

    // Build players.
    let players: Vec<Player> = senders
        .into_iter()
        .zip(receivers)
        .enumerate()
        .map(|(id, (senders, receivers))| Player {
            id,
            senders,
            receivers,
        })
        .collect();
    let mut handles = Vec::new();
    for mut player in players {
        handles.push(std::thread::spawn(move || {
            player.run();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}
