use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};

pub trait CardProvider {
    type Deck: IntoIterator<Item = u16>;
    const DECK_SIZE: u16;
    fn get_deck() -> Self::Deck;
}

pub fn encode_card(id: u16) -> RistrettoPoint {
    Scalar::from(id as u64) * RISTRETTO_BASEPOINT_POINT
}

pub fn decode_card<C: CardProvider>(point: &RistrettoPoint) -> Option<u16> {
    (1..=C::DECK_SIZE).find(|&id| encode_card(id) == *point)
}
