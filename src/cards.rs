use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};

/// Defines the behaviour required to apply the Secure Spades protocol
/// to a card game.
///
/// A [`CardProvider`] specifies how a game's deck is represented and
/// provides the information required by the protocol to validate and
/// manipulate that deck.
pub trait CardProvider {
    /// The type used to represent the game's deck.
    ///
    /// The deck must be iterable and each card must be represented
    /// by a [`u16`] identifier.
    type Deck: IntoIterator<Item = u16>;

    /// The number of cards in the deck.
    ///
    /// This value is used by the protocol to validate card identifiers,
    /// permutations, and other deck-related data.
    ///
    /// The value must accurately represent the number of cards returned
    /// by [`Self::get_deck`].
    const DECK_SIZE: u16;

    /// Returns the complete deck of the game.
    ///
    /// Each card must be represented by a unique [`u16`] identifier.
    /// The returned deck must contain exactly [`Self::DECK_SIZE`] cards.
    fn get_deck() -> Self::Deck;
}

/// Encodes a card identifier as a [`RistrettoPoint`].
///
/// The identifier is interpreted as a scalar and multiplied by the
/// Ristretto base point.
///
/// This encoding is deterministic: the same card identifier always
/// produces the same point.
pub fn encode_card(id: u16) -> RistrettoPoint {
    Scalar::from(id as u64) * RISTRETTO_BASEPOINT_POINT
}

/// Attempts to decode a [`RistrettoPoint`] into its corresponding
/// card identifier.
///
/// Returns [`Some`] with the card identifier if `point` corresponds
/// to a valid card in the deck defined by `C`. Returns [`None`] if
/// no card in the deck produces the given point.
pub fn decode_card<C: CardProvider>(point: &RistrettoPoint) -> Option<u16> {
    (1..=C::DECK_SIZE).find(|&id| encode_card(id) == *point)
}
