use x25519_dalek::{StaticSecret, PublicKey};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};

/// The packet sent over the wire to establish a session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakePacket {
    pub protocol_version: u16,
    pub session_id: u64,
    pub public_key: [u8; 32],
}

pub struct KeyExchange {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyExchange {
    /// Generate a fresh, random keypair.
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Combine our Secret with their Public to get the Shared Key.
    pub fn derive_shared_secret(self, peer_public_bytes: [u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(peer_public_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}
