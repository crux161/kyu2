use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// Protocol version used by the authenticated handshake.
pub const PROTOCOL_VERSION: u16 = 2;
/// Baseline capability bit for interoperable peers.
pub const PROTOCOL_BASELINE_CAPS: u16 = 0x0001;
const HANDSHAKE_DOMAIN: &[u8] = b"kyu2/handshake/v2";

const TAG_SIZE: usize = 16;
const TAG_LABEL_CLIENT: u8 = 0x43; // 'C'
const TAG_LABEL_SERVER: u8 = 0x53; // 'S'

/// The initiator/respondent role used for directional key assignment.
#[derive(Debug, Clone, Copy)]
pub enum HandshakeRole {
    Client,
    Server,
}

/// Transcript fields used for context binding.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeContext {
    pub protocol_version: u16,
    pub capabilities: u16,
    pub session_id: u64,
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
}

/// Directional keys split by protocol purpose.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    pub payload_tx: [u8; 32],
    pub payload_rx: [u8; 32],
    pub header_tx: [u8; 32],
    pub header_rx: [u8; 32],
}

/// The packet sent over the wire to establish and authenticate a session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakePacket {
    pub protocol_version: u16,
    pub capabilities: u16,
    pub session_id: u64,
    pub public_key: [u8; 32],
    pub auth_tag: [u8; TAG_SIZE],
}

impl HandshakePacket {
    /// Builds a client hello authenticated with the configured PSK.
    pub fn new_client(session_id: u64, public_key: [u8; 32], psk: &[u8; 32]) -> Self {
        let protocol_version = PROTOCOL_VERSION;
        let capabilities = PROTOCOL_BASELINE_CAPS;
        let auth_tag =
            compute_client_tag(psk, protocol_version, capabilities, session_id, public_key);
        Self {
            protocol_version,
            capabilities,
            session_id,
            public_key,
            auth_tag,
        }
    }

    /// Builds a server hello authenticated with the configured PSK.
    pub fn new_server(
        session_id: u64,
        server_public: [u8; 32],
        client_public: [u8; 32],
        psk: &[u8; 32],
    ) -> Self {
        let protocol_version = PROTOCOL_VERSION;
        let capabilities = PROTOCOL_BASELINE_CAPS;
        let auth_tag = compute_server_tag(
            psk,
            protocol_version,
            capabilities,
            session_id,
            client_public,
            server_public,
        );
        Self {
            protocol_version,
            capabilities,
            session_id,
            public_key: server_public,
            auth_tag,
        }
    }

    /// Verifies the client hello tag and mandatory capability bits.
    pub fn verify_client(&self, psk: &[u8; 32]) -> bool {
        if self.protocol_version != PROTOCOL_VERSION {
            return false;
        }
        if self.capabilities & PROTOCOL_BASELINE_CAPS == 0 {
            return false;
        }

        let expected = compute_client_tag(
            psk,
            self.protocol_version,
            self.capabilities,
            self.session_id,
            self.public_key,
        );
        constant_time_eq(&expected, &self.auth_tag)
    }

    /// Verifies the server hello tag against the known client key.
    pub fn verify_server(&self, psk: &[u8; 32], client_public: [u8; 32]) -> bool {
        if self.protocol_version != PROTOCOL_VERSION {
            return false;
        }
        if self.capabilities & PROTOCOL_BASELINE_CAPS == 0 {
            return false;
        }

        let expected = compute_server_tag(
            psk,
            self.protocol_version,
            self.capabilities,
            self.session_id,
            client_public,
            self.public_key,
        );
        constant_time_eq(&expected, &self.auth_tag)
    }
}

fn constant_time_eq(left: &[u8; TAG_SIZE], right: &[u8; TAG_SIZE]) -> bool {
    let mut diff = 0u8;
    for index in 0..TAG_SIZE {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn build_nonce(label: u8, protocol_version: u16, capabilities: u16, session_id: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[0] = label;
    nonce[1..9].copy_from_slice(&session_id.to_le_bytes());
    nonce[9..11].copy_from_slice(&protocol_version.to_le_bytes());
    nonce[11] = (capabilities as u8) ^ ((capabilities >> 8) as u8);
    *Nonce::from_slice(&nonce)
}

fn build_client_tag_aad(
    protocol_version: u16,
    capabilities: u16,
    session_id: u64,
    client_public: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 2 + 2 + 8 + 32 + 6);
    aad.extend_from_slice(HANDSHAKE_DOMAIN);
    aad.extend_from_slice(b"/client");
    aad.extend_from_slice(&protocol_version.to_le_bytes());
    aad.extend_from_slice(&capabilities.to_le_bytes());
    aad.extend_from_slice(&session_id.to_le_bytes());
    aad.extend_from_slice(&client_public);
    aad
}

fn build_server_tag_aad(
    protocol_version: u16,
    capabilities: u16,
    session_id: u64,
    client_public: [u8; 32],
    server_public: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 2 + 2 + 8 + 32 + 32 + 6);
    aad.extend_from_slice(HANDSHAKE_DOMAIN);
    aad.extend_from_slice(b"/server");
    aad.extend_from_slice(&protocol_version.to_le_bytes());
    aad.extend_from_slice(&capabilities.to_le_bytes());
    aad.extend_from_slice(&session_id.to_le_bytes());
    aad.extend_from_slice(&client_public);
    aad.extend_from_slice(&server_public);
    aad
}

fn compute_tag(psk: &[u8; 32], nonce: Nonce, aad: &[u8]) -> [u8; TAG_SIZE] {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(psk));
    let Ok(tag) = cipher.encrypt(&nonce, Payload { msg: &[], aad }) else {
        return [0u8; TAG_SIZE];
    };

    let mut out = [0u8; TAG_SIZE];
    if tag.len() == TAG_SIZE {
        out.copy_from_slice(&tag);
    }
    out
}

fn compute_client_tag(
    psk: &[u8; 32],
    protocol_version: u16,
    capabilities: u16,
    session_id: u64,
    client_public: [u8; 32],
) -> [u8; TAG_SIZE] {
    let nonce = build_nonce(TAG_LABEL_CLIENT, protocol_version, capabilities, session_id);
    let aad = build_client_tag_aad(protocol_version, capabilities, session_id, client_public);
    compute_tag(psk, nonce, &aad)
}

fn compute_server_tag(
    psk: &[u8; 32],
    protocol_version: u16,
    capabilities: u16,
    session_id: u64,
    client_public: [u8; 32],
    server_public: [u8; 32],
) -> [u8; TAG_SIZE] {
    let nonce = build_nonce(TAG_LABEL_SERVER, protocol_version, capabilities, session_id);
    let aad = build_server_tag_aad(
        protocol_version,
        capabilities,
        session_id,
        client_public,
        server_public,
    );
    compute_tag(psk, nonce, &aad)
}

fn transcript_aad(context: &HandshakeContext, label: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 2 + 2 + 8 + 32 + 32 + label.len());
    aad.extend_from_slice(HANDSHAKE_DOMAIN);
    aad.extend_from_slice(label);
    aad.extend_from_slice(&context.protocol_version.to_le_bytes());
    aad.extend_from_slice(&context.capabilities.to_le_bytes());
    aad.extend_from_slice(&context.session_id.to_le_bytes());
    aad.extend_from_slice(&context.client_public);
    aad.extend_from_slice(&context.server_public);
    aad
}

fn derive_key_material(
    shared_secret: [u8; 32],
    psk: &[u8; 32],
    context: &HandshakeContext,
    nonce_label: u8,
    label: &[u8],
) -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    for index in 0..32 {
        seed[index] = shared_secret[index] ^ psk[index];
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&seed));
    let nonce = build_nonce(
        nonce_label,
        context.protocol_version,
        context.capabilities,
        context.session_id,
    );
    let aad = transcript_aad(context, label);

    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &[0u8; 32],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("session key derivation failed"))?;

    if encrypted.len() < 32 {
        return Err(anyhow!(
            "session key derivation returned too little material"
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&encrypted[..32]);
    Ok(out)
}

/// Derives purpose- and direction-scoped keys from the shared secret and transcript.
pub fn derive_session_keys(
    shared_secret: [u8; 32],
    psk: &[u8; 32],
    role: HandshakeRole,
    context: &HandshakeContext,
) -> Result<SessionKeys> {
    let payload_c2s = derive_key_material(shared_secret, psk, context, 0xA1, b"/payload/c2s")?;
    let payload_s2c = derive_key_material(shared_secret, psk, context, 0xA2, b"/payload/s2c")?;
    let header_c2s = derive_key_material(shared_secret, psk, context, 0xB1, b"/header/c2s")?;
    let header_s2c = derive_key_material(shared_secret, psk, context, 0xB2, b"/header/s2c")?;

    let keys = match role {
        HandshakeRole::Client => SessionKeys {
            payload_tx: payload_c2s,
            payload_rx: payload_s2c,
            header_tx: header_c2s,
            header_rx: header_s2c,
        },
        HandshakeRole::Server => SessionKeys {
            payload_tx: payload_s2c,
            payload_rx: payload_c2s,
            header_tx: header_s2c,
            header_rx: header_c2s,
        },
    };

    Ok(keys)
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

    /// Combine our Secret with their Public to get the shared secret bytes.
    pub fn derive_shared_secret(self, peer_public_bytes: [u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(peer_public_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HandshakeContext, HandshakePacket, HandshakeRole, PROTOCOL_BASELINE_CAPS, PROTOCOL_VERSION,
        derive_session_keys,
    };

    #[test]
    fn authenticated_tags_reject_tampering() {
        let psk = [0xAB; 32];
        let client_pub = [0x11; 32];
        let mut packet = HandshakePacket::new_client(7, client_pub, &psk);
        assert!(packet.verify_client(&psk));

        packet.session_id = 8;
        assert!(!packet.verify_client(&psk));
    }

    #[test]
    fn directional_key_derivation_matches_opposite_roles() {
        let psk = [0x22; 32];
        let shared_secret = [0x44; 32];
        let context = HandshakeContext {
            protocol_version: PROTOCOL_VERSION,
            capabilities: PROTOCOL_BASELINE_CAPS,
            session_id: 1234,
            client_public: [0x10; 32],
            server_public: [0x20; 32],
        };

        let client = derive_session_keys(shared_secret, &psk, HandshakeRole::Client, &context)
            .expect("client derivation should succeed");
        let server = derive_session_keys(shared_secret, &psk, HandshakeRole::Server, &context)
            .expect("server derivation should succeed");

        assert_eq!(client.payload_tx, server.payload_rx);
        assert_eq!(client.payload_rx, server.payload_tx);
        assert_eq!(client.header_tx, server.header_rx);
        assert_eq!(client.header_rx, server.header_tx);
        assert_ne!(client.payload_tx, client.header_tx);
    }

    #[test]
    fn server_tag_binds_client_and_server_keys() {
        let psk = [0xBC; 32];
        let client_pub = [0xAA; 32];
        let server_pub = [0xCC; 32];
        let packet = HandshakePacket::new_server(9, server_pub, client_pub, &psk);

        assert!(packet.verify_server(&psk, client_pub));
        assert!(!packet.verify_server(&psk, [0xDD; 32]));
    }
}
