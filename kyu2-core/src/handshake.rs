use anyhow::{Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

/// Protocol version used by the authenticated handshake.
pub const PROTOCOL_VERSION: u16 = 2;
/// Baseline capability bit for interoperable peers.
pub const PROTOCOL_BASELINE_CAPS: u16 = 0x0001;
/// Capability bit signaling support for ticket-based session resumption.
pub const PROTOCOL_CAP_RESUMPTION: u16 = 0x0002;
const HANDSHAKE_DOMAIN: &[u8] = b"kyu2/handshake/v2";
const TICKET_DOMAIN: &[u8] = b"kyu2/ticket/v1";
const RESUME_DOMAIN: &[u8] = b"kyu2/resume/v1";

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

/// Client-storable resumption ticket.
///
/// `identity` is an opaque server-encrypted blob.
/// `resumption_secret` is the client-side secret used to build a resume binder and keys.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionTicket {
    pub identity: Vec<u8>,
    pub resumption_secret: [u8; 32],
    pub expires_at: u64,
}

/// Client hello used for 0-RTT ticket resumption.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResumePacket {
    pub protocol_version: u16,
    pub session_id: u64,
    pub ticket_identity: Vec<u8>,
    pub expires_at: u64,
    pub client_nonce: [u8; 24],
    pub binder: [u8; TAG_SIZE],
}

impl ResumePacket {
    /// Builds a 0-RTT resume packet from a previously stored ticket.
    pub fn new_client(session_id: u64, ticket: &SessionTicket) -> Self {
        let mut client_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut client_nonce);

        let binder = compute_resumption_binder(
            &ticket.resumption_secret,
            session_id,
            &ticket.identity,
            ticket.expires_at,
            client_nonce,
        );

        Self {
            protocol_version: PROTOCOL_VERSION,
            session_id,
            ticket_identity: ticket.identity.clone(),
            expires_at: ticket.expires_at,
            client_nonce,
            binder,
        }
    }

    /// Verifies ticket freshness and binder validity using the ticket's resumption secret.
    pub fn verify(&self, resumption_secret: &[u8; 32], now_secs: u64) -> bool {
        if self.protocol_version != PROTOCOL_VERSION {
            return false;
        }
        if self.expires_at < now_secs {
            return false;
        }

        let expected = compute_resumption_binder(
            resumption_secret,
            self.session_id,
            &self.ticket_identity,
            self.expires_at,
            self.client_nonce,
        );
        constant_time_eq(&expected, &self.binder)
    }
}

/// Result of validating an opaque ticket identity on the server side.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedTicket {
    /// Server-generated ticket identifier used for anti-replay tracking.
    pub ticket_id: [u8; 16],
    pub resumption_secret: [u8; 32],
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct TicketIdentityFields {
    protocol_version: u16,
    ticket_id: [u8; 16],
    expires_at: u64,
    resumption_secret: [u8; 32],
}

/// The packet sent over the wire to establish and authenticate a session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakePacket {
    pub protocol_version: u16,
    pub capabilities: u16,
    pub session_id: u64,
    pub public_key: [u8; 32],
    pub auth_tag: [u8; TAG_SIZE],
    #[serde(default)]
    pub session_ticket: Option<SessionTicket>,
}

impl HandshakePacket {
    /// Builds a client hello authenticated with the configured PSK.
    pub fn new_client(session_id: u64, public_key: [u8; 32], psk: &[u8; 32]) -> Self {
        let protocol_version = PROTOCOL_VERSION;
        let capabilities = PROTOCOL_BASELINE_CAPS | PROTOCOL_CAP_RESUMPTION;
        let auth_tag =
            compute_client_tag(psk, protocol_version, capabilities, session_id, public_key);
        Self {
            protocol_version,
            capabilities,
            session_id,
            public_key,
            auth_tag,
            session_ticket: None,
        }
    }

    /// Builds a server hello authenticated with the configured PSK.
    pub fn new_server(
        session_id: u64,
        server_public: [u8; 32],
        client_public: [u8; 32],
        psk: &[u8; 32],
        session_ticket: Option<SessionTicket>,
    ) -> Self {
        let protocol_version = PROTOCOL_VERSION;
        let capabilities = PROTOCOL_BASELINE_CAPS | PROTOCOL_CAP_RESUMPTION;
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
            session_ticket,
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

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn build_resumption_nonce(label: u8, session_id: u64, client_nonce: [u8; 24]) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[0] = label;
    nonce[1..9].copy_from_slice(&session_id.to_le_bytes());
    nonce[9..12].copy_from_slice(&client_nonce[..3]);
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

fn resumption_binder_aad(
    session_id: u64,
    ticket_identity: &[u8],
    expires_at: u64,
    client_nonce: [u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RESUME_DOMAIN.len() + 8 + 8 + 24 + ticket_identity.len());
    aad.extend_from_slice(RESUME_DOMAIN);
    aad.extend_from_slice(b"/binder");
    aad.extend_from_slice(&session_id.to_le_bytes());
    aad.extend_from_slice(&expires_at.to_le_bytes());
    aad.extend_from_slice(&client_nonce);
    aad.extend_from_slice(ticket_identity);
    aad
}

fn compute_resumption_binder(
    resumption_secret: &[u8; 32],
    session_id: u64,
    ticket_identity: &[u8],
    expires_at: u64,
    client_nonce: [u8; 24],
) -> [u8; TAG_SIZE] {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(resumption_secret));
    let nonce = build_resumption_nonce(0xD1, session_id, client_nonce);
    let aad = resumption_binder_aad(session_id, ticket_identity, expires_at, client_nonce);

    let Ok(tag) = cipher.encrypt(
        &nonce,
        Payload {
            msg: &[],
            aad: &aad,
        },
    ) else {
        return [0u8; TAG_SIZE];
    };

    let mut out = [0u8; TAG_SIZE];
    if tag.len() == TAG_SIZE {
        out.copy_from_slice(&tag);
    }
    out
}

fn derive_resumption_key_material(
    resumption_secret: [u8; 32],
    session_id: u64,
    client_nonce: [u8; 24],
    nonce_label: u8,
    label: &[u8],
) -> Result<[u8; 32]> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&resumption_secret));
    let nonce = build_resumption_nonce(nonce_label, session_id, client_nonce);

    let mut aad = Vec::with_capacity(RESUME_DOMAIN.len() + label.len() + 8 + 24);
    aad.extend_from_slice(RESUME_DOMAIN);
    aad.extend_from_slice(label);
    aad.extend_from_slice(&session_id.to_le_bytes());
    aad.extend_from_slice(&client_nonce);

    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &[0u8; 32],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("resumption key derivation failed"))?;

    if encrypted.len() < 32 {
        return Err(anyhow!(
            "resumption key derivation returned too little material"
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&encrypted[..32]);
    Ok(out)
}

/// Issues a resumable session ticket for a recently authenticated client.
pub fn issue_session_ticket(ticket_key: &[u8; 32], lifetime_secs: u64) -> Result<SessionTicket> {
    if lifetime_secs == 0 {
        bail!("ticket lifetime must be greater than zero");
    }

    let now = unix_now_secs();
    let expires_at = now.saturating_add(lifetime_secs);

    let mut resumption_secret = [0u8; 32];
    OsRng.fill_bytes(&mut resumption_secret);
    if resumption_secret == [0u8; 32] {
        resumption_secret[0] = 1;
    }
    let mut ticket_id = [0u8; 16];
    OsRng.fill_bytes(&mut ticket_id);

    let fields = TicketIdentityFields {
        protocol_version: PROTOCOL_VERSION,
        ticket_id,
        expires_at,
        resumption_secret,
    };
    let plaintext = bincode::serialize(&fields)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(ticket_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: TICKET_DOMAIN,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt ticket identity"))?;

    let mut identity = Vec::with_capacity(12 + ciphertext.len());
    identity.extend_from_slice(&nonce_bytes);
    identity.extend_from_slice(&ciphertext);

    Ok(SessionTicket {
        identity,
        resumption_secret,
        expires_at,
    })
}

/// Validates and decrypts an opaque ticket identity on the server.
pub fn validate_ticket_identity(
    ticket_key: &[u8; 32],
    identity: &[u8],
    now_secs: u64,
) -> Option<ValidatedTicket> {
    if identity.len() <= 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = identity.split_at(12);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(ticket_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: TICKET_DOMAIN,
            },
        )
        .ok()?;

    let fields: TicketIdentityFields = bincode::deserialize(&plaintext).ok()?;
    if fields.protocol_version != PROTOCOL_VERSION {
        return None;
    }
    if fields.expires_at < now_secs {
        return None;
    }

    Some(ValidatedTicket {
        ticket_id: fields.ticket_id,
        resumption_secret: fields.resumption_secret,
        expires_at: fields.expires_at,
    })
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

/// Derives purpose- and direction-scoped keys for 0-RTT ticket resumption.
pub fn derive_resumption_session_keys(
    resumption_secret: [u8; 32],
    role: HandshakeRole,
    session_id: u64,
    client_nonce: [u8; 24],
) -> Result<SessionKeys> {
    let payload_c2s = derive_resumption_key_material(
        resumption_secret,
        session_id,
        client_nonce,
        0xC1,
        b"/payload/c2s",
    )?;
    let payload_s2c = derive_resumption_key_material(
        resumption_secret,
        session_id,
        client_nonce,
        0xC2,
        b"/payload/s2c",
    )?;
    let header_c2s = derive_resumption_key_material(
        resumption_secret,
        session_id,
        client_nonce,
        0xD1,
        b"/header/c2s",
    )?;
    let header_s2c = derive_resumption_key_material(
        resumption_secret,
        session_id,
        client_nonce,
        0xD2,
        b"/header/s2c",
    )?;

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
        ResumePacket, derive_resumption_session_keys, derive_session_keys, issue_session_ticket,
        validate_ticket_identity,
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
        let packet = HandshakePacket::new_server(9, server_pub, client_pub, &psk, None);

        assert!(packet.verify_server(&psk, client_pub));
        assert!(!packet.verify_server(&psk, [0xDD; 32]));
    }

    #[test]
    fn ticket_round_trip_and_resumption_keys_match() {
        let ticket_key = [0x55; 32];
        let ticket = issue_session_ticket(&ticket_key, 60).expect("ticket should be issued");
        let validated = validate_ticket_identity(
            &ticket_key,
            &ticket.identity,
            ticket.expires_at.saturating_sub(1),
        )
        .expect("ticket identity should validate");

        assert_ne!(validated.ticket_id, [0u8; 16]);
        assert_eq!(validated.expires_at, ticket.expires_at);
        assert_eq!(validated.resumption_secret, ticket.resumption_secret);

        let resume = ResumePacket::new_client(88, &ticket);
        assert!(resume.verify(&validated.resumption_secret, ticket.expires_at - 1));

        let client = derive_resumption_session_keys(
            ticket.resumption_secret,
            HandshakeRole::Client,
            resume.session_id,
            resume.client_nonce,
        )
        .expect("client resumption key derivation should succeed");
        let server = derive_resumption_session_keys(
            validated.resumption_secret,
            HandshakeRole::Server,
            resume.session_id,
            resume.client_nonce,
        )
        .expect("server resumption key derivation should succeed");

        assert_eq!(client.payload_tx, server.payload_rx);
        assert_eq!(client.payload_rx, server.payload_tx);
        assert_eq!(client.header_tx, server.header_rx);
        assert_eq!(client.header_rx, server.header_tx);
    }

    #[test]
    fn resumption_binder_rejects_tampering() {
        let ticket_key = [0x99; 32];
        let ticket = issue_session_ticket(&ticket_key, 60).expect("ticket should be issued");
        let validated = validate_ticket_identity(
            &ticket_key,
            &ticket.identity,
            ticket.expires_at.saturating_sub(1),
        )
        .expect("ticket identity should validate");

        let mut resume = ResumePacket::new_client(144, &ticket);
        assert!(resume.verify(&validated.resumption_secret, ticket.expires_at - 1));

        resume.session_id = 145;
        assert!(!resume.verify(&validated.resumption_secret, ticket.expires_at - 1));
    }

    #[test]
    fn ticket_identity_contains_stable_unique_ticket_id() {
        let ticket_key = [0x77; 32];
        let ticket_a = issue_session_ticket(&ticket_key, 60).expect("ticket a should be issued");
        let ticket_b = issue_session_ticket(&ticket_key, 60).expect("ticket b should be issued");

        let validated_a =
            validate_ticket_identity(&ticket_key, &ticket_a.identity, ticket_a.expires_at - 1)
                .expect("ticket a should validate");
        let validated_b =
            validate_ticket_identity(&ticket_key, &ticket_b.identity, ticket_b.expires_at - 1)
                .expect("ticket b should validate");

        assert_eq!(
            validated_a.ticket_id,
            validate_ticket_identity(&ticket_key, &ticket_a.identity, ticket_a.expires_at - 1)
                .expect("ticket a should validate repeatedly")
                .ticket_id
        );
        assert_ne!(validated_a.ticket_id, validated_b.ticket_id);
    }
}
