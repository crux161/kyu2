pub mod fec;
pub mod handshake;
pub mod metadata;
pub mod pipeline;
pub mod session;

pub use fec::{FecError, WirehairDecoder, WirehairEncoder};
pub use handshake::{
    HandshakeContext, HandshakePacket, HandshakeRole, KeyExchange, PROTOCOL_BASELINE_CAPS,
    PROTOCOL_CAP_RESUMPTION, PROTOCOL_VERSION, ResumePacket, SessionKeys, SessionTicket,
    ValidatedTicket, derive_resumption_session_keys, issue_session_ticket,
    validate_ticket_identity,
};
pub use metadata::SessionManifest;
pub use pipeline::KyuPipeline;
pub use session::{KyuErrorCode, KyuEvent, KyuReceiver, KyuSender, parse_psk_hex};

use std::sync::OnceLock;

/// Initialize global library state (Wirehair tables).
pub fn init() {
    static WIREHAIR_INIT: OnceLock<()> = OnceLock::new();
    WIREHAIR_INIT.get_or_init(|| unsafe {
        let _ = kyu2_wirehair_sys::wirehair_init_(2);
    });
}
