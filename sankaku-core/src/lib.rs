pub mod fec;
pub mod handshake;
pub mod metadata;
pub mod openzl;
pub mod pipeline;
pub mod session;
#[cfg(feature = "webrtc")]
pub mod webrtc;

pub use fec::{FecError, WirehairDecoder, WirehairEncoder};
pub use handshake::{
    DefaultHandshakeEngine, HandshakeContext, HandshakeEngine, HandshakePacket, HandshakeRole,
    KeyExchange, PROTOCOL_BASELINE_CAPS, PROTOCOL_CAP_RESUMPTION, PROTOCOL_VERSION, ResumePacket,
    SessionKeys, SessionTicket, ValidatedTicket, derive_resumption_session_keys,
    issue_session_ticket, validate_ticket_identity,
};
pub use metadata::{SessionManifest, StreamSemantics};
pub use pipeline::{
    CompressionMode, KyuPipeline, PipelineConfig, SankakuPipeline, VideoPayloadKind,
};
pub use session::{
    FecPolicy, InboundFrame, InboundVideoFrame, KyuErrorCode, KyuEvent, KyuReceiver, KyuSender,
    MediaFrame, PaddingMode, SankakuReceiver, SankakuSender, SankakuStream, SessionBootstrapMode,
    TransportConfig, VideoFrame, parse_psk_hex,
};
#[cfg(feature = "webrtc")]
pub use webrtc::{
    DEFAULT_STUN_SERVER, IceServerConfig, InboundDataChannelMessage, InboundRtpFrame, WebRtcConfig,
    WebRtcPeer,
};

use std::sync::OnceLock;

/// Initialize global library state (Wirehair tables).
pub fn init() {
    static WIREHAIR_INIT: OnceLock<()> = OnceLock::new();
    WIREHAIR_INIT.get_or_init(|| unsafe {
        let _ = sankaku_wirehair_sys::wirehair_init_(2);
    });
}
