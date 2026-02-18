pub mod fec;
pub mod pipeline;
pub mod metadata;
pub mod handshake;

pub use handshake::{KeyExchange, HandshakePacket};
pub use fec::{WirehairEncoder, WirehairDecoder, FecError};
pub use pipeline::KyuPipeline;
pub use metadata::SessionManifest;


/// Initialize global library state (Wirehair tables).
pub fn init() {
    unsafe {
        kyu2_wirehair_sys::wirehair_init_(2);
    }
}
