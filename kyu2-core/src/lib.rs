pub mod fec;
pub mod pipeline; // <--- This loads the file

// Re-export these so they are available at the top level (kyu2_core::...)
pub use fec::{WirehairEncoder, WirehairDecoder, FecError};
pub use pipeline::KyuPipeline; // <--- This fixes your Error

/// Initialize global library state (Wirehair tables).
pub fn init() {
    unsafe {
        kyu2_wirehair_sys::wirehair_init_(2);
    }
}
