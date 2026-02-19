use sankaku_wirehair_sys::*;
use std::ptr;
use thiserror::Error;

const MAX_WIREHAIR_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_WIREHAIR_PACKET_BYTES: u32 = 1500;

#[derive(Error, Debug)]
pub enum FecError {
    #[error("Wirehair initialization failed")]
    InitFailed,
    #[error("Invalid input parameters")]
    InvalidInput,
    #[error("Recovery failed")]
    RecoveryFailed,
    #[error("Need more data to recover")]
    NeedMoreData,
    #[error("Packet size out of bounds")]
    PacketSizeOutOfBounds,
    #[error("Message size out of bounds")]
    MessageSizeOutOfBounds,
    #[error("Internal Wirehair error: {0}")]
    Internal(i32),
}

/// A safe wrapper around the Wirehair Encoder
pub struct WirehairEncoder {
    inner: WirehairCodec,
    _block_bytes: u32,
    packet_size: u32,
}

impl WirehairEncoder {
    /// Creates an encoder and ensures Wirehair global state is initialized first.
    pub fn new(message: &[u8], packet_size: u32) -> Result<Self, FecError> {
        // Auto-init makes the FFI safe-by-default for callers that forget `sankaku_core::init()`.
        crate::init();
        if message.is_empty() || message.len() > MAX_WIREHAIR_MESSAGE_BYTES {
            return Err(FecError::MessageSizeOutOfBounds);
        }
        if packet_size == 0 || packet_size > MAX_WIREHAIR_PACKET_BYTES {
            return Err(FecError::PacketSizeOutOfBounds);
        }

        unsafe {
            let codec = wirehair_encoder_create(
                ptr::null_mut(),
                message.as_ptr() as *const _,
                message.len() as u64,
                packet_size,
            );

            if codec.is_null() {
                return Err(FecError::InitFailed);
            }

            Ok(Self {
                inner: codec,
                _block_bytes: message.len() as u32,
                packet_size,
            })
        }
    }

    /// Generates the encoded packet for a specific Block ID.
    /// In Wirehair:
    /// ID < N  = Original Data (Systematic)
    /// ID >= N = Repair Data (Parity)
    pub fn encode(&self, block_id: u32) -> Result<Vec<u8>, FecError> {
        let mut output = vec![0u8; self.packet_size as usize];
        let mut bytes_written = 0u32;

        unsafe {
            let result = wirehair_encode(
                self.inner,
                block_id,
                output.as_mut_ptr() as *mut _,
                self.packet_size,
                &mut bytes_written,
            );

            if result != WirehairResult_t_Wirehair_Success {
                return Err(FecError::Internal(result as i32));
            }
        }

        if bytes_written > self.packet_size {
            return Err(FecError::Internal(-1));
        }

        // Trim if the actual data written is smaller (usually only for the last packet)
        output.truncate(bytes_written as usize);
        Ok(output)
    }
}

impl Drop for WirehairEncoder {
    fn drop(&mut self) {
        unsafe {
            if !self.inner.is_null() {
                wirehair_free(self.inner);
            }
        }
    }
}

/// A safe wrapper around the Wirehair Decoder
pub struct WirehairDecoder {
    inner: WirehairCodec,
    message_size: u64,
    _packet_size: u32, // <--- Renamed with leading underscore
}

impl WirehairDecoder {
    /// Creates a decoder and ensures Wirehair global state is initialized first.
    pub fn new(message_size: u64, packet_size: u32) -> Result<Self, FecError> {
        // Auto-init makes the FFI safe-by-default for callers that forget `sankaku_core::init()`.
        crate::init();
        if message_size == 0 || message_size as usize > MAX_WIREHAIR_MESSAGE_BYTES {
            return Err(FecError::MessageSizeOutOfBounds);
        }
        if packet_size == 0 || packet_size > MAX_WIREHAIR_PACKET_BYTES {
            return Err(FecError::PacketSizeOutOfBounds);
        }

        unsafe {
            let codec = wirehair_decoder_create(ptr::null_mut(), message_size, packet_size);

            if codec.is_null() {
                return Err(FecError::InitFailed);
            }

            Ok(Self {
                inner: codec,
                message_size,
                _packet_size: packet_size, // <--- Updated here too
            })
        }
    }

    pub fn decode(&mut self, block_id: u32, data: &[u8]) -> Result<bool, FecError> {
        if data.is_empty() || data.len() as u32 > self._packet_size {
            return Err(FecError::PacketSizeOutOfBounds);
        }

        unsafe {
            let result = wirehair_decode(
                self.inner,
                block_id,
                data.as_ptr() as *const _,
                data.len() as u32,
            );

            // Allow C-style enum names for this match block
            #[allow(non_upper_case_globals)]
            match result {
                WirehairResult_t_Wirehair_Success => Ok(true),
                WirehairResult_t_Wirehair_NeedMore => Ok(false),
                _ => Err(FecError::Internal(result as i32)),
            }
        }
    }
    /// Reconstructs the full message once decode() returns true.
    pub fn recover(&self) -> Result<Vec<u8>, FecError> {
        let mut output = vec![0u8; self.message_size as usize];

        unsafe {
            let result =
                wirehair_recover(self.inner, output.as_mut_ptr() as *mut _, self.message_size);

            if result != WirehairResult_t_Wirehair_Success {
                return Err(FecError::RecoveryFailed);
            }
        }

        Ok(output)
    }
}

impl Drop for WirehairDecoder {
    fn drop(&mut self) {
        unsafe {
            if !self.inner.is_null() {
                wirehair_free(self.inner);
            }
        }
    }
}
