use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use anyhow::{Context, Result};

/// The Pipeline configuration.
/// 0 = Fastest (Realtime), 22 = Smallest (Archival).
/// For streaming, 1-3 is usually the sweet spot.
const COMPRESSION_LEVEL: i32 = 1;

pub struct KyuPipeline {
    cipher: ChaCha20Poly1305,
    // We keep a reusable buffer for compression to reduce memory allocation churn
    // (Note: Currently unused in the simple implementation below, but good practice for future optimization)
    #[allow(dead_code)]
    compression_buffer: Vec<u8>,
}

impl KyuPipeline {
    /// Initialize with a 32-byte secret key.
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        
        Self {
            cipher,
            compression_buffer: Vec::with_capacity(1024 * 64), // Pre-allocate 64KB
        }
    }

    /// STAGE 1 & 2: Squeeze and Seal
    /// Takes raw data -> Returns Compressed + Encrypted data
    pub fn protect_block(&mut self, raw_data: &[u8], block_id: u64) -> Result<Vec<u8>> {
        // 1. Compress (tANS)
        // We use the 'bulk' API here for simplicity.
        let compressed_data = zstd::encode_all(raw_data, COMPRESSION_LEVEL)
            .context("Compression failed")?;

        // 2. Encrypt (ChaCha20-Poly1305)
        // CRITICAL: We use the Block ID as the Nonce (IV).
        let nonce = Self::generate_nonce(block_id);
        
        // Poly1305 requires 'AAD' (Additional Authenticated Data).
        // We authenticate the Block ID itself so attackers can't swap blocks around.
        let payload = Payload {
            msg: &compressed_data,
            aad: &block_id.to_le_bytes(),
        };

        let encrypted_data = self.cipher.encrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        Ok(encrypted_data)
    }

    /// REVERSE STAGE: Open and Expand
    /// Takes Encrypted blob -> Returns Raw Data
    pub fn restore_block(&self, protected_data: &[u8], block_id: u64) -> Result<Vec<u8>> {
        // 1. Decrypt & Verify
        let nonce = Self::generate_nonce(block_id);
        
        let payload = Payload {
            msg: protected_data,
            aad: &block_id.to_le_bytes(),
        };

        let compressed_data = self.cipher.decrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Decryption failed (Auth Tag Mismatch)"))?;

        // 2. Decompress
        let raw_data = zstd::decode_all(&compressed_data[..])
            .context("Decompression failed")?;

        Ok(raw_data)
    }

    /// Helper: Converts a 64-bit Block ID into a 12-byte ChaCha20 Nonce.
    /// Format: [ 00 00 00 00 | BlockID (8 bytes) ]
    fn generate_nonce(block_id: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        let id_bytes = block_id.to_le_bytes();
        
        // We put the counter at the end (standard practice)
        nonce_bytes[4..12].copy_from_slice(&id_bytes);
        
        *Nonce::from_slice(&nonce_bytes)
    }
}
