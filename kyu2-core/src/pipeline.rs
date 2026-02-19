use anyhow::{Context, Result};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

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
    /// Nonce scope is bound to (stream_id, block_id) so per-key nonce reuse is avoided.
    pub fn protect_block(
        &mut self,
        raw_data: &[u8],
        stream_id: u32,
        block_id: u64,
    ) -> Result<Vec<u8>> {
        // 1. Compress (tANS)
        // We use the 'bulk' API here for simplicity.
        let compressed_data =
            zstd::encode_all(raw_data, COMPRESSION_LEVEL).context("Compression failed")?;

        // 2. Encrypt (ChaCha20-Poly1305)
        let nonce = Self::generate_nonce(stream_id, block_id);
        let aad = Self::generate_aad(stream_id, block_id);

        // Poly1305 requires AAD. We bind both stream and block identity.
        let payload = Payload {
            msg: &compressed_data,
            aad: &aad,
        };

        let encrypted_data = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        Ok(encrypted_data)
    }

    /// REVERSE STAGE: Open and Expand
    /// Takes Encrypted blob -> Returns Raw Data
    pub fn restore_block(
        &self,
        protected_data: &[u8],
        stream_id: u32,
        block_id: u64,
    ) -> Result<Vec<u8>> {
        // 1. Decrypt & Verify
        let nonce = Self::generate_nonce(stream_id, block_id);
        let aad = Self::generate_aad(stream_id, block_id);

        let payload = Payload {
            msg: protected_data,
            aad: &aad,
        };

        let compressed_data = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Decryption failed (Auth Tag Mismatch)"))?;

        // 2. Decompress
        let raw_data = zstd::decode_all(&compressed_data[..]).context("Decompression failed")?;

        Ok(raw_data)
    }

    /// Helper: Builds a nonce from stream and block identity.
    /// Format: [ StreamID (4 bytes) | BlockID (8 bytes) ]
    fn generate_nonce(stream_id: u32, block_id: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&stream_id.to_le_bytes());
        nonce_bytes[4..12].copy_from_slice(&block_id.to_le_bytes());

        *Nonce::from_slice(&nonce_bytes)
    }

    /// Helper: AAD mirrors nonce scope to authenticate stream and block routing.
    fn generate_aad(stream_id: u32, block_id: u64) -> [u8; 12] {
        let mut aad = [0u8; 12];
        aad[0..4].copy_from_slice(&stream_id.to_le_bytes());
        aad[4..12].copy_from_slice(&block_id.to_le_bytes());
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::KyuPipeline;

    #[test]
    fn stream_id_is_bound_to_authentication() {
        let key = [0x99; 32];
        let mut pipeline = KyuPipeline::new(&key);
        let protected = pipeline
            .protect_block(b"hello world", 10, 1)
            .expect("encryption should succeed");

        let ok = pipeline
            .restore_block(&protected, 10, 1)
            .expect("decryption should succeed");
        assert_eq!(ok, b"hello world");

        let wrong_stream = pipeline.restore_block(&protected, 11, 1);
        assert!(
            wrong_stream.is_err(),
            "stream mismatch must fail authentication"
        );
    }

    #[test]
    fn ciphertext_changes_when_stream_changes() {
        let key = [0x44; 32];
        let mut pipeline = KyuPipeline::new(&key);
        let data = b"same plaintext";
        let block_id = 7;
        let c1 = pipeline
            .protect_block(data, 1, block_id)
            .expect("encryption should succeed");
        let c2 = pipeline
            .protect_block(data, 2, block_id)
            .expect("encryption should succeed");
        assert_ne!(c1, c2);
    }
}
