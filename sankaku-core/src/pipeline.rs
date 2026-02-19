use crate::openzl;
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

const ENVELOPE_RAW_NAL: u8 = 0;
const ENVELOPE_RAW_SAO: u8 = 1;
const ENVELOPE_OPENZL_SAO: u8 = 2;

/// Identifies the media payload class carried by a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoPayloadKind {
    NalUnit,
    SaoParameters,
}

impl VideoPayloadKind {
    pub fn from_header_flag(flag: u8) -> Option<Self> {
        match flag {
            0 => Some(Self::NalUnit),
            1 => Some(Self::SaoParameters),
            _ => None,
        }
    }

    pub fn as_header_flag(self) -> u8 {
        match self {
            Self::NalUnit => 0,
            Self::SaoParameters => 1,
        }
    }
}

/// Compression mode for protected blocks.
#[derive(Debug, Clone, Copy)]
pub enum CompressionMode {
    Disabled,
    OpenZlForSao,
}

/// Pipeline behavior toggles selected by the embedding transport.
#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    pub compression: CompressionMode,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            compression: CompressionMode::OpenZlForSao,
        }
    }
}

/// Encrypt/decrypt + optional pre-encryption OpenZL stage.
pub struct SankakuPipeline {
    cipher: ChaCha20Poly1305,
    config: PipelineConfig,
    openzl: openzl::OpenZlContext,
}

impl SankakuPipeline {
    /// Initialize with a 32-byte key.
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Self::new_with_config(key_bytes, PipelineConfig::default())
    }

    /// Initialize with explicit pipeline behavior.
    pub fn new_with_config(key_bytes: &[u8; 32], config: PipelineConfig) -> Self {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let openzl =
            openzl::OpenZlContext::new(&[]).expect("OpenZL context allocation should succeed");
        Self {
            cipher,
            config,
            openzl,
        }
    }

    /// Updates the active serialized OpenZL compression graph without resetting session keys.
    pub fn update_compression_graph(&mut self, serialized_graph: &[u8]) -> Result<()> {
        self.openzl.update_graph(serialized_graph)
    }

    /// Returns the currently installed serialized OpenZL graph payload.
    pub fn compression_graph(&self) -> &[u8] {
        self.openzl.graph()
    }

    /// Applies optional OpenZL (for SAO) and seals with ChaCha20-Poly1305.
    pub fn protect_frame(
        &mut self,
        raw_data: &[u8],
        kind: VideoPayloadKind,
        stream_id: u32,
        frame_index: u64,
    ) -> Result<Vec<u8>> {
        let (mode, body) = match (kind, self.config.compression) {
            (VideoPayloadKind::NalUnit, _) => (ENVELOPE_RAW_NAL, raw_data.to_vec()),
            (VideoPayloadKind::SaoParameters, CompressionMode::Disabled) => {
                (ENVELOPE_RAW_SAO, raw_data.to_vec())
            }
            (VideoPayloadKind::SaoParameters, CompressionMode::OpenZlForSao) => (
                ENVELOPE_OPENZL_SAO,
                self.openzl
                    .encode_sao(raw_data)
                    .context("OpenZL encode failed")?,
            ),
        };

        let mut plaintext = Vec::with_capacity(body.len().saturating_add(1));
        plaintext.push(mode);
        plaintext.extend_from_slice(&body);

        let nonce = Self::generate_nonce(stream_id, frame_index);
        let aad = Self::generate_aad(stream_id, frame_index);
        let payload = Payload {
            msg: &plaintext,
            aad: &aad,
        };
        let encrypted = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        Ok(encrypted)
    }

    /// Opens an encrypted block and applies OpenZL decode when needed.
    pub fn restore_frame(
        &self,
        protected_data: &[u8],
        stream_id: u32,
        frame_index: u64,
    ) -> Result<(VideoPayloadKind, Vec<u8>)> {
        let nonce = Self::generate_nonce(stream_id, frame_index);
        let aad = Self::generate_aad(stream_id, frame_index);
        let payload = Payload {
            msg: protected_data,
            aad: &aad,
        };
        let plaintext = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Decryption failed (Auth Tag mismatch)"))?;

        let Some((&mode, body)) = plaintext.split_first() else {
            bail!("Decryption produced empty block");
        };

        match mode {
            ENVELOPE_RAW_NAL => Ok((VideoPayloadKind::NalUnit, body.to_vec())),
            ENVELOPE_RAW_SAO => Ok((VideoPayloadKind::SaoParameters, body.to_vec())),
            ENVELOPE_OPENZL_SAO => Ok((
                VideoPayloadKind::SaoParameters,
                self.openzl
                    .decode_sao(body)
                    .context("OpenZL decode failed")?,
            )),
            _ => bail!("Unsupported pipeline envelope mode"),
        }
    }

    /// Compatibility adapter for legacy block callers (treated as NAL-like payload).
    pub fn protect_block(
        &mut self,
        raw_data: &[u8],
        stream_id: u32,
        block_id: u64,
    ) -> Result<Vec<u8>> {
        self.protect_frame(raw_data, VideoPayloadKind::NalUnit, stream_id, block_id)
    }

    /// Compatibility adapter for legacy block callers.
    pub fn restore_block(
        &self,
        protected_data: &[u8],
        stream_id: u32,
        block_id: u64,
    ) -> Result<Vec<u8>> {
        let (_kind, payload) = self.restore_frame(protected_data, stream_id, block_id)?;
        Ok(payload)
    }

    fn generate_nonce(stream_id: u32, block_id: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&stream_id.to_le_bytes());
        nonce_bytes[4..12].copy_from_slice(&block_id.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    fn generate_aad(stream_id: u32, block_id: u64) -> [u8; 12] {
        let mut aad = [0u8; 12];
        aad[0..4].copy_from_slice(&stream_id.to_le_bytes());
        aad[4..12].copy_from_slice(&block_id.to_le_bytes());
        aad
    }
}

pub type KyuPipeline = SankakuPipeline;

#[cfg(test)]
mod tests {
    use super::{CompressionMode, PipelineConfig, SankakuPipeline, VideoPayloadKind};

    #[test]
    fn stream_id_is_bound_to_authentication() {
        let key = [0x99; 32];
        let mut pipeline = SankakuPipeline::new(&key);
        let protected = pipeline
            .protect_frame(b"hello world", VideoPayloadKind::NalUnit, 10, 1)
            .expect("encryption should succeed");

        let ok = pipeline
            .restore_frame(&protected, 10, 1)
            .expect("decryption should succeed");
        assert_eq!(ok.1, b"hello world");

        let wrong_stream = pipeline.restore_frame(&protected, 11, 1);
        assert!(
            wrong_stream.is_err(),
            "stream mismatch must fail authentication"
        );
    }

    #[test]
    fn ciphertext_changes_when_stream_changes() {
        let key = [0x44; 32];
        let mut pipeline = SankakuPipeline::new(&key);
        let data = b"same plaintext";
        let block_id = 7;
        let c1 = pipeline
            .protect_frame(data, VideoPayloadKind::NalUnit, 1, block_id)
            .expect("encryption should succeed");
        let c2 = pipeline
            .protect_frame(data, VideoPayloadKind::NalUnit, 2, block_id)
            .expect("encryption should succeed");
        assert_ne!(c1, c2);
    }

    #[test]
    fn sao_payload_round_trips_when_compression_is_disabled() {
        let key = [0x55; 32];
        let config = PipelineConfig {
            compression: CompressionMode::Disabled,
        };
        let mut pipeline = SankakuPipeline::new_with_config(&key, config);

        let raw = b"\x11\x22\x33\x44\x55";
        let protected = pipeline
            .protect_frame(raw, VideoPayloadKind::SaoParameters, 1, 1)
            .expect("protection should succeed");
        let restored = pipeline
            .restore_frame(&protected, 1, 1)
            .expect("restore should succeed");
        assert_eq!(restored.0, VideoPayloadKind::SaoParameters);
        assert_eq!(restored.1, raw);
    }
}
