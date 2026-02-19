use serde::{Deserialize, Serialize};

/// High-level stream semantics declared by the sender in block-0 metadata.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamSemantics {
    #[default]
    FiniteFile,
    MediaFrames,
    OpenEnded,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionManifest {
    pub filename: String,
    /// Legacy fixed byte length used by older peers.
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub trace_id: u64,
    /// Preferred size field for modern peers; `None` for open streams.
    #[serde(default)]
    pub declared_size: Option<u64>,
    #[serde(default)]
    pub semantics: StreamSemantics,
    pub timestamp: u64, // Good for versioning/sync
}

impl SessionManifest {
    /// Creates metadata for a stream, including its stable trace id.
    pub fn new(filename: &str, file_size: u64, trace_id: u64) -> Self {
        Self {
            filename: filename.to_string(),
            file_size,
            trace_id,
            declared_size: Some(file_size),
            semantics: StreamSemantics::FiniteFile,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Creates metadata for frame-centric or open-ended streaming use-cases.
    pub fn new_stream(
        filename: &str,
        trace_id: u64,
        declared_size: Option<u64>,
        semantics: StreamSemantics,
    ) -> Self {
        Self {
            filename: filename.to_string(),
            file_size: declared_size.unwrap_or(0),
            trace_id,
            declared_size,
            semantics,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Returns the declared size if known, with backward compatibility for legacy manifests.
    pub fn expected_size(&self) -> Option<u64> {
        self.declared_size.or({
            if self.file_size == 0 {
                None
            } else {
                Some(self.file_size)
            }
        })
    }

    /// Serializes metadata using bincode.
    pub fn to_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(self)
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionManifest, StreamSemantics};

    #[test]
    fn expected_size_supports_open_streams() {
        let open = SessionManifest::new_stream("live.opus", 7, None, StreamSemantics::OpenEnded);
        assert_eq!(open.expected_size(), None);

        let finite =
            SessionManifest::new_stream("chunk.bin", 8, Some(1024), StreamSemantics::MediaFrames);
        assert_eq!(finite.expected_size(), Some(1024));
    }
}
