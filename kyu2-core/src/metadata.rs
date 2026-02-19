use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionManifest {
    pub filename: String,
    pub file_size: u64,
    #[serde(default)]
    pub trace_id: u64,
    pub timestamp: u64, // Good for versioning/sync
}

impl SessionManifest {
    /// Creates metadata for a stream, including its stable trace id.
    pub fn new(filename: &str, file_size: u64, trace_id: u64) -> Self {
        Self {
            filename: filename.to_string(),
            file_size,
            trace_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Serializes metadata using bincode.
    pub fn to_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(self)
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}
