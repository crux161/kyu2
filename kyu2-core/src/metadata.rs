use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionManifest {
    pub filename: String,
    pub file_size: u64,
    pub timestamp: u64, // Good for versioning/sync
}

impl SessionManifest {
    pub fn new(filename: &str, file_size: u64) -> Self {
        Self {
            filename: filename.to_string(),
            file_size,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}
