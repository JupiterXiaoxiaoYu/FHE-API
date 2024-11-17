use std::collections::HashMap;
use tfhe::{CompactPublicKey, ClientKey};
use tokio::sync::RwLock;

pub struct AppState {
    pub key_pairs: RwLock<HashMap<String, (ClientKey, CompactPublicKey)>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            key_pairs: RwLock::new(HashMap::new()),
        }
    }
} 