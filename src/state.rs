use std::collections::HashMap;
use tfhe::{CompactPublicKey, ClientKey, CompressedServerKey};
use tokio::sync::RwLock;
use ring::signature::Ed25519KeyPair;
use ring::rand::SystemRandom;

pub struct AppState {
    pub key_pairs: RwLock<HashMap<String, (ClientKey, CompactPublicKey)>>,
    pub server_keys: RwLock<HashMap<String, CompressedServerKey>>,
    pub signing_key: Ed25519KeyPair,
}

impl AppState {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signing_key = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        
        Self {
            key_pairs: RwLock::new(HashMap::new()),
            server_keys: RwLock::new(HashMap::new()),
            signing_key,
        }
    }
} 