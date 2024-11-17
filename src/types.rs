use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct KeyGenRequest {
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub public_key: String,
    pub data_type: String,
    pub value: u8,
}

#[derive(Deserialize)]
pub struct ComputeRequest {
    pub task_id: String,
    pub data_type: String,
    pub encrypted_values: Vec<String>, // Base64 encoded encrypted values
}

#[derive(Serialize)]
pub struct KeyResponse {
    pub fhe_public_key: String, // Base64 encoded
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub encrypted_value: String, // Base64 encoded
}

#[derive(Serialize)]
pub struct ComputeResponse {
    pub result: String, // Base64 encoded
} 