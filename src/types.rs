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
    pub public_key: String,
    pub task_id: String,
    pub data_type: String,
    pub encrypted_values: Vec<String>, // Base64 encoded encrypted values
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub public_key: String,
    pub data_type: String,
    pub encrypted_value: String, // Base64 encoded encrypted value
}

#[derive(Serialize)]
pub struct KeyResponse {
    pub fhe_public_key: String,    // Base64 encoded
    pub server_key: String,        // Base64 encoded
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub encrypted_value: String, // Base64 encoded
}

#[derive(Serialize)]
pub struct ComputeResponse {
    pub result: String, // Base64 encoded FheUint8
}

#[derive(Serialize)]
pub struct DecryptResponse {
    pub value: u8,
    pub signature: String, // Base64 encoded signature
} 