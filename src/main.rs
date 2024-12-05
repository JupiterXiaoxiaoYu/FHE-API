use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, CompactCiphertextList, CompactPublicKey, CompressedCompactPublicKey,
    ConfigBuilder, CompressedFheUint64, FheUint64, set_server_key,
    CompressedServerKey, 
};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tower_http::limit::RequestBodyLimitLayer;
use ring::signature::{self, KeyPair, Ed25519KeyPair};
use ring::rand::SystemRandom;
use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

mod state;
mod types;
use state::AppState;
use types::*;

// Define global variables
static CONFIG: Lazy<tfhe::Config> = Lazy::new(|| {
    let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let cpk_params = tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let casting_params = tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        .build()
});

static CRS: Lazy<CompactPkeCrs> = Lazy::new(|| {
    CompactPkeCrs::from_config(CONFIG.clone().into(), 64).unwrap()
});

#[tokio::main]
async fn main() {
    let app_state = Arc::new(AppState::new());

    let app = Router::new()
        .route("/generate_keys", post(generate_fhe_keys))
        .route("/get_public_key", post(get_fhe_public_key))
        .route("/encrypt", post(encrypt_data))
        .route("/compute", post(compute_sum))
        .route("/decrypt", post(decrypt_data))
        .with_state(Arc::clone(&app_state))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024));

    let addr = "0.0.0.0:3000".parse().unwrap();
    println!("Server running on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn generate_fhe_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<KeyGenRequest>,
) -> Json<KeyResponse> {
    let (client_key, server_key) = generate_keys(CONFIG.clone());
    let compressed_public_key = CompressedCompactPublicKey::new(&client_key);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    println!(
        "compressed public key size  : {}",
        bincode::serialize(&compressed_public_key).unwrap().len()
    );
    println!(
        "compressed server key size  : {}",
        bincode::serialize(&compressed_server_key).unwrap().len()
    );
    println!(
        "client key size            : {}",
        bincode::serialize(&client_key).unwrap().len()
    );
    
    let mut key_pairs = state.key_pairs.write().await;
    key_pairs.insert(request.public_key.clone(), (client_key.clone(), compressed_public_key.clone()));
    
    let mut server_keys = state.server_keys.write().await;
    server_keys.insert(request.public_key.clone(), compressed_server_key.clone());
    
    set_server_key(compressed_server_key.decompress());
    
    Json(KeyResponse {
        fhe_public_key: base64::encode(bincode::serialize(&compressed_public_key).unwrap()),
        server_key: base64::encode(bincode::serialize(&compressed_server_key).unwrap()),
        client_key: base64::encode(bincode::serialize(&client_key).unwrap()),
    })
}

async fn get_fhe_public_key(
    State(state): State<Arc<AppState>>,
    Json(request): Json<KeyGenRequest>,
) -> Json<KeyResponse> {
    let key_pairs = state.key_pairs.read().await;
    let (_, compressed_public_key) = key_pairs.get(&request.public_key).unwrap();
    
    let server_keys = state.server_keys.read().await;
    let compressed_server_key = server_keys.get(&request.public_key).unwrap();
    
    Json(KeyResponse {
        fhe_public_key: base64::encode(bincode::serialize(compressed_public_key).unwrap()),
        server_key: "".to_string(),
        client_key: "".to_string(),
    })
}

async fn encrypt_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EncryptRequest>,
) -> Json<EncryptResponse> {
    let key_pairs = state.key_pairs.read().await;
    let public_zk_params = CRS.public_params();
    let (client_key, compressed_public_key) = key_pairs.get(&request.public_key).unwrap();

    let public_key = compressed_public_key.decompress();
    let server_keys = state.server_keys.read().await;
    let compressed_server_key = server_keys.get(&request.public_key).unwrap();
    
    set_server_key(compressed_server_key.decompress());
    
    let compressed = CompressedFheUint64::try_encrypt(request.value, client_key).unwrap();
    let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];
    let proven_compact_list = match tfhe::ProvenCompactCiphertextList::builder(&public_key)
        .push(request.value)
        .build_with_proof_packed(public_zk_params, &metadata, ZkComputeLoad::Verify)
    {
        Ok(list) => list,
        Err(e) => return Json(EncryptResponse {
            encrypted_value: format!("Error: {:?}", e),
        }),
    };

    // Verify the ciphertexts
    let expander = match proven_compact_list.verify_and_expand(public_zk_params, &public_key, &metadata) {
        Ok(exp) => exp,
        Err(e) => return Json(EncryptResponse {
            encrypted_value: format!("Error: {:?}", e),
        }),
    };

    Json(EncryptResponse {
        encrypted_value: base64::encode(bincode::serialize(&compressed).unwrap()),
    })
}

async fn compute_sum(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ComputeRequest>,
) -> Json<ComputeResponse> {
    let server_keys = state.server_keys.read().await;
    let compressed_server_key = server_keys.get(&request.public_key).unwrap();
    
    set_server_key(compressed_server_key.decompress());
    
    let mut sum: Option<FheUint64> = None;
    
    for encrypted_value in request.encrypted_values {
        let compressed: CompressedFheUint64 = bincode::deserialize(
            &base64::decode(encrypted_value).unwrap()
        ).unwrap();
        
        let value = compressed.decompress();
        
        match sum {
            None => sum = Some(value),
            Some(ref mut s) => {
                let current = s.clone();
                *s = current + value;
            }
        }
    }
    
    let result = sum.unwrap();
    let compressed_result = result.compress();
    
    Json(ComputeResponse {
        result: base64::encode(bincode::serialize(&compressed_result).unwrap()),
    })
}

async fn decrypt_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DecryptRequest>,
) -> Json<DecryptResponse> {
    let key_pairs = state.key_pairs.read().await;
    let (client_key, _) = key_pairs.get(&request.public_key).unwrap();
    
    let compressed: CompressedFheUint64 = bincode::deserialize(
        &base64::decode(request.encrypted_value).unwrap()
    ).unwrap();
    
    let value = compressed.decompress();
    let decrypted_value: u64 = value.decrypt(client_key);
    
    let value_bytes = decrypted_value.to_le_bytes();
    let signature = state.signing_key.sign(&value_bytes);
    
    Json(DecryptResponse {
        value: decrypted_value,
        signature: base64::encode(signature.as_ref()),
    })
}