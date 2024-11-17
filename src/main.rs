use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, CompactCiphertextList, CompactPublicKey,
    ConfigBuilder, FheUint8,
};
use tower_http::limit::RequestBodyLimitLayer;

mod state;
mod types;
use state::AppState;
use types::*;

#[tokio::main]
async fn main() {
    let app_state = Arc::new(AppState::new());

    let app = Router::new()
        .route("/generate_keys", post(generate_fhe_keys))
        .route("/get_public_key", get(get_fhe_public_key))
        .route("/encrypt", post(encrypt_data))
        .route("/compute", post(compute_sum))
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
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
        )
        .build();
    
    let (client_key, _) = generate_keys(config);
    let public_key = CompactPublicKey::new(&client_key);
    
    let mut key_pairs = state.key_pairs.write().await;
    key_pairs.insert(request.public_key, (client_key, public_key.clone()));
    
    Json(KeyResponse {
        fhe_public_key: base64::encode(bincode::serialize(&public_key).unwrap()),
    })
}

async fn get_fhe_public_key(
    State(state): State<Arc<AppState>>,
    Json(request): Json<KeyGenRequest>,
) -> Json<KeyResponse> {
    let key_pairs = state.key_pairs.read().await;
    let (_, public_key) = key_pairs.get(&request.public_key).unwrap();
    
    Json(KeyResponse {
        fhe_public_key: base64::encode(bincode::serialize(public_key).unwrap()),
    })
}

async fn encrypt_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EncryptRequest>,
) -> Json<EncryptResponse> {
    let key_pairs = state.key_pairs.read().await;
    let (_, public_key) = key_pairs.get(&request.public_key).unwrap();
    
    let compact_list = CompactCiphertextList::builder(public_key)
        .push(request.value)
        .build();
    
    let encrypted = compact_list.expand().unwrap();
    let encrypted_value: FheUint8 = encrypted.get(0).unwrap().unwrap();
    
    Json(EncryptResponse {
        encrypted_value: base64::encode(bincode::serialize(&encrypted_value).unwrap()),
    })
}

async fn compute_sum(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ComputeRequest>,
) -> Json<ComputeResponse> {
    let _key_pairs = state.key_pairs.read().await;
    
    let mut sum: Option<FheUint8> = None;
    for encrypted_value in request.encrypted_values {
        let value: FheUint8 = bincode::deserialize(&base64::decode(encrypted_value).unwrap()).unwrap();
        match sum {
            None => sum = Some(value),
            Some(ref mut s) => {
                let current = s.clone();
                *s = current + value;
            }
        }
    }
    
    Json(ComputeResponse {
        result: base64::encode(bincode::serialize(&sum.unwrap()).unwrap()),
    })
}