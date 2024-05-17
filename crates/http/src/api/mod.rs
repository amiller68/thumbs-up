use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use http::header::{ACCEPT, ORIGIN};
use http::Method;
use tower_http::cors::{Any, CorsLayer};

use crate::app::AppState;
use crate::extractors::ApiIdentity;

// Simple axum handler that extracts the api identity and passes along an empty response
async fn identity(identity: ApiIdentity) -> Response {
    tracing::info!("validating identity: {:?}", identity);
    (StatusCode::OK, "ok").into_response()
}

pub fn router(state: AppState) -> Router<AppState> {
    let cors_layer = CorsLayer::new()
        .allow_methods(vec![Method::GET])
        .allow_headers(vec![ACCEPT, ORIGIN])
        .allow_origin(Any)
        .allow_credentials(false);

    Router::new()
        .route("/identity", any(identity))
        .with_state(state)
        .layer(cors_layer)
}
