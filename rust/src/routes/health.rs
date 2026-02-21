//! GET /health

use axum::Json;
use axum::extract::State;
use std::sync::Arc;

use crate::types::HealthResponse;

/// Health check — returns OK + Cedar status.
pub async fn health(State(state): State<Arc<crate::AppState>>) -> Json<HealthResponse> {
    let cedar_status = if state.cedar.is_some() {
        "ready"
    } else {
        "unavailable"
    };
    Json(HealthResponse {
        status: "ok".into(),
        mode: "token-handler".into(),
        cedar: cedar_status.into(),
    })
}
