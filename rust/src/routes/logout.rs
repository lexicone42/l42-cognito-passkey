//! POST /auth/logout

use axum::Json;

use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, SuccessResponse};

/// Destroy session and log OCSF event.
pub async fn logout(session: SessionHandle) -> Json<SuccessResponse> {
    // Best-effort extraction before destroying session
    let (email, auth_protocol, auth_protocol_name) = {
        let tokens: Option<SessionTokens> = session.tokens_opt().await;

        let email = tokens.as_ref().and_then(|t| {
            crate::cognito::jwt::decode_jwt_unverified(&t.id_token)
                .ok()
                .and_then(|c| c.email)
        });

        // Use the shared mapping — this used to be an inline copy that had
        // drifted (it reported "password" logins as OAuth 2.0/OIDC).
        let (proto, proto_name) = ocsf::auth_protocol_from_method(
            tokens.and_then(|t| t.auth_method).as_deref().unwrap_or(""),
        );

        (email, proto, proto_name)
    };

    // Destroy session
    session.destroy().await;

    ocsf::authentication_event(
        ocsf::ACTIVITY_LOGOFF,
        "Logoff",
        ocsf::STATUS_SUCCESS,
        ocsf::SEVERITY_INFORMATIONAL,
        email.as_deref(),
        auth_protocol,
        auth_protocol_name,
        "User logged out",
    );

    Json(SuccessResponse { success: true })
}
