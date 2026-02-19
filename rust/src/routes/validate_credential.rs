//! POST /auth/validate-credential
//!
//! Pre-registration validation gate: parses the WebAuthn attestation object,
//! extracts AAGUID and backup flags, and checks against configurable policies.

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::credential;
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{
    DeviceInfo, SessionTokens, ValidateCredentialRequest, ValidateCredentialResponse,
};

/// Validate a WebAuthn credential before registration with Cognito.
///
/// Requires an authenticated session. Parses the attestation object to
/// extract AAGUID and flags, then enforces AAGUID allowlist and device-bound
/// policies. Returns 200 with device info if allowed, 403 if rejected.
pub async fn validate_credential(
    State(state): State<Arc<crate::AppState>>,
    session: SessionHandle,
    Json(body): Json<ValidateCredentialRequest>,
) -> Result<Json<ValidateCredentialResponse>, AppError> {
    // Require authenticated session
    let data = session.data.lock().await;
    let tokens: SessionTokens = data
        .get("tokens")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(AppError::NotAuthenticated)?;
    drop(data);

    let user_email = ocsf::email_from_session(Some(&tokens));

    // Parse attestation object
    let device = match credential::parse_attestation_object(&body.attestation_object) {
        Ok(d) => d,
        Err(e) => {
            ocsf::authentication_event(
                ocsf::ACTIVITY_OTHER,
                "Other",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_MEDIUM,
                user_email.as_deref(),
                ocsf::AUTH_PROTOCOL_FIDO2,
                "FIDO2/Passkey",
                &format!("Credential validation failed: {e}"),
            );
            return Err(AppError::BadRequest(format!(
                "Invalid attestation object: {e}"
            )));
        }
    };

    // Check AAGUID allowlist
    if let Err(reason) = credential::check_aaguid_allowed(
        &device.aaguid,
        &state.config.aaguid_allowlist,
    ) {
        log_validation_result(&device, user_email.as_deref(), false, &reason);
        return Err(AppError::CredentialRejected(reason));
    }

    // Check device-bound requirement
    if let Err(reason) =
        credential::check_device_bound(&device, state.config.require_device_bound)
    {
        log_validation_result(&device, user_email.as_deref(), false, &reason);
        return Err(AppError::CredentialRejected(reason));
    }

    // Store validated device info in session for audit trail
    let mut data = session.data.lock().await;
    data.set(
        "last_validated_credential",
        serde_json::to_value(&device).unwrap(),
    );
    drop(data);

    log_validation_result(&device, user_email.as_deref(), true, "Credential accepted");

    Ok(Json(ValidateCredentialResponse {
        allowed: true,
        reason: None,
        device: Some(device),
    }))
}

fn log_validation_result(
    device: &DeviceInfo,
    user_email: Option<&str>,
    allowed: bool,
    message: &str,
) {
    let status_id = if allowed {
        ocsf::STATUS_SUCCESS
    } else {
        ocsf::STATUS_FAILURE
    };
    let severity = if allowed {
        ocsf::SEVERITY_INFORMATIONAL
    } else {
        ocsf::SEVERITY_HIGH
    };

    let msg = format!(
        "Credential validation: {} (aaguid={}, be={}, bs={})",
        message, device.aaguid, device.backup_eligible, device.backup_state
    );

    ocsf::authentication_event(
        ocsf::ACTIVITY_OTHER,
        "Other",
        status_id,
        severity,
        user_email,
        ocsf::AUTH_PROTOCOL_FIDO2,
        "FIDO2/Passkey",
        &msg,
    );
}
