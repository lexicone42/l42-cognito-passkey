//! Cedar authorization engine: init, validate, and evaluate.
//!
//! This is the core architectural win of the Rust rewrite — calling
//! `cedar-policy` directly instead of through WASM (JS) or FFI (Python).
//! The Authorizer, PolicySet, and Schema are pre-parsed at startup and
//! shared via `Arc<CedarState>` across all requests.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Schema, Validator, ValidationMode,
};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::cognito::jwt::Claims;
use crate::types::ResourceDescriptor;

use super::entities::build_entities;

/// Pre-parsed Cedar authorization state.
///
/// `Send + Sync` — safe to share via `Arc<CedarState>` across Axum handlers.
pub struct CedarState {
    authorizer: Authorizer,
    policy_set: PolicySet,
    schema: Schema,
}

/// Result of a Cedar authorization evaluation.
#[derive(Debug)]
pub struct AuthorizeResult {
    pub authorized: bool,
    pub reason: String,
}

impl CedarState {
    /// Initialize Cedar from schema file and policy directory.
    ///
    /// Loads the JSON schema, reads all `.cedar` policy files, parses them,
    /// and validates the policies against the schema. Returns an error if
    /// any step fails (fail-closed).
    pub fn init(schema_path: &Path, policy_dir: &Path) -> Result<Self, CedarError> {
        // Load schema
        let schema_text = fs::read_to_string(schema_path)
            .map_err(|e| CedarError::Init(format!("Failed to read schema: {e}")))?;
        let schema_json: serde_json::Value = serde_json::from_str(&schema_text)
            .map_err(|e| CedarError::Init(format!("Failed to parse schema JSON: {e}")))?;
        let schema = Schema::from_json_value(schema_json)
            .map_err(|e| CedarError::Init(format!("Failed to load Cedar schema: {e}")))?;

        // Load policies from all .cedar files
        let mut policy_files: Vec<_> = fs::read_dir(policy_dir)
            .map_err(|e| CedarError::Init(format!("Failed to read policy directory: {e}")))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "cedar")
            })
            .collect();
        policy_files.sort_by_key(|e| e.file_name());

        if policy_files.is_empty() {
            return Err(CedarError::Init(format!(
                "No .cedar files found in {}",
                policy_dir.display()
            )));
        }

        // Concatenate all policy files and parse as one PolicySet.
        // The @id("...") annotations in each .cedar file give unique IDs.
        let mut all_policies = String::new();
        for entry in &policy_files {
            let content = fs::read_to_string(entry.path())
                .map_err(|e| CedarError::Init(format!("Failed to read {}: {e}", entry.path().display())))?;
            all_policies.push_str(&content);
            all_policies.push_str("\n\n");
        }

        let policy_set = PolicySet::from_str(&all_policies)
            .map_err(|e| CedarError::Init(format!("Failed to parse policies: {e}")))?;

        // Validate policies against schema
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policy_set, ValidationMode::default());
        if !result.validation_passed() {
            let errors: Vec<String> = result
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(CedarError::Init(format!(
                "Cedar validation failed: {}",
                errors.join("; ")
            )));
        }

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set,
            schema,
        })
    }

    /// Initialize from raw schema JSON and policy text (for testing).
    pub fn from_raw(schema_json: serde_json::Value, policy_text: &str) -> Result<Self, CedarError> {
        let schema = Schema::from_json_value(schema_json)
            .map_err(|e| CedarError::Init(format!("Schema error: {e}")))?;

        let policy_set = PolicySet::from_str(policy_text)
            .map_err(|e| CedarError::Init(format!("Policy parse error: {e}")))?;

        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policy_set, ValidationMode::default());
        if !result.validation_passed() {
            let errors: Vec<String> = result
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(CedarError::Init(format!(
                "Validation failed: {}",
                errors.join("; ")
            )));
        }

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set,
            schema,
        })
    }

    /// Evaluate a Cedar authorization request.
    ///
    /// Builds entities from JWT claims, constructs a Cedar Request, and
    /// calls the authorizer. Returns the decision.
    pub fn authorize(
        &self,
        claims: &Claims,
        action: &str,
        resource: Option<&ResourceDescriptor>,
        _context: Option<&serde_json::Value>,
    ) -> Result<AuthorizeResult, CedarError> {
        // Build entities
        let entity_list = build_entities(claims, resource)
            .map_err(|e| CedarError::Evaluation(e.to_string()))?;

        let entities = Entities::from_entities(entity_list, Some(&self.schema))
            .map_err(|e| CedarError::Evaluation(format!("Failed to build entity set: {e}")))?;

        // Build request
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("App::User").unwrap(),
            EntityId::from_str(&claims.sub).unwrap(),
        );
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("App::Action").unwrap(),
            EntityId::from_str(action).unwrap(),
        );
        let resource_id = resource
            .and_then(|r| r.id.as_deref())
            .unwrap_or("_application");
        let resource_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("App::Resource").unwrap(),
            EntityId::from_str(resource_id).unwrap(),
        );

        let cedar_context = Context::empty();

        let request = cedar_policy::Request::new(
            principal,
            action_uid,
            resource_uid,
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarError::Evaluation(format!("Invalid request: {e}")))?;

        // Evaluate
        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        match response.decision() {
            Decision::Allow => Ok(AuthorizeResult {
                authorized: true,
                reason: "allowed".into(),
            }),
            Decision::Deny => Ok(AuthorizeResult {
                authorized: false,
                reason: "No matching permit policy".into(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    #[error("Cedar initialization failed: {0}")]
    Init(String),

    #[error("Cedar evaluation failed: {0}")]
    Evaluation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cedar_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cedar")
    }

    fn init_real_cedar() -> CedarState {
        CedarState::init(
            &cedar_dir().join("schema.cedarschema.json"),
            &cedar_dir().join("policies"),
        )
        .expect("Cedar init should succeed with real schema + policies")
    }

    fn claims(sub: &str, groups: &[&str]) -> Claims {
        Claims {
            sub: sub.into(),
            email: Some("test@example.com".into()),
            iss: None,
            aud: None,
            exp: None,
            iat: None,
            token_use: None,
            cognito_groups: groups.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_init_real_policies() {
        let _state = init_real_cedar();
        // If we get here without error, schema + 9 policies loaded and validated
    }

    #[test]
    fn test_admin_permit_all() {
        let state = init_real_cedar();
        let admin = claims("admin-user", &["admin"]);

        let result = state
            .authorize(&admin, "read:content", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&admin, "admin:delete-user", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&admin, "write:all", None, None)
            .unwrap();
        assert!(result.authorized);
    }

    #[test]
    fn test_user_own_resources() {
        let state = init_real_cedar();
        let user = claims("user-sub", &["users"]);

        // Users can read:own and write:own
        let result = state
            .authorize(&user, "read:own", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&user, "write:own", None, None)
            .unwrap();
        assert!(result.authorized);

        // Users cannot admin:delete-user
        let result = state
            .authorize(&user, "admin:delete-user", None, None)
            .unwrap();
        assert!(!result.authorized);
    }

    #[test]
    fn test_ownership_enforcement() {
        let state = init_real_cedar();
        let user = claims("user-sub", &["users"]);

        // Write own resource (owner matches) → allowed
        let own_resource = ResourceDescriptor {
            id: Some("doc-1".into()),
            resource_type: Some("document".into()),
            owner: Some("user-sub".into()),
        };
        let result = state
            .authorize(&user, "write:own", Some(&own_resource), None)
            .unwrap();
        assert!(result.authorized, "User should be able to write own resource");

        // Write someone else's resource → denied by forbid policy
        let other_resource = ResourceDescriptor {
            id: Some("doc-2".into()),
            resource_type: Some("document".into()),
            owner: Some("other-user".into()),
        };
        let result = state
            .authorize(&user, "write:own", Some(&other_resource), None)
            .unwrap();
        assert!(
            !result.authorized,
            "User should NOT be able to write someone else's resource"
        );
    }

    #[test]
    fn test_admin_bypasses_ownership_via_write_all() {
        let state = init_real_cedar();
        let admin = claims("admin-sub", &["admin"]);

        // Admin uses write:all (not write:own) to bypass the forbid policy
        let other_resource = ResourceDescriptor {
            id: Some("doc-2".into()),
            resource_type: Some("document".into()),
            owner: Some("other-user".into()),
        };
        let result = state
            .authorize(&admin, "write:all", Some(&other_resource), None)
            .unwrap();
        assert!(result.authorized);
    }

    #[test]
    fn test_readonly_permissions() {
        let state = init_real_cedar();
        let viewer = claims("viewer-sub", &["readonly"]);

        // Readonly can read
        let result = state
            .authorize(&viewer, "read:content", None, None)
            .unwrap();
        assert!(result.authorized);

        // Readonly cannot write
        let result = state
            .authorize(&viewer, "write:content", None, None)
            .unwrap();
        assert!(!result.authorized);
    }

    #[test]
    fn test_editor_permissions() {
        let state = init_real_cedar();
        let editor = claims("editor-sub", &["editors"]);

        let result = state
            .authorize(&editor, "read:content", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&editor, "write:content", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&editor, "publish:content", None, None)
            .unwrap();
        assert!(result.authorized);

        // Editors cannot manage users
        let result = state
            .authorize(&editor, "admin:manage", None, None)
            .unwrap();
        assert!(!result.authorized);
    }

    #[test]
    fn test_developer_permissions() {
        let state = init_real_cedar();
        let dev = claims("dev-sub", &["developers"]);

        let result = state
            .authorize(&dev, "api:read", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&dev, "read:logs", None, None)
            .unwrap();
        assert!(result.authorized);

        let result = state
            .authorize(&dev, "debug:view", None, None)
            .unwrap();
        assert!(result.authorized);

        // Developers cannot admin
        let result = state
            .authorize(&dev, "admin:manage", None, None)
            .unwrap();
        assert!(!result.authorized);
    }

    #[test]
    fn test_no_groups_denied() {
        let state = init_real_cedar();
        let nobody = claims("nobody-sub", &[]);

        let result = state
            .authorize(&nobody, "read:content", None, None)
            .unwrap();
        assert!(!result.authorized);
    }

    #[test]
    fn test_init_fails_no_policies() {
        let result = CedarState::init(
            &cedar_dir().join("schema.cedarschema.json"),
            Path::new("/nonexistent"),
        );
        assert!(result.is_err());
    }
}
