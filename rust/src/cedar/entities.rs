//! Build Cedar entities from JWT claims and resource descriptors.
//!
//! Creates the entity hierarchy required for Cedar policy evaluation:
//! - `App::User::"<sub>"` — the principal, with email/sub attrs and group parents
//! - `App::UserGroup::"<group>"` — stub entities for each resolved group
//! - `App::Resource::"<id>"` — the resource, with type and optional owner

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use std::collections::HashSet;
use std::str::FromStr;

use crate::cognito::jwt::Claims;
use crate::types::ResourceDescriptor;

use super::groups::resolve_group;

/// Build a Cedar `Entity` set from JWT claims and an optional resource.
///
/// Returns a Vec of entities that should be passed to `Entities::from_entities`.
pub fn build_entities(
    claims: &Claims,
    resource: Option<&ResourceDescriptor>,
) -> Result<Vec<Entity>, EntityBuildError> {
    let mut entities = Vec::new();

    // Resolve Cognito groups to canonical Cedar group IDs (deduplicated)
    let canonical_groups: HashSet<String> = claims
        .cognito_groups
        .iter()
        .map(|g| resolve_group(g))
        .collect();

    // Principal (User) entity
    let user_uid = make_uid("App::User", &claims.sub)?;
    let parent_uids: HashSet<EntityUid> = canonical_groups
        .iter()
        .map(|g| make_uid("App::UserGroup", g))
        .collect::<Result<_, _>>()?;

    let user_attrs = vec![
        (
            "email".into(),
            RestrictedExpression::new_string(claims.email.clone().unwrap_or_default()),
        ),
        (
            "sub".into(),
            RestrictedExpression::new_string(claims.sub.clone()),
        ),
    ];

    let user_entity = Entity::new(user_uid, user_attrs.into_iter().collect(), parent_uids)
        .map_err(|e| EntityBuildError(format!("Failed to build User entity: {e}")))?;
    entities.push(user_entity);

    // UserGroup stub entities (Cedar requires referenced entities to exist)
    for group in &canonical_groups {
        let group_uid = make_uid("App::UserGroup", group)?;
        let group_entity = Entity::new_no_attrs(group_uid, HashSet::new());
        entities.push(group_entity);
    }

    // Resource entity
    let resource_id = resource
        .and_then(|r| r.id.as_deref())
        .unwrap_or("_application");
    let resource_type = resource
        .and_then(|r| r.resource_type.as_deref())
        .unwrap_or("application");

    let resource_uid = make_uid("App::Resource", resource_id)?;
    let mut resource_attrs: Vec<(String, RestrictedExpression)> = vec![(
        "resourceType".into(),
        RestrictedExpression::new_string(resource_type.to_string()),
    )];

    // Optional owner attribute — only set if present in the resource descriptor.
    // When present, it's an entity reference to App::User.
    if let Some(owner) = resource.and_then(|r| r.owner.as_deref()) {
        let owner_expr = RestrictedExpression::from_str(&format!(
            "App::User::\"{}\"",
            owner.replace('\\', "\\\\").replace('"', "\\\"")
        ))
        .map_err(|e| EntityBuildError(format!("Failed to build owner expression: {e}")))?;
        resource_attrs.push(("owner".into(), owner_expr));
    }

    let resource_entity = Entity::new(
        resource_uid,
        resource_attrs.into_iter().collect(),
        HashSet::new(),
    )
    .map_err(|e| EntityBuildError(format!("Failed to build Resource entity: {e}")))?;
    entities.push(resource_entity);

    Ok(entities)
}

/// Create an EntityUid from type name and ID strings.
fn make_uid(type_name: &str, id: &str) -> Result<EntityUid, EntityBuildError> {
    let tn = EntityTypeName::from_str(type_name)
        .map_err(|e| EntityBuildError(format!("Invalid entity type name '{type_name}': {e}")))?;
    let eid = EntityId::from_str(id)
        .map_err(|e| EntityBuildError(format!("Invalid entity ID '{id}': {e}")))?;
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct EntityBuildError(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claims(sub: &str, groups: &[&str]) -> Claims {
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
    fn test_build_entities_admin() {
        let claims = test_claims("user-123", &["admin"]);
        let entities = build_entities(&claims, None).unwrap();

        // Should have: User + UserGroup("admin") + Resource("_application")
        assert_eq!(entities.len(), 3);

        // Check user entity
        let user = &entities[0];
        assert_eq!(user.uid().to_string(), "App::User::\"user-123\"");

        // Check group entity
        let group = &entities[1];
        assert_eq!(group.uid().to_string(), "App::UserGroup::\"admin\"");

        // Check resource entity
        let resource = &entities[2];
        assert_eq!(
            resource.uid().to_string(),
            "App::Resource::\"_application\""
        );
    }

    #[test]
    fn test_build_entities_with_resource() {
        let claims = test_claims("user-456", &["users"]);
        let resource = ResourceDescriptor {
            id: Some("doc-1".into()),
            resource_type: Some("document".into()),
            owner: Some("user-456".into()),
        };
        let entities = build_entities(&claims, Some(&resource)).unwrap();

        // User + UserGroup("users") + Resource("doc-1")
        assert_eq!(entities.len(), 3);

        let resource_entity = &entities[2];
        assert_eq!(
            resource_entity.uid().to_string(),
            "App::Resource::\"doc-1\""
        );
    }

    #[test]
    fn test_build_entities_multiple_groups() {
        let claims = test_claims("user-789", &["admin", "editors", "admin"]);
        let entities = build_entities(&claims, None).unwrap();

        // User + 2 groups (admin, editors — deduplicated) + Resource
        assert_eq!(entities.len(), 4);
    }

    #[test]
    fn test_build_entities_alias_resolution() {
        let claims = test_claims("user-abc", &["admins", "viewers"]);
        let entities = build_entities(&claims, None).unwrap();

        // "admins" → "admin", "viewers" → "readonly"
        let group_names: Vec<String> = entities
            .iter()
            .filter(|e| e.uid().to_string().starts_with("App::UserGroup"))
            .map(|e| AsRef::<str>::as_ref(e.uid().id()).to_string())
            .collect();

        assert!(group_names.contains(&"admin".to_string()));
        assert!(group_names.contains(&"readonly".to_string()));
    }

    #[test]
    fn test_build_entities_no_groups() {
        let claims = test_claims("user-no-groups", &[]);
        let entities = build_entities(&claims, None).unwrap();

        // User + Resource only (no groups)
        assert_eq!(entities.len(), 2);
    }
}
