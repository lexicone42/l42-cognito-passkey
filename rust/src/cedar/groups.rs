//! Cognito group alias resolution for Cedar entity mapping.
//!
//! Mirrors the `DEFAULT_GROUP_MAP` from:
//! - `examples/backends/express/cedar-engine.js`
//!
//! Each Cognito group name (case-insensitive) maps to a canonical Cedar
//! UserGroup entity ID. Unknown groups pass through unchanged.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Mapping from lowercase Cognito group aliases to canonical Cedar group IDs.
static DEFAULT_GROUP_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        // Admin
        ("admin", "admin"),
        ("admins", "admin"),
        ("administrators", "admin"),
        // Readonly
        ("readonly", "readonly"),
        ("read-only", "readonly"),
        ("viewer", "readonly"),
        ("viewers", "readonly"),
        // User
        ("user", "users"),
        ("users", "users"),
        ("member", "users"),
        ("members", "users"),
        // Editor
        ("editor", "editors"),
        ("editors", "editors"),
        // Reviewer
        ("reviewer", "reviewers"),
        ("reviewers", "reviewers"),
        // Publisher
        ("publisher", "publishers"),
        ("publishers", "publishers"),
        // Moderator
        ("moderator", "moderators"),
        ("moderators", "moderators"),
        ("mod", "moderators"),
        ("mods", "moderators"),
        // Developer
        ("developer", "developers"),
        ("developers", "developers"),
        ("dev", "developers"),
        ("devs", "developers"),
    ])
});

/// Resolve a Cognito group name to its canonical Cedar entity ID.
///
/// Case-insensitive. Unknown groups pass through as-is (lowercase).
pub fn resolve_group(group: &str) -> String {
    let lower = group.to_lowercase();
    DEFAULT_GROUP_MAP
        .get(lower.as_str())
        .map(|s| s.to_string())
        .unwrap_or(lower)
}

/// Get all canonical group names (the values, deduplicated).
pub fn canonical_groups() -> Vec<&'static str> {
    let mut groups: Vec<&str> = DEFAULT_GROUP_MAP.values().copied().collect();
    groups.sort();
    groups.dedup();
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_aliases() {
        assert_eq!(resolve_group("admin"), "admin");
        assert_eq!(resolve_group("admins"), "admin");
        assert_eq!(resolve_group("administrators"), "admin");
        assert_eq!(resolve_group("Admin"), "admin");
        assert_eq!(resolve_group("ADMIN"), "admin");
    }

    #[test]
    fn test_readonly_aliases() {
        assert_eq!(resolve_group("readonly"), "readonly");
        assert_eq!(resolve_group("read-only"), "readonly");
        assert_eq!(resolve_group("viewer"), "readonly");
        assert_eq!(resolve_group("viewers"), "readonly");
    }

    #[test]
    fn test_user_aliases() {
        assert_eq!(resolve_group("user"), "users");
        assert_eq!(resolve_group("users"), "users");
        assert_eq!(resolve_group("member"), "users");
        assert_eq!(resolve_group("members"), "users");
    }

    #[test]
    fn test_editor_aliases() {
        assert_eq!(resolve_group("editor"), "editors");
        assert_eq!(resolve_group("editors"), "editors");
    }

    #[test]
    fn test_moderator_aliases() {
        assert_eq!(resolve_group("moderator"), "moderators");
        assert_eq!(resolve_group("mod"), "moderators");
        assert_eq!(resolve_group("mods"), "moderators");
    }

    #[test]
    fn test_developer_aliases() {
        assert_eq!(resolve_group("developer"), "developers");
        assert_eq!(resolve_group("dev"), "developers");
        assert_eq!(resolve_group("devs"), "developers");
    }

    #[test]
    fn test_unknown_group_passthrough() {
        assert_eq!(resolve_group("custom-role"), "custom-role");
        assert_eq!(resolve_group("MyCustomGroup"), "mycustomgroup");
    }

    #[test]
    fn test_canonical_groups_count() {
        let groups = canonical_groups();
        // 8 canonical groups: admin, developers, editors, moderators,
        // publishers, readonly, reviewers, users
        assert_eq!(groups.len(), 8);
        assert!(groups.contains(&"admin"));
        assert!(groups.contains(&"users"));
        assert!(groups.contains(&"readonly"));
    }

    #[test]
    fn test_resolve_is_idempotent() {
        // Resolving a canonical group name returns itself
        assert_eq!(resolve_group("admin"), "admin");
        assert_eq!(resolve_group("users"), "users");
        assert_eq!(resolve_group("editors"), "editors");

        // And double-resolution is stable
        let first = resolve_group("admins");
        let second = resolve_group(&first);
        assert_eq!(first, second);
    }
}
