// Readonly: view-only access to all readable resources.
// Maps to CORE_ROLES.readonly with permissions: ['read:*']
// Cedar has no wildcards, so we enumerate all read actions.
@id("readonly-read")
permit(
    principal in App::UserGroup::"readonly",
    action in [
        App::Action::"read:content",
        App::Action::"read:own",
        App::Action::"read:all",
        App::Action::"read:users",
        App::Action::"read:logs",
        App::Action::"read:metrics"
    ],
    resource
);
