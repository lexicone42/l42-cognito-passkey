// User: standard authenticated user with own-resource access.
// Maps to CORE_ROLES.user with permissions: ['read:own', 'write:own']
@id("user-own-resources")
permit(
    principal in App::UserGroup::"users",
    action in [
        App::Action::"read:own",
        App::Action::"write:own"
    ],
    resource
);
