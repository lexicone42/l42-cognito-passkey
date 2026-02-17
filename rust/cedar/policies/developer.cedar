// Developer: access to dev tools, APIs, logs, and metrics.
// Maps to STANDARD_ROLES.developer with permissions:
//   ['api:*', 'read:logs', 'read:metrics', 'debug:*']
@id("developer-api")
permit(
    principal in App::UserGroup::"developers",
    action in [
        App::Action::"api:read",
        App::Action::"api:write",
        App::Action::"read:logs",
        App::Action::"read:metrics",
        App::Action::"debug:view"
    ],
    resource
);
