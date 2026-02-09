// Admin: full access to all actions on all resources.
// Maps to CORE_ROLES.admin with permissions: ['*']
@id("admin-permit-all")
permit(
    principal in App::UserGroup::"admin",
    action,
    resource
);
