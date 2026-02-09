// Moderator: community moderation, can manage users and chat.
// Maps to STANDARD_ROLES.moderator with permissions:
//   ['read:users', 'mute:users', 'kick:users', 'manage:chat']
@id("moderator-community")
permit(
    principal in App::UserGroup::"moderators",
    action in [
        App::Action::"read:users",
        App::Action::"mute:users",
        App::Action::"kick:users",
        App::Action::"manage:chat"
    ],
    resource
);
