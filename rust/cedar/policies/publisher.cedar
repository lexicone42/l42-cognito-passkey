// Publisher: publish approved content to static site.
// Maps to STANDARD_ROLES.publisher with permissions:
//   ['read:content', 'publish:content', 'deploy:static']
@id("publisher-content")
permit(
    principal in App::UserGroup::"publishers",
    action in [
        App::Action::"read:content",
        App::Action::"publish:content",
        App::Action::"deploy:static"
    ],
    resource
);
