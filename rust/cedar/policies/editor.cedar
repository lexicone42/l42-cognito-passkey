// Editor: create and edit content, push to static site.
// Maps to STANDARD_ROLES.editor with permissions:
//   ['read:content', 'write:content', 'publish:content']
@id("editor-content")
permit(
    principal in App::UserGroup::"editors",
    action in [
        App::Action::"read:content",
        App::Action::"write:content",
        App::Action::"publish:content"
    ],
    resource
);
