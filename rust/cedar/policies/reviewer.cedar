// Reviewer: review and approve content before publishing.
// Maps to STANDARD_ROLES.reviewer with permissions:
//   ['read:content', 'approve:content', 'reject:content']
@id("reviewer-content")
permit(
    principal in App::UserGroup::"reviewers",
    action in [
        App::Action::"read:content",
        App::Action::"approve:content",
        App::Action::"reject:content"
    ],
    resource
);
