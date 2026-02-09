// Ownership enforcement: deny write:own and delete:own when resource
// has an owner and that owner is not the requesting principal.
//
// Uses "forbid ... when { has && != }" pattern so Cedar's validator can
// prove the optional attribute access is safe (&&-guarded by `has`).
// If the caller omits resource.owner, the `has` check fails and the
// forbid does not fire — the permit policies still apply.
//
// Design note: This policy enables a future persistent entity store
// (DynamoDB, Redis) to populate resource.owner automatically.
// Until then, callers must include resource.owner in the request body
// for ownership enforcement to activate.

@id("deny-non-owner-write")
forbid(
    principal,
    action == App::Action::"write:own",
    resource
) when { resource has owner && resource.owner != principal };

@id("deny-non-owner-delete")
forbid(
    principal,
    action == App::Action::"delete:own",
    resource
) when { resource has owner && resource.owner != principal };
