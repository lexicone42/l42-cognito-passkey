# Design Note: RFC 8707 Resource Indicators

**Status:** Design / not yet implemented. The build decision hinges on one
question about *your* app architecture — see [Decision gate](#decision-gate).

## What it is

[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) ("Resource Indicators
for OAuth 2.0") lets a client name the **specific resource server** an access
token is intended for, via a `resource` parameter on the authorization/token
request. Cognito then mints an access token whose **`aud` (audience) claim is
scoped to that resource** (GA October 2025, Essentials/Plus tiers). The resource
server rejects any token whose `aud` isn't itself.

It is **token confinement**, not authorization:

| | Question | Mechanism | Where it lives |
|---|---|---|---|
| **Authorization** | *Who* may do this? (GMs view monsters) | Cedar policy | `/auth/authorize` gateway — already built |
| **Token confinement (8707)** | *Which API* is this token even valid for? | `aud`-scoped access token | Cognito + each resource server's validation |

They **stack**. Cedar decides the GM may view the monster; 8707 ensures the token
you hand the *monster API* can't be replayed against your *billing API* if it
leaks. 8707 does not decide who's allowed — remove Cedar and 8707 alone still
lets any authenticated user hit the monster API.

## Decision gate

**Does your monster (or other sensitive) data live behind a separate
resource-server API that validates the access token's `aud`?**

- **Yes — separate APIs, each validating `aud`** → 8707 is worth building. It
  turns a stolen access token from "usable against every API" into "usable
  against one." Proceed to [If we build it](#if-we-build-it).
- **No — everything goes through the Cedar `/auth/authorize` gateway** → 8707
  adds little. The gateway already gates each action server-side; there's no
  second audience-scoped API for a confined token to protect. Cedar is your
  answer; revisit 8707 only when you split out a standalone API.

This library uses the **Token Handler** pattern: the browser never holds a
long-lived access token for general API use — tokens live in the server session,
and authorization runs through `/auth/authorize`. So 8707 only pays off for the
`fetchWithAuth` Bearer-token path against a *distinct* resource-server API.

## If we build it

The pieces, roughly in order:

1. **Cognito** — register a resource server + custom scopes for each protected
   API (e.g. `monster-api`), and enable resource indicators on the app client.
2. **Backend `/auth/login`** — accept an optional `resource` query param and
   forward it to Cognito's authorize request (the endpoint already owns the
   redirect; this is a passthrough of the `resource` parameter).
3. **Backend token exchange** — pass `resource` to
   `exchange_code_for_tokens`/`GetTokensFromRefreshToken` so Cognito scopes the
   `aud`. Store one access token per resource, or re-exchange on demand.
4. **`/auth/token`** — let the client request a token *for a named resource*
   (`GET /auth/token?resource=monster-api`), returning an `aud`-scoped access
   token. This is the one real client-facing API change.
5. **`fetchWithAuth`** — add a `{ resource }` option that fetches the
   resource-scoped token for that call.
6. **Resource server** — validate `aud == monster-api` (in addition to
   signature/issuer/exp) and reject otherwise. This is where the confinement is
   actually enforced; without it, 8707 is inert.

### Sketch

```javascript
// Client
const res = await auth.fetchWithAuth('/api/monsters/goblin-1', {
    resource: 'monster-api'   // NEW: mints/uses an aud=monster-api token
});
```

```
// Monster API (any language) — the enforcement point
verify(access_token):
    check signature against Cognito JWKS
    check iss == https://cognito-idp.{region}.amazonaws.com/{poolId}
    check exp
    check aud == "monster-api"      # ← RFC 8707 confinement
```

## Interaction with what shipped in v0.22.0

- **Cedar gating** (`docs/rust-backend.md` → "Gating a resource type by role")
  is the "GMs only" half and works today.
- **Refresh token rotation** (`docs/integration.md`) is orthogonal and already
  wired — resource-scoped access tokens are still refreshed the same way.
- **`validateTokenClaims`** already checks `aud` on the client for the session
  token; an 8707 resource token would carry a *different* `aud` (the resource
  name), so the client-side check would need a per-resource allowance if we ever
  surfaced these tokens to `auth.js` validation (we likely won't — they're for
  API calls, not the session).

## Recommendation

Ship the Cedar gating now (done). Treat 8707 as a **fast-follow once a standalone
`monster-api` exists** with its own `aud` validation. Until there's a second API
to confine a token *to*, 8707 is architecture waiting for a use — real, but
premature. When you're ready, the [decision gate](#decision-gate) answer of "yes"
is the green light, and the six steps above are the build.

## References

- [RFC 8707 — Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [Amazon Cognito now supports resource indicators (AWS, Oct 2025)](https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-cognito-resource-indicators-protection-oauth-2-0-resources/)
- [Scopes, M2M, and resource servers — Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html)
