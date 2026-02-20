# L42 Token Handler — Rust Backend

Native Rust implementation of the Token Handler backend for [l42-cognito-passkey](https://github.com/lexicone42/l42-cognito-passkey). The preferred backend — runs as a single static binary in both AWS Lambda and local development. Express (Node.js) is available as an alternative in `examples/backends/express/`.

## Why Rust?

The Express backend calls the Cedar policy engine through WASM (`@cedar-policy/cedar-wasm`) — wrapping the same Rust library underneath. This backend calls `cedar-policy` directly:

| Metric | Express (WASM) | Rust backend |
|--------|-------------------|--------------|
| Lambda cold start | 2–5 s (WASM init) | 10–50 ms |
| Lambda memory | 512 MB | 128–256 MB |
| Cedar evaluation | WASM marshalling | Direct native calls |
| Deployment artifact | Runtime + deps | Single static binary |

## Quick Start

```bash
# Copy .env.example and fill in your Cognito values
cp .env.example .env

# Run locally (port 3001 by default)
cargo run

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings
```

The same binary runs in Lambda — detection is automatic via the `AWS_LAMBDA_RUNTIME_API` env var.

## Architecture

```
rust/
├── cedar/                          # Cedar schema + 9 policy files (same as Express)
│   ├── schema.cedarschema.json
│   └── policies/*.cedar
├── src/
│   ├── main.rs                     # Dual-mode: Lambda or local Axum server
│   ├── lib.rs                      # create_app(), AppState
│   ├── config.rs                   # Config from env vars
│   ├── error.rs                    # AppError → HTTP status + JSON
│   ├── types.rs                    # Request/response DTOs
│   ├── ocsf.rs                     # OCSF structured security logging
│   ├── cognito/
│   │   ├── client.rs               # Token exchange, InitiateAuth refresh
│   │   └── jwt.rs                  # JWT decode, JWKS cache, RS256 verify
│   ├── cedar/
│   │   ├── engine.rs               # CedarState: native Authorizer + PolicySet
│   │   ├── entities.rs             # Build Cedar entities from JWT claims
│   │   └── groups.rs               # Cognito group alias resolution (30+ aliases)
│   ├── session/
│   │   ├── cookie.rs               # HMAC-SHA256 session cookie signing
│   │   ├── memory.rs               # InMemoryBackend (dev/test)
│   │   ├── dynamodb.rs             # DynamoDBBackend (prod/Lambda)
│   │   └── middleware.rs           # Axum session middleware layer
│   ├── middleware/
│   │   └── csrf.rs                 # X-L42-CSRF: 1 header check
│   └── routes/
│       ├── health.rs               # GET /health
│       ├── token.rs                # GET /auth/token
│       ├── session.rs              # POST /auth/session
│       ├── refresh.rs              # POST /auth/refresh
│       ├── logout.rs               # POST /auth/logout
│       ├── callback.rs             # GET /auth/callback (OAuth)
│       ├── me.rs                   # GET /auth/me
│       └── authorize.rs            # POST /auth/authorize (Cedar)
└── tests/
    ├── common/mod.rs               # RSA keypair, JWT factory, test app builder
    └── test_routes.rs              # 22 integration tests
```

## Endpoints

All endpoints match the Express backend exactly — the same `auth.js` client works without changes.

| Endpoint | Method | Auth | CSRF | Purpose |
|----------|--------|------|------|---------|
| `/health` | GET | — | — | Health check + Cedar status |
| `/auth/token` | GET | yes | — | Return access + id tokens (never refresh) |
| `/auth/session` | POST | — | yes | Store tokens from passkey/password login |
| `/auth/refresh` | POST | yes | yes | Refresh tokens via Cognito |
| `/auth/logout` | POST | — | yes | Destroy session |
| `/auth/callback` | GET | — | — | OAuth code exchange + redirect |
| `/auth/me` | GET | yes | — | Return user info from ID token |
| `/auth/authorize` | POST | yes | yes | Cedar policy evaluation |

## Configuration

See `.env.example` for all options. Required variables:

| Variable | Example |
|----------|---------|
| `COGNITO_CLIENT_ID` | `abc123def456` |
| `COGNITO_USER_POOL_ID` | `us-west-2_AbCdEfG` |
| `COGNITO_DOMAIN` | `myapp.auth.us-west-2.amazoncognito.com` |

For production (Lambda), also set:
- `SESSION_SECRET` — random 32+ character string
- `SESSION_BACKEND=dynamodb`
- `SESSION_HTTPS_ONLY=true`

## DynamoDB Session Table

DynamoDB session table schema:

| Attribute | Type | Purpose |
|-----------|------|---------|
| `session_id` | S (PK) | Partition key |
| `data` | S | JSON-encoded session payload |
| `created_at` | N | Unix timestamp |
| `ttl` | N | DynamoDB TTL (auto-cleanup) |

Enable TTL on the `ttl` attribute in the DynamoDB console or CDK.

## Lambda Deployment

```bash
# Build for Lambda (ARM64 for Graviton2)
cargo lambda build --release --arm64

# The binary is at target/lambda/l42-token-handler/bootstrap
```

CDK stack configuration:
```typescript
new lambda.Function(this, 'TokenHandler', {
  runtime: lambda.Runtime.PROVIDED_AL2023,
  handler: 'bootstrap',
  code: lambda.Code.fromAsset('rust/target/lambda/l42-token-handler'),
  architecture: lambda.Architecture.ARM_64,
  memorySize: 256,
  timeout: Duration.seconds(5),
  environment: {
    COGNITO_CLIENT_ID: '...',
    COGNITO_USER_POOL_ID: '...',
    COGNITO_DOMAIN: '...',
    SESSION_SECRET: '...',
    SESSION_BACKEND: 'dynamodb',
    DYNAMODB_TABLE: 'l42_sessions',
    SESSION_HTTPS_ONLY: 'true',
    FRONTEND_URL: 'https://your-site.com',
  },
});
```

## Cedar Policies

The 9 `.cedar` policy files in `cedar/policies/` are identical to the Express backend. They enforce:

- **Admin**: Full access to all actions
- **Users**: Read/write own resources
- **Ownership forbid**: `forbid` policy denies `write:own` when `resource.owner != principal` (overrides any permit)
- **Readonly/Editor/Publisher/Reviewer/Moderator/Developer**: Scoped permissions

Admin bypasses ownership via `write:all` (separate action not covered by the forbid policy).

## Tests

```bash
# All tests (149 total: 110 unit + 39 integration)
cargo test

# Just integration tests
cargo test --test test_routes

# Just Cedar engine tests
cargo test cedar::engine
```

Integration tests cover: health, token retrieval, expired token rejection, CSRF enforcement, session CRUD, Cedar authorization (admin/user/ownership), callback redirects, credential validation, OCSF logging, session isolation.
