# L42 Token Handler — FastAPI Backend

A Python/FastAPI implementation of the [Token Handler protocol](../../../docs/token-handler-spec.md) for [l42-cognito-passkey](https://github.com/lexicone42/l42-cognito-passkey).

Implements all 8 endpoints with Cedar authorization via [cedarpy](https://github.com/k9securityio/cedar-py).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/token` | Return tokens from session |
| POST | `/auth/session` | Store tokens from direct login (JWKS-verified) |
| POST | `/auth/refresh` | Refresh tokens via Cognito |
| POST | `/auth/logout` | Destroy session |
| GET | `/auth/callback` | OAuth callback (code → tokens) |
| POST | `/auth/authorize` | Cedar policy authorization |
| GET | `/auth/me` | User info from ID token |
| GET | `/health` | Liveness check (includes Cedar status) |

## Quick Start

### 1. Install

```bash
# With uv (recommended)
uv sync --all-extras

# Or with pip
pip install -e ".[dev]"
```

### 2. Configure

```bash
export COGNITO_CLIENT_ID=your-client-id
export COGNITO_USER_POOL_ID=us-west-2_abc123
export COGNITO_DOMAIN=myapp.auth.us-west-2.amazoncognito.com
export SESSION_SECRET=your-secret-key
export FRONTEND_URL=http://localhost:3000
```

### 3. Run

```bash
uvicorn app.main:create_app --factory --port 3001
```

### 4. Test

```bash
uv run pytest -v
```

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COGNITO_CLIENT_ID` | Yes | — | Cognito app client ID |
| `COGNITO_CLIENT_SECRET` | No | `""` | Cognito client secret (confidential clients) |
| `COGNITO_USER_POOL_ID` | Yes | — | User pool ID (e.g., `us-west-2_abc123`) |
| `COGNITO_DOMAIN` | Yes | — | Cognito domain |
| `COGNITO_REGION` | No | `us-west-2` | AWS region |
| `SESSION_SECRET` | Yes | — | Secret for signing session cookies |
| `FRONTEND_URL` | No | `http://localhost:3000` | Frontend origin (CORS + redirects) |
| `PORT` | No | `3001` | Server port |
| `SESSION_BACKEND` | No | `memory` | `memory` or `dynamodb` |
| `DYNAMODB_TABLE` | No | `l42_sessions` | DynamoDB table name |

## Session Backends

### In-Memory (default)

Development/testing only. Sessions are lost on restart.

### DynamoDB

For production. Set `SESSION_BACKEND=dynamodb` and create a table:

```bash
aws dynamodb create-table \
  --table-name l42_sessions \
  --attribute-definitions AttributeName=session_id,AttributeType=S \
  --key-schema AttributeName=session_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

Enable TTL on the `ttl` attribute for automatic session cleanup.

## Cedar Authorization

Cedar policies and schema are shared with the Express backend via symlink:

```
fastapi/cedar → ../express/cedar
```

On Windows, copy the directory instead:

```bash
cp -r ../express/cedar ./cedar
```

The Cedar engine initializes at startup and pre-validates all policies against the schema. If Cedar fails to load, the server still starts but `/auth/authorize` returns 503 (fail-closed).

## Security Invariants

1. Refresh tokens never leave the server (`/auth/token` strips them)
2. Session cookie is `HttpOnly` (no JavaScript access)
3. CSRF header (`X-L42-CSRF: 1`) required on all POST endpoints
4. JWKS verification on `/auth/session` (prevents forged tokens)
5. Fail-closed: 503 if Cedar unavailable
6. Session destroyed on refresh failure
7. CORS restricted to single frontend origin

## Project Structure

```
app/
├── main.py              # App factory, lifespan, middleware
├── config.py            # Pydantic Settings (env vars)
├── cognito.py           # Token exchange, refresh, JWKS verify
├── cedar_engine.py      # Cedar engine (cedarpy wrapper)
├── dependencies.py      # DI: session, CSRF, auth
├── session/
│   ├── middleware.py     # ASGI server-side session middleware
│   ├── backend.py       # SessionBackend protocol + InMemoryBackend
│   └── dynamodb.py      # DynamoDB backend
└── routes/
    ├── token.py          # GET  /auth/token
    ├── session_ep.py     # POST /auth/session
    ├── refresh.py        # POST /auth/refresh
    ├── logout.py         # POST /auth/logout
    ├── callback.py       # GET  /auth/callback
    ├── authorize.py      # POST /auth/authorize
    ├── me.py             # GET  /auth/me
    └── health.py         # GET  /health
```

## Differences from Express Backend

| Aspect | Express | FastAPI |
|--------|---------|---------|
| Session | `express-session` (cookie-based ID) | Custom ASGI middleware (`itsdangerous` signed ID) |
| JWKS | `jose` (`createRemoteJWKSet`) | `PyJWT` + `httpx` (async fetch + cache) |
| Cedar | `@cedar-policy/cedar-wasm` | `cedarpy` (Rust bindings) |
| HTTP client | Node `fetch` | `httpx` (async) |
| Session cookie name | `connect.sid` | `l42_session` |

## License

Apache-2.0
