# Rust Backend

The Rust Token Handler backend: deployment, Cedar policies, and configuration.

See [rust/README.md](../rust/README.md) for development setup and [rust/CLAUDE.md](../rust/CLAUDE.md) for contributor details.

## Architecture

```
Browser → CloudFront → API Gateway (HTTP API) → Lambda (Rust binary) → DynamoDB (sessions)
                                                                       → Cognito (tokens)
                                                                       → Cedar (policies)
```

The binary is dual-mode: detects `AWS_LAMBDA_RUNTIME_API` at startup and runs as either a Lambda handler (`lambda_http`) or a local Axum server.

- **Framework**: Axum 0.8 + Tower
- **Cedar**: Native `cedar-policy` crate (no WASM)
- **Sessions**: InMemory (dev) via DashMap, DynamoDB (prod)
- **Cookies**: HMAC-SHA256 signed session IDs

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `COGNITO_CLIENT_ID` | Yes | Cognito app client ID |
| `COGNITO_CLIENT_SECRET` | No | For confidential clients |
| `COGNITO_USER_POOL_ID` | Yes | User pool ID (e.g., `us-west-2_abc123`) |
| `COGNITO_DOMAIN` | Yes | Cognito domain |
| `SESSION_SECRET` | Yes | Random 32+ char string for HMAC signing |
| `SESSION_BACKEND` | Yes | `memory` (dev) or `dynamodb` (prod) |
| `DYNAMODB_TABLE` | Prod | DynamoDB table name |
| `SESSION_HTTPS_ONLY` | Yes | `true` for production |
| `FRONTEND_URL` | Yes | Frontend origin for CORS + redirects |
| `COOKIE_DOMAIN` | No | `Domain=` on cookies (e.g., `.example.com`) |
| `AUTH_PATH_PREFIX` | No | Route prefix (default: `/auth`) |
| `CALLBACK_USE_ORIGIN` | No | `true` for multi-CloudFront deployments |
| `CALLBACK_ALLOWED_ORIGINS` | No | Comma-separated allowed origins |
| `AAGUID_ALLOWLIST` | No | Comma-separated allowed authenticator AAGUIDs |
| `REQUIRE_DEVICE_BOUND` | No | `true` to reject synced passkeys at registration |

## Local Development

```bash
cd rust/
cp .env.example .env  # fill in Cognito values
cargo run             # starts on :3001
```

## Lambda Deployment

### 1. Build

```bash
cd rust/
cargo lambda build --release --arm64
# Binary: target/lambda/l42-token-handler/bootstrap
```

### 2. CDK Stack

```typescript
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

const table = new dynamodb.Table(this, 'Sessions', {
  tableName: 'l42_sessions',
  partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  timeToLiveAttribute: 'ttl',
});

const handler = new lambda.Function(this, 'TokenHandler', {
  runtime: lambda.Runtime.PROVIDED_AL2023,
  handler: 'bootstrap',
  code: lambda.Code.fromAsset('rust/target/lambda/l42-token-handler'),
  architecture: lambda.Architecture.ARM_64,
  memorySize: 256,
  timeout: Duration.seconds(5),
  environment: {
    COGNITO_CLIENT_ID: 'your-client-id',
    COGNITO_USER_POOL_ID: 'us-west-2_abc123',
    COGNITO_DOMAIN: 'myapp.auth.us-west-2.amazoncognito.com',
    SESSION_SECRET: 'generate-a-random-32-char-string',
    SESSION_BACKEND: 'dynamodb',
    DYNAMODB_TABLE: table.tableName,
    SESSION_HTTPS_ONLY: 'true',
    FRONTEND_URL: 'https://your-site.com',
  },
});
table.grantReadWriteData(handler);
```

### 3. API Gateway

```typescript
const api = new apigateway.HttpApi(this, 'Api', {
  defaultIntegration: new apigateway.HttpLambdaIntegration('Handler', handler),
  corsPreflight: {
    allowOrigins: ['https://your-site.com'],
    allowMethods: [apigateway.CorsHttpMethod.ANY],
    allowHeaders: ['Content-Type', 'X-L42-CSRF'],
    allowCredentials: true,
  },
});
```

### Cold Start Performance

| Phase | Time |
|-------|------|
| Binary load | ~5-10 ms |
| Cedar init | <5 ms |
| JWKS fetch | ~100-200 ms (first `/auth/session`, cached 1 hour) |
| **Total** | **10-50 ms** |

### DynamoDB Session Table

| Attribute | Type | Purpose |
|-----------|------|---------|
| `session_id` | S (PK) | Partition key |
| `data` | S | JSON-encoded session |
| `created_at` | N | Unix timestamp |
| `ttl` | N | DynamoDB TTL (auto-cleanup) |

Enable TTL on the `ttl` attribute.

### IAM Permissions

The Lambda only needs `dynamodb:GetItem`, `PutItem`, `DeleteItem` on the sessions table. No `Scan` or `Query` — the session backend does point lookups only.

## CloudFront Configuration

```
CloudFront (app.example.com)
  └── Default behavior → S3 (static frontend)
  └── /_auth/* → API Gateway → Lambda
```

```bash
AUTH_PATH_PREFIX=/_auth
COOKIE_DOMAIN=.example.com
FRONTEND_URL=https://app.example.com
```

### Multi-Origin

One Lambda behind multiple CloudFront distributions:

```bash
CALLBACK_USE_ORIGIN=true
CALLBACK_ALLOWED_ORIGINS=https://app1.example.com,https://app2.example.com
```

Each origin must be registered as a callback URL in the Cognito app client.

## Cedar Policies

Cedar is built into the Rust backend. Schema and policies are in `rust/cedar/`.

### File Layout

```
rust/cedar/
├── schema.cedarschema.json    # Entity types + 23 actions
└── policies/
    ├── admin.cedar            # Admin wildcard permit
    ├── editor.cedar           # Content editing
    ├── reviewer.cedar         # Content review
    ├── publisher.cedar        # Content publishing + deploy
    ├── readonly.cedar         # Read-only access
    ├── user.cedar             # Standard user (own resources)
    ├── moderator.cedar        # Community moderation
    ├── developer.cedar        # Dev tools, APIs, logs
    └── owner-only.cedar       # Ownership enforcement (forbid)
```

### Writing Policies

```cedar
// Basic permit — editors can manage content
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

// Admin wildcard
@id("admin-permit-all")
permit(principal in App::UserGroup::"admin", action, resource);

// Ownership enforcement — forbid always overrides permit
@id("deny-non-owner-write")
forbid(
    principal,
    action == App::Action::"write:own",
    resource
) when { resource has owner && resource.owner != principal };
```

### Adding a New Action

1. Add to schema (`cedar/schema.cedarschema.json`):
   ```json
   "export:report": {
       "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Resource"] }
   }
   ```

2. Create or update a policy file:
   ```cedar
   @id("reporter-export")
   permit(
       principal in App::UserGroup::"reporters",
       action == App::Action::"export:report",
       resource
   );
   ```

3. Add the Cognito group alias in the group resolver.

4. Validate — Cedar validates policies against the schema at startup.

### Group Alias Resolution

Cognito group names are resolved automatically:

```
admin, admins, administrators  →  admin
readonly, read-only, viewer    →  readonly
editor, editors                →  editors
dev, devs, developer           →  developers
```

### Debugging Authorization

| Symptom | Cause | Fix |
|---------|-------|-----|
| 503 on `/auth/authorize` | Cedar failed to initialize | Check startup logs |
| 401 on `/auth/authorize` | No session cookie | Ensure `credentials: 'include'` |
| 403 with empty reason | No permit policy matches | Check user's Cognito groups |
| 403 with non-empty reason | A `forbid` policy blocked | Check ownership — is `resource.owner` correct? |

### Performance

Cedar uses pre-parsed policies and schema (`statefulIsAuthorized`). Per-request evaluation is typically <0.1ms.

### Fail-Closed

If Cedar fails to initialize, the server still starts but `/auth/authorize` returns HTTP 503 with `authorized: false`.

## Credential Validation

The Rust backend can enforce policies on passkey credentials at registration time via `POST /auth/validate-credential`:

- Parses CBOR attestation object to extract AAGUID and BE/BS flags
- Checks AAGUID against `AAGUID_ALLOWLIST`
- Enforces device-bound policy via `REQUIRE_DEVICE_BOUND`
- Returns 403 with `{"allowed": false, "reason": "..."}` on rejection

The client calls this endpoint automatically before completing registration with Cognito (configured via `validateCredentialEndpoint`).

## Post-Deploy Verification

```bash
API_URL=https://abc123.execute-api.us-west-2.amazonaws.com

# Health check
curl $API_URL/health
# → {"status":"ok","mode":"token-handler","cedar":"ready"}

# CORS headers
curl -I -X OPTIONS $API_URL/auth/token \
  -H "Origin: https://your-site.com" \
  -H "Access-Control-Request-Method: GET"
```

## Updating

```bash
cd rust/
cargo lambda build --release --arm64
cd ../deploy && cdk deploy
```

## Session Cookie Notes

API Gateway v2 HTTP APIs terminate HTTPS, so Lambda sees HTTP internally. Set `SESSION_HTTPS_ONLY=true` to force the `Secure` flag regardless. For production, store `SESSION_SECRET` in AWS Secrets Manager.
