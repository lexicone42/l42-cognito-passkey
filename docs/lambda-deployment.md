# Lambda Deployment Guide

Deploy the Rust Token Handler backend to AWS Lambda.

## Architecture

```
Browser → CloudFront → API Gateway (HTTP API) → Lambda (Rust binary) → DynamoDB (sessions)
                                                                      → Cognito (token exchange)
```

## Prerequisites

- AWS CLI configured (`aws sts get-caller-identity`)
- [cargo-lambda](https://www.cargo-lambda.info/) installed
- Rust 1.85+ (edition 2024)
- A Cognito User Pool with an app client

## Quick Deploy

### 1. Build the Lambda binary

```bash
cd rust/

# Build for ARM64 (Graviton2 — recommended for cost/perf)
cargo lambda build --release --arm64

# Binary is at target/lambda/l42-token-handler/bootstrap
```

### 2. Deploy with CDK

```typescript
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

// Session table
const table = new dynamodb.Table(this, 'Sessions', {
  tableName: 'l42_sessions',
  partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  timeToLiveAttribute: 'ttl',
});

// Lambda function
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

### 3. Add API Gateway

```typescript
import * as apigateway from 'aws-cdk-lib/aws-apigatewayv2';

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

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `COGNITO_CLIENT_ID` | Yes | Cognito app client ID |
| `COGNITO_CLIENT_SECRET` | No | For confidential clients |
| `COGNITO_USER_POOL_ID` | Yes | User pool ID (e.g., `us-west-2_abc123`) |
| `COGNITO_DOMAIN` | Yes | Cognito domain |
| `SESSION_SECRET` | Yes | Random 32+ char string for HMAC cookie signing |
| `SESSION_BACKEND` | Yes | `dynamodb` for production |
| `DYNAMODB_TABLE` | Yes | DynamoDB table name |
| `SESSION_HTTPS_ONLY` | Yes | `true` for production |
| `FRONTEND_URL` | Yes | Frontend origin for CORS + redirects |
| `COOKIE_DOMAIN` | No | `Domain=` on cookies (e.g., `.example.com` for cross-subdomain SSO) |
| `AUTH_PATH_PREFIX` | No | Route prefix (default: `/auth`). Set to `/_auth` if CloudFront routes `/_auth/*` to Lambda |
| `CALLBACK_USE_ORIGIN` | No | `true` to redirect OAuth callback to request origin (multi-CloudFront) |
| `CALLBACK_ALLOWED_ORIGINS` | No | Comma-separated allowed origins (required when `CALLBACK_USE_ORIGIN=true`) |
| `AAGUID_ALLOWLIST` | No | Comma-separated allowed authenticator AAGUIDs (empty = allow all) |
| `REQUIRE_DEVICE_BOUND` | No | `true` to reject synced passkeys at registration |

## Cold Start Performance

| Phase | Time | Notes |
|-------|------|-------|
| Binary load | ~5-10 ms | Single static binary, no runtime |
| Cedar init | <5 ms | File reads + policy parsing (bundled in binary) |
| JWKS fetch | ~100-200 ms | First `/auth/session` call; cached 1 hour |

Total cold start: **10–50 ms** (dramatically better than Python/Node.js backends).

## DynamoDB Session Table

Same schema works for both Rust and Express backends:

| Attribute | Type | Purpose |
|-----------|------|---------|
| `session_id` | S (PK) | Partition key |
| `data` | S | JSON-encoded session payload |
| `created_at` | N | Unix timestamp |
| `ttl` | N | DynamoDB TTL (auto-cleanup) |

Enable TTL on the `ttl` attribute in DynamoDB console or CDK.

## CloudFront Configuration

For CDN deployment with CloudFront:

```
CloudFront (app.example.com)
  └── Default behavior → S3 (static frontend)
  └── /_auth/* → API Gateway → Lambda
      Headers: X-Forwarded-Host, X-Forwarded-Proto
```

Lambda env:
```bash
AUTH_PATH_PREFIX=/_auth
COOKIE_DOMAIN=.example.com
FRONTEND_URL=https://app.example.com
```

### Multi-Origin Deployment

For one Lambda behind multiple CloudFront distributions:

```bash
CALLBACK_USE_ORIGIN=true
CALLBACK_ALLOWED_ORIGINS=https://app1.example.com,https://app2.example.com
```

Each origin must be registered as a callback URL in the Cognito app client.

## Session Cookie Configuration

API Gateway v2 HTTP APIs terminate HTTPS, so Lambda sees HTTP internally. Set `SESSION_HTTPS_ONLY=true` to force the `Secure` flag on cookies regardless.

| Setting | Value | Why |
|---------|-------|-----|
| `Secure` | `true` | API Gateway is always HTTPS |
| `HttpOnly` | `true` | Always set (no JS access) |
| `SameSite` | `Lax` | Default; set to `None` if frontend and API are on different domains |

## Security Notes

### SESSION_SECRET

For production, store the secret in AWS Secrets Manager and read at startup:

```rust
// In your deployment: set SESSION_SECRET from Secrets Manager
// via CDK's Secret.fromSecretsManager() → Lambda environment
```

### IAM Permissions

The Lambda function only needs:
- `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` on the sessions table
- CloudWatch Logs (auto-granted by CDK)

No `dynamodb:Scan` or `dynamodb:Query` — the session backend only does point lookups.

## Post-Deploy Verification

```bash
# Get the API URL from CDK output
API_URL=https://abc123.execute-api.us-west-2.amazonaws.com

# Health check
curl $API_URL/health
# → {"status":"ok","mode":"token-handler","cedar":"ready"}

# Verify CORS headers
curl -I -X OPTIONS $API_URL/auth/token \
  -H "Origin: https://your-site.com" \
  -H "Access-Control-Request-Method: GET"
```

## Updating

After code changes:

```bash
cd rust/
cargo lambda build --release --arm64
cd ../deploy  # or wherever your CDK stack is
cdk deploy
```

## Further Reading

- [rust/README.md](../rust/README.md) — Full Rust backend documentation
- [rust/CLAUDE.md](../rust/CLAUDE.md) — Guide for Claude instances working on the Rust backend
- [Handler Mode](handler-mode.md) — Token Handler architecture
- [Cedar Authorization](cedar-integration.md) — Cedar policy setup
