# Lambda Deployment Guide

Deploy the FastAPI Token Handler backend to AWS Lambda behind an HTTP API (API Gateway v2).

## Architecture

```
Browser → API Gateway (HTTP API) → Lambda (Mangum + FastAPI) → DynamoDB (sessions)
                                                             → Cognito (token exchange)
```

## Prerequisites

- AWS CLI configured with credentials (`aws sts get-caller-identity`)
- AWS CDK v2 installed (`npm install -g aws-cdk`)
- Python 3.13+
- A Cognito User Pool with an app client

## Quick Deploy

```bash
cd examples/backends/fastapi/deploy

# Install CDK dependencies
pip install -r requirements.txt

# Deploy (replace values)
cdk deploy \
  -c cognito_client_id=YOUR_CLIENT_ID \
  -c cognito_user_pool_id=us-west-2_abc123 \
  -c cognito_domain=myapp.auth.us-west-2.amazoncognito.com \
  -c session_secret=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))") \
  -c frontend_url=https://myapp.example.com
```

CDK outputs:
- **ApiUrl** — the HTTP API endpoint (e.g., `https://abc123.execute-api.us-west-2.amazonaws.com/`)
- **TableName** — the DynamoDB sessions table
- **FunctionName** — the Lambda function name

## What Gets Deployed

| Resource | Details |
|----------|---------|
| DynamoDB table | `l42_sessions`, partition key `session_id` (S), TTL on `ttl`, PAY_PER_REQUEST |
| Lambda function | Python 3.13, 512 MB, 30s timeout, `handler.handler` entry point |
| HTTP API | API Gateway v2, `ANY /{proxy+}` → Lambda, CORS configured |
| IAM | Lambda gets `dynamodb:GetItem/PutItem/DeleteItem` on sessions table + CloudWatch Logs |

## Environment Variables

The CDK stack sets these automatically:

| Variable | Source | Description |
|----------|--------|-------------|
| `COGNITO_CLIENT_ID` | CDK context | Cognito app client ID |
| `COGNITO_USER_POOL_ID` | CDK context | User pool ID |
| `COGNITO_DOMAIN` | CDK context | Cognito domain |
| `SESSION_SECRET` | CDK context | Session signing key |
| `FRONTEND_URL` | CDK context | Frontend origin (CORS + redirects) |
| `SESSION_BACKEND` | `dynamodb` (hardcoded) | Session storage backend |
| `DYNAMODB_TABLE` | From CDK table ref | DynamoDB table name |
| `SESSION_HTTPS_ONLY` | `true` (hardcoded) | Secure cookie flag |

## handler.py

The Lambda entry point at `examples/backends/fastapi/handler.py`:

```python
from mangum import Mangum
from app.config import get_settings
from app.main import create_app
from app.session import DynamoDBSessionBackend

s = get_settings()
session_backend = DynamoDBSessionBackend(...)  # from env vars
app = create_app(session_backend=session_backend)
handler = Mangum(app, lifespan="auto")
```

- **Module-level init**: `create_app()` runs once per Lambda container (reused across warm invocations)
- **`lifespan="auto"`**: Mangum runs FastAPI's lifespan events (Cedar init) on first invocation
- **DynamoDB backend**: Configured from `SESSION_BACKEND` env var

## Cold Start Considerations

| Phase | Time | Notes |
|-------|------|-------|
| Python import | ~200-400ms | FastAPI + dependencies |
| Cedar init | <10ms | File reads + policy validation (no network) |
| JWKS fetch | ~100-200ms | First `/auth/session` call fetches from Cognito, cached 1hr |

Total cold start: **~300-600ms** (dominated by Python imports).

### Mitigation

- **Provisioned concurrency**: Set to 1+ if cold starts are unacceptable for your use case
- **JWKS cache**: Lost on container recycle; first request after recycle adds ~150ms
- Cedar policies are bundled in the deployment package — no S3 or network fetch needed

## Session Cookie Configuration

API Gateway v2 HTTP APIs terminate HTTPS, so the Lambda function sees the request as HTTP internally. The session middleware uses `SESSION_HTTPS_ONLY=true` to set the `Secure` flag on cookies regardless.

| Setting | Value | Why |
|---------|-------|-----|
| `Secure` | `true` | API Gateway is always HTTPS |
| `HttpOnly` | `true` | Always set (no JS access) |
| `SameSite` | `Lax` | Default; set to `None` if frontend and API are on different domains |

### Cross-domain deployments

If your frontend (`app.example.com`) and API (`api.example.com`) are on different origins, you need `SameSite=None` + `Secure`. The session middleware's `same_site` parameter can be made configurable the same way as `https_only` (add `SESSION_SAME_SITE` to `config.py`).

## Security Notes

### SESSION_SECRET

The CDK stack passes `session_secret` as a Lambda environment variable. For production:

1. Store the secret in AWS Secrets Manager
2. Grant the Lambda function `secretsmanager:GetSecretValue`
3. Read it at startup in `handler.py` instead of from env

### CORS

`allow_credentials=True` requires an explicit origin — never `*`. The CDK stack sets this from the `frontend_url` context value. The FastAPI CORS middleware and API Gateway CORS config must agree.

### CSRF Header

API Gateway v2 HTTP APIs pass through all headers by default. Verify that `X-L42-CSRF` reaches the Lambda by checking the `/health` endpoint response or CloudWatch logs.

### IAM Permissions

The Lambda function only gets:
- `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` on the sessions table
- CloudWatch Logs (`logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`)

No `dynamodb:Scan` or `dynamodb:Query` — the session backend only does point lookups.

## Post-Deploy Verification

```bash
# Get the API URL from CDK output
API_URL=https://abc123.execute-api.us-west-2.amazonaws.com

# Health check
curl $API_URL/health

# Smoke test (from the FastAPI project)
python scripts/smoke_test.py --base-url $API_URL

# Full flow (requires valid tokens from Cognito)
python scripts/smoke_test.py --base-url $API_URL \
  --access-token <TOKEN> --id-token <TOKEN>
```

## Updating

After code changes:

```bash
cd deploy
cdk deploy   # Re-bundles and deploys the Lambda
```

To update only environment variables (no code change), use the AWS Console or:

```bash
aws lambda update-function-configuration \
  --function-name L42TokenHandler-Handler... \
  --environment '{"Variables": {...}}'
```

## Cleanup

```bash
cd deploy
cdk destroy
```

This removes the Lambda, API Gateway, and DynamoDB table. If you set `removal_policy=RETAIN` on the table in `stack.py`, the table persists after stack deletion.

## Native Dependencies

`cedarpy` and `aioboto3` include native extensions. The CDK `Code.from_asset` approach works if your build machine matches the Lambda runtime (Linux x86_64). For cross-platform builds, consider:

1. **Docker-based bundling** (CDK `BundlingOptions` with a Python image)
2. **Lambda layers** for `cedarpy` and other native deps
3. **Container image** deployment (`aws_lambda.DockerImageFunction`)
