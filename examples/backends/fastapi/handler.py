"""AWS Lambda handler via Mangum.

Wraps the FastAPI app for API Gateway (v2 HTTP API) events.
The app and Mangum adapter are created at module level so they persist
across warm Lambda invocations.

Environment variables (required):
    COGNITO_CLIENT_ID, COGNITO_USER_POOL_ID, COGNITO_DOMAIN, SESSION_SECRET

Environment variables (recommended for Lambda):
    SESSION_BACKEND=dynamodb
    SESSION_HTTPS_ONLY=true
    DYNAMODB_TABLE=l42_sessions
"""

from mangum import Mangum

from app.config import get_settings
from app.main import create_app
from app.session import DynamoDBSessionBackend

s = get_settings()

# Choose session backend based on config
session_backend = None
if s.session_backend == "dynamodb":
    session_backend = DynamoDBSessionBackend(
        table_name=s.dynamodb_table,
        endpoint_url=s.dynamodb_endpoint,
        region_name=s.cognito_region,
    )

app = create_app(session_backend=session_backend)

handler = Mangum(app, lifespan="auto")
