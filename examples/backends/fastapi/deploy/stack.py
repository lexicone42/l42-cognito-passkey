"""CDK stack for the L42 Token Handler FastAPI backend on Lambda."""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_logs as logs,
)
from aws_cdk.aws_apigatewayv2 import CorsHttpMethod, CorsPreflightOptions, HttpApi, HttpMethod
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration
from constructs import Construct


class L42TokenHandlerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Context values (pass via -c or cdk.json) ---
        cognito_client_id = self.node.try_get_context("cognito_client_id") or "CHANGE_ME"
        cognito_user_pool_id = self.node.try_get_context("cognito_user_pool_id") or "CHANGE_ME"
        cognito_domain = self.node.try_get_context("cognito_domain") or "CHANGE_ME"
        session_secret = self.node.try_get_context("session_secret") or "CHANGE_ME"
        frontend_url = self.node.try_get_context("frontend_url") or "https://example.com"

        # --- DynamoDB sessions table ---
        sessions_table = dynamodb.Table(
            self,
            "SessionsTable",
            table_name="l42_sessions",
            partition_key=dynamodb.Attribute(
                name="session_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )

        # --- Lambda function ---
        fn = lambda_.Function(
            self,
            "Handler",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.handler",
            code=lambda_.Code.from_asset(
                "..",
                exclude=[
                    "deploy/*",
                    "tests/*",
                    "scripts/*",
                    ".venv/*",
                    "__pycache__",
                    "*.pyc",
                    ".pytest_cache",
                    ".git",
                ],
            ),
            memory_size=512,
            timeout=Duration.seconds(30),
            log_retention=logs.RetentionDays.TWO_WEEKS,
            environment={
                "COGNITO_CLIENT_ID": cognito_client_id,
                "COGNITO_USER_POOL_ID": cognito_user_pool_id,
                "COGNITO_DOMAIN": cognito_domain,
                "SESSION_SECRET": session_secret,
                "FRONTEND_URL": frontend_url,
                "SESSION_BACKEND": "dynamodb",
                "DYNAMODB_TABLE": sessions_table.table_name,
                "SESSION_HTTPS_ONLY": "true",
            },
        )

        sessions_table.grant_read_write_data(fn)

        # --- HTTP API (API Gateway v2) ---
        integration = HttpLambdaIntegration("LambdaIntegration", fn)

        api = HttpApi(
            self,
            "HttpApi",
            api_name="l42-token-handler",
            cors_preflight=CorsPreflightOptions(
                allow_origins=[frontend_url],
                allow_methods=[CorsHttpMethod.ANY],
                allow_headers=["*"],
                allow_credentials=True,
            ),
        )

        api.add_routes(
            path="/{proxy+}",
            methods=[HttpMethod.ANY],
            integration=integration,
        )

        # --- Outputs ---
        CfnOutput(self, "ApiUrl", value=api.url or "")
        CfnOutput(self, "TableName", value=sessions_table.table_name)
        CfnOutput(self, "FunctionName", value=fn.function_name)
