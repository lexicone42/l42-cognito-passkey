"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    cognito_client_id: str
    cognito_client_secret: str = ""
    cognito_user_pool_id: str
    cognito_domain: str
    cognito_region: str = "us-west-2"
    session_secret: str = "change-me-in-production"
    frontend_url: str = "http://localhost:3000"
    port: int = 3001
    session_backend: str = "memory"  # "memory" or "dynamodb"
    dynamodb_table: str = "l42_sessions"
    dynamodb_endpoint: str = ""  # For local DynamoDB

    @property
    def cognito_issuer(self) -> str:
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def jwks_url(self) -> str:
        return f"{self.cognito_issuer}/.well-known/jwks.json"

    @property
    def cognito_idp_url(self) -> str:
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/"

    @property
    def cognito_token_url(self) -> str:
        return f"https://{self.cognito_domain}/oauth2/token"

    model_config = {"env_prefix": "", "case_sensitive": False}


settings: Settings | None = None


def get_settings() -> Settings:
    global settings
    if settings is None:
        settings = Settings()
    return settings


def override_settings(s: Settings) -> None:
    """For testing: inject a Settings instance."""
    global settings
    settings = s
