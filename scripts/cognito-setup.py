#!/usr/bin/env python3
"""
Configure Cognito User Pool for WebAuthn/Passkey support.

Usage:
    python cognito-setup.py --pool-id us-west-2_xxx --domain your-domain.com

Requirements:
    pip install boto3

Note: CDK/CloudFormation don't support WebAuthn configuration as of January 2026.
This script uses boto3 to configure the required settings.
"""

import argparse
import boto3
import sys


def configure_webauthn(pool_id: str, relying_party_id: str, region: str = 'us-west-2'):
    """Configure Cognito User Pool for WebAuthn support."""
    client = boto3.client('cognito-idp', region_name=region)

    print(f"Configuring WebAuthn for User Pool: {pool_id}")
    print(f"Relying Party ID: {relying_party_id}")
    print(f"Region: {region}")
    print()

    # Step 1: Enable WEB_AUTHN in sign-in policy
    print("Step 1: Enabling WEB_AUTHN in sign-in policy...")
    try:
        client.update_user_pool(
            UserPoolId=pool_id,
            Policies={
                'SignInPolicy': {
                    'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']
                }
            }
        )
        print("  ✓ WEB_AUTHN enabled in AllowedFirstAuthFactors")
    except client.exceptions.InvalidParameterException as e:
        print(f"  ✗ Failed: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False

    # Step 2: Configure WebAuthn relying party
    print("Step 2: Configuring WebAuthn relying party...")
    try:
        client.set_user_pool_mfa_config(
            UserPoolId=pool_id,
            WebAuthnConfiguration={
                'RelyingPartyId': relying_party_id,
                'UserVerification': 'preferred'
            },
            MfaConfiguration='OPTIONAL'
        )
        print(f"  ✓ WebAuthn RelyingPartyId set to: {relying_party_id}")
    except client.exceptions.InvalidParameterException as e:
        print(f"  ✗ Failed: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False

    print()
    print("=" * 60)
    print("Configuration complete!")
    print("=" * 60)
    print()
    print("IMPORTANT NOTES:")
    print()
    print(f"1. Passkeys registered on '{relying_party_id}' will ONLY work on that domain")
    print(f"   and its subdomains (e.g., app.{relying_party_id})")
    print()
    print("2. Passkeys will NOT work from 'localhost' or other domains")
    print()
    print("3. For local development:")
    print("   - Use password authentication, OR")
    print("   - Create a separate User Pool with RelyingPartyId='localhost', OR")
    print("   - Use ngrok to tunnel to a subdomain")
    print()

    return True


def verify_config(pool_id: str, client_id: str, region: str = 'us-west-2'):
    """Verify Cognito configuration."""
    client = boto3.client('cognito-idp', region_name=region)

    print(f"Verifying configuration for User Pool: {pool_id}")
    print()

    # Check User Pool Client
    print("User Pool Client configuration:")
    try:
        response = client.describe_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id
        )
        upc = response['UserPoolClient']

        scopes = upc.get('AllowedOAuthScopes', [])
        flows = upc.get('ExplicitAuthFlows', [])

        has_admin_scope = 'aws.cognito.signin.user.admin' in scopes
        has_user_auth = 'ALLOW_USER_AUTH' in flows

        print(f"  OAuth Scopes: {scopes}")
        print(f"    ✓ aws.cognito.signin.user.admin" if has_admin_scope else "    ✗ MISSING: aws.cognito.signin.user.admin")
        print()
        print(f"  Auth Flows: {flows}")
        print(f"    ✓ ALLOW_USER_AUTH" if has_user_auth else "    ✗ MISSING: ALLOW_USER_AUTH")
        print()
    except Exception as e:
        print(f"  ✗ Error checking client: {e}")

    # Check WebAuthn config
    print("WebAuthn configuration:")
    try:
        response = client.get_user_pool_mfa_config(UserPoolId=pool_id)
        webauthn = response.get('WebAuthnConfiguration', {})

        if webauthn:
            print(f"  ✓ RelyingPartyId: {webauthn.get('RelyingPartyId', 'NOT SET')}")
            print(f"  ✓ UserVerification: {webauthn.get('UserVerification', 'NOT SET')}")
        else:
            print("  ✗ WebAuthn not configured")
    except Exception as e:
        print(f"  ✗ Error checking WebAuthn: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Configure Cognito User Pool for WebAuthn/Passkey support'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Configure command
    configure_parser = subparsers.add_parser('configure', help='Configure WebAuthn')
    configure_parser.add_argument('--pool-id', required=True, help='Cognito User Pool ID')
    configure_parser.add_argument('--domain', required=True, help='Relying Party ID (your domain)')
    configure_parser.add_argument('--region', default='us-west-2', help='AWS region')

    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify configuration')
    verify_parser.add_argument('--pool-id', required=True, help='Cognito User Pool ID')
    verify_parser.add_argument('--client-id', required=True, help='Cognito Client ID')
    verify_parser.add_argument('--region', default='us-west-2', help='AWS region')

    args = parser.parse_args()

    if args.command == 'configure':
        success = configure_webauthn(args.pool_id, args.domain, args.region)
        sys.exit(0 if success else 1)
    elif args.command == 'verify':
        verify_config(args.pool_id, args.client_id, args.region)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
