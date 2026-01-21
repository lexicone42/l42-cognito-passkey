# Cognito Setup Guide

Complete guide to configuring AWS Cognito for l42-cognito-passkey.

## Overview

L42 Cognito Passkey requires:
1. **User Pool Client** - OAuth scopes and auth flows (CDK/CloudFormation)
2. **User Pool Settings** - WebAuthn configuration (boto3 only)

## 1. User Pool Client Configuration

### CDK (TypeScript)

```typescript
import * as cognito from 'aws-cdk-lib/aws-cognito';

const userPool = new cognito.UserPool(this, 'UserPool', {
    userPoolName: 'my-app-pool',
    selfSignUpEnabled: true,
    signInAliases: { email: true },
    standardAttributes: {
        email: { required: true, mutable: true }
    }
});

const userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
    userPool,
    generateSecret: false,
    oAuth: {
        flows: {
            authorizationCodeGrant: true
        },
        scopes: [
            cognito.OAuthScope.OPENID,
            cognito.OAuthScope.EMAIL,
            cognito.OAuthScope.COGNITO_ADMIN  // Required for passkey management
        ],
        callbackUrls: [
            'https://your-domain.com/callback',
            'http://localhost:3000/callback'  // For development
        ],
        logoutUrls: [
            'https://your-domain.com/',
            'http://localhost:3000/'
        ]
    }
});

// CDK doesn't expose ALLOW_USER_AUTH - use escape hatch
const cfnClient = userPoolClient.node.defaultChild as cognito.CfnUserPoolClient;
cfnClient.addPropertyOverride('ExplicitAuthFlows', [
    'ALLOW_USER_PASSWORD_AUTH',
    'ALLOW_USER_SRP_AUTH',
    'ALLOW_CUSTOM_AUTH',
    'ALLOW_USER_AUTH',  // Required for passkey login
    'ALLOW_REFRESH_TOKEN_AUTH'
]);

// Add Cognito domain
userPool.addDomain('CognitoDomain', {
    cognitoDomain: {
        domainPrefix: 'my-app-auth'
    }
});
```

### CloudFormation

```yaml
Resources:
  UserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: my-app-pool
      UsernameAttributes:
        - email
      AutoVerifiedAttributes:
        - email

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties:
      UserPoolId: !Ref UserPool
      ClientName: my-app-client
      GenerateSecret: false
      ExplicitAuthFlows:
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_CUSTOM_AUTH
        - ALLOW_USER_AUTH  # Required for passkey
        - ALLOW_REFRESH_TOKEN_AUTH
      AllowedOAuthFlows:
        - code
      AllowedOAuthScopes:
        - openid
        - email
        - aws.cognito.signin.user.admin  # Required for passkey management
      AllowedOAuthFlowsUserPoolClient: true
      CallbackURLs:
        - https://your-domain.com/callback
        - http://localhost:3000/callback
      LogoutURLs:
        - https://your-domain.com/
        - http://localhost:3000/

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties:
      Domain: my-app-auth
      UserPoolId: !Ref UserPool
```

## 2. WebAuthn Configuration (boto3)

**Important:** CDK and CloudFormation do NOT support WebAuthn configuration as of January 2026. You must use boto3, AWS CLI v2.15+, or the AWS Console.

### Using boto3

```python
#!/usr/bin/env python3
"""Configure Cognito User Pool for WebAuthn/Passkey support."""

import boto3

# Configuration
USER_POOL_ID = 'us-west-2_xxxxxxxxx'  # Your User Pool ID
REGION = 'us-west-2'
RELYING_PARTY_ID = 'your-domain.com'  # MUST match your production domain

def configure_webauthn():
    client = boto3.client('cognito-idp', region_name=REGION)

    # Step 1: Enable WEB_AUTHN in sign-in policy
    print(f"Enabling WEB_AUTHN for {USER_POOL_ID}...")

    client.update_user_pool(
        UserPoolId=USER_POOL_ID,
        Policies={
            'SignInPolicy': {
                'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']
            }
        }
    )
    print("✓ WEB_AUTHN enabled in sign-in policy")

    # Step 2: Configure WebAuthn relying party
    print(f"Configuring WebAuthn with RelyingPartyId: {RELYING_PARTY_ID}...")

    client.set_user_pool_mfa_config(
        UserPoolId=USER_POOL_ID,
        WebAuthnConfiguration={
            'RelyingPartyId': RELYING_PARTY_ID,
            'UserVerification': 'preferred'
        },
        MfaConfiguration='OPTIONAL'
    )
    print("✓ WebAuthn configuration complete")

    print(f"""
Configuration complete!

IMPORTANT: Passkeys are domain-bound.
- Passkeys registered on '{RELYING_PARTY_ID}' will NOT work from 'localhost'
- For local development, use password auth or create a separate user pool
- Subdomains work: passkeys for 'example.com' work on 'app.example.com'
""")

if __name__ == '__main__':
    configure_webauthn()
```

Save as `scripts/cognito-setup.py` and run:

```bash
python scripts/cognito-setup.py
```

### Using AWS Console

1. Go to **Cognito** > **User Pools** > Your Pool
2. Go to **Sign-in experience** tab
3. Under **Multi-factor authentication**, click **Edit**
4. Enable **Passkey** as an authentication method
5. Set **Relying Party ID** to your domain (e.g., `your-domain.com`)
6. Set **User verification** to `preferred`
7. Save changes

## 3. Verify Configuration

### Check User Pool Client

```bash
aws cognito-idp describe-user-pool-client \
    --user-pool-id us-west-2_xxxxxxxxx \
    --client-id your-client-id \
    --query 'UserPoolClient.{Scopes:AllowedOAuthScopes,Flows:ExplicitAuthFlows}'
```

Expected output should include:
- `aws.cognito.signin.user.admin` in Scopes
- `ALLOW_USER_AUTH` in Flows

### Check WebAuthn Configuration

```bash
aws cognito-idp get-user-pool-mfa-config \
    --user-pool-id us-west-2_xxxxxxxxx \
    --query 'WebAuthnConfiguration'
```

Expected output:
```json
{
    "RelyingPartyId": "your-domain.com",
    "UserVerification": "preferred"
}
```

## Domain Considerations

### Passkeys are Domain-Bound

- A passkey registered on `example.com` will **ONLY** work on `example.com` and its subdomains
- It will **NOT** work on `localhost` or any other domain
- This is a WebAuthn security feature, not a bug

### Development Strategies

**Option 1: Use password auth for development**
```javascript
// In development, use password login
if (window.location.hostname === 'localhost') {
    await loginWithPassword(email, password);
} else {
    await loginWithPasskey(email);
}
```

**Option 2: Separate user pool for development**
Create a second Cognito User Pool with `RelyingPartyId: 'localhost'` for local passkey testing.

**Option 3: Use ngrok or similar**
Tunnel localhost to a subdomain of your production domain.

## Troubleshooting

### "USER_AUTH flow not enabled for this client"

Add `ALLOW_USER_AUTH` to ExplicitAuthFlows on the User Pool Client.

### "WebAuthn not enabled for this pool"

Run the boto3 script to enable WEB_AUTHN in AllowedFirstAuthFactors.

### "Relying party ID is not a registrable domain suffix"

The `RelyingPartyId` in WebAuthn configuration must match your domain. Update it using boto3.

### "Admin scope required"

The user must log in via Hosted UI with `aws.cognito.signin.user.admin` scope to manage passkeys. Ensure this scope is:
1. Allowed on the User Pool Client
2. Requested in the authorization URL

## Required Cognito Tier

WebAuthn works on **Cognito ESSENTIALS** tier. You do NOT need Advanced Security Mode.
