# AWS Cedar Integration Design

This document describes how to integrate AWS Cedar (via Amazon Verified Permissions) with L42 Cognito Passkey for fine-grained authorization.

## Overview

**Cedar** is AWS's open-source policy language for authorization. Combined with **Amazon Verified Permissions (AVP)**, it provides:

- **Externalized authorization**: Policies live outside application code
- **Fine-grained access control**: Attribute-based (ABAC) and role-based (RBAC) policies
- **Native Cognito integration**: Uses JWT tokens directly from Cognito
- **Formal verification**: Mathematically proven correct

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────────┐
│                 │     │                 │     │                         │
│  L42 Auth.js    │────▶│  API Gateway    │────▶│  Verified Permissions   │
│  (Client)       │     │  + Lambda       │     │  (Cedar Policies)       │
│                 │     │                 │     │                         │
└─────────────────┘     └─────────────────┘     └─────────────────────────┘
        │                        │                         │
        │                        │                         │
        ▼                        ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────────┐
│  Cognito        │     │  Lambda         │     │  Policy Store           │
│  User Pool      │     │  Authorizer     │     │  (Identity Source:      │
│                 │     │                 │     │   Cognito User Pool)    │
└─────────────────┘     └─────────────────┘     └─────────────────────────┘
```

## Setup Steps

### 1. Create Verified Permissions Policy Store

```bash
aws verifiedpermissions create-policy-store \
    --validation-settings mode=STRICT \
    --description "L42 Auth Policy Store"
```

### 2. Add Cognito as Identity Source

```bash
aws verifiedpermissions create-identity-source \
    --policy-store-id <POLICY_STORE_ID> \
    --configuration '{
        "cognitoUserPoolConfiguration": {
            "userPoolArn": "arn:aws:cognito-idp:us-west-2:123456789:userpool/us-west-2_EXAMPLE",
            "clientIds": ["your-app-client-id"],
            "groupConfiguration": {
                "groupEntityType": "L42::UserGroup"
            }
        }
    }'
```

### 3. Define Schema

```json
{
    "L42": {
        "entityTypes": {
            "User": {
                "memberOfTypes": ["UserGroup"],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "email": { "type": "String" },
                        "department": { "type": "String", "required": false }
                    }
                }
            },
            "UserGroup": {},
            "Resource": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "owner": { "type": "Entity", "name": "User" }
                    }
                }
            }
        },
        "actions": {
            "read": { "appliesTo": { "resourceTypes": ["Resource"] } },
            "write": { "appliesTo": { "resourceTypes": ["Resource"] } },
            "delete": { "appliesTo": { "resourceTypes": ["Resource"] } },
            "publish": { "appliesTo": { "resourceTypes": ["Resource"] } },
            "manage-users": { "appliesTo": { "resourceTypes": ["Resource"] } }
        }
    }
}
```

## Cedar Policy Examples

### Static Site Pattern Policies

```cedar
// Editors can read and write content
permit(
    principal in L42::UserGroup::"editors",
    action in [L42::Action::"read", L42::Action::"write"],
    resource
);

// Publishers can publish content
permit(
    principal in L42::UserGroup::"publishers",
    action == L42::Action::"publish",
    resource
);

// Admins can do everything
permit(
    principal in L42::UserGroup::"admin",
    action,
    resource
);

// Users can only access their own resources
permit(
    principal,
    action == L42::Action::"read",
    resource
) when {
    resource.owner == principal
};
```

### Multi-User WASM Pattern Policies

```cedar
// Players can join sessions and control their character
permit(
    principal in L42::UserGroup::"players",
    action in [
        L42::Action::"join-session",
        L42::Action::"move-character",
        L42::Action::"send-chat"
    ],
    resource
);

// Moderators can mute and kick players
permit(
    principal in L42::UserGroup::"moderators",
    action in [L42::Action::"mute-player", L42::Action::"kick-player"],
    resource
);

// DMs have full session control
permit(
    principal in L42::UserGroup::"dms",
    action in [
        L42::Action::"spawn-npc",
        L42::Action::"reveal-area",
        L42::Action::"pause-session",
        L42::Action::"end-session"
    ],
    resource
);
```

## Client Integration

### Using requireServerAuthorization with Cedar

The `requireServerAuthorization()` function in auth.js is designed to work with Cedar:

```javascript
// Client-side
async function deleteUser(userId) {
    const result = await auth.requireServerAuthorization('manage-users', {
        endpoint: '/api/authorize',  // Your Cedar-backed endpoint
        context: { targetUserId: userId }
    });
    
    if (!result.authorized) {
        throw new Error(`Not authorized: ${result.reason}`);
    }
    
    await fetch(`/api/users/${userId}`, { method: 'DELETE' });
}
```

### Server-Side Lambda Authorizer

```javascript
// Lambda authorizer for API Gateway
import { VerifiedPermissionsClient, IsAuthorizedWithTokenCommand } from '@aws-sdk/client-verifiedpermissions';

const client = new VerifiedPermissionsClient({ region: 'us-west-2' });

export async function handler(event) {
    const token = event.headers.authorization?.replace('Bearer ', '');
    const { action, context } = JSON.parse(event.body);
    
    const command = new IsAuthorizedWithTokenCommand({
        policyStoreId: process.env.POLICY_STORE_ID,
        accessToken: token,  // or identityToken for ABAC
        action: {
            actionType: 'L42::Action',
            actionId: action
        },
        resource: {
            entityType: 'L42::Resource',
            entityId: context.resourceId || 'default'
        }
    });
    
    const response = await client.send(command);
    
    return {
        statusCode: response.decision === 'ALLOW' ? 200 : 403,
        body: JSON.stringify({
            authorized: response.decision === 'ALLOW',
            reason: response.decision === 'DENY' ? 'Policy denied access' : null
        })
    };
}
```

## Migration from RBAC Roles

### Current System → Cedar Mapping

| Current Role | Cedar Group | Cedar Permissions |
|--------------|-------------|-------------------|
| `admin` | `L42::UserGroup::"admin"` | All actions (wildcard) |
| `editor` | `L42::UserGroup::"editors"` | read, write |
| `publisher` | `L42::UserGroup::"publishers"` | read, write, publish |
| `dm` | `L42::UserGroup::"dms"` | Session control actions |
| `moderator` | `L42::UserGroup::"moderators"` | Mute, kick |

### Migration Steps

1. **Create policy store** with Cognito identity source
2. **Define Cedar policies** matching current RBAC rules
3. **Deploy Lambda authorizer** with Verified Permissions
4. **Update `requireServerAuthorization()`** to call Cedar endpoint
5. **Test with existing Cognito groups** (Cedar uses same groups)
6. **Gradually migrate** complex rules to Cedar

## Benefits Over Current System

| Aspect | Current (rbac-roles.js) | Cedar |
|--------|------------------------|-------|
| Policy location | In-code | Externalized |
| Policy updates | Code deploy | Policy update only |
| Audit trail | Manual | Built-in |
| Formal verification | None | Automated |
| ABAC support | Manual | Native |
| Cross-service | Single app | Shared policies |

## Cost Considerations

Amazon Verified Permissions pricing (as of 2026):
- **Authorization requests**: $0.45 per 10,000 requests
- **Policy management**: $0.10 per policy per month
- **No upfront costs**

For a medium app with 100K auth requests/month:
- ~$4.50/month for authorization
- Policies are negligible cost

## References

- [AWS Cedar Policy Language](https://www.cedarpolicy.com/)
- [Amazon Verified Permissions Docs](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html)
- [Cognito + AVP Integration](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-authorization-with-avp.html)
- [Cedar GitHub](https://github.com/cedar-policy)

## Status

**Current**: Design phase  
**Target**: Post-1.0 implementation  
**Priority**: Medium (current RBAC works, Cedar adds sophistication)
