# OCSF Security Logging

L42 Cognito Passkey supports structured security logging in [OCSF (Open Cybersecurity Schema Framework)](https://schema.ocsf.io/) format, enabling integration with AWS Security Lake and other SIEM systems.

## Quick Start

Enable OCSF logging by setting `securityLogger` in your configuration:

```javascript
// Option 1: Console output (for development/debugging)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    securityLogger: 'console'
});

// Option 2: Custom handler (for production/SIEM integration)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    securityLogger: (event) => {
        // Send to your logging backend
        fetch('/api/security-logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event)
        });
    }
});
```

## Event Schema

All events follow the OCSF v1.0 base event schema:

```json
{
    "class_uid": 3001,
    "class_name": "Authentication",
    "activity_id": 1,
    "activity_name": "Logon",
    "severity_id": 1,
    "severity": "Informational",
    "status_id": 1,
    "status": "Success",
    "time": 1737474123456,
    "metadata": {
        "product": {
            "name": "l42-cognito-passkey",
            "version": "0.15.1",
            "vendor_name": "L42"
        }
    },
    "actor": {
        "user": {
            "email_addr": "user@example.com",
            "type_id": 1,
            "type": "User"
        }
    },
    "auth_protocol_id": 2,
    "auth_protocol": "Password",
    "message": "User logged in with password"
}
```

## Event Classes

### Authentication (3001)

Covers login, logout, and token operations.

| Activity | ID | Description |
|----------|-----|-------------|
| Logon | 1 | User login (password, passkey, OAuth) |
| Logoff | 2 | User logout |
| Authentication Ticket | 3 | OAuth token exchange |
| Service Ticket | 4 | Token refresh |

### Account Change (3002)

Covers credential management.

| Activity | ID | Description |
|----------|-----|-------------|
| Create | 1 | Passkey registered |
| Delete | 4 | Passkey deleted |

## Authentication Protocols

| Protocol | ID | Description |
|----------|-----|-------------|
| Unknown | 0 | Protocol not determined |
| Password | 2 | Username/password auth |
| OAuth 2.0/OIDC | 10 | Hosted UI OAuth flow |
| WebAuthn/FIDO2 | 99 | Passkey authentication |

## Severity Levels

| Level | ID | Used For |
|-------|-----|----------|
| Informational | 1 | Successful operations |
| Low | 2 | User-cancelled operations, MFA prompts |
| Medium | 3 | Failed authentications, token errors |
| High | 4 | CSRF/state validation failures, login rate limit threshold breach |
| Critical | 5 | Cognito account lockout detected |

## AWS Security Lake Integration

To send events to AWS Security Lake:

### 1. Create a Kinesis Data Firehose

Configure a Firehose delivery stream to write to your Security Lake S3 bucket in OCSF format.

### 2. Configure the Logger

```javascript
import { FirehoseClient, PutRecordCommand } from '@aws-sdk/client-firehose';

const firehose = new FirehoseClient({ region: 'us-west-2' });

configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    securityLogger: async (event) => {
        try {
            await firehose.send(new PutRecordCommand({
                DeliveryStreamName: 'security-lake-auth-events',
                Record: {
                    Data: Buffer.from(JSON.stringify(event) + '\n')
                }
            }));
        } catch (e) {
            console.error('Failed to send security event:', e);
        }
    }
});
```

### 3. Map to Security Lake Schema

Security Lake expects OCSF events. The events from this library are already in OCSF format, so no transformation is needed.

## CloudWatch Logs Integration

For simpler setups, send events to CloudWatch Logs:

```javascript
configure({
    securityLogger: (event) => {
        // CloudWatch Logs via Lambda or CloudWatch RUM
        console.log(JSON.stringify({
            ...event,
            '@timestamp': new Date(event.time).toISOString()
        }));
    }
});
```

Then use CloudWatch Logs Insights:

```sql
fields @timestamp, actor.user.email_addr, activity_name, status, message
| filter class_name = 'Authentication'
| sort @timestamp desc
| limit 100
```

## Splunk Integration

```javascript
configure({
    securityLogger: (event) => {
        fetch('https://your-splunk-hec/services/collector/event', {
            method: 'POST',
            headers: {
                'Authorization': 'Splunk YOUR_HEC_TOKEN',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                event: event,
                sourcetype: 'ocsf:authentication',
                index: 'security'
            })
        });
    }
});
```

## Client-Side Events (auth.js)

| Function | Event | Class | Activity |
|----------|-------|-------|----------|
| `loginWithPassword()` | Success/Failure | Authentication | Logon |
| `loginWithPasskey()` | Success/Failure | Authentication | Logon |
| `exchangeCodeForTokens()` | Success/Failure | Authentication | Authentication Ticket |
| `refreshTokens()` | Success/Failure | Authentication | Service Ticket |
| `logout()` | Success | Authentication | Logoff |
| `registerPasskey()` | Success/Failure | Account Change | Create |
| `deletePasskey()` | Success/Failure | Account Change | Delete |
| Rate limit threshold | Failure (HIGH) | Authentication | Logon |
| Cognito account lockout | Failure (CRITICAL) | Authentication | Logon |

## Server-Side Events (FastAPI)

The FastAPI Token Handler backend (`examples/backends/fastapi/`) emits OCSF events for all server-side security operations. Events are logged to a Python logger named `ocsf` as JSON.

### Event Table

| Route | Event | Activity | Severity |
|-------|-------|----------|----------|
| `POST /auth/session` | Session created | Logon (1) | Informational |
| `POST /auth/session` | Token verification failed | Logon (1) | Medium |
| `GET /auth/callback` | OAuth token exchange succeeded | Authentication Ticket (3) | Informational |
| `GET /auth/callback` | OAuth error from Cognito | Authentication Ticket (3) | High |
| `GET /auth/callback` | Token exchange failed | Authentication Ticket (3) | Medium |
| `POST /auth/refresh` | Token refresh succeeded | Service Ticket (4) | Informational |
| `POST /auth/refresh` | Token refresh failed | Service Ticket (4) | Medium |
| `POST /auth/logout` | User logged out | Logoff (2) | Informational |
| `POST /auth/authorize` | Cedar permit | Other (99) | Informational |
| `POST /auth/authorize` | Cedar deny | Other (99) | Medium |
| `POST /auth/authorize` | Cedar evaluation error | Other (99) | High |
| `POST /auth/authorize` | Cedar engine unavailable | Other (99) | High |

### Python Logging Integration

Events are emitted to the `ocsf` named logger. Attach handlers to consume events:

```python
import logging
import json

# Basic: Log OCSF events to a file
ocsf_logger = logging.getLogger("ocsf")
ocsf_logger.setLevel(logging.INFO)
handler = logging.FileHandler("ocsf-events.jsonl")
ocsf_logger.addHandler(handler)
```

### CloudWatch JSON Formatter Example

```python
import logging
import json
import sys

class CloudWatchJsonFormatter(logging.Formatter):
    def format(self, record):
        # Parse the OCSF JSON from the log message
        event = json.loads(record.getMessage())
        event["@timestamp"] = self.formatTime(record)
        event["log_level"] = record.levelname
        return json.dumps(event)

ocsf_logger = logging.getLogger("ocsf")
ocsf_logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(CloudWatchJsonFormatter())
ocsf_logger.addHandler(handler)
```

### structlog Integration

```python
import structlog
import json

def ocsf_processor(logger, method_name, event_dict):
    """Parse OCSF JSON and merge into structlog event."""
    if "event" in event_dict:
        try:
            ocsf_event = json.loads(event_dict["event"])
            event_dict.update(ocsf_event)
            del event_dict["event"]
        except json.JSONDecodeError:
            pass
    return event_dict
```

> **Note:** The Express backend (`examples/backends/express/`) does not yet emit server-side OCSF events.

## Disabling Logging

By default, security logging is disabled. To explicitly disable:

```javascript
configure({
    securityLogger: null  // or simply omit the option
});
```

## Best Practices

1. **Production**: Use a reliable transport (Firehose, direct SIEM API)
2. **Development**: Use `'console'` for debugging
3. **Error Handling**: The library catches logger errors to prevent auth flow interruption
4. **PII Considerations**: Events include email addresses; ensure your SIEM has appropriate access controls

## OCSF Resources

- [OCSF Schema Browser](https://schema.ocsf.io/)
- [AWS Security Lake Documentation](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html)
- [OCSF GitHub](https://github.com/ocsf)
