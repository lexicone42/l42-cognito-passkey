# L42 Token Handler - Express Backend

This is a reference implementation of the Token Handler pattern for L42 Cognito Passkey.

## What is Token Handler Mode?

Token Handler mode stores tokens server-side in HttpOnly session cookies, making them inaccessible to JavaScript and thus immune to XSS attacks. The client calls server endpoints to retrieve tokens, which are cached briefly in memory.

## Quick Start

```bash
# Install dependencies
npm install

# Set environment variables
export COGNITO_CLIENT_ID=your-client-id
export COGNITO_DOMAIN=your-app.auth.us-west-2.amazoncognito.com
export FRONTEND_URL=http://localhost:3000
export SESSION_SECRET=your-secure-secret

# Start server
npm start
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `COGNITO_CLIENT_ID` | Yes | Cognito app client ID |
| `COGNITO_DOMAIN` | Yes | Cognito domain (e.g., `myapp.auth.us-west-2.amazoncognito.com`) |
| `COGNITO_CLIENT_SECRET` | No | Client secret (if your app client has one) |
| `COGNITO_REGION` | No | AWS region (default: `us-west-2`) |
| `SESSION_SECRET` | Yes* | Secret for session encryption |
| `FRONTEND_URL` | No | Frontend URL for CORS (default: `http://localhost:3000`) |
| `PORT` | No | Server port (default: `3001`) |

*Required in production

## Endpoints

### GET /auth/token

Returns the current user's tokens from the session.

**Response (200):**
```json
{
    "access_token": "eyJ...",
    "id_token": "eyJ...",
    "auth_method": "handler"
}
```

**Response (401):** Not authenticated

Note: `refresh_token` is never returned - it stays server-side.

### POST /auth/refresh

Refreshes tokens using the server-side refresh token.

**Response (200):** New tokens (same format as GET /auth/token)

**Response (401):** Session expired

### POST /auth/logout

Destroys the session and clears cookies.

**Response (200):**
```json
{ "success": true }
```

### GET /auth/callback

OAuth callback endpoint. Configure this URL in your Cognito app client's callback URLs.

**Flow:**
1. Receives authorization code from Cognito
2. Exchanges code for tokens
3. Stores tokens in session
4. Redirects to frontend

### GET /auth/me

Helper endpoint to get current user info.

**Response (200):**
```json
{
    "email": "user@example.com",
    "sub": "user-uuid",
    "groups": ["admin", "users"]
}
```

## Frontend Configuration

Configure your frontend to use Token Handler mode:

```javascript
import { configure } from './auth.js';

configure({
    clientId: 'your-client-id',
    cognitoDomain: 'your-app.auth.us-west-2.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: 'http://localhost:3001/auth/token',
    refreshEndpoint: 'http://localhost:3001/auth/refresh',
    logoutEndpoint: 'http://localhost:3001/auth/logout',
    oauthCallbackUrl: 'http://localhost:3001/auth/callback'
});
```

## Production Considerations

1. **Session Store**: Use Redis or DynamoDB instead of in-memory sessions
2. **HTTPS**: Enable secure cookies (`cookie.secure: true`)
3. **Session Secret**: Use a strong, randomly generated secret
4. **CORS**: Restrict to your frontend domain only
5. **Rate Limiting**: Add rate limiting to auth endpoints

### Example with Redis Session Store

```javascript
import RedisStore from 'connect-redis';
import { createClient } from 'redis';

const redisClient = createClient({ url: process.env.REDIS_URL });
await redisClient.connect();

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));
```

## Security Benefits

| Threat | localStorage Mode | Token Handler Mode |
|--------|------------------|-------------------|
| XSS stealing tokens | Vulnerable | Protected (HttpOnly) |
| XSS reading tokens | Vulnerable | Protected |
| CSRF | SameSite cookie | SameSite cookie |
| Refresh token exposure | Client has it | Server-side only |

## Troubleshooting

### CORS errors
Ensure `FRONTEND_URL` matches your frontend origin exactly.

### "Not authenticated" after login
Check that cookies are being sent (`credentials: 'include'` on frontend).

### "Refresh failed"
The refresh token may have expired. User needs to re-authenticate.
