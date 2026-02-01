/**
 * L42 Cognito Passkey - Token Handler Express Backend
 *
 * This example backend implements the Token Handler pattern for secure
 * token storage. Tokens are stored server-side in HttpOnly session cookies,
 * making them inaccessible to XSS attacks.
 *
 * Endpoints:
 * - GET  /auth/token    - Return tokens from session
 * - POST /auth/refresh  - Refresh tokens via Cognito
 * - POST /auth/logout   - Destroy session
 * - GET  /auth/callback - OAuth callback (exchange code for tokens)
 *
 * Environment variables:
 * - COGNITO_CLIENT_ID    - Cognito app client ID
 * - COGNITO_CLIENT_SECRET - Cognito app client secret (if applicable)
 * - COGNITO_DOMAIN       - e.g., 'myapp.auth.us-west-2.amazoncognito.com'
 * - COGNITO_REGION       - e.g., 'us-west-2'
 * - SESSION_SECRET       - Secret for session encryption
 * - FRONTEND_URL         - Frontend URL for CORS and redirects
 * - PORT                 - Server port (default: 3001)
 */

import express from 'express';
import session from 'express-session';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

// ============================================================================
// Configuration
// ============================================================================

const config = {
    cognitoClientId: process.env.COGNITO_CLIENT_ID,
    cognitoClientSecret: process.env.COGNITO_CLIENT_SECRET,
    cognitoDomain: process.env.COGNITO_DOMAIN,
    cognitoRegion: process.env.COGNITO_REGION || 'us-west-2',
    sessionSecret: process.env.SESSION_SECRET || 'change-me-in-production',
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
    port: process.env.PORT || 3001
};

// Validate required config
if (!config.cognitoClientId || !config.cognitoDomain) {
    console.error('Missing required environment variables:');
    console.error('  COGNITO_CLIENT_ID and COGNITO_DOMAIN are required');
    console.error('');
    console.error('Example:');
    console.error('  COGNITO_CLIENT_ID=abc123 \\');
    console.error('  COGNITO_DOMAIN=myapp.auth.us-west-2.amazoncognito.com \\');
    console.error('  FRONTEND_URL=http://localhost:3000 \\');
    console.error('  node server.js');
    process.exit(1);
}

// ============================================================================
// Middleware
// ============================================================================

// CORS for frontend
app.use(cors({
    origin: config.frontendUrl,
    credentials: true // Allow cookies
}));

app.use(express.json());
app.use(cookieParser());

// Session configuration
// In production, use a persistent store (Redis, DynamoDB, etc.)
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,     // Prevents XSS access
        secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
        sameSite: 'lax',    // CSRF protection
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    }
}));

// ============================================================================
// Cognito Helpers
// ============================================================================

/**
 * Make a request to Cognito IDP
 */
async function cognitoRequest(action, body) {
    const response = await fetch(
        `https://cognito-idp.${config.cognitoRegion}.amazonaws.com/`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': `AWSCognitoIdentityProviderService.${action}`
            },
            body: JSON.stringify(body)
        }
    );

    const data = await response.json();

    if (!response.ok || data.__type) {
        const error = new Error(data.message || data.__type || 'Cognito request failed');
        error.code = data.__type;
        throw error;
    }

    return data;
}

/**
 * Exchange authorization code for tokens
 */
async function exchangeCodeForTokens(code, redirectUri) {
    const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: config.cognitoClientId,
        code: code,
        redirect_uri: redirectUri
    });

    // Add client secret if configured
    if (config.cognitoClientSecret) {
        params.set('client_secret', config.cognitoClientSecret);
    }

    const response = await fetch(
        `https://${config.cognitoDomain}/oauth2/token`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        }
    );

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Token exchange failed: ${text}`);
    }

    return response.json();
}

/**
 * Decode JWT payload (no verification - server trusts Cognito)
 */
function decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString());
}

/**
 * Check if token is expired
 */
function isTokenExpired(token) {
    try {
        const payload = decodeJwtPayload(token);
        return Date.now() >= payload.exp * 1000;
    } catch {
        return true;
    }
}

// ============================================================================
// Auth Routes
// ============================================================================

/**
 * GET /auth/token - Return tokens from session
 *
 * Returns access_token and id_token (NOT refresh_token).
 * The refresh_token stays server-side for security.
 */
app.get('/auth/token', (req, res) => {
    const tokens = req.session.tokens;

    if (!tokens || !tokens.access_token || !tokens.id_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check if tokens are expired
    if (isTokenExpired(tokens.id_token)) {
        return res.status(401).json({ error: 'Token expired' });
    }

    // Return tokens WITHOUT refresh_token
    res.json({
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        auth_method: tokens.auth_method || 'handler'
    });
});

/**
 * POST /auth/refresh - Refresh tokens
 *
 * Uses the server-side refresh_token to get new tokens from Cognito.
 */
app.post('/auth/refresh', async (req, res) => {
    const tokens = req.session.tokens;

    if (!tokens || !tokens.refresh_token) {
        return res.status(401).json({ error: 'No refresh token' });
    }

    try {
        const result = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: config.cognitoClientId,
            AuthParameters: {
                REFRESH_TOKEN: tokens.refresh_token
            }
        });

        if (!result.AuthenticationResult) {
            return res.status(500).json({ error: 'Refresh failed' });
        }

        // Update session with new tokens
        req.session.tokens = {
            access_token: result.AuthenticationResult.AccessToken,
            id_token: result.AuthenticationResult.IdToken,
            refresh_token: result.AuthenticationResult.RefreshToken || tokens.refresh_token,
            auth_method: tokens.auth_method
        };

        // Return new tokens WITHOUT refresh_token
        res.json({
            access_token: result.AuthenticationResult.AccessToken,
            id_token: result.AuthenticationResult.IdToken,
            auth_method: tokens.auth_method || 'handler'
        });
    } catch (error) {
        console.error('Token refresh error:', error.message);

        // Clear session on refresh failure
        req.session.destroy();

        res.status(401).json({
            error: 'Refresh failed',
            message: error.message
        });
    }
});

/**
 * POST /auth/logout - Destroy session
 */
app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destroy error:', err);
        }

        // Clear the session cookie
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

/**
 * GET /auth/callback - OAuth callback
 *
 * Handles the OAuth redirect from Cognito:
 * 1. Exchanges the authorization code for tokens
 * 2. Stores tokens in session
 * 3. Redirects to frontend
 */
app.get('/auth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    if (error) {
        console.error('OAuth error:', error, error_description);
        return res.redirect(
            `${config.frontendUrl}/login?error=${encodeURIComponent(error_description || error)}`
        );
    }

    if (!code) {
        return res.redirect(
            `${config.frontendUrl}/login?error=${encodeURIComponent('Missing authorization code')}`
        );
    }

    try {
        // Build the redirect URI (must match what was sent to authorize)
        const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;

        // Exchange code for tokens
        const tokenResponse = await exchangeCodeForTokens(code, redirectUri);

        // Store ALL tokens in session (including refresh_token)
        req.session.tokens = {
            access_token: tokenResponse.access_token,
            id_token: tokenResponse.id_token,
            refresh_token: tokenResponse.refresh_token,
            auth_method: 'oauth'
        };

        // Redirect to frontend with success
        // The frontend can then call /auth/token to get the tokens
        res.redirect(`${config.frontendUrl}/auth/success?state=${state || ''}`);
    } catch (error) {
        console.error('Token exchange error:', error.message);
        res.redirect(
            `${config.frontendUrl}/login?error=${encodeURIComponent('Authentication failed')}`
        );
    }
});

/**
 * GET /auth/me - Get current user info (optional helper)
 */
app.get('/auth/me', (req, res) => {
    const tokens = req.session.tokens;

    if (!tokens || !tokens.id_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const claims = decodeJwtPayload(tokens.id_token);
        res.json({
            email: claims.email,
            sub: claims.sub,
            groups: claims['cognito:groups'] || []
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to decode token' });
    }
});

// ============================================================================
// Health Check
// ============================================================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', mode: 'token-handler' });
});

// ============================================================================
// Start Server
// ============================================================================

app.listen(config.port, () => {
    console.log(`\n🔐 L42 Token Handler Backend`);
    console.log(`   Mode: Token Handler (server-side sessions)`);
    console.log(`   Port: ${config.port}`);
    console.log(`   Frontend: ${config.frontendUrl}`);
    console.log(`   Cognito: ${config.cognitoDomain}`);
    console.log(`\n   Endpoints:`);
    console.log(`   GET  /auth/token    - Get tokens from session`);
    console.log(`   POST /auth/refresh  - Refresh tokens`);
    console.log(`   POST /auth/logout   - Logout`);
    console.log(`   GET  /auth/callback - OAuth callback`);
    console.log(`   GET  /auth/me       - Get current user`);
    console.log('');
});
