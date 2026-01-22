/**
 * L42 Cognito Passkey - Authentication Library
 *
 * Reusable authentication library with AWS Cognito + WebAuthn/Passkey support.
 * Designed to be self-hosted - copy this file to your project.
 *
 * Usage:
 *   import { configure, isAuthenticated, loginWithPassword } from './auth.js';
 *   configure({ clientId: 'xxx', cognitoDomain: 'xxx.auth.region.amazoncognito.com' });
 *
 * @version 0.6.0
 * @license Apache-2.0
 */

export const VERSION = '0.6.0';

// ==================== CONFIGURATION ====================

const DEFAULT_CONFIG = {
    cognitoDomain: null,        // REQUIRED: e.g., 'myapp.auth.us-west-2.amazoncognito.com'
    cognitoRegion: 'us-west-2',
    clientId: null,             // REQUIRED: Cognito app client ID
    tokenKey: 'l42_auth_tokens',
    stateKey: 'l42_auth_state',
    scopes: 'openid email profile aws.cognito.signin.user.admin',
    cookieName: 'l42_id_token',
    cookieDomain: null,         // Auto-detected if not set
    allowedDomains: null,       // Auto-allow current domain if not set
    relyingPartyId: null,       // For WebAuthn - usually your domain
    // Structured logging for OCSF/Security Lake integration
    // Set to a function(event) to receive OCSF-formatted security events
    // Set to 'console' for console.log output, or null to disable
    securityLogger: null
};

// ==================== OCSF SECURITY EVENT SCHEMA ====================
// Open Cybersecurity Schema Framework (OCSF) for AWS Security Lake integration
// See: https://schema.ocsf.io/

/**
 * OCSF Event Class UIDs
 */
const OCSF_CLASS = {
    AUTHENTICATION: 3001,       // Authentication events (login, logout, token refresh)
    ACCOUNT_CHANGE: 3002        // Account changes (passkey add/delete)
};

/**
 * OCSF Activity IDs for Authentication (class 3001)
 */
const OCSF_AUTH_ACTIVITY = {
    LOGON: 1,
    LOGOFF: 2,
    AUTHENTICATION_TICKET: 3,   // Initial token grant
    SERVICE_TICKET: 4           // Token refresh
};

/**
 * OCSF Activity IDs for Account Change (class 3002)
 */
const OCSF_ACCOUNT_ACTIVITY = {
    CREATE: 1,                  // Passkey registered
    DELETE: 4                   // Passkey deleted
};

/**
 * OCSF Status IDs
 */
const OCSF_STATUS = {
    SUCCESS: 1,
    FAILURE: 2
};

/**
 * OCSF Severity IDs
 */
const OCSF_SEVERITY = {
    INFORMATIONAL: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5
};

/**
 * Authentication protocol IDs (OCSF auth_protocol_id)
 */
const OCSF_AUTH_PROTOCOL = {
    UNKNOWN: 0,
    PASSWORD: 2,                // Username/Password
    OAUTH2: 10,                 // OAuth 2.0 / OIDC
    FIDO2: 99                   // WebAuthn/Passkey (custom, not in OCSF 1.0)
};

/**
 * Log a security event in OCSF format.
 * Events are sent to the configured securityLogger.
 *
 * @param {Object} params - Event parameters
 * @param {number} params.class_uid - OCSF event class
 * @param {number} params.activity_id - Activity within the class
 * @param {string} params.activity_name - Human-readable activity name
 * @param {number} params.status_id - Success or failure
 * @param {number} params.severity_id - Event severity
 * @param {string} [params.user_email] - Actor's email
 * @param {number} [params.auth_protocol_id] - Authentication protocol
 * @param {string} [params.auth_protocol] - Protocol name
 * @param {string} [params.message] - Additional message
 * @param {Object} [params.metadata] - Additional metadata
 */
function logSecurityEvent({
    class_uid,
    activity_id,
    activity_name,
    status_id,
    severity_id,
    user_email = null,
    auth_protocol_id = OCSF_AUTH_PROTOCOL.UNKNOWN,
    auth_protocol = 'Unknown',
    message = null,
    metadata = {}
}) {
    const logger = config.securityLogger;
    if (!logger) return;

    const event = {
        // OCSF base event
        class_uid,
        class_name: class_uid === OCSF_CLASS.AUTHENTICATION ? 'Authentication' : 'Account Change',
        activity_id,
        activity_name,
        severity_id,
        severity: ['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical'][severity_id] || 'Unknown',
        status_id,
        status: status_id === OCSF_STATUS.SUCCESS ? 'Success' : 'Failure',
        time: Date.now(),
        // Product info
        metadata: {
            product: {
                name: 'l42-cognito-passkey',
                version: VERSION,
                vendor_name: 'L42'
            },
            ...metadata
        },
        // Actor
        actor: user_email ? {
            user: {
                email_addr: user_email,
                type_id: 1,  // User
                type: 'User'
            }
        } : undefined,
        // Auth-specific fields (for class 3001)
        ...(class_uid === OCSF_CLASS.AUTHENTICATION ? {
            auth_protocol_id,
            auth_protocol
        } : {}),
        // Message
        message
    };

    // Remove undefined fields
    Object.keys(event).forEach(key => event[key] === undefined && delete event[key]);

    if (logger === 'console') {
        console.log('[L42-AUTH-OCSF]', JSON.stringify(event));
    } else if (typeof logger === 'function') {
        try {
            logger(event);
        } catch (e) {
            // Don't let logger errors break auth flow
            console.error('Security logger error:', e);
        }
    }
}

// Token refresh configuration by auth method
const REFRESH_CONFIG = {
    password: {
        cookieMaxAge: 86400,      // 1 day in seconds
        refreshBefore: 300000     // Refresh 5 minutes before expiry (ms)
    },
    passkey: {
        cookieMaxAge: 2592000,    // 30 days in seconds
        refreshBefore: 3600000    // Refresh 1 hour before expiry (ms)
    }
};

let config = { ...DEFAULT_CONFIG };
let _configured = false;

/**
 * Auto-read configuration from window.L42_AUTH_CONFIG if present.
 * Called automatically on first use if configure() hasn't been called.
 */
function autoConfigureFromWindow() {
    if (_configured) return;

    if (typeof window !== 'undefined' && window.L42_AUTH_CONFIG) {
        const windowConfig = window.L42_AUTH_CONFIG;
        configure({
            clientId: windowConfig.clientId,
            cognitoDomain: windowConfig.domain || windowConfig.cognitoDomain,
            cognitoRegion: windowConfig.region || windowConfig.cognitoRegion || 'us-west-2',
            redirectUri: windowConfig.redirectUri,
            scopes: Array.isArray(windowConfig.scopes)
                ? windowConfig.scopes.join(' ')
                : windowConfig.scopes,
            allowedDomains: windowConfig.allowedDomains,
            cookieDomain: windowConfig.cookieDomain
        });
    }
}

/**
 * Ensure configuration is valid before use.
 * @throws {Error} If required configuration is missing
 */
function requireConfig() {
    autoConfigureFromWindow();

    if (!_configured) {
        throw new Error(
            'Auth not configured. Call configure() first or set window.L42_AUTH_CONFIG.\n' +
            'Example: configure({ clientId: "xxx", cognitoDomain: "xxx.auth.region.amazoncognito.com" })'
        );
    }
}

/**
 * Common public suffixes (ccTLDs with second-level domains).
 * These require 3 parts minimum for a valid registrable domain.
 * @see https://publicsuffix.org/list/
 */
const PUBLIC_SUFFIXES = [
    // UK
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    // Australia
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    // Brazil
    'com.br', 'net.br', 'org.br',
    // Japan
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp',
    // New Zealand
    'co.nz', 'org.nz', 'net.nz',
    // South Africa
    'co.za', 'org.za', 'net.za',
    // India
    'co.in', 'org.in', 'net.in',
    // Hong Kong
    'com.hk', 'org.hk', 'edu.hk',
    // Singapore
    'com.sg', 'org.sg', 'edu.sg',
    // Germany (rare but exists)
    'com.de',
    // France
    'asso.fr', 'com.fr',
    // Spain
    'com.es', 'org.es',
    // Mexico
    'com.mx', 'org.mx',
    // Argentina
    'com.ar', 'org.ar'
];

/**
 * Get the effective cookie domain based on current hostname.
 * Handles ccTLDs (country-code TLDs) with public suffixes correctly.
 *
 * @returns {string|null} Cookie domain or null (for current domain only)
 */
function getCookieDomain() {
    // If explicitly configured, use that
    if (config.cookieDomain) {
        return config.cookieDomain;
    }

    // For localhost, don't set domain (use current host)
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return null;
    }

    // For IP addresses, don't set domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        return null;
    }

    const parts = hostname.split('.');

    // Check if hostname ends with a known public suffix
    // e.g., app.example.co.uk -> needs .example.co.uk (3 parts)
    const lastTwo = parts.slice(-2).join('.');
    if (PUBLIC_SUFFIXES.includes(lastTwo)) {
        // This is a public suffix - need at least 3 parts
        if (parts.length < 3) {
            // Hostname IS the public suffix (e.g., co.uk) - can't set domain
            console.warn(`Cookie domain cannot be set for public suffix: ${hostname}`);
            return null;
        }
        // Return the registrable domain (e.g., .example.co.uk)
        return '.' + parts.slice(-3).join('.');
    }

    // Standard TLD - use last 2 parts
    if (parts.length >= 2) {
        return '.' + parts.slice(-2).join('.');
    }

    return null;
}

/**
 * Check if a domain is allowed for redirects.
 * @param {string} hostname - Hostname to check
 * @returns {boolean} True if allowed
 */
function isDomainAllowed(hostname) {
    hostname = hostname.toLowerCase();

    // Always allow localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return true;
    }

    // If allowedDomains is configured, check against it
    if (config.allowedDomains && config.allowedDomains.length > 0) {
        return config.allowedDomains.some(domain =>
            hostname === domain || hostname.endsWith('.' + domain)
        );
    }

    // If not configured, allow current domain and its subdomains
    const currentHostname = window.location.hostname.toLowerCase();
    if (hostname === currentHostname) {
        return true;
    }

    // Allow subdomains of current domain
    const currentParts = currentHostname.split('.');
    if (currentParts.length >= 2) {
        const currentBase = currentParts.slice(-2).join('.');
        return hostname === currentBase || hostname.endsWith('.' + currentBase);
    }

    return false;
}

/**
 * Configure the auth module.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.clientId - REQUIRED: Cognito app client ID
 * @param {string} options.cognitoDomain - REQUIRED: Cognito domain (e.g., 'myapp.auth.us-west-2.amazoncognito.com')
 * @param {string} [options.cognitoRegion='us-west-2'] - AWS region
 * @param {string} [options.tokenKey='l42_auth_tokens'] - localStorage key for tokens
 * @param {string} [options.redirectUri] - OAuth callback URL (defaults to current origin + /callback)
 * @param {string} [options.scopes] - OAuth scopes
 * @param {string[]} [options.allowedDomains] - Allowed redirect domains (auto-allows current domain if not set)
 * @param {string} [options.cookieDomain] - Cookie domain (auto-detected if not set)
 * @throws {Error} If required configuration is invalid
 */
export function configure(options = {}) {
    const newConfig = { ...DEFAULT_CONFIG, ...options };

    // Validate required fields
    if (!newConfig.clientId || typeof newConfig.clientId !== 'string') {
        throw new Error('configure() requires clientId: must be a non-empty string');
    }
    if (!newConfig.cognitoDomain || typeof newConfig.cognitoDomain !== 'string') {
        throw new Error('configure() requires cognitoDomain: must be a non-empty string');
    }
    // Validate cognitoDomain format to prevent open redirect attacks
    // Format: custom-prefix.auth.region.amazoncognito.com OR custom domain
    const cognitoDomain = newConfig.cognitoDomain.toLowerCase();
    const isAmazonCognito = /^[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/.test(cognitoDomain);
    const isValidCustomDomain = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(cognitoDomain) &&
        !cognitoDomain.includes('..') &&
        !cognitoDomain.includes('://');
    if (!isAmazonCognito && !isValidCustomDomain) {
        throw new Error(
            'Invalid cognitoDomain format.\n' +
            'Expected: "your-app.auth.region.amazoncognito.com" or a valid custom domain.\n' +
            'Do not include protocol (https://).'
        );
    }
    if (!newConfig.cognitoRegion || typeof newConfig.cognitoRegion !== 'string') {
        throw new Error('Invalid cognitoRegion: must be a non-empty string');
    }
    if (!newConfig.tokenKey || typeof newConfig.tokenKey !== 'string') {
        throw new Error('Invalid tokenKey: must be a non-empty string');
    }

    // Validate redirectUri if provided
    if (newConfig.redirectUri) {
        try {
            const url = new URL(newConfig.redirectUri);
            const hostname = url.hostname.toLowerCase();
            const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

            // HTTPS required for non-localhost (prevents token interception)
            if (!isLocalhost && url.protocol !== 'https:') {
                throw new Error(
                    'Invalid redirectUri: HTTPS is required for non-localhost URLs.\n' +
                    'HTTP is only allowed for localhost development.'
                );
            }

            // Store allowedDomains first so isDomainAllowed can use it
            config.allowedDomains = newConfig.allowedDomains;

            if (!isDomainAllowed(hostname)) {
                const allowedList = newConfig.allowedDomains
                    ? newConfig.allowedDomains.join(', ')
                    : 'current domain (' + window.location.hostname + ')';
                throw new Error(
                    `Invalid redirectUri: domain '${hostname}' not allowed.\n` +
                    `Allowed: ${allowedList}\n` +
                    `Add it via configure({ allowedDomains: ['${hostname}'] }) or self-host the library.`
                );
            }
        } catch (e) {
            if (e.message.includes('Invalid redirectUri')) throw e;
            throw new Error('Invalid redirectUri: must be a valid URL');
        }
    }

    config = newConfig;
    _configured = true;
}

/**
 * Check if the library has been configured.
 * @returns {boolean} True if configured
 */
export function isConfigured() {
    return _configured;
}

// ==================== TOKEN MANAGEMENT ====================

/**
 * Get stored authentication tokens.
 * @returns {Object|null} Tokens object or null if not authenticated
 */
export function getTokens() {
    try {
        return JSON.parse(localStorage.getItem(config.tokenKey));
    } catch {
        return null;
    }
}

/**
 * Store authentication tokens.
 * Also sets a cookie for server-side validation (e.g., Lambda@Edge).
 * Cookie lifetime varies by auth method: 1 day for password, 30 days for passkey.
 *
 * SECURITY NOTE: Cookie is NOT HttpOnly
 * -----------------------------------
 * The cookie is set via document.cookie (client-side), which cannot set HttpOnly.
 * HttpOnly cookies can only be set via server-side Set-Cookie headers.
 *
 * Mitigations in place:
 * - Secure flag: Cookie only sent over HTTPS
 * - SameSite=Lax: CSRF protection
 * - Short-lived tokens: ID tokens expire quickly (Cognito default: 1 hour)
 * - Domain validation: Cookie domain restricted to current site
 *
 * For maximum security, consider:
 * - Using server-side session management with HttpOnly cookies
 * - Implementing a BFF (Backend for Frontend) pattern
 *
 * @param {Object} tokens - Tokens to store (should include auth_method)
 */
/**
 * Store tokens in localStorage and set cookie for server-side validation.
 *
 * @param {Object} tokens - The tokens to store
 * @param {Object} [options] - Options
 * @param {boolean} [options.isRefresh=false] - If true, skip notifying auth state listeners
 *   (prevents reload loops when token refresh triggers onAuthStateChange)
 */
export function setTokens(tokens, options = {}) {
    requireConfig();
    localStorage.setItem(config.tokenKey, JSON.stringify(tokens));

    // Set cookie for server-side validation
    if (tokens && tokens.id_token) {
        const domain = getCookieDomain();
        const authMethod = tokens.auth_method || 'password';
        const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
        const maxAge = refreshConfig.cookieMaxAge;

        let cookieStr = `${config.cookieName}=${tokens.id_token}; path=/; max-age=${maxAge}; secure; samesite=lax`;
        if (domain) {
            cookieStr += `; domain=${domain}`;
        }
        document.cookie = cookieStr;
    }

    // Only notify listeners on new login, not on token refresh
    // This prevents reload loops when listeners perform navigation
    if (!options.isRefresh) {
        notifyAuthStateChange(true);
    }
}

/**
 * Get the auth method used for current session.
 * @returns {string|null} 'password', 'passkey', or null if not authenticated
 */
export function getAuthMethod() {
    const tokens = getTokens();
    return tokens ? (tokens.auth_method || 'password') : null;
}

/**
 * Clear stored tokens (logout).
 * Also clears the server-side validation cookie.
 */
export function clearTokens() {
    localStorage.removeItem(config.tokenKey);

    // Clear the cookie
    const domain = getCookieDomain();
    let cookieStr = `${config.cookieName}=; path=/; max-age=0; secure; samesite=lax`;
    if (domain) {
        cookieStr += `; domain=${domain}`;
    }
    document.cookie = cookieStr;

    notifyAuthStateChange(false);
    notifyLogout();
}

/**
 * Decode a JWT token payload WITHOUT signature verification.
 *
 * ⚠️  SECURITY WARNING ⚠️
 * This function does NOT verify the JWT signature.
 * The returned claims are UNVERIFIED and UNTRUSTED.
 *
 * ❌ NEVER use for authorization decisions
 * ✅ ONLY use for display purposes (e.g., showing user email in UI)
 *
 * Server-side validation handles actual authentication and authorization.
 * For authorization checks, use ensureValidTokens() and verify on your server.
 *
 * @param {string} token - JWT token string
 * @returns {Object} Decoded payload (UNVERIFIED - do not trust for auth decisions)
 */
export function UNSAFE_decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
}

/**
 * @deprecated Use UNSAFE_decodeJwtPayload() instead. This alias will be removed in v1.0.
 * @param {string} token - JWT token string
 * @returns {Object} Decoded payload (UNVERIFIED)
 */
export function decodeJwtPayload(token) {
    console.warn('decodeJwtPayload() is deprecated. Use UNSAFE_decodeJwtPayload() to acknowledge the security implications.');
    return UNSAFE_decodeJwtPayload(token);
}

/**
 * @deprecated Use UNSAFE_decodeJwtPayload() instead. This alias will be removed in v1.0.
 * @param {string} token - JWT token string
 * @returns {Object} Decoded payload (UNVERIFIED)
 */
export function parseJwt(token) {
    console.warn('parseJwt() is deprecated. Use UNSAFE_decodeJwtPayload() instead.');
    return UNSAFE_decodeJwtPayload(token);
}

/**
 * Check if token is expired.
 * @param {Object} tokens - Tokens object
 * @returns {boolean} True if expired
 */
export function isTokenExpired(tokens) {
    try {
        return Date.now() >= UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
    } catch {
        return true;
    }
}

/**
 * Check if token should be refreshed (approaching expiry).
 * @param {Object} tokens - Tokens object
 * @returns {boolean} True if should refresh
 */
export function shouldRefreshToken(tokens) {
    if (!tokens || !tokens.id_token || !tokens.refresh_token) return false;
    try {
        const exp = UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
        const authMethod = tokens.auth_method || 'password';
        const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
        return Date.now() >= (exp - refreshConfig.refreshBefore);
    } catch {
        return false;
    }
}

/**
 * Detect auth method from token claims (for migration from older versions).
 * @param {Object} tokens - Tokens object
 * @returns {string} Detected auth method ('password' or 'passkey')
 */
function detectAuthMethod(tokens) {
    if (tokens.auth_method) return tokens.auth_method;

    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
        const amr = claims.amr || [];
        if (amr.includes('webauthn') || amr.includes('mfa')) {
            return 'passkey';
        }
    } catch {
        // Ignore decode errors
    }

    return 'password';
}

/**
 * Refresh tokens using Cognito refresh token flow.
 * @returns {Promise<Object>} New tokens
 * @throws {Error} If refresh fails
 */
export async function refreshTokens() {
    requireConfig();
    const currentTokens = getTokens();
    const email = getUserEmail();

    if (!currentTokens || !currentTokens.refresh_token) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
            activity_name: 'Service Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.LOW,
            user_email: email,
            message: 'No refresh token available'
        });
        throw new Error('No refresh token available');
    }

    try {
        const res = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: config.clientId,
            AuthParameters: {
                REFRESH_TOKEN: currentTokens.refresh_token
            }
        });

        if (res.AuthenticationResult) {
            const authMethod = detectAuthMethod(currentTokens);

            const newTokens = {
                access_token: res.AuthenticationResult.AccessToken,
                id_token: res.AuthenticationResult.IdToken,
                refresh_token: res.AuthenticationResult.RefreshToken || currentTokens.refresh_token,
                auth_method: authMethod
            };
            // Pass isRefresh: true to prevent notifying auth state listeners
            // This avoids reload loops when listeners perform navigation on auth changes
            setTokens(newTokens, { isRefresh: true });

            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
                activity_name: 'Service Ticket',
                status_id: OCSF_STATUS.SUCCESS,
                severity_id: OCSF_SEVERITY.INFORMATIONAL,
                user_email: email,
                message: 'Token refresh successful'
            });

            return newTokens;
        }
        throw new Error('Token refresh failed');
    } catch (e) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
            activity_name: 'Service Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            user_email: email,
            message: 'Token refresh failed: ' + e.message
        });
        throw e;
    }
}

/**
 * Ensure tokens are valid, refreshing if needed.
 * Call this before making authenticated API requests.
 * @returns {Promise<Object|null>} Valid tokens or null if not authenticated
 */
export async function ensureValidTokens() {
    const tokens = getTokens();
    if (!tokens) return null;

    if (isTokenExpired(tokens)) {
        if (!tokens.refresh_token) {
            clearTokens();
            return null;
        }
        try {
            return await refreshTokens();
        } catch (e) {
            console.error('Token refresh failed:', e);
            clearTokens();
            return null;
        }
    }

    if (shouldRefreshToken(tokens)) {
        try {
            return await refreshTokens();
        } catch (e) {
            console.warn('Proactive token refresh failed:', e);
            return tokens;
        }
    }

    return tokens;
}

/**
 * Check if currently authenticated with valid tokens.
 * @returns {boolean} True if authenticated, false otherwise
 */
export function isAuthenticated() {
    const tokens = getTokens();
    return !!(tokens && !isTokenExpired(tokens));
}

/**
 * Get parsed ID token claims.
 * @returns {Object|null} ID token claims or null
 */
export function getIdTokenClaims() {
    const tokens = getTokens();
    if (!tokens || !tokens.id_token) return null;
    try {
        return UNSAFE_decodeJwtPayload(tokens.id_token);
    } catch {
        return null;
    }
}

/**
 * Get user email from tokens.
 * @returns {string|null} User email or null
 */
export function getUserEmail() {
    const claims = getIdTokenClaims();
    return claims ? claims.email : null;
}

/**
 * Check if tokens have admin scope for passkey management.
 * @returns {boolean} True if admin scope present
 */
export function hasAdminScope() {
    const tokens = getTokens();
    if (!tokens || !tokens.access_token) return false;
    try {
        const payload = UNSAFE_decodeJwtPayload(tokens.access_token);
        const scope = payload.scope || '';
        return scope.includes('aws.cognito.signin.user.admin');
    } catch {
        return false;
    }
}

/**
 * Get user's Cognito groups from ID token.
 * @returns {string[]} Array of group names
 */
export function getUserGroups() {
    const claims = getIdTokenClaims();
    return claims && claims['cognito:groups'] ? claims['cognito:groups'] : [];
}

/**
 * Check if user is in the admin group.
 * @returns {boolean} True if user has admin role
 */
export function isAdmin() {
    return getUserGroups().includes('admin');
}

/**
 * Check if user is in readonly group (and NOT admin).
 * @returns {boolean} True if user has readonly-only access
 */
export function isReadonly() {
    const groups = getUserGroups();
    return groups.includes('readonly') && !groups.includes('admin');
}

// ==================== COGNITO API ====================

const RETRY_CONFIG = {
    maxRetries: 3,
    baseDelayMs: 1000,
    maxDelayMs: 10000,
    retryableStatusCodes: [429, 500, 502, 503, 504]
};

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function getBackoffDelay(attempt) {
    const exponentialDelay = RETRY_CONFIG.baseDelayMs * Math.pow(2, attempt);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, RETRY_CONFIG.maxDelayMs);
}

async function cognitoRequest(action, body) {
    requireConfig();
    let lastError;

    for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
        try {
            const res = await fetch('https://cognito-idp.' + config.cognitoRegion + '.amazonaws.com/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + action
                },
                body: JSON.stringify(body)
            });

            if (RETRY_CONFIG.retryableStatusCodes.includes(res.status) && attempt < RETRY_CONFIG.maxRetries) {
                const delay = getBackoffDelay(attempt);
                console.warn(`Cognito request failed with ${res.status}, retrying in ${Math.round(delay)}ms`);
                await sleep(delay);
                continue;
            }

            const data = await res.json();
            if (!res.ok || data.__type) {
                throw new Error(data.message || data.__type || 'Request failed');
            }
            return data;

        } catch (error) {
            lastError = error;

            if (error.name === 'TypeError' && attempt < RETRY_CONFIG.maxRetries) {
                const delay = getBackoffDelay(attempt);
                console.warn(`Cognito network error, retrying in ${Math.round(delay)}ms`);
                await sleep(delay);
                continue;
            }

            throw error;
        }
    }

    throw lastError || new Error('Request failed after retries');
}

// ==================== BASE64URL HELPERS ====================

function b64ToArrayBuffer(b64) {
    const pad = '='.repeat((4 - b64.length % 4) % 4);
    const base64 = b64.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ==================== LOGIN METHODS ====================

/**
 * Get redirect URI for OAuth flows.
 * @returns {string} Redirect URI
 */
export function getRedirectUri() {
    return config.redirectUri || window.location.origin + '/callback';
}

/**
 * Login with password using direct Cognito API.
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise<Object>} Authentication result with tokens
 */
export async function loginWithPassword(email, password) {
    requireConfig();

    try {
        const res = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: config.clientId,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password
            }
        });

        if (res.AuthenticationResult) {
            const tokens = {
                access_token: res.AuthenticationResult.AccessToken,
                id_token: res.AuthenticationResult.IdToken,
                refresh_token: res.AuthenticationResult.RefreshToken,
                auth_method: 'password'
            };
            setTokens(tokens);
            notifyLogin(tokens, 'password');

            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.SUCCESS,
                severity_id: OCSF_SEVERITY.INFORMATIONAL,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'User logged in with password'
            });

            return tokens;
        } else if (res.ChallengeName) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.LOW,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'MFA challenge required: ' + res.ChallengeName
            });
            throw new Error('Additional verification required: ' + res.ChallengeName);
        }
        throw new Error('Authentication failed');
    } catch (e) {
        if (!e.message.includes('Additional verification required')) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.MEDIUM,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'Password authentication failed: ' + e.message
            });
        }
        throw e;
    }
}

/**
 * Login with passkey using direct WebAuthn flow.
 * @param {string} email - User email
 * @returns {Promise<Object>} Authentication result with tokens
 */
export async function loginWithPasskey(email) {
    requireConfig();

    try {
        // Step 1: Initiate auth with USER_AUTH and PREFERRED_CHALLENGE=WEB_AUTHN
        const initRes = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'USER_AUTH',
            ClientId: config.clientId,
            AuthParameters: {
                USERNAME: email,
                PREFERRED_CHALLENGE: 'WEB_AUTHN'
            }
        });

        if (initRes.ChallengeName !== 'WEB_AUTHN') {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.LOW,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'Passkey not available for user'
            });
            throw new Error('Passkey not available. Register one first or use password.');
        }

        // Step 2: Parse WebAuthn challenge
        const credentialOptions = JSON.parse(initRes.ChallengeParameters.CREDENTIAL_REQUEST_OPTIONS);

        const publicKey = {
            challenge: b64ToArrayBuffer(credentialOptions.challenge),
            timeout: credentialOptions.timeout,
            rpId: credentialOptions.rpId,
            allowCredentials: credentialOptions.allowCredentials.map(function(cred) {
                return {
                    id: b64ToArrayBuffer(cred.id),
                    type: cred.type,
                    transports: cred.transports
                };
            }),
            userVerification: credentialOptions.userVerification
        };

        // Step 3: Get passkey assertion
        const credential = await navigator.credentials.get({ publicKey: publicKey });

        // Step 4: Build response
        const assertionResponse = {
            id: credential.id,
            rawId: arrayBufferToB64(credential.rawId),
            response: {
                clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
                authenticatorData: arrayBufferToB64(credential.response.authenticatorData),
                signature: arrayBufferToB64(credential.response.signature)
            },
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults() || {}
        };

        if (credential.response.userHandle) {
            assertionResponse.response.userHandle = arrayBufferToB64(credential.response.userHandle);
        }
        if (credential.authenticatorAttachment) {
            assertionResponse.authenticatorAttachment = credential.authenticatorAttachment;
        }

        // Step 5: Complete challenge
        const authRes = await cognitoRequest('RespondToAuthChallenge', {
            ChallengeName: 'WEB_AUTHN',
            ClientId: config.clientId,
            Session: initRes.Session,
            ChallengeResponses: {
                USERNAME: email,
                CREDENTIAL: JSON.stringify(assertionResponse)
            }
        });

        if (authRes.AuthenticationResult) {
            const tokens = {
                access_token: authRes.AuthenticationResult.AccessToken,
                id_token: authRes.AuthenticationResult.IdToken,
                refresh_token: authRes.AuthenticationResult.RefreshToken,
                auth_method: 'passkey'
            };
            setTokens(tokens);
            notifyLogin(tokens, 'passkey');

            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.SUCCESS,
                severity_id: OCSF_SEVERITY.INFORMATIONAL,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'User logged in with passkey'
            });

            return tokens;
        }
        throw new Error('Passkey authentication failed');
    } catch (e) {
        // Log failure (if not already logged above)
        if (!e.message.includes('Passkey not available')) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: e.name === 'NotAllowedError' ? OCSF_SEVERITY.LOW : OCSF_SEVERITY.MEDIUM,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'Passkey authentication failed: ' + e.message
            });
        }
        throw e;
    }
}

/**
 * Generate a cryptographically secure random state for OAuth CSRF protection.
 * @returns {string} Random state string
 */
function generateOAuthState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Store OAuth state for CSRF protection.
 * Uses localStorage instead of sessionStorage to survive cross-domain navigation
 * (Safari ITP and Firefox ETP can clear sessionStorage during OAuth redirects).
 * State is cleared immediately after verification for security.
 */
function storeOAuthState(state) {
    localStorage.setItem(config.stateKey, state);
}

function verifyOAuthState(state) {
    const stored = localStorage.getItem(config.stateKey);
    localStorage.removeItem(config.stateKey);  // Clear immediately - single use
    return stored && stored === state;
}

// ==================== PKCE (Proof Key for Code Exchange) ====================

const PKCE_VERIFIER_KEY = 'l42_pkce_verifier';

/**
 * Generate a cryptographically secure code verifier for PKCE.
 * RFC 7636 requires 43-128 characters from unreserved URI characters.
 * @returns {string} Random code verifier (64 characters)
 */
function generateCodeVerifier() {
    const array = new Uint8Array(48); // 48 bytes = 64 base64url chars
    crypto.getRandomValues(array);
    // Base64url encoding without padding
    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Generate SHA-256 code challenge from verifier for PKCE.
 * @param {string} verifier - Code verifier
 * @returns {Promise<string>} Base64url-encoded SHA-256 hash
 */
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    // Base64url encoding without padding
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Store PKCE code verifier.
 * Uses localStorage to survive cross-domain navigation during OAuth flow.
 * Cleared immediately after token exchange for security.
 */
function storeCodeVerifier(verifier) {
    localStorage.setItem(PKCE_VERIFIER_KEY, verifier);
}

function getAndClearCodeVerifier() {
    const verifier = localStorage.getItem(PKCE_VERIFIER_KEY);
    localStorage.removeItem(PKCE_VERIFIER_KEY);  // Clear immediately - single use
    return verifier;
}

/**
 * Redirect to Cognito Hosted UI for login.
 * Uses PKCE (Proof Key for Code Exchange) for enhanced security.
 * Use this for OAuth flow with full scopes (needed for passkey management).
 * @param {string} [email] - Optional email hint
 * @returns {Promise<void>}
 */
export async function loginWithHostedUI(email) {
    requireConfig();

    const state = generateOAuthState();
    storeOAuthState(state);

    // PKCE: Generate code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    storeCodeVerifier(codeVerifier);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const params = new URLSearchParams({
        client_id: config.clientId,
        response_type: 'code',
        scope: config.scopes,
        redirect_uri: getRedirectUri(),
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });
    if (email) {
        params.set('login_hint', email);
    }
    window.location.href = 'https://' + config.cognitoDomain + '/oauth2/authorize?' + params;
}

/**
 * Exchange authorization code for tokens (call from callback page).
 * Uses PKCE code_verifier for enhanced security.
 * @param {string} code - Authorization code from OAuth redirect
 * @param {string} state - State parameter from OAuth redirect (for CSRF verification)
 * @returns {Promise<Object>} Tokens
 * @throws {Error} If state/PKCE verification fails or token exchange fails
 */
export async function exchangeCodeForTokens(code, state) {
    requireConfig();

    if (!state || !verifyOAuthState(state)) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.HIGH,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Invalid OAuth state - possible CSRF attack'
        });
        throw new Error('Invalid OAuth state - possible CSRF attack');
    }

    // PKCE: Retrieve and clear the code verifier
    const codeVerifier = getAndClearCodeVerifier();
    if (!codeVerifier) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Missing PKCE code verifier - OAuth flow may have been interrupted'
        });
        throw new Error('Missing PKCE code verifier - OAuth flow may have been interrupted');
    }

    const res = await fetch('https://' + config.cognitoDomain + '/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: config.clientId,
            code: code,
            redirect_uri: getRedirectUri(),
            code_verifier: codeVerifier
        })
    });

    if (!res.ok) {
        const errorText = await res.text();
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Token exchange failed: ' + (errorText || res.status)
        });
        throw new Error('Token exchange failed: ' + (errorText || res.status));
    }

    const data = await res.json();
    const tokens = {
        access_token: data.access_token,
        id_token: data.id_token,
        refresh_token: data.refresh_token,
        auth_method: 'oauth'
    };
    setTokens(tokens);
    notifyLogin(tokens, 'oauth');

    // Extract email from the new token for logging
    const claims = UNSAFE_decodeJwtPayload(tokens.id_token);

    logSecurityEvent({
        class_uid: OCSF_CLASS.AUTHENTICATION,
        activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
        activity_name: 'Authentication Ticket',
        status_id: OCSF_STATUS.SUCCESS,
        severity_id: OCSF_SEVERITY.INFORMATIONAL,
        user_email: claims?.email,
        auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
        auth_protocol: 'OAuth 2.0/OIDC',
        message: 'OAuth token exchange successful'
    });

    return tokens;
}

/**
 * Logout - clear tokens.
 */
export function logout() {
    const email = getUserEmail();
    clearTokens();

    logSecurityEvent({
        class_uid: OCSF_CLASS.AUTHENTICATION,
        activity_id: OCSF_AUTH_ACTIVITY.LOGOFF,
        activity_name: 'Logoff',
        status_id: OCSF_STATUS.SUCCESS,
        severity_id: OCSF_SEVERITY.INFORMATIONAL,
        user_email: email,
        message: 'User logged out'
    });
}

// ==================== PASSKEY MANAGEMENT ====================

/**
 * List registered passkeys for current user.
 * Requires admin scope (use OAuth login).
 * @returns {Promise<Array>} Array of passkey credentials
 */
export async function listPasskeys() {
    const tokens = getTokens();
    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    const res = await cognitoRequest('ListWebAuthnCredentials', {
        AccessToken: tokens.access_token
    });
    return res.Credentials || [];
}

/**
 * Register a new passkey for current user.
 * Requires admin scope (use OAuth login).
 * @returns {Promise<void>}
 */
export async function registerPasskey() {
    const tokens = getTokens();
    const email = getUserEmail();

    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    try {
        // Step 1: Get credential creation options
        const startRes = await cognitoRequest('StartWebAuthnRegistration', {
            AccessToken: tokens.access_token
        });

        // Step 2: Convert to WebAuthn format
        const credOpts = startRes.CredentialCreationOptions;
        const publicKeyOptions = {
            challenge: b64ToArrayBuffer(credOpts.challenge),
            rp: {
                name: credOpts.rp.name,
                id: credOpts.rp.id
            },
            user: {
                id: b64ToArrayBuffer(credOpts.user.id),
                name: credOpts.user.name,
                displayName: credOpts.user.displayName
            },
            pubKeyCredParams: credOpts.pubKeyCredParams,
            timeout: credOpts.timeout || 60000,
            attestation: credOpts.attestation || 'none',
            authenticatorSelection: credOpts.authenticatorSelection || {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                userVerification: 'preferred'
            }
        };

        if (credOpts.excludeCredentials) {
            publicKeyOptions.excludeCredentials = credOpts.excludeCredentials.map(function(c) {
                return {
                    type: c.type,
                    id: b64ToArrayBuffer(c.id),
                    transports: c.transports
                };
            });
        }

        // Step 3: Create credential
        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

        // Step 4: Format for Cognito
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToB64(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
                attestationObject: arrayBufferToB64(credential.response.attestationObject)
            },
            clientExtensionResults: credential.getClientExtensionResults() || {}
        };

        if (credential.response.getTransports) {
            credentialResponse.response.transports = credential.response.getTransports();
        }
        if (credential.authenticatorAttachment) {
            credentialResponse.authenticatorAttachment = credential.authenticatorAttachment;
        }
        if (credential.response.getPublicKey) {
            credentialResponse.response.publicKey = arrayBufferToB64(credential.response.getPublicKey());
        }
        if (credential.response.getPublicKeyAlgorithm) {
            credentialResponse.response.publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
        }
        if (credential.response.getAuthenticatorData) {
            credentialResponse.response.authenticatorData = arrayBufferToB64(credential.response.getAuthenticatorData());
        }

        // Step 5: Complete registration
        await cognitoRequest('CompleteWebAuthnRegistration', {
            AccessToken: tokens.access_token,
            Credential: credentialResponse
        });

        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.CREATE,
            activity_name: 'Create',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: 'Passkey registered successfully',
            metadata: { credential_id: credential.id }
        });
    } catch (e) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.CREATE,
            activity_name: 'Create',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: e.name === 'NotAllowedError' ? OCSF_SEVERITY.LOW : OCSF_SEVERITY.MEDIUM,
            user_email: email,
            message: 'Passkey registration failed: ' + e.message
        });
        throw e;
    }
}

/**
 * Delete a registered passkey.
 * Requires admin scope (use OAuth login).
 * @param {string} credentialId - Credential ID to delete
 * @returns {Promise<void>}
 */
export async function deletePasskey(credentialId) {
    const tokens = getTokens();
    const email = getUserEmail();

    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    try {
        await cognitoRequest('DeleteWebAuthnCredential', {
            AccessToken: tokens.access_token,
            CredentialId: credentialId
        });

        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.DELETE,
            activity_name: 'Delete',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: 'Passkey deleted',
            metadata: { credential_id: credentialId }
        });
    } catch (e) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.DELETE,
            activity_name: 'Delete',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            user_email: email,
            message: 'Passkey deletion failed: ' + e.message,
            metadata: { credential_id: credentialId }
        });
        throw e;
    }
}

// ==================== SERVER-SIDE AUTHORIZATION ====================

/**
 * Require server-side authorization for sensitive actions.
 *
 * ⚠️  SECURITY: Client-side role checks are for UI only!
 * ALL authorization decisions MUST be validated on the server.
 *
 * This helper enforces the pattern of server-side validation by making
 * it the easy path. Use this before any sensitive operation.
 *
 * @param {string} action - The action being authorized (e.g., 'admin:delete-user')
 * @param {Object} [options] - Optional configuration
 * @param {string} [options.endpoint='/api/authorize'] - Authorization endpoint
 * @param {Object} [options.context={}] - Additional context for authorization
 * @returns {Promise<{authorized: boolean, reason?: string}>} Authorization result
 * @throws {Error} If not authenticated or network error
 *
 * @example
 * // Before sensitive admin action
 * async function deleteUser(userId) {
 *     const authResult = await requireServerAuthorization('admin:delete-user', {
 *         context: { targetUserId: userId }
 *     });
 *
 *     if (!authResult.authorized) {
 *         throw new Error(`Not authorized: ${authResult.reason}`);
 *     }
 *
 *     // Proceed with deletion...
 * }
 */
export async function requireServerAuthorization(action, options = {}) {
    const { endpoint = '/api/authorize', context = {} } = options;

    const tokens = await ensureValidTokens();
    if (!tokens) {
        throw new Error('Authentication required for this action');
    }

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${tokens.access_token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action, context })
        });

        if (response.status === 401) {
            clearTokens();
            throw new Error('Session expired. Please log in again.');
        }

        if (response.status === 403) {
            const data = await response.json().catch(() => ({}));
            return {
                authorized: false,
                reason: data.reason || 'Permission denied'
            };
        }

        if (!response.ok) {
            throw new Error(`Authorization check failed: ${response.status}`);
        }

        const data = await response.json();
        return {
            authorized: data.authorized === true,
            reason: data.reason
        };
    } catch (error) {
        if (error.message.includes('Authentication') || error.message.includes('Session')) {
            throw error;
        }
        throw new Error(`Authorization check failed: ${error.message}`);
    }
}

/**
 * Client-side role check for UI display purposes ONLY.
 *
 * ⚠️  WARNING: This is for UI hints only (showing/hiding buttons).
 * NEVER use this for actual authorization - use requireServerAuthorization().
 *
 * @param {string} requiredRole - Role to check
 * @returns {boolean} True if user appears to have role (UNTRUSTED)
 */
export function UI_ONLY_hasRole(requiredRole) {
    const groups = getUserGroups();
    // Normalize to handle singular/plural variations
    const normalizedGroups = groups.map(g => g.toLowerCase());
    const normalizedRole = requiredRole.toLowerCase();
    return normalizedGroups.includes(normalizedRole) ||
           normalizedGroups.includes(normalizedRole + 's') ||
           normalizedGroups.includes(normalizedRole.replace(/s$/, ''));
}

// ==================== AUTH STATE CHANGE LISTENERS ====================

const authStateListeners = new Set();
const loginListeners = new Set();
const logoutListeners = new Set();

function notifyAuthStateChange(isAuth) {
    authStateListeners.forEach(callback => {
        try {
            callback(isAuth);
        } catch (e) {
            console.error('Auth state listener error:', e);
        }
    });
}

/**
 * Notify login listeners when a user logs in.
 * @param {Object} tokens - The authentication tokens
 * @param {string} method - The auth method used ('password', 'passkey', 'oauth')
 */
function notifyLogin(tokens, method) {
    loginListeners.forEach(callback => {
        try {
            callback(tokens, method);
        } catch (e) {
            console.error('Login listener error:', e);
        }
    });
}

/**
 * Notify logout listeners when a user logs out.
 */
function notifyLogout() {
    logoutListeners.forEach(callback => {
        try {
            callback();
        } catch (e) {
            console.error('Logout listener error:', e);
        }
    });
}

/**
 * Subscribe to authentication state changes.
 * Note: This fires on login and logout, but NOT on token refresh (v0.5.7+).
 * For more explicit control, use onLogin() and onLogout().
 *
 * @param {Function} callback - Called with boolean isAuthenticated
 * @returns {Function} Unsubscribe function
 */
export function onAuthStateChange(callback) {
    authStateListeners.add(callback);
    return () => authStateListeners.delete(callback);
}

/**
 * Subscribe to login events.
 * Only fires on actual login (password, passkey, or OAuth), never on token refresh.
 *
 * @param {Function} callback - Called with (tokens, method) where method is 'password', 'passkey', or 'oauth'
 * @returns {Function} Unsubscribe function
 *
 * @example
 * const unsubscribe = onLogin((tokens, method) => {
 *     console.log('User logged in via:', method);
 *     window.location.href = '/dashboard';
 * });
 */
export function onLogin(callback) {
    loginListeners.add(callback);
    return () => loginListeners.delete(callback);
}

/**
 * Subscribe to logout events.
 * Fires when the user logs out or tokens are cleared.
 *
 * @param {Function} callback - Called with no arguments
 * @returns {Function} Unsubscribe function
 *
 * @example
 * const unsubscribe = onLogout(() => {
 *     showLoginScreen();
 * });
 */
export function onLogout(callback) {
    logoutListeners.add(callback);
    return () => logoutListeners.delete(callback);
}

// ==================== DEFAULT EXPORT ====================

export default {
    VERSION,
    configure,
    isConfigured,
    getTokens,
    setTokens,
    clearTokens,
    UNSAFE_decodeJwtPayload,
    decodeJwtPayload,  // deprecated alias
    parseJwt,          // deprecated alias
    isTokenExpired,
    shouldRefreshToken,
    refreshTokens,
    ensureValidTokens,
    getAuthMethod,
    isAuthenticated,
    getIdTokenClaims,
    getUserEmail,
    hasAdminScope,
    getUserGroups,
    isAdmin,
    isReadonly,
    getRedirectUri,
    loginWithPassword,
    loginWithPasskey,
    loginWithHostedUI,
    exchangeCodeForTokens,
    logout,
    listPasskeys,
    registerPasskey,
    deletePasskey,
    onAuthStateChange,
    onLogin,
    onLogout,
    // Server-side authorization (v0.3.0+)
    requireServerAuthorization,
    UI_ONLY_hasRole
};
