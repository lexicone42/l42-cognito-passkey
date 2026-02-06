/**
 * L42 Cognito Passkey - TypeScript Type Declarations
 *
 * Type declarations for the l42-cognito-passkey authentication library.
 * These types match the exports of src/auth.js (v0.11.0).
 *
 * @version 0.11.0
 * @license Apache-2.0
 */

// ==================== INTERFACES ====================

/**
 * Authentication tokens returned by Cognito.
 */
export interface TokenSet {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  /** Authentication method used to obtain these tokens */
  auth_method?: 'password' | 'passkey' | 'oauth';
}

/**
 * Decoded ID token claims from Cognito.
 * These are UNVERIFIED client-side claims - never use for authorization.
 */
export interface IdTokenClaims {
  sub: string;
  email: string;
  email_verified: boolean;
  'cognito:groups'?: string[];
  [key: string]: unknown;
}

/**
 * Information about a registered passkey credential.
 */
export interface PasskeyInfo {
  credentialId: string;
  createdAt: string;
  friendlyName?: string;
}

/**
 * Configuration options for the auth library.
 */
export interface AuthConfigOptions {
  /** Cognito User Pool Client ID (required) */
  clientId: string;
  /** Cognito domain, e.g. 'myapp.auth.us-west-2.amazoncognito.com' (required) */
  cognitoDomain: string;
  /** AWS region (default: 'us-west-2') */
  cognitoRegion?: string;
  /** OAuth redirect URI (defaults to current origin + /callback) */
  redirectUri?: string;
  /** OAuth scopes */
  scopes?: string;
  /** Allowed redirect domains (auto-allows current domain if not set) */
  allowedDomains?: string[];
  /** Cookie domain (auto-detected if not set) */
  cookieDomain?: string;
  /** Cookie name (default: 'l42_id_token') */
  cookieName?: string;
  /** Key for token storage (default: 'l42_auth_tokens') */
  tokenKey?: string;
  /** Key for OAuth state storage (default: 'l42_auth_state') */
  stateKey?: string;
  /** WebAuthn Relying Party ID */
  relyingPartyId?: string;
  /** Token storage mode */
  tokenStorage?: 'localStorage' | 'memory' | 'handler';
  /** Token Handler GET endpoint (required for handler mode) */
  tokenEndpoint?: string;
  /** Token Handler refresh POST endpoint (required for handler mode) */
  refreshEndpoint?: string;
  /** Token Handler logout POST endpoint (required for handler mode) */
  logoutEndpoint?: string;
  /** Backend OAuth callback URL (optional, for handler mode) */
  oauthCallbackUrl?: string;
  /** Token Handler cache TTL in milliseconds (default: 30000) */
  handlerCacheTtl?: number;
  /**
   * Structured security logging for OCSF/Security Lake integration.
   * Set to 'console' for console.log output, a function to receive events, or null to disable.
   */
  securityLogger?: 'console' | ((event: Record<string, unknown>) => void) | null;
  /**
   * Debug logging mode.
   * - false: disabled (default)
   * - true: log to console.debug with [l42-auth] prefix
   * - 'verbose': also include data payloads in console output
   * - function: receive debug events programmatically
   */
  debug?: boolean | 'verbose' | ((event: DebugEvent) => void);
}

/**
 * WebAuthn/Passkey capability detection results.
 */
export interface PasskeyCapabilities {
  /** Whether the browser supports WebAuthn */
  supported: boolean;
  /** Whether conditional mediation (autofill) is available */
  conditionalMediation: boolean;
  /** Whether a platform authenticator (Touch ID, Windows Hello) is available */
  platformAuthenticator: boolean;
  /** Whether the page is in a secure context (HTTPS) */
  secureContext: boolean;
}

/**
 * Result from requireServerAuthorization().
 */
export interface AuthorizationResult {
  /** Whether the action is authorized */
  authorized: boolean;
  /** Reason for denial or additional context */
  reason?: string;
}

/**
 * Options for requireServerAuthorization().
 */
export interface ServerAuthorizationOptions {
  /** Server endpoint to check authorization (default: '/api/authorize') */
  endpoint?: string;
  /** Additional context to send to the authorization endpoint */
  context?: Record<string, unknown>;
}

/**
 * Options for startAutoRefresh().
 */
export interface AutoRefreshOptions {
  /** Check interval in milliseconds (default: 60000) */
  intervalMs?: number;
  /** Whether to pause refresh when the tab is hidden (default: true) */
  pauseWhenHidden?: boolean;
}

/**
 * A debug event logged by the library.
 */
export interface DebugEvent {
  /** Unix timestamp in milliseconds */
  timestamp: number;
  /** Event category (token, auth, config, state, refresh, session, passkey) */
  category: string;
  /** Human-readable event message */
  message: string;
  /** Optional data payload */
  data?: Record<string, unknown>;
  /** Library version */
  version: string;
}

/**
 * Current auth state diagnostics snapshot.
 */
export interface DiagnosticsInfo {
  configured: boolean;
  tokenStorage: string;
  hasTokens: boolean;
  isAuthenticated: boolean;
  tokenExpiry: Date | null;
  authMethod: string | null;
  userEmail: string | null;
  userGroups: string[];
  isAdmin: boolean;
  isReadonly: boolean;
  autoRefreshActive: boolean;
  debug: boolean | string;
  version: string;
}

// ==================== EXPORTS ====================

/** Library version string */
export const VERSION: string;

// -- Configuration --

/**
 * Configure the auth library. Must be called before using auth functions.
 * @throws {Error} If required configuration is invalid
 */
export function configure(options: AuthConfigOptions): void;

/** Check if the library has been configured. */
export function isConfigured(): boolean;

// -- Token Management --

/**
 * Get stored authentication tokens.
 *
 * In handler mode, returns a Promise that fetches tokens from the server.
 * In localStorage/memory modes, returns tokens synchronously.
 * For cross-mode compatibility, use `await getTokens()`.
 */
export function getTokens(): TokenSet | null | Promise<TokenSet | null>;

/**
 * Store tokens and set cookie for server-side validation.
 * @param tokens - The tokens to store
 * @param options - Options (e.g., `{ isRefresh: true }` to skip notifying listeners)
 */
export function setTokens(tokens: TokenSet, options?: { isRefresh?: boolean }): void;

/** Clear all stored tokens and cookies. */
export function clearTokens(): void;

/** Get the authentication method used for the current session. */
export function getAuthMethod(): 'password' | 'passkey' | 'oauth' | null;

/**
 * Decode a JWT payload WITHOUT verification.
 *
 * WARNING: Returns UNVERIFIED claims. Use only for display purposes,
 * never for authorization decisions.
 */
export function UNSAFE_decodeJwtPayload(token: string): Record<string, unknown>;

/** Check if tokens are expired. */
export function isTokenExpired(tokens: TokenSet): boolean;

/** Check if tokens should be proactively refreshed. */
export function shouldRefreshToken(tokens: TokenSet): boolean;

/** Refresh tokens using the refresh token or handler endpoint. */
export function refreshTokens(): Promise<TokenSet>;

/**
 * Ensure valid tokens are available, refreshing if needed.
 * @returns Valid tokens, or null if not authenticated.
 */
export function ensureValidTokens(): Promise<TokenSet | null>;

// -- Authentication Status --

/**
 * Check if user is authenticated (synchronous).
 * In handler mode, uses cached tokens.
 */
export function isAuthenticated(): boolean;

/**
 * Check if user is authenticated (asynchronous).
 * In handler mode, fetches fresh token status from server.
 */
export function isAuthenticatedAsync(): Promise<boolean>;

/** Get decoded ID token claims, or null if not authenticated. */
export function getIdTokenClaims(): IdTokenClaims | null;

/** Get the authenticated user's email, or null. */
export function getUserEmail(): string | null;

/** Check if the access token contains admin scope. */
export function hasAdminScope(): boolean;

/** Get the user's Cognito group memberships. */
export function getUserGroups(): string[];

/**
 * Check if user has admin role.
 * Checks Cognito groups case-insensitively with alias support
 * (admin, admins, administrators).
 */
export function isAdmin(): boolean;

/**
 * Check if user has readonly-only access.
 * Checks Cognito groups case-insensitively with alias support
 * (readonly, read-only, viewer, viewers), excluding admins.
 */
export function isReadonly(): boolean;

// -- Login Methods --

/**
 * Log in with email and password via Cognito USER_PASSWORD_AUTH.
 * @returns Authentication tokens on success
 */
export function loginWithPassword(email: string, password: string): Promise<TokenSet>;

/**
 * Log in with a passkey (WebAuthn).
 * @returns Authentication tokens on success
 */
export function loginWithPasskey(email: string): Promise<TokenSet>;

/**
 * Redirect to Cognito Hosted UI for OAuth login.
 * @param email - Optional email hint for the login form
 */
export function loginWithHostedUI(email?: string): Promise<void>;

/** Get the configured OAuth redirect URI. */
export function getRedirectUri(): string;

/**
 * Exchange an OAuth authorization code for tokens.
 * @param code - Authorization code from the OAuth redirect
 * @param state - State parameter for CSRF verification
 */
export function exchangeCodeForTokens(code: string, state: string): Promise<TokenSet>;

/** Log out - clears tokens, cookies, and calls server logout in handler mode. */
export function logout(): void;

// -- Passkey Management --

/** List registered passkey credentials. */
export function listPasskeys(): Promise<PasskeyInfo[]>;

/** Register a new passkey for the authenticated user. */
export function registerPasskey(): Promise<void>;

/** Delete a registered passkey. */
export function deletePasskey(credentialId: string): Promise<void>;

// -- WebAuthn Feature Detection --

/**
 * Check if the browser supports WebAuthn passkeys.
 * Checks for PublicKeyCredential API and secure context.
 */
export function isPasskeySupported(): boolean;

/** Check if conditional mediation (passkey autofill) is available. */
export function isConditionalMediationAvailable(): Promise<boolean>;

/** Check if a platform authenticator (Touch ID, Windows Hello) is available. */
export function isPlatformAuthenticatorAvailable(): Promise<boolean>;

/** Get comprehensive passkey capability information. */
export function getPasskeyCapabilities(): Promise<PasskeyCapabilities>;

// -- Server-Side Authorization --

/**
 * Check authorization with the server before performing a sensitive action.
 *
 * This is the CORRECT way to authorize actions. Client-side role checks
 * (getUserGroups, isAdmin) are for UI display only.
 *
 * @param action - The action to authorize (e.g., 'admin:delete-user')
 * @param options - Endpoint and context options
 * @throws {Error} If not authenticated or network error
 */
export function requireServerAuthorization(
  action: string,
  options?: ServerAuthorizationOptions
): Promise<AuthorizationResult>;

/**
 * Client-side role check for UI display purposes ONLY.
 *
 * WARNING: Never use this for actual authorization.
 * Use requireServerAuthorization() instead.
 *
 * @param requiredRole - Role to check (handles singular/plural variations)
 * @returns True if user appears to have role (UNTRUSTED)
 */
export function UI_ONLY_hasRole(requiredRole: string): boolean;

// -- Event Listeners --

/**
 * Subscribe to authentication state changes.
 * @param callback - Called with boolean indicating authenticated state
 * @returns Unsubscribe function
 */
export function onAuthStateChange(callback: (isAuthenticated: boolean) => void): () => void;

/**
 * Subscribe to login events.
 * Only fires on actual login (password, passkey, OAuth), never on token refresh.
 * @param callback - Called with tokens and auth method
 * @returns Unsubscribe function
 */
export function onLogin(callback: (tokens: TokenSet, method: string) => void): () => void;

/**
 * Subscribe to logout events.
 * @returns Unsubscribe function
 */
export function onLogout(callback: () => void): () => void;

// -- Auto-Refresh & Session Management --

/**
 * Start automatic background token refresh.
 *
 * Periodically checks token expiry and refreshes proactively.
 * Pauses when the tab is hidden and checks immediately when visible again.
 * Called automatically on login.
 *
 * @returns Stop function to cancel auto-refresh
 */
export function startAutoRefresh(options?: AutoRefreshOptions): () => void;

/** Stop automatic background token refresh. */
export function stopAutoRefresh(): void;

/** Check if auto-refresh is currently active. */
export function isAutoRefreshActive(): boolean;

/**
 * Subscribe to session expiry events.
 * Fires when the session cannot be recovered (refresh failure, expired tokens).
 * @param callback - Called with a reason string
 * @returns Unsubscribe function
 */
export function onSessionExpired(callback: (reason: string) => void): () => void;

/**
 * Fetch with automatic Bearer token injection.
 *
 * Convenience wrapper around fetch() that:
 * - Injects the access token as a Bearer token
 * - Handles 401 with retry-after-refresh
 * - Fires onSessionExpired if retry fails
 *
 * @param url - Request URL
 * @param options - Standard fetch options
 * @returns Fetch response
 */
export function fetchWithAuth(url: string, options?: RequestInit): Promise<Response>;

// -- Debug & Diagnostics --

/** Get a copy of the debug event history (newest last). */
export function getDebugHistory(): DebugEvent[];

/** Get a snapshot of current auth diagnostics. Works regardless of debug mode. */
export function getDiagnostics(): DiagnosticsInfo;

/** Clear the debug event history. */
export function clearDebugHistory(): void;

// ==================== DEFAULT EXPORT ====================

declare const auth: {
  VERSION: typeof VERSION;
  configure: typeof configure;
  isConfigured: typeof isConfigured;
  getTokens: typeof getTokens;
  setTokens: typeof setTokens;
  clearTokens: typeof clearTokens;
  UNSAFE_decodeJwtPayload: typeof UNSAFE_decodeJwtPayload;
  isTokenExpired: typeof isTokenExpired;
  shouldRefreshToken: typeof shouldRefreshToken;
  refreshTokens: typeof refreshTokens;
  ensureValidTokens: typeof ensureValidTokens;
  getAuthMethod: typeof getAuthMethod;
  isAuthenticated: typeof isAuthenticated;
  isAuthenticatedAsync: typeof isAuthenticatedAsync;
  getIdTokenClaims: typeof getIdTokenClaims;
  getUserEmail: typeof getUserEmail;
  hasAdminScope: typeof hasAdminScope;
  getUserGroups: typeof getUserGroups;
  isAdmin: typeof isAdmin;
  isReadonly: typeof isReadonly;
  getRedirectUri: typeof getRedirectUri;
  loginWithPassword: typeof loginWithPassword;
  loginWithPasskey: typeof loginWithPasskey;
  loginWithHostedUI: typeof loginWithHostedUI;
  exchangeCodeForTokens: typeof exchangeCodeForTokens;
  logout: typeof logout;
  listPasskeys: typeof listPasskeys;
  registerPasskey: typeof registerPasskey;
  deletePasskey: typeof deletePasskey;
  onAuthStateChange: typeof onAuthStateChange;
  onLogin: typeof onLogin;
  onLogout: typeof onLogout;
  requireServerAuthorization: typeof requireServerAuthorization;
  UI_ONLY_hasRole: typeof UI_ONLY_hasRole;
  startAutoRefresh: typeof startAutoRefresh;
  stopAutoRefresh: typeof stopAutoRefresh;
  isAutoRefreshActive: typeof isAutoRefreshActive;
  onSessionExpired: typeof onSessionExpired;
  fetchWithAuth: typeof fetchWithAuth;
  isPasskeySupported: typeof isPasskeySupported;
  isConditionalMediationAvailable: typeof isConditionalMediationAvailable;
  isPlatformAuthenticatorAvailable: typeof isPlatformAuthenticatorAvailable;
  getPasskeyCapabilities: typeof getPasskeyCapabilities;
  getDebugHistory: typeof getDebugHistory;
  getDiagnostics: typeof getDiagnostics;
  clearDebugHistory: typeof clearDebugHistory;
};

export default auth;
