# Accessibility Guide

This guide covers accessibility best practices when integrating l42-cognito-passkey into your application.

## Login Form Patterns

### Basic Accessible Login Form

```html
<form id="login-form" aria-labelledby="login-heading">
    <h2 id="login-heading">Sign In</h2>

    <!-- Live region for error announcements -->
    <div id="login-errors" role="alert" aria-live="assertive" aria-atomic="true"></div>

    <div class="form-group">
        <label for="email">Email address</label>
        <input
            type="email"
            id="email"
            name="email"
            autocomplete="email"
            required
            aria-describedby="email-hint"
        >
        <span id="email-hint" class="hint">Enter the email you registered with</span>
    </div>

    <div class="form-group">
        <label for="password">Password</label>
        <input
            type="password"
            id="password"
            name="password"
            autocomplete="current-password"
            required
        >
    </div>

    <button type="submit">Sign In</button>

    <div class="alternatives">
        <button type="button" id="passkey-login" aria-describedby="passkey-hint">
            Sign in with Passkey
        </button>
        <span id="passkey-hint" class="visually-hidden">
            Uses biometric or security key authentication
        </span>
    </div>
</form>
```

### Error Announcement Pattern

```javascript
import { loginWithPassword, loginWithPasskey } from '/auth/auth.js';

const errorRegion = document.getElementById('login-errors');

function announceError(message, isUserError = true) {
    // Clear previous errors
    errorRegion.textContent = '';

    // Use setTimeout to ensure screen readers announce the change
    setTimeout(() => {
        errorRegion.textContent = message;

        // For user errors, focus the relevant field
        if (isUserError) {
            document.getElementById('email')?.focus();
        }
    }, 100);
}

function clearError() {
    errorRegion.textContent = '';
}

async function handleLogin(email, password) {
    clearError();

    try {
        await loginWithPassword(email, password);
        // Success - redirect handled by onLogin listener
    } catch (error) {
        // Categorize errors for appropriate announcement
        if (error.message.includes('Incorrect username or password')) {
            announceError('The email or password you entered is incorrect. Please try again.', true);
        } else if (error.message.includes('User does not exist')) {
            announceError('No account found with this email address.', true);
        } else if (error.message.includes('Additional verification')) {
            announceError('Additional verification required. Redirecting to secure login.', false);
            loginWithHostedUI(email);
        } else {
            // System error - not user's fault
            announceError('Unable to sign in. Please check your connection and try again.', false);
        }
    }
}
```

## WebAuthn/Passkey Accessibility

### Browser Handles Most UI

WebAuthn authentication prompts are handled by the browser/OS, which generally provide good accessibility:

- **Touch ID/Face ID**: VoiceOver announces biometric prompts
- **Windows Hello**: Narrator supports the authentication dialog
- **Security Keys**: Browser prompts are keyboard accessible

### Fallback Guidance

Always provide a fallback when passkey isn't available:

```javascript
import { loginWithPasskey, loginWithPassword, loginWithHostedUI } from '/auth/auth.js';

async function attemptPasskeyLogin(email) {
    const statusRegion = document.getElementById('auth-status');

    try {
        statusRegion.textContent = 'Waiting for passkey authentication...';
        await loginWithPasskey(email);
        statusRegion.textContent = 'Signed in successfully.';
    } catch (error) {
        if (error.name === 'NotAllowedError') {
            // User cancelled or timeout
            statusRegion.textContent = 'Passkey authentication cancelled. You can try again or use password.';
            showPasswordFallback();
        } else if (error.message.includes('Passkey not available')) {
            // No passkey registered
            statusRegion.textContent = 'No passkey found for this account. Please use password login.';
            showPasswordFallback();
        } else {
            // Other error
            statusRegion.textContent = 'Passkey authentication failed. Please try password login.';
            showPasswordFallback();
        }
    }
}

function showPasswordFallback() {
    const passwordSection = document.getElementById('password-section');
    passwordSection.hidden = false;
    passwordSection.querySelector('input')?.focus();
}
```

### Keyboard Navigation

Ensure passkey buttons are keyboard accessible:

```html
<div class="auth-methods" role="group" aria-labelledby="auth-methods-label">
    <span id="auth-methods-label" class="visually-hidden">Choose sign-in method</span>

    <button
        type="button"
        id="passkey-btn"
        aria-describedby="passkey-desc"
    >
        <span aria-hidden="true">🔐</span>
        Sign in with Passkey
    </button>
    <p id="passkey-desc" class="method-description">
        Use fingerprint, face recognition, or security key
    </p>

    <button
        type="button"
        id="password-btn"
        aria-describedby="password-desc"
    >
        <span aria-hidden="true">🔑</span>
        Sign in with Password
    </button>
    <p id="password-desc" class="method-description">
        Use your email and password
    </p>
</div>
```

## Loading States

Announce loading states for screen reader users:

```javascript
import { onLogin, onLogout } from '/auth/auth.js';

const statusRegion = document.getElementById('auth-status');

// Announce auth state changes
onLogin((tokens, method) => {
    const methodName = {
        'password': 'password',
        'passkey': 'passkey',
        'oauth': 'secure login'
    }[method] || method;

    statusRegion.textContent = `Signed in successfully using ${methodName}.`;
});

onLogout(() => {
    statusRegion.textContent = 'You have been signed out.';
});

// During login attempt
function setLoading(isLoading) {
    const submitBtn = document.getElementById('submit-btn');

    if (isLoading) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
        statusRegion.textContent = 'Signing in...';
    } else {
        submitBtn.disabled = false;
        submitBtn.removeAttribute('aria-busy');
    }
}
```

## Session Timeout Handling

Warn users before session expires:

```javascript
import { getTokens, UNSAFE_decodeJwtPayload, ensureValidTokens } from '/auth/auth.js';

function checkSessionExpiry() {
    const tokens = getTokens();
    if (!tokens) return;

    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
        const expiresAt = claims.exp * 1000;
        const warningTime = 5 * 60 * 1000; // 5 minutes
        const timeLeft = expiresAt - Date.now();

        if (timeLeft < warningTime && timeLeft > 0) {
            announceSessionWarning(Math.ceil(timeLeft / 60000));
        }
    } catch {
        // Ignore decode errors
    }
}

function announceSessionWarning(minutesLeft) {
    const warningRegion = document.getElementById('session-warning');
    warningRegion.textContent = `Your session will expire in ${minutesLeft} minute${minutesLeft === 1 ? '' : 's'}. Save your work.`;
    warningRegion.hidden = false;

    // Offer to extend session
    const extendBtn = document.getElementById('extend-session');
    extendBtn.hidden = false;
    extendBtn.focus();
}

async function extendSession() {
    const statusRegion = document.getElementById('session-warning');
    try {
        await ensureValidTokens();
        statusRegion.textContent = 'Session extended successfully.';
    } catch {
        statusRegion.textContent = 'Unable to extend session. Please save your work and sign in again.';
    }
}

// Check every minute
setInterval(checkSessionExpiry, 60000);
```

## CSS for Screen Reader Only Content

```css
/* Visually hidden but accessible to screen readers */
.visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}

/* Skip link for keyboard navigation */
.skip-link {
    position: absolute;
    top: -40px;
    left: 0;
    background: #000;
    color: #fff;
    padding: 8px;
    z-index: 100;
}

.skip-link:focus {
    top: 0;
}
```

## Focus Management

### After Login Success

```javascript
import { onLogin } from '/auth/auth.js';

onLogin(() => {
    // Move focus to main content after login
    const mainHeading = document.querySelector('main h1');
    if (mainHeading) {
        mainHeading.setAttribute('tabindex', '-1');
        mainHeading.focus();
    }
});
```

### After Logout

```javascript
import { onLogout } from '/auth/auth.js';

onLogout(() => {
    // Move focus to login form
    const loginHeading = document.getElementById('login-heading');
    if (loginHeading) {
        loginHeading.setAttribute('tabindex', '-1');
        loginHeading.focus();
    }
});
```

## Testing Accessibility

### Manual Testing Checklist

- [ ] Navigate entire login flow using keyboard only (Tab, Enter, Escape)
- [ ] Test with screen reader (VoiceOver, NVDA, or Narrator)
- [ ] Verify error messages are announced
- [ ] Check passkey prompts are accessible
- [ ] Test session timeout warnings
- [ ] Verify focus moves appropriately after login/logout

### Automated Testing

```javascript
// Example accessibility test with axe-core
import { axe } from 'axe-core';

async function testLoginFormAccessibility() {
    const results = await axe.run('#login-form');

    if (results.violations.length > 0) {
        console.error('Accessibility violations:', results.violations);
    }

    return results.violations.length === 0;
}
```

## ARIA Live Regions Summary

| Region | Purpose | aria-live |
|--------|---------|-----------|
| Error messages | Announce validation/auth errors | `assertive` |
| Loading states | Announce "Signing in..." | `polite` |
| Success messages | Announce "Signed in successfully" | `polite` |
| Session warnings | Announce expiry warnings | `assertive` |

## Resources

- [WebAuthn Accessibility](https://www.w3.org/TR/webauthn-2/#sctn-accessibility-considerations)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)
