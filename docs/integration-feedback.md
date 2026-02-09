# L42 Cognito Passkey - Integration Guide & Feedback

This document helps you integrate the library and structure feedback for improvements.

## Quick Integration Checklist

### 1. Copy the Library (2 min)

```bash
# Copy auth.js to your project
cp src/auth.js /your-project/public/auth/auth.js
```

### 2. Add Configuration (2 min)

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'your-cognito-client-id',
    domain: 'your-app.auth.us-west-2.amazoncognito.com',
    region: 'us-west-2'
};
</script>
```

### 3. Add Callback Page (1 min)

Copy `plugin/templates/callback.html` to your site at `/callback.html` or `/callback/index.html`.

### 4. Test Basic Flow (5 min)

```javascript
import * as auth from '/auth/auth.js';

// Test 1: Check version
console.log('Auth version:', auth.VERSION); // Should be 0.13.0

// Test 2: Login flow
auth.loginWithHostedUI();

// Test 3: After callback
if (auth.isAuthenticated()) {
    console.log('Email:', auth.getUserEmail());
    console.log('Groups:', auth.getUserGroups());
}
```

---

## Feedback Template

When testing the library, please capture feedback in this structure. You can create an issue or send directly.

### Site Info

```yaml
Site: [Your site name/URL]
Type: [static-site | wasm-app | spa | other]
Auth needs: [password-only | passkey | both]
Roles needed: [list roles, e.g., admin, editor, user]
```

### Integration Experience

Rate 1-5 (1=painful, 5=smooth):

| Area | Rating | Notes |
|------|--------|-------|
| Setup/copy process | | |
| Configuration | | |
| Callback handling | | |
| Documentation clarity | | |
| Error messages | | |

### What Worked Well

```
- 
- 
```

### What Was Confusing

```
- 
- 
```

### Bugs Found

```yaml
Bug 1:
  Description: 
  Steps to reproduce:
  Expected:
  Actual:
  Browser/OS:

Bug 2:
  ...
```

### Missing Features

```yaml
Feature 1:
  What I needed:
  Workaround used:
  Priority: [blocking | nice-to-have]

Feature 2:
  ...
```

### API Friction

Any function calls that felt awkward or required extra steps:

```javascript
// What I had to write:

// What I wished I could write:
```

### Questions That Came Up

```
1. 
2. 
```

---

## Common Integration Patterns

### Pattern A: Static Marketing Site + Protected Downloads

```
public/
├── index.html          # Public homepage
├── about.html          # Public pages
├── auth/
│   ├── auth.js         # L42 library
│   └── callback.html   # OAuth callback
└── members/
    └── index.html      # Protected (check isAuthenticated)
```

**Key code:**
```javascript
if (!auth.isAuthenticated()) {
    auth.loginWithHostedUI();
} else {
    showMemberContent();
}
```

### Pattern B: SPA with Role-Based UI

```javascript
import * as auth from '/auth/auth.js';
import { isInCognitoGroup, COGNITO_GROUPS } from '/auth/rbac-roles.js';

function renderNav() {
    const groups = auth.getUserGroups();
    
    // Show/hide based on role (UI only!)
    document.getElementById('admin-link').hidden = 
        !isInCognitoGroup(groups, 'ADMIN');
    
    document.getElementById('editor-tools').hidden = 
        !isInCognitoGroup(groups, 'EDITOR');
}

// For actual protected actions, use server validation
async function deleteUser(id) {
    const result = await auth.requireServerAuthorization('admin:delete-user');
    if (!result.authorized) {
        alert('Not authorized');
        return;
    }
    // proceed...
}
```

### Pattern C: Multi-Page with Shared Auth State

```javascript
// shared-auth.js - import on every page
import * as auth from '/auth/auth.js';

// Update UI on every page load
document.addEventListener('DOMContentLoaded', async () => {
    await auth.ensureValidTokens(); // Refresh if needed
    
    const loginBtn = document.getElementById('login-btn');
    const userInfo = document.getElementById('user-info');
    
    if (auth.isAuthenticated()) {
        loginBtn.style.display = 'none';
        userInfo.textContent = auth.getUserEmail();
    } else {
        loginBtn.style.display = 'block';
        userInfo.textContent = '';
    }
});
```

---

## Troubleshooting

### "Auth not configured" Error

The library auto-configures from `window.L42_AUTH_CONFIG`. Make sure:
1. Config script runs BEFORE importing auth.js
2. `clientId` and `domain` are set

### Callback Not Working

Check:
1. Callback URL matches Cognito app client settings exactly
2. `callback.html` exists at the configured path
3. No CSP blocking Cognito domain

### Cookies Not Set

For ccTLDs (`.co.uk`, `.com.au`), explicitly set:
```javascript
window.L42_AUTH_CONFIG = {
    // ...
    cookieDomain: '.yoursite.co.uk'
};
```

### Groups Not Appearing

1. User must be added to Cognito User Pool Groups
2. App client must NOT have "read/write attributes" restrictions
3. Check token: `console.log(auth.UNSAFE_decodeJwtPayload(auth.getTokens().id_token))`

---

## Submitting Feedback

Options:
1. **GitHub Issue**: [Create issue](https://github.com/lexicone42/l42-cognito-passkey/issues) with feedback template
2. **PR**: Fix issues directly and submit PR
3. **Direct**: Share feedback template with maintainers

We prioritize feedback that includes:
- Specific reproduction steps
- Browser/environment details
- Suggested solutions (if any)
