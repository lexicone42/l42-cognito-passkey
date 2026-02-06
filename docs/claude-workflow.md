# Claude-to-Claude Integration Workflow

This document describes how Claude Code instances can collaborate on l42-cognito-passkey via GitHub issues.

## Overview

When a Claude instance integrating this library encounters issues or has feedback:

1. **Reporter** creates a GitHub issue using the appropriate template
2. **Maintainer** processes the issue using `pnpm process-issue <number>`
3. **Maintainer** implements fix/feature, references issue in commits
4. **Reporter** updates the library and provides feedback on the issue

## For Reporters (Integrating Projects)

### Creating Bug Reports

```bash
# Use gh CLI to create an issue
gh issue create --repo lexicone42/l42-cognito-passkey \
  --title "bug: Brief description" \
  --body "$(cat <<'EOF'
## Summary
One-line description of the issue.

## Environment
- Library version: 0.12.1
- Browser: Safari/Chrome/Firefox
- Auth methods: Passkey, Password, OAuth

## Steps to Reproduce
1. Step one
2. Step two
3. Observe error

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Code Sample
\`\`\`javascript
// Minimal reproduction
\`\`\`

## Workaround (if any)
Describe any workaround you're using.
EOF
)" \
  --label "bug"
```

### Creating Feature Requests

```bash
gh issue create --repo lexicone42/l42-cognito-passkey \
  --title "feat: Brief description" \
  --body "$(cat <<'EOF'
## Summary
What you want to add.

## Motivation
Why this would be useful.

## Proposed API
\`\`\`javascript
// How you'd like to use it
\`\`\`

## Alternatives Considered
Other approaches you considered.
EOF
)" \
  --label "enhancement"
```

### Providing Feedback on Fixes

After updating to a new version with a fix:

```bash
# Comment on the issue with results
gh issue comment <number> --repo lexicone42/l42-cognito-passkey \
  --body "$(cat <<'EOF'
## Integration Test Results

- **Version tested**: 0.12.1
- **Result**: ✅ Working / ❌ Still failing

### Notes
Any additional observations...
EOF
)"
```

## For Maintainers (This Repository)

### Processing Issues

```bash
# Fetch and sanitize the issue
pnpm process-issue <number>

# Read the processed issue
cat .claude/issues/issue-<number>.md
```

The `process-issue` script:
- Fetches issue via GitHub API (using `gh` CLI)
- Sanitizes content (removes control chars, scripts, injection attempts)
- Creates a structured bug fix workflow checklist
- Outputs are gitignored

### Implementing Fixes

1. **Create a todo list** with steps from the issue
2. **Write failing tests** if applicable
3. **Implement the fix/feature**
4. **Reference the issue in commits**:
   ```bash
   git commit -m "fix: description

   Fixes #42"
   ```
5. **Release** with `pnpm release:patch` or `pnpm release:minor`

### Closing Issues

Issues are auto-closed when commits with `Fixes #N` are merged. For manual closure:

```bash
gh issue close <number> --repo lexicone42/l42-cognito-passkey \
  --comment "Fixed in v0.12.1. Please update and confirm."
```

## Security Considerations

### Issue Processing

The `process-issue` script includes security measures:
- Uses `execFileSync` (no shell) to prevent command injection
- Validates issue number as positive integer
- Sanitizes all text content
- Detects suspicious patterns (shell injection, path traversal)
- Issues are processed read-only (never executed)

### Content Guidelines

When creating issues:
- Don't include real credentials, tokens, or secrets
- Sanitize log output before pasting
- Use placeholder values for sensitive data

## Workflow Diagram

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Integrating     │     │  GitHub         │     │ l42-cognito-    │
│ Claude Instance │────▶│  Issues         │◀────│ passkey Claude  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │  1. Create issue      │                       │
        │──────────────────────▶│                       │
        │                       │  2. process-issue     │
        │                       │◀──────────────────────│
        │                       │                       │
        │                       │  3. Fix + commit      │
        │                       │◀──────────────────────│
        │                       │                       │
        │  4. Update + test     │                       │
        │◀──────────────────────│                       │
        │                       │                       │
        │  5. Comment results   │                       │
        │──────────────────────▶│                       │
        │                       │  6. Close issue       │
        │                       │◀──────────────────────│
```

## Related Files

- `scripts/process-issue.js` - Issue fetching and sanitization
- `.claude/issues/` - Processed issues (gitignored)
- `CLAUDE.md` - Integration guide for Claude instances
