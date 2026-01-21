# Release Process

This document describes how to release new versions of l42-cognito-passkey.

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backwards compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backwards compatible

## Prerequisites

1. **NPM_TOKEN**: Set up in GitHub repository secrets for npm publishing
2. **Clean working directory**: All changes committed
3. **Tests passing**: `pnpm test` should pass

## Release Commands

### Patch Release (Bug fixes)

```bash
pnpm release:patch
```

### Minor Release (New features)

```bash
pnpm release:minor
```

### Major Release (Breaking changes)

```bash
pnpm release:major
```

### Pre-release (RC/Beta)

```bash
pnpm release:prerelease
# Creates versions like 0.4.1-rc.0, 0.4.1-rc.1, etc.
```

## What Happens During Release

1. **Tests run** (`preversion` hook)
   - All tests must pass before version bump

2. **Version synced** (`version` hook)
   - `package.json` version is bumped by npm
   - `scripts/sync-version.js` updates:
     - `src/auth.js` (@version JSDoc)
     - `dist/auth.js` (@version JSDoc)
     - `plugin/plugin.json`
     - `plugin/CLAUDE.md`
     - `CLAUDE.md`
     - `docs/api-reference.md`
   - Changes are staged for commit

3. **Git operations** (`postversion` hook)
   - Commits version bump
   - Creates git tag (e.g., `v0.5.0`)
   - Pushes commit and tag to GitHub

4. **CI/CD Pipeline** (GitHub Actions)
   - Runs tests on tag push
   - Publishes to npm with provenance
   - Creates GitHub Release with changelog

## Manual Release (if automation fails)

```bash
# 1. Bump version in package.json manually
# 2. Run sync script
node scripts/sync-version.js

# 3. Commit
git add -A
git commit -m "v0.5.0"

# 4. Tag
git tag -a v0.5.0 -m "v0.5.0 - Description"

# 5. Push
git push origin main --tags

# 6. Publish manually (if workflow fails)
npm publish --access public
```

## Changelog

Before releasing, update `CHANGELOG.md` with:

```markdown
## [0.5.0] - YYYY-MM-DD

### Added
- New feature X

### Changed
- Improved Y

### Fixed
- Bug in Z

### Security
- Fixed vulnerability in W
```

## Version History

All versions are kept on npm and can be installed by version:

```bash
# Latest
pnpm add l42-cognito-passkey

# Specific version
pnpm add l42-cognito-passkey@0.4.0

# Check available versions
npm view l42-cognito-passkey versions
```

## Troubleshooting

### Version mismatch errors

Run the version consistency tests:
```bash
pnpm test -- plugin/templates/version-consistency.test.js
```

### NPM publish fails

1. Check `NPM_TOKEN` secret is set in GitHub
2. Verify you have publish rights to the package
3. Check npm registry status: https://status.npmjs.org/

### GitHub Release missing changelog

The workflow extracts changelog from `CHANGELOG.md`. Ensure the version header matches:
```markdown
## [0.5.0] - 2024-01-15
```
or
```markdown
## 0.5.0
```
