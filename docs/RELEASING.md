# Release Process

This document describes how to release new versions of l42-cognito-passkey.

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backwards compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backwards compatible

## Prerequisites

1. **`gh` CLI**: Installed and authenticated (for GitHub release creation)
2. **Clean working directory**: All changes committed
3. **Tests passing**: `pnpm test` should pass
4. **CHANGELOG updated**: Add entry for the new version before releasing

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

When you run `pnpm release:patch` (or minor/major), npm's version lifecycle runs automatically:

### 1. `preversion` — Tests + dist check + doc validation

```
pnpm test && node scripts/check-dist-sync.js && pnpm validate-docs
```

All 696+ tests must pass. `dist/auth.js` must match `src/auth.js`. Documentation version and test count references must be current.

### 2. `version` — Sync version across all files

```
node scripts/sync-version.js && node scripts/sync-test-counts.js && cp src/auth.js dist/auth.js && cp src/auth.d.ts dist/auth.d.ts && git add -A
```

`sync-version.js` updates version references in:
- `src/auth.js` — `@version` JSDoc + `VERSION` constant
- `dist/auth.js` — same
- `plugin/plugin.json` — `version` field
- `plugin/CLAUDE.md` — version references
- `CLAUDE.md` — version references
- `docs/api-reference.md` — version examples
- `docs/architecture.md` — version header
- `docs/integration-feedback.md` — version example
- `docs/ocsf-logging.md` — version in JSON example
- `docs/claude-workflow.md` — version in templates
- `README.md` — version badge + VERSION examples

`sync-test-counts.js` updates per-file and total test counts in:
- `CLAUDE.md` — total count
- `plugin/CLAUDE.md` — total + per-file counts
- `docs/architecture.md` — total + per-file table + file count
- `docs/RELEASING.md` — total count in preversion description

npm then commits the changes and creates the git tag (e.g., `v0.15.0`).

### 3. `postversion` — Push + create GitHub release

```
git push && git push --tags && node scripts/create-release.js
```

`create-release.js`:
- Extracts release notes from `CHANGELOG.md` for the version
- Creates a GitHub release via `gh release create`
- Skips gracefully if `gh` isn't installed or the release already exists

## Before Releasing

1. **Update CHANGELOG.md** with the new version entry
2. **Run tests**: `pnpm test`
3. **Sync test counts**: `pnpm sync-counts` (auto-updates doc files with current counts)
4. **Run doc validation**: `pnpm validate-docs`
5. **Ensure dist is in sync**: `pnpm check-dist`

## Manual Release (if automation fails)

```bash
# 1. Bump version in package.json manually
# 2. Run sync script
node scripts/sync-version.js

# 3. Copy dist
cp src/auth.js dist/auth.js && cp src/auth.d.ts dist/auth.d.ts

# 4. Commit
git add -A
git commit -m "v0.15.0"

# 5. Tag
git tag -a v0.15.0 -m "v0.15.0"

# 6. Push
git push origin main --tags

# 7. Create GitHub release
node scripts/create-release.js
# or manually:
gh release create v0.15.0 --title "v0.15.0" --notes "Release notes here"
```

## Changelog Format

Use [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [0.15.0] - YYYY-MM-DD

### Added
- New feature X

### Changed
- Improved Y

### Fixed
- Bug in Z

### Deprecated
- Old API W (removed in v1.0)

### Security
- Fixed vulnerability in V
```

## Troubleshooting

### Version mismatch errors

Run the version consistency tests:
```bash
pnpm test -- plugin/templates/version-consistency.test.js
```

### Files not updated by sync-version.js

Check `scripts/sync-version.js` — each file has specific regex patterns for version matching. If you add a new file with version references, add it to the `updates` array in that script.

### GitHub Release not created

If `gh` CLI isn't authenticated or available:
```bash
# Authenticate
gh auth login

# Create release manually
node scripts/create-release.js
```

### validate-docs fails

```bash
pnpm validate-docs
```

This checks version references, test counts, and file references across CLAUDE.md, plugin/CLAUDE.md, and docs/architecture.md.
