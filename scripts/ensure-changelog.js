#!/usr/bin/env node

/**
 * Ensures CHANGELOG.md has an entry for the current version.
 * If no entry exists, inserts a placeholder after the header.
 *
 * Called automatically by the `version` npm hook (after sync-version.js
 * updates package.json with the new version number).
 *
 * This prevents the version-consistency test from failing in CI when
 * the release was created without manually writing changelog notes first.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const version = packageJson.version;

const changelogPath = path.join(ROOT, 'CHANGELOG.md');
const changelog = fs.readFileSync(changelogPath, 'utf8');

const versionHeader = `## [${version}]`;

if (changelog.includes(versionHeader)) {
  console.log(`  CHANGELOG.md already has entry for ${version}`);
  process.exit(0);
}

// Insert placeholder after the file header line
const today = new Date().toISOString().slice(0, 10);
const placeholder = `${versionHeader} - ${today}\n\n_Release notes pending._\n`;

const updatedChangelog = changelog.replace(
  /^(# Changelog\n\nAll notable changes.*\n)\n/m,
  `$1\n${placeholder}\n`
);

fs.writeFileSync(changelogPath, updatedChangelog);
console.log(`  Added CHANGELOG.md placeholder for ${version}`);
