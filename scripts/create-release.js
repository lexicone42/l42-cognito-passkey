#!/usr/bin/env node

/**
 * Creates a GitHub release from the current version tag.
 * Extracts release notes from CHANGELOG.md for the current version.
 *
 * Called automatically by the `postversion` npm hook after pushing tags.
 * Requires `gh` CLI to be installed and authenticated.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const version = packageJson.version;
const tag = `v${version}`;

// Extract changelog section for this version
function extractChangelog(version) {
  const changelog = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
  const lines = changelog.split('\n');

  let capturing = false;
  const section = [];

  for (const line of lines) {
    // Match version headers like "## [0.14.0]" or "## 0.14.0"
    if (/^## \[?[\d.]+/.test(line)) {
      if (capturing) {
        // Hit the next version header — stop
        break;
      }
      if (line.includes(version)) {
        capturing = true;
        continue; // Skip the header line itself
      }
    } else if (capturing) {
      section.push(line);
    }
  }

  // Trim leading/trailing blank lines
  const trimmed = section.join('\n').trim();
  return trimmed || `Release ${tag}`;
}

// Check if gh CLI is available
try {
  execFileSync('gh', ['--version'], { stdio: 'ignore' });
} catch {
  console.log(`⚠ gh CLI not found — skipping GitHub release creation for ${tag}`);
  console.log('  Install: https://cli.github.com/');
  console.log(`  Manual: gh release create ${tag} --title "${tag}" --notes "..."`);
  process.exit(0); // Don't fail the release if gh isn't available
}

// Check if release already exists
try {
  execFileSync('gh', ['release', 'view', tag], { stdio: 'ignore' });
  console.log(`✓ GitHub release ${tag} already exists — skipping`);
  process.exit(0);
} catch {
  // Release doesn't exist yet — create it
}

const notes = extractChangelog(version);

console.log(`Creating GitHub release ${tag}...`);

try {
  const result = execFileSync('gh', [
    'release', 'create', tag,
    '--title', tag,
    '--notes', notes
  ], { encoding: 'utf8', cwd: ROOT });

  console.log(`✓ GitHub release created: ${result.trim()}`);
} catch (err) {
  console.error(`⚠ Failed to create GitHub release: ${err.message}`);
  console.log('  You can create it manually:');
  console.log(`  gh release create ${tag} --title "${tag}"`);
  // Don't fail the release process
  process.exit(0);
}
