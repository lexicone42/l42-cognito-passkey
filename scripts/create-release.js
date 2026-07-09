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

const PLACEHOLDER = '_Release notes pending._';
const notes = extractChangelog(version);

// Never publish the placeholder. If the changelog wasn't filled in, refuse to
// create/update the release with garbage — the maintainer fills CHANGELOG.md and
// re-runs `node scripts/create-release.js`. (Historically the placeholder was
// published verbatim and the fill-in commit never reached the release.)
if (notes.includes(PLACEHOLDER) || notes === `Release ${tag}`) {
  console.error(`⚠ CHANGELOG.md has no real notes for ${version} (found placeholder).`);
  console.error('  Fill in the changelog entry, then run:');
  console.error(`  node scripts/create-release.js`);
  process.exit(0); // Don't fail the release process; just don't publish garbage.
}

// If the release already exists, UPDATE its notes (so a later "fill in changelog"
// commit propagates to the published release instead of being stranded).
let exists = false;
try {
  execFileSync('gh', ['release', 'view', tag], { stdio: 'ignore' });
  exists = true;
} catch {
  // Release doesn't exist yet.
}

try {
  if (exists) {
    console.log(`Updating existing GitHub release ${tag} with current notes...`);
    execFileSync('gh', ['release', 'edit', tag, '--notes', notes], {
      encoding: 'utf8',
      cwd: ROOT,
    });
    console.log(`✓ GitHub release ${tag} notes updated`);
  } else {
    console.log(`Creating GitHub release ${tag}...`);
    const result = execFileSync(
      'gh',
      ['release', 'create', tag, '--title', tag, '--notes', notes],
      { encoding: 'utf8', cwd: ROOT }
    );
    console.log(`✓ GitHub release created: ${result.trim()}`);
  }
} catch (err) {
  console.error(`⚠ Failed to create/update GitHub release: ${err.message}`);
  console.log(`  Manual: gh release create ${tag} --title "${tag}" --notes-file CHANGELOG.md`);
  process.exit(0);
}
