#!/usr/bin/env node

/**
 * Syncs test counts from vitest JSON output into documentation files.
 * Run ad-hoc after adding/removing tests, or automatically during `npm version`.
 *
 * Updates:
 * - CLAUDE.md — total count
 * - plugin/CLAUDE.md — total + per-file counts
 * - docs/architecture.md — total + per-file counts + file count
 * - docs/release.md — total count
 *
 * Note: execSync is used with static commands only (no user input).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. Run vitest and collect per-file counts
// ---------------------------------------------------------------------------

console.log('Running tests to collect counts...\n');

let testResults;
try {
  const output = execFileSync('npx', ['vitest', 'run', 'plugin/templates/', '--reporter=json'], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe']
  });
  testResults = JSON.parse(output);
} catch (err) {
  // vitest writes JSON to stdout even on failure; try parsing stdout
  if (err.stdout) {
    try { testResults = JSON.parse(err.stdout); } catch { /* fall through */ }
  }
  if (!testResults) {
    console.error('Failed to run vitest:', err.message);
    process.exit(1);
  }
}

const totalTests = testResults.numTotalTests;
const fileCount = testResults.testResults.length;

// Map: basename → count  (e.g. "token-storage.test.js" → 15)
const perFile = {};
for (const suite of testResults.testResults) {
  const name = path.basename(suite.name);
  perFile[name] = suite.assertionResults.length;
}

console.log(`Total: ${totalTests} tests across ${fileCount} files\n`);
for (const [name, count] of Object.entries(perFile).sort()) {
  console.log(`  ${name}: ${count}`);
}
console.log('');

// ---------------------------------------------------------------------------
// 2. Helper: regex-replace in a file, report changes
// ---------------------------------------------------------------------------

let filesUpdated = 0;

function updateFile(relPath, replacements) {
  const filePath = path.join(ROOT, relPath);
  if (!fs.existsSync(filePath)) {
    console.log(`  Skipping ${relPath} (not found)`);
    return;
  }

  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;

  for (const { regex, replacement } of replacements) {
    const newContent = content.replace(regex, replacement);
    if (newContent !== content) {
      content = newContent;
      modified = true;
    }
  }

  if (modified) {
    fs.writeFileSync(filePath, content);
    console.log(`  Updated ${relPath}`);
    filesUpdated++;
  } else {
    console.log(`  No changes needed in ${relPath}`);
  }
}

// ---------------------------------------------------------------------------
// 3. Build per-file regex replacements for architecture.md table rows
//    Pattern: | `filename` | NNN | description |
// ---------------------------------------------------------------------------

function archTableReplacements() {
  const replacements = [];
  for (const [name, count] of Object.entries(perFile)) {
    // Escape dots in filename for regex
    const escaped = name.replace(/\./g, '\\.');
    replacements.push({
      regex: new RegExp(`(\\| \`${escaped}\`\\s*\\|\\s*)\\d+(\\s*\\|)`, 'g'),
      replacement: `$1${count}$2`
    });
  }
  return replacements;
}

// ---------------------------------------------------------------------------
// 4. Build per-file regex replacements for plugin/CLAUDE.md listing
//    Pattern: (NNN description text)
//    We match the filename on the same line, then the (NNN ...)
// ---------------------------------------------------------------------------

function pluginListingReplacements() {
  const replacements = [];
  for (const [name, count] of Object.entries(perFile)) {
    const escaped = name.replace(/\./g, '\\.');
    // Match: filename followed by (NNN words) on the same line
    replacements.push({
      regex: new RegExp(`(${escaped}[^\n]*\\()\\d+(\\s[^)]+\\))`, 'g'),
      replacement: `$1${count}$2`
    });
  }
  return replacements;
}

// ---------------------------------------------------------------------------
// 5. Apply updates to each file
// ---------------------------------------------------------------------------

// CLAUDE.md — total only: **Tests**: ~NNN (...)
updateFile('CLAUDE.md', [
  {
    regex: /(\*\*Tests\*\*:\s*~?)\d+/,
    replacement: `$1${totalTests}`
  }
]);

// plugin/CLAUDE.md — total + per-file
updateFile('plugin/CLAUDE.md', [
  // **Tests**: NNN passing
  {
    regex: /(\*\*Tests\*\*:\s*)\d+(\s*passing)/,
    replacement: `$1${totalTests}$2`
  },
  // **Total: NNN tests**
  {
    regex: /(\*\*Total:\s*)\d+(\s*tests\*\*)/,
    replacement: `$1${totalTests}$2`
  },
  // Per-file counts in the listing
  ...pluginListingReplacements()
]);

// docs/architecture.md — total (3 locations) + per-file table + file count
updateFile('docs/architecture.md', [
  // Header: **Tests**: NNN
  {
    regex: /(\*\*Tests\*\*:\s*)\d+/,
    replacement: `$1${totalTests}`
  },
  // "NN test files (NNN tests)"
  {
    regex: /\d+(\s*test files\s*\()\d+(\s*tests\))/,
    replacement: `${fileCount}$1${totalTests}$2`
  },
  // "NNN tests across NN files"
  {
    regex: /\d+(\s*tests across\s*)\d+(\s*files)/,
    replacement: `${totalTests}$1${fileCount}$2`
  },
  // Per-file counts in the table
  ...archTableReplacements()
]);

// docs/release.md — "NNN vitest" in current version line
updateFile('docs/release.md', [
  {
    regex: /(\*\*[\d.]+\*\*\s*—\s*)\d+(\s*vitest)/,
    replacement: `$1${totalTests}$2`
  }
]);

console.log(`\nTest count sync complete: ${filesUpdated} file(s) updated (${totalTests} total tests)`);
