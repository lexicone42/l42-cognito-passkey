#!/usr/bin/env node

/**
 * Checks that dist/auth.js is in sync with src/auth.js.
 *
 * The dist file should be an exact copy of src (no build step).
 * This prevents shipping outdated dist files like happened in v0.5.3.
 *
 * Usage:
 *   node scripts/check-dist-sync.js        # Check only
 *   node scripts/check-dist-sync.js --fix  # Auto-fix by copying src to dist
 *
 * Exit codes:
 *   0 - Files are in sync
 *   1 - Files are out of sync (use --fix to resolve)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const SRC_FILE = path.join(ROOT, 'src/auth.js');
const DIST_FILE = path.join(ROOT, 'dist/auth.js');

const shouldFix = process.argv.includes('--fix');

// Read both files
const srcContent = fs.readFileSync(SRC_FILE, 'utf8');
const distContent = fs.existsSync(DIST_FILE) ? fs.readFileSync(DIST_FILE, 'utf8') : null;

if (srcContent === distContent) {
  console.log('✓ dist/auth.js is in sync with src/auth.js');
  process.exit(0);
}

// Files are out of sync
if (shouldFix) {
  fs.writeFileSync(DIST_FILE, srcContent);
  console.log('✓ Fixed: copied src/auth.js to dist/auth.js');
  process.exit(0);
}

// Report the difference
console.error('✗ dist/auth.js is OUT OF SYNC with src/auth.js');
console.error('');

if (!distContent) {
  console.error('  dist/auth.js does not exist');
} else {
  // Show a brief diff summary
  const srcLines = srcContent.split('\n').length;
  const distLines = distContent.split('\n').length;
  console.error(`  src/auth.js:  ${srcLines} lines`);
  console.error(`  dist/auth.js: ${distLines} lines`);

  // Find first differing line
  const srcArr = srcContent.split('\n');
  const distArr = distContent.split('\n');
  for (let i = 0; i < Math.max(srcArr.length, distArr.length); i++) {
    if (srcArr[i] !== distArr[i]) {
      console.error(`  First difference at line ${i + 1}`);
      break;
    }
  }
}

console.error('');
console.error('To fix, run one of:');
console.error('  node scripts/check-dist-sync.js --fix');
console.error('  cp src/auth.js dist/auth.js');
console.error('');

process.exit(1);
