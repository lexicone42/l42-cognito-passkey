#!/usr/bin/env node

/**
 * Sets up git hooks for this repository.
 *
 * Run: node scripts/setup-hooks.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const hooks = [
  { src: 'scripts/hooks/pre-commit', dest: '.git/hooks/pre-commit' }
];

console.log('Setting up git hooks...\n');

for (const hook of hooks) {
  const srcPath = path.join(ROOT, hook.src);
  const destPath = path.join(ROOT, hook.dest);

  if (!fs.existsSync(srcPath)) {
    console.error(`  ✗ Source not found: ${hook.src}`);
    continue;
  }

  // Copy the hook
  fs.copyFileSync(srcPath, destPath);

  // Make it executable
  fs.chmodSync(destPath, 0o755);

  console.log(`  ✓ Installed ${hook.dest}`);
}

console.log('\nGit hooks installed successfully!');
