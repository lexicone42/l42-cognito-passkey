#!/usr/bin/env node

/**
 * Syncs the version from package.json to all other files that contain version references.
 * This script is run automatically during `npm version` via the "version" script hook.
 *
 * Files updated:
 * - src/auth.js (@version JSDoc tag)
 * - dist/auth.js (@version JSDoc tag)
 * - plugin/plugin.json (version field)
 * - plugin/CLAUDE.md (version references)
 * - CLAUDE.md (version references)
 * - docs/api-reference.md (version references)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

// Read the new version from package.json
const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const newVersion = packageJson.version;

console.log(`Syncing version to ${newVersion}...`);

// Files and their update patterns
const updates = [
  {
    file: 'src/auth.js',
    patterns: [
      { regex: /@version\s+[\d.]+(-[\w.]+)?/g, replacement: `@version ${newVersion}` },
      { regex: /export const VERSION = ['"][\d.]+(-[\w.]+)?['"]/g, replacement: `export const VERSION = '${newVersion}'` }
    ]
  },
  {
    file: 'dist/auth.js',
    optional: true,
    patterns: [
      { regex: /@version\s+[\d.]+(-[\w.]+)?/g, replacement: `@version ${newVersion}` },
      { regex: /export const VERSION = ['"][\d.]+(-[\w.]+)?['"]/g, replacement: `export const VERSION = '${newVersion}'` }
    ]
  },
  {
    file: 'plugin/plugin.json',
    json: true,
    transform: (obj) => {
      obj.version = newVersion;
      return obj;
    }
  },
  {
    file: 'plugin/CLAUDE.md',
    optional: true,
    patterns: [
      // Match "**Current Version**: X.Y.Z" or "**Version**: X.Y.Z" (markdown bold)
      { regex: /\*\*(?:Current )?Version\*\*:\s*[\d.]+(-[\w.]+)?/gi, replacement: `**Current Version**: ${newVersion}` },
      { regex: /l42-cognito-passkey@[\d.]+(-[\w.]+)?/g, replacement: `l42-cognito-passkey@${newVersion}` },
      // Match VERSION example: // "0.5.0"
      { regex: /\/\/\s*"[\d.]+(-[\w.]+)?"/g, replacement: `// "${newVersion}"` }
    ]
  },
  {
    file: 'CLAUDE.md',
    optional: true,
    patterns: [
      // Match "**Current Version**: X.Y.Z" or "**Version**: X.Y.Z" (markdown bold)
      { regex: /\*\*(?:Current )?Version\*\*:\s*[\d.]+(-[\w.]+)?/gi, replacement: `**Current Version**: ${newVersion}` },
      { regex: /l42-cognito-passkey@[\d.]+(-[\w.]+)?/g, replacement: `l42-cognito-passkey@${newVersion}` }
    ]
  },
  {
    file: 'docs/api-reference.md',
    optional: true,
    patterns: [
      // Only match "Current version: X.Y.Z" or "l42-cognito-passkey@X.Y.Z" patterns
      // NOT arbitrary version numbers like "removed in v3.0"
      { regex: /Current version:\s*[\d.]+(-[\w.]+)?/gi, replacement: `Current version: ${newVersion}` },
      { regex: /l42-cognito-passkey@[\d.]+(-[\w.]+)?/g, replacement: `l42-cognito-passkey@${newVersion}` }
    ]
  },
  {
    file: 'README.md',
    optional: true,
    patterns: [
      // Match VERSION constant examples like: VERSION === '0.4.0' or // "0.4.0"
      { regex: /VERSION\s*===?\s*['"][\d.]+(-[\w.]+)?['"]/g, replacement: `VERSION === '${newVersion}'` },
      { regex: /\/\/\s*"[\d.]+(-[\w.]+)?"/g, replacement: `// "${newVersion}"` },
      // Match static version badge: version-0.5.1-blue
      { regex: /version-[\d.]+(-[\w.]+)?-blue/g, replacement: `version-${newVersion}-blue` }
    ]
  }
];

let filesUpdated = 0;

for (const update of updates) {
  const filePath = path.join(ROOT, update.file);

  if (!fs.existsSync(filePath)) {
    if (update.optional) {
      console.log(`  Skipping ${update.file} (not found)`);
      continue;
    } else {
      console.error(`  ERROR: Required file not found: ${update.file}`);
      process.exit(1);
    }
  }

  try {
    if (update.json) {
      // JSON file - parse, transform, stringify
      const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const updated = update.transform(content);
      fs.writeFileSync(filePath, JSON.stringify(updated, null, 2) + '\n');
      console.log(`  Updated ${update.file}`);
      filesUpdated++;
    } else {
      // Text file - apply regex patterns
      let content = fs.readFileSync(filePath, 'utf8');
      let modified = false;

      for (const pattern of update.patterns) {
        const newContent = content.replace(pattern.regex, pattern.replacement);
        if (newContent !== content) {
          content = newContent;
          modified = true;
        }
      }

      if (modified) {
        fs.writeFileSync(filePath, content);
        console.log(`  Updated ${update.file}`);
        filesUpdated++;
      } else {
        console.log(`  No changes needed in ${update.file}`);
      }
    }
  } catch (err) {
    console.error(`  ERROR updating ${update.file}: ${err.message}`);
    process.exit(1);
  }
}

console.log(`\nVersion sync complete: ${filesUpdated} file(s) updated to v${newVersion}`);

// Reminder for manual updates
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  REMEMBER: Update these files manually if there are breaking     ║
║  changes or upgrade notes for this version:                      ║
║                                                                  ║
║  1. CHANGELOG.md      - Add version entry with changes           ║
║  2. CLAUDE.md         - Add to "Upgrade Notes" section           ║
║  3. docs/upgrade-prompt.md - Update if major breaking changes    ║
╚══════════════════════════════════════════════════════════════════╝
`);
