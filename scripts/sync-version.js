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
 * - docs/architecture.md (version references)
 * - README.md (version badge)
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
    file: 'rust/Cargo.toml',
    optional: true,
    patterns: [
      // The [package] version line — keep the Rust backend aligned with the
      // product so OCSF events (env!("CARGO_PKG_VERSION")) report the real version.
      { regex: /^version = "[\d.]+(-[\w.]+)?"/m, replacement: `version = "${newVersion}"`, required: true }
    ]
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
      // Primary version refs (required: must always match, or the doc drifted):
      // "L42 Cognito Passkey (X.Y.Z)." header and "Library version string (`'X.Y.Z'`)".
      { regex: /L42 Cognito Passkey \([\d.]+(-[\w.]+)?\)/g, replacement: `L42 Cognito Passkey (${newVersion})`, required: true },
      { regex: /Library version string \(`'[\d.]+(-[\w.]+)?'`\)/g, replacement: `Library version string (\`'${newVersion}'\`)`, required: true },
      // Speculative (best-effort) refs:
      { regex: /Current version:\s*[\d.]+(-[\w.]+)?/gi, replacement: `Current version: ${newVersion}` },
      { regex: /l42-cognito-passkey@[\d.]+(-[\w.]+)?/g, replacement: `l42-cognito-passkey@${newVersion}` },
      { regex: /console\.log\(VERSION\);\s*\/\/\s*"[\d.]+(-[\w.]+)?"/g, replacement: `console.log(VERSION); // "${newVersion}"` }
    ]
  },
  {
    file: 'docs/architecture.md',
    optional: true,
    patterns: [
      // Match "**Version**: X.Y.Z" in the header line (speculative — not all docs have it)
      { regex: /\*\*Version\*\*:\s*[\d.]+(-[\w.]+)?/g, replacement: `**Version**: ${newVersion}` }
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
let staleFailures = 0;

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
      const stalePatterns = [];

      for (const pattern of update.patterns) {
        const matched = content.match(pattern.regex);
        const newContent = content.replace(pattern.regex, pattern.replacement);
        if (newContent !== content) {
          content = newContent;
          modified = true;
        } else if (pattern.required && !matched && !content.includes(pattern.replacement)) {
          // A REQUIRED pattern matched nothing AND its target value isn't present:
          // the doc wording drifted out from under this pattern. Fail loudly
          // instead of silently leaving a stale version (this is exactly how
          // docs/api-reference.md froze at an old version). Speculative patterns
          // (no `required` flag) legitimately match nothing and are ignored.
          stalePatterns.push(pattern.regex.toString());
        }
      }

      if (stalePatterns.length > 0) {
        console.error(
          `  ✗ ${update.file}: ${stalePatterns.length} pattern(s) matched nothing and ` +
          `the target value is absent — the doc wording likely drifted:\n` +
          stalePatterns.map((p) => `      ${p}`).join('\n')
        );
        staleFailures += stalePatterns.length;
      }

      if (modified) {
        fs.writeFileSync(filePath, content);
        console.log(`  Updated ${update.file}`);
        filesUpdated++;
      } else if (stalePatterns.length === 0) {
        console.log(`  Already current: ${update.file}`);
      }
    }
  } catch (err) {
    console.error(`  ERROR updating ${update.file}: ${err.message}`);
    process.exit(1);
  }
}

console.log(`\nVersion sync complete: ${filesUpdated} file(s) updated to v${newVersion}`);

if (staleFailures > 0) {
  console.error(
    `\n✗ ${staleFailures} version pattern(s) matched nothing — a doc's wording ` +
    `drifted from its sync pattern. Fix the pattern in scripts/sync-version.js ` +
    `or the doc, so versions can't silently go stale.`
  );
  process.exit(1);
}

// Reminder for manual updates
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  REMEMBER: Update these files manually if there are breaking     ║
║  changes or upgrade notes for this version:                      ║
║                                                                  ║
║  1. CHANGELOG.md      - Add version entry with changes           ║
║  2. CLAUDE.md         - Add to "Upgrade Notes" section           ║
╚══════════════════════════════════════════════════════════════════╝
`);
