#!/usr/bin/env node

/**
 * Validates documentation files for consistency.
 * Checks:
 * - Version references match package.json
 * - Test counts are accurate
 * - Referenced files exist
 *
 * Run as part of CI or before release.
 *
 * Note: execSync is used with static commands only (no user input).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

// Read package.json version
const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const expectedVersion = packageJson.version;

let errors = [];
let warnings = [];

console.log(`\nValidating documentation (expected version: ${expectedVersion})...\n`);

// ============================================================================
// 1. Check version references in CLAUDE.md files
// ============================================================================

const claudeFiles = [
  'CLAUDE.md',
  'plugin/CLAUDE.md'
];

for (const file of claudeFiles) {
  const filePath = path.join(ROOT, file);
  if (!fs.existsSync(filePath)) {
    warnings.push(`${file}: File not found`);
    continue;
  }

  const content = fs.readFileSync(filePath, 'utf8');

  // Check "Current Version" or "Version" header
  const versionMatch = content.match(/\*\*(?:Current )?Version\*\*:\s*(\d+\.\d+\.\d+)/i);
  if (versionMatch) {
    if (versionMatch[1] !== expectedVersion) {
      errors.push(`${file}: Version mismatch - found ${versionMatch[1]}, expected ${expectedVersion}`);
    } else {
      console.log(`  ✓ ${file}: Version ${versionMatch[1]}`);
    }
  } else {
    warnings.push(`${file}: No version reference found`);
  }

  // Check VERSION example in code blocks
  const codeVersionMatch = content.match(/VERSION.*?\/\/\s*"(\d+\.\d+\.\d+)"/);
  if (codeVersionMatch && codeVersionMatch[1] !== expectedVersion) {
    errors.push(`${file}: Code example version mismatch - found ${codeVersionMatch[1]}, expected ${expectedVersion}`);
  }
}

// ============================================================================
// 2. Check test counts
// ============================================================================

try {
  // Run vitest to get actual test count (static command, no user input)
  const testOutput = execSync('npx vitest run plugin/templates/ --reporter=json 2>/dev/null', {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe']
  });

  const testResults = JSON.parse(testOutput);
  const actualTestCount = testResults.numTotalTests;

  for (const file of claudeFiles) {
    const filePath = path.join(ROOT, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');

    // Check test count references
    const testCountMatches = content.matchAll(/\*\*(?:Tests|Total)\*\*:\s*(\d+)/gi);
    for (const match of testCountMatches) {
      const docCount = parseInt(match[1], 10);
      if (docCount !== actualTestCount) {
        errors.push(`${file}: Test count mismatch - found ${docCount}, actual ${actualTestCount}`);
      } else {
        console.log(`  ✓ ${file}: Test count ${docCount}`);
      }
    }
  }
} catch (err) {
  warnings.push(`Could not verify test count: ${err.message}`);
}

// ============================================================================
// 3. Check referenced files exist
// ============================================================================

const fileReferences = [
  { doc: 'CLAUDE.md', refs: [
    'src/auth.js',
    'plugin/templates/rbac-roles.js',
    'plugin/templates/static-site-pattern.html',
    'plugin/templates/admin-panel-pattern.html',
    'scripts/sync-version.js',
    'docs/RELEASING.md',
    'docs/integration-feedback.md'
  ]},
  { doc: 'plugin/CLAUDE.md', refs: [
    'src/auth.js',
    'plugin/templates/rbac-roles.js'
  ]}
];

for (const { doc, refs } of fileReferences) {
  for (const ref of refs) {
    const refPath = path.join(ROOT, ref);
    if (!fs.existsSync(refPath)) {
      warnings.push(`${doc}: Referenced file not found: ${ref}`);
    }
  }
}

// ============================================================================
// 4. Check CHANGELOG has entry for current version
// ============================================================================

const changelogPath = path.join(ROOT, 'CHANGELOG.md');
if (fs.existsSync(changelogPath)) {
  const changelog = fs.readFileSync(changelogPath, 'utf8');
  const changelogVersionPattern = `## [${expectedVersion}]`;

  if (changelog.includes(changelogVersionPattern)) {
    console.log(`  ✓ CHANGELOG.md: Entry for v${expectedVersion}`);
  } else {
    errors.push(`CHANGELOG.md: No entry for v${expectedVersion} - add changelog before release`);
  }
}

// ============================================================================
// 5. Check upgrade notes exist for current version
// ============================================================================

const claudeMdPath = path.join(ROOT, 'CLAUDE.md');
if (fs.existsSync(claudeMdPath)) {
  const claudeContent = fs.readFileSync(claudeMdPath, 'utf8');
  const upgradeNotesPattern = new RegExp(`### v${expectedVersion.replace(/\./g, '\\.')}`, 'i');

  if (upgradeNotesPattern.test(claudeContent)) {
    console.log(`  ✓ CLAUDE.md: Upgrade notes for v${expectedVersion}`);
  } else {
    // Check if CHANGELOG has this version with breaking/async/renamed changes
    if (fs.existsSync(changelogPath)) {
      const changelog = fs.readFileSync(changelogPath, 'utf8');
      const hasBreakingChanges = changelog.includes(`## [${expectedVersion}]`) &&
        (changelog.includes('Breaking') || changelog.includes('async') || changelog.includes('renamed'));

      if (hasBreakingChanges) {
        warnings.push(`CLAUDE.md: No upgrade notes for v${expectedVersion} (CHANGELOG suggests breaking changes)`);
      }
    }
  }
}

// ============================================================================
// Report results
// ============================================================================

console.log('');

if (warnings.length > 0) {
  console.log('Warnings:');
  for (const warning of warnings) {
    console.log(`  ⚠ ${warning}`);
  }
  console.log('');
}

if (errors.length > 0) {
  console.log('Errors:');
  for (const error of errors) {
    console.log(`  ✗ ${error}`);
  }
  console.log('');
  console.log(`Documentation validation failed with ${errors.length} error(s).`);
  process.exit(1);
} else {
  console.log(`Documentation validation passed.`);
  process.exit(0);
}
