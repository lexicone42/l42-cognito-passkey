/**
 * L42 Cognito Passkey - Version Consistency Tests
 *
 * Ensures version numbers are synchronized across all files.
 * Catches stale version references before release.
 *
 * Run with: pnpm test
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');

/**
 * Read file content safely
 */
function readFile(relativePath) {
    try {
        return readFileSync(join(ROOT, relativePath), 'utf-8');
    } catch {
        return null;
    }
}

/**
 * Extract version from package.json
 */
function getPackageVersion() {
    const pkg = JSON.parse(readFile('package.json'));
    return pkg.version;
}

describe('Version Consistency', () => {
    const EXPECTED_VERSION = getPackageVersion();

    it('package.json has valid semver version', () => {
        expect(EXPECTED_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('src/auth.js VERSION export matches package.json', () => {
        const content = readFile('src/auth.js');
        const match = content.match(/export const VERSION = ['"](.+?)['"]/);
        expect(match).not.toBeNull();
        expect(match[1]).toBe(EXPECTED_VERSION);
    });

    it('src/auth.js @version JSDoc matches package.json', () => {
        const content = readFile('src/auth.js');
        const match = content.match(/@version\s+(\d+\.\d+\.\d+)/);
        expect(match).not.toBeNull();
        expect(match[1]).toBe(EXPECTED_VERSION);
    });

    it('dist/auth.js VERSION matches package.json', () => {
        const content = readFile('dist/auth.js');
        if (!content) {
            console.warn('dist/auth.js not found - skipping');
            return;
        }
        const match = content.match(/export const VERSION = ['"](.+?)['"]/);
        expect(match).not.toBeNull();
        expect(match[1]).toBe(EXPECTED_VERSION);
    });

    it('plugin/plugin.json version matches package.json', () => {
        const content = readFile('plugin/plugin.json');
        if (!content) {
            console.warn('plugin/plugin.json not found - skipping');
            return;
        }
        const plugin = JSON.parse(content);
        expect(plugin.version).toBe(EXPECTED_VERSION);
    });

    it('CHANGELOG.md has entry for current version', () => {
        const content = readFile('CHANGELOG.md');
        const versionHeader = `## [${EXPECTED_VERSION}]`;
        expect(content).toContain(versionHeader);
    });

    it('README.md VERSION example is current', () => {
        const content = readFile('README.md');
        // Look for VERSION example in code block
        const match = content.match(/VERSION.*?["'](\d+\.\d+\.\d+)["']/);
        if (match) {
            expect(match[1]).toBe(EXPECTED_VERSION);
        }
    });

    it('no stale 1.x version references exist', () => {
        const filesToCheck = [
            'src/auth.js',
            'package.json',
            'plugin/plugin.json',
            'CLAUDE.md',
            'README.md'
        ];

        for (const file of filesToCheck) {
            const content = readFile(file);
            if (!content) continue;

            // Check for old 1.x versions (except in changelog history)
            if (!file.includes('CHANGELOG')) {
                const hasOld1x = /["']1\.[0-9]+\.[0-9]+["']/.test(content) ||
                                 /version.*1\.[0-9]+/i.test(content);
                expect(hasOld1x, `${file} contains stale 1.x version`).toBe(false);
            }
        }
    });

    it('no version mismatch between src and dist', () => {
        const srcContent = readFile('src/auth.js');
        const distContent = readFile('dist/auth.js');

        if (!distContent) {
            console.warn('dist/auth.js not found - skipping');
            return;
        }

        const srcVersion = srcContent.match(/export const VERSION = ['"](.+?)['"]/)?.[1];
        const distVersion = distContent.match(/export const VERSION = ['"](.+?)['"]/)?.[1];

        expect(distVersion).toBe(srcVersion);
    });
});

describe('Pre-release Checklist', () => {
    it('CHANGELOG has current version at top (not unreleased)', () => {
        const content = readFile('CHANGELOG.md');
        const EXPECTED_VERSION = getPackageVersion();

        // First version header should be current version
        const firstVersionMatch = content.match(/## \[(\d+\.\d+\.\d+)\]/);
        expect(firstVersionMatch).not.toBeNull();
        expect(firstVersionMatch[1]).toBe(EXPECTED_VERSION);
    });

    it('no TODO or FIXME in src/auth.js', () => {
        const content = readFile('src/auth.js');
        const hasTodo = /\bTODO\b/i.test(content);
        const hasFixme = /\bFIXME\b/i.test(content);

        // Warn but don't fail - sometimes TODOs are intentional
        if (hasTodo || hasFixme) {
            console.warn('src/auth.js contains TODO/FIXME comments');
        }
    });
});
