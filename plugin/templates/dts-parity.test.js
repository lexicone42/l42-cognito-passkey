/**
 * L42 Cognito Passkey - auth.d.ts ↔ auth.js parity
 *
 * Design review #29: the TypeScript declarations drifted out of sync with the
 * runtime exports and nothing caught it. This test fails if any named export of
 * src/auth.js lacks a declaration in src/auth.d.ts, so the two can't diverge.
 *
 * @vitest-environment node
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import * as auth from '../../src/auth.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '../..');
const dts = readFileSync(resolve(ROOT, 'src/auth.d.ts'), 'utf8');

/** True if the .d.ts declares `name` as a top-level export (function/const/class/type/interface). */
function declaresExport(name) {
    const patterns = [
        new RegExp(`export\\s+function\\s+${name}\\b`),
        new RegExp(`export\\s+declare\\s+function\\s+${name}\\b`),
        new RegExp(`export\\s+const\\s+${name}\\b`),
        new RegExp(`export\\s+class\\s+${name}\\b`),
        new RegExp(`export\\s+(?:type|interface)\\s+${name}\\b`)
    ];
    return patterns.some((re) => re.test(dts));
}

describe('auth.d.ts parity', () => {
    it('declares every named runtime export', () => {
        const runtimeNames = Object.keys(auth).filter((k) => k !== 'default');
        const missing = runtimeNames.filter((name) => !declaresExport(name));
        expect(missing, `Missing from src/auth.d.ts: ${missing.join(', ')}`).toEqual([]);
    });

    it('has a VERSION matching package.json', () => {
        const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8'));
        expect(auth.VERSION).toBe(pkg.version);
        expect(dts).toContain(`@version ${pkg.version}`);
    });
});
