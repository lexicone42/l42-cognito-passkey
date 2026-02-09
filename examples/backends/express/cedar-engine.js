/**
 * L42 Cedar Authorization Engine
 *
 * Server-side Cedar policy evaluation for l42-cognito-passkey.
 * Wraps @cedar-policy/cedar-wasm directly — no middleware dependencies.
 *
 * Usage:
 *   import { initCedarEngine, authorize } from './cedar-engine.js';
 *   await initCedarEngine({ schemaPath: './cedar/schema.cedarschema.json', policyDir: './cedar/policies/' });
 *   const result = await authorize({ session: req.session, action: 'read:content' });
 *
 * License: Apache-2.0 (cedar-wasm is also Apache-2.0)
 *
 * Entity Provider Interface (post-1.0 extensibility):
 *   The authorize() function accepts an optional entityProvider parameter.
 *   Default: builds entities from the current request (JWT claims + request body).
 *   Future: implement EntityProvider to load entities from DynamoDB, Redis, etc.
 *
 *   interface EntityProvider {
 *       getEntities(claims: object, resource: object, context: object): Promise<EntityJson[]>
 *   }
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

let cedar;

// ── Configuration ─────────────────────────────────────────────────────────

const POLICY_SET_ID = 'l42-policies';
const SCHEMA_NAME = 'l42-schema';

/**
 * Default Cognito group → Cedar UserGroup entity ID mapping.
 * Mirrors COGNITO_GROUPS aliases from rbac-roles.js.
 * Override via initCedarEngine({ resolveGroup }).
 */
const DEFAULT_GROUP_MAP = {
    admin: 'admin', admins: 'admin', administrators: 'admin',
    readonly: 'readonly', 'read-only': 'readonly', viewer: 'readonly', viewers: 'readonly',
    user: 'users', users: 'users', member: 'users', members: 'users',
    editor: 'editors', editors: 'editors',
    reviewer: 'reviewers', reviewers: 'reviewers',
    publisher: 'publishers', publishers: 'publishers',
    moderator: 'moderators', moderators: 'moderators', mod: 'moderators', mods: 'moderators',
    developer: 'developers', developers: 'developers', dev: 'developers', devs: 'developers'
};

let _resolveGroup = (group) => DEFAULT_GROUP_MAP[group.toLowerCase()] || group;
let _initialized = false;
let _schema = null;
let _policyText = null;

// ── Initialization ────────────────────────────────────────────────────────

/**
 * Initialize the Cedar engine. Call once at server startup.
 *
 * Loads and pre-parses the schema and policies for fast per-request evaluation.
 * Validates policies against the schema — throws on any errors.
 *
 * @param {Object} options
 * @param {string} [options.schemaPath] - Path to Cedar JSON schema file
 * @param {string} [options.policyDir] - Directory containing .cedar policy files
 * @param {Object} [options.schema] - Inline Cedar JSON schema (alternative to schemaPath)
 * @param {string} [options.policies] - Inline Cedar policy text (alternative to policyDir)
 * @param {Function} [options.resolveGroup] - Custom Cognito group → Cedar group resolver
 * @throws {Error} If schema or policies are invalid
 */
export async function initCedarEngine(options = {}) {
    if (!cedar) {
        cedar = await import('@cedar-policy/cedar-wasm/nodejs');
    }

    // Load schema
    if (options.schema) {
        _schema = typeof options.schema === 'string' ? JSON.parse(options.schema) : options.schema;
    } else if (options.schemaPath) {
        _schema = JSON.parse(readFileSync(options.schemaPath, 'utf8'));
    } else {
        throw new Error('initCedarEngine requires schema or schemaPath');
    }

    // Pre-parse schema
    const schemaResult = cedar.preparseSchema(SCHEMA_NAME, _schema);
    if (schemaResult.type === 'failure') {
        const msgs = schemaResult.errors.map(e => e.message).join('\n');
        throw new Error(`Cedar schema invalid:\n${msgs}`);
    }

    // Load policies
    if (options.policies) {
        _policyText = options.policies;
    } else if (options.policyDir) {
        const files = readdirSync(options.policyDir).filter(f => f.endsWith('.cedar')).sort();
        if (files.length === 0) {
            throw new Error(`No .cedar files found in ${options.policyDir}`);
        }
        _policyText = files.map(f => readFileSync(join(options.policyDir, f), 'utf8')).join('\n\n');
    } else {
        throw new Error('initCedarEngine requires policies or policyDir');
    }

    // Pre-parse policies
    const policyResult = cedar.preparsePolicySet(POLICY_SET_ID, { staticPolicies: _policyText });
    if (policyResult.type === 'failure') {
        const msgs = policyResult.errors.map(e => e.message).join('\n');
        throw new Error(`Cedar policies invalid:\n${msgs}`);
    }

    // Validate policies against schema
    const validation = cedar.validate({
        schema: _schema,
        policies: { staticPolicies: _policyText }
    });
    if (validation.type === 'failure') {
        const msgs = validation.errors.map(e => e.message).join('\n');
        throw new Error(`Cedar validation failed:\n${msgs}`);
    }
    if (validation.validationErrors?.length > 0) {
        const msgs = validation.validationErrors.map(e => `${e.policyId}: ${e.error.message}`).join('\n');
        throw new Error(`Cedar policy errors:\n${msgs}`);
    }

    if (options.resolveGroup) {
        _resolveGroup = options.resolveGroup;
    }

    _initialized = true;
}

// ── Entity Building ───────────────────────────────────────────────────────

/**
 * Build Cedar entities from JWT claims and a resource descriptor.
 *
 * This is the default "request-scoped" entity provider — it builds entities
 * from data available in the current request (JWT + request body).
 *
 * For a persistent entity store, implement the EntityProvider interface:
 *   { getEntities(claims, resource, context) => Promise<EntityJson[]> }
 *
 * @param {Object} claims - Decoded JWT claims (sub, email, cognito:groups)
 * @param {Object} [resource] - Resource descriptor { id?, type?, owner? }
 * @returns {Array} Cedar EntityJson array
 */
export function buildEntities(claims, resource = {}) {
    const groups = claims['cognito:groups'] || [];
    const canonicalGroups = [...new Set(groups.map(_resolveGroup))];
    const entities = [];

    // Principal (User) entity
    entities.push({
        uid: { type: 'App::User', id: claims.sub },
        attrs: { email: claims.email || '', sub: claims.sub },
        parents: canonicalGroups.map(g => ({ type: 'App::UserGroup', id: g }))
    });

    // UserGroup entities — Cedar requires these to exist in the entity store
    for (const group of canonicalGroups) {
        entities.push({
            uid: { type: 'App::UserGroup', id: group },
            attrs: {},
            parents: []
        });
    }

    // Resource entity
    const resourceId = resource.id || '_application';
    const resourceAttrs = { resourceType: resource.type || 'application' };
    if (resource.owner) {
        resourceAttrs.owner = { __entity: { type: 'App::User', id: resource.owner } };
    }
    entities.push({
        uid: { type: 'App::Resource', id: resourceId },
        attrs: resourceAttrs,
        parents: []
    });

    return entities;
}

// ── Authorization ─────────────────────────────────────────────────────────

/**
 * Evaluate a Cedar authorization request.
 *
 * @param {Object} params
 * @param {Object} params.session - Express session (must have session.tokens.id_token)
 * @param {string} params.action - Action string (e.g., 'admin:delete-user')
 * @param {Object} [params.resource] - Resource { id?, type?, owner? }
 * @param {Object} [params.context] - Additional Cedar context attributes
 * @param {Object} [params.entityProvider] - Custom entity provider (post-1.0 extensibility)
 * @returns {Promise<{ authorized: boolean, reason: string, diagnostics: Object }>}
 */
export async function authorize({ session, action, resource = {}, context = {}, entityProvider = null }) {
    if (!_initialized) {
        throw new Error('Cedar engine not initialized. Call initCedarEngine() first.');
    }

    const claims = decodeJwtPayload(session.tokens.id_token);

    // Build entities — use custom provider or default request-scoped builder
    const entities = entityProvider
        ? await entityProvider.getEntities(claims, resource, context)
        : buildEntities(claims, resource);

    const resourceId = resource.id || '_application';

    const result = cedar.statefulIsAuthorized({
        principal: { type: 'App::User', id: claims.sub },
        action: { type: 'App::Action', id: action },
        resource: { type: 'App::Resource', id: resourceId },
        context,
        preparsedPolicySetId: POLICY_SET_ID,
        preparsedSchemaName: SCHEMA_NAME,
        validateRequest: true,
        entities
    });

    if (result.type === 'failure') {
        return {
            authorized: false,
            reason: `Evaluation error: ${result.errors.map(e => e.message).join(', ')}`,
            diagnostics: { errors: result.errors, warnings: result.warnings }
        };
    }

    const { decision, diagnostics } = result.response;
    return {
        authorized: decision === 'allow',
        reason: decision === 'allow'
            ? diagnostics.reason.join(', ') || 'allowed'
            : 'No matching permit policy',
        diagnostics: {
            ...diagnostics,
            warnings: result.warnings
        }
    };
}

// ── Utilities ─────────────────────────────────────────────────────────────

/**
 * Re-validate policies against schema. Useful after hot-reloading.
 * @returns {{ valid: boolean, errors?: string[] }}
 */
export function validatePolicies() {
    if (!_schema || !_policyText) {
        return { valid: false, errors: ['Engine not initialized'] };
    }
    const result = cedar.validate({
        schema: _schema,
        policies: { staticPolicies: _policyText }
    });
    if (result.type === 'failure') {
        return { valid: false, errors: result.errors.map(e => e.message) };
    }
    if (result.validationErrors?.length > 0) {
        return { valid: false, errors: result.validationErrors.map(e => e.error.message) };
    }
    return { valid: true };
}

/** @returns {boolean} Whether the engine is initialized */
export function isInitialized() {
    return _initialized;
}

/** @returns {Object|null} The loaded schema (for debugging/testing) */
export function getSchema() {
    return _schema;
}

/** @returns {string|null} The loaded policy text (for debugging/testing) */
export function getPolicies() {
    return _policyText;
}

/** @returns {Function} The current group resolver */
export function getResolveGroup() {
    return _resolveGroup;
}

/**
 * Reset engine state. Intended for testing only.
 */
export function _resetForTesting() {
    _initialized = false;
    _schema = null;
    _policyText = null;
    _resolveGroup = (group) => DEFAULT_GROUP_MAP[group.toLowerCase()] || group;
}

function decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString());
}
