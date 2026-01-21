/**
 * L42 Cognito RBAC Role Definitions
 *
 * This file defines the standard RBAC roles for l42-cognito-passkey.
 * Roles are implemented as Cognito User Pool Groups.
 *
 * Site Architecture Patterns Supported:
 * 1. Static Site Pattern: site.domain (public) + /auth (protected) + admin push
 * 2. Multi-User WASM Pattern: Players, DM/Moderators, Admin hierarchy
 */

// =============================================================================
// COGNITO GROUP NAME MAPPING
// =============================================================================

/**
 * Canonical Cognito group names with their accepted aliases.
 * Use isInCognitoGroup() for consistent group membership checks.
 *
 * This centralizes group name handling to prevent mismatches between
 * singular/plural forms (e.g., 'admin' vs 'admins').
 */
export const COGNITO_GROUPS = {
    ADMIN: { canonical: 'admin', aliases: ['admin', 'admins', 'administrators'] },
    READONLY: { canonical: 'readonly', aliases: ['readonly', 'read-only', 'viewer', 'viewers'] },
    USER: { canonical: 'users', aliases: ['user', 'users', 'member', 'members'] },
    EDITOR: { canonical: 'editors', aliases: ['editor', 'editors'] },
    REVIEWER: { canonical: 'reviewers', aliases: ['reviewer', 'reviewers'] },
    PUBLISHER: { canonical: 'publishers', aliases: ['publisher', 'publishers'] },
    PLAYER: { canonical: 'players', aliases: ['player', 'players'] },
    DM: { canonical: 'dms', aliases: ['dm', 'dms', 'dungeon-master', 'game-master', 'gm'] },
    MODERATOR: { canonical: 'moderators', aliases: ['moderator', 'moderators', 'mod', 'mods'] },
    DEVELOPER: { canonical: 'developers', aliases: ['developer', 'developers', 'dev', 'devs'] },
    ANALYST: { canonical: 'analysts', aliases: ['analyst', 'analysts'] },
    AUDITOR: { canonical: 'auditors', aliases: ['auditor', 'auditors'] },
    SUPPORT: { canonical: 'support-agents', aliases: ['support', 'support-agent', 'support-agents'] },
    BILLING: { canonical: 'billing-admins', aliases: ['billing', 'billing-admin', 'billing-admins'] }
};

/**
 * Check if user's groups include a specific role (handles aliases).
 *
 * @param {string[]} userGroups - Array of Cognito group names from token
 * @param {string} groupKey - Key from COGNITO_GROUPS (e.g., 'ADMIN', 'EDITOR')
 * @returns {boolean} True if user is in the specified group
 *
 * @example
 * const groups = auth.getUserGroups(); // ['admins', 'developers']
 * isInCognitoGroup(groups, 'ADMIN');   // true (admins is an alias)
 * isInCognitoGroup(groups, 'EDITOR');  // false
 */
export function isInCognitoGroup(userGroups, groupKey) {
    const groupConfig = COGNITO_GROUPS[groupKey];
    if (!groupConfig) {
        console.warn(`Unknown Cognito group key: ${groupKey}`);
        return false;
    }
    const normalizedUserGroups = userGroups.map(g => g.toLowerCase());
    return groupConfig.aliases.some(alias => normalizedUserGroups.includes(alias.toLowerCase()));
}

/**
 * Get the canonical group name for a given key.
 * Use this when creating Cognito groups via CDK/CloudFormation.
 *
 * @param {string} groupKey - Key from COGNITO_GROUPS
 * @returns {string} Canonical group name
 */
export function getCanonicalGroupName(groupKey) {
    return COGNITO_GROUPS[groupKey]?.canonical || groupKey.toLowerCase();
}

/**
 * Check if user has any of the specified roles (handles aliases).
 *
 * @param {string[]} userGroups - Array of Cognito group names from token
 * @param {string[]} groupKeys - Array of keys from COGNITO_GROUPS
 * @returns {boolean} True if user is in any of the specified groups
 */
export function isInAnyCognitoGroup(userGroups, groupKeys) {
    return groupKeys.some(key => isInCognitoGroup(userGroups, key));
}

// =============================================================================
// CORE ROLES (Always Required)
// =============================================================================

export const CORE_ROLES = {
    /**
     * Super Administrator - Full system access
     * Can manage users, roles, and all content
     */
    admin: {
        name: 'admin',
        displayName: 'Administrator',
        description: 'Full system access with user and role management',
        level: 100,
        permissions: ['*'],  // Wildcard - all permissions
        cognitoGroup: 'admin'
    },

    /**
     * Read-Only User - View access to all resources
     * Cannot modify, create, or delete anything
     */
    readonly: {
        name: 'readonly',
        displayName: 'Read Only',
        description: 'View-only access to all resources',
        level: 10,
        permissions: ['read:*'],
        cognitoGroup: 'readonly'
    },

    /**
     * Authenticated User - Basic authenticated access
     * Default role for all logged-in users
     */
    user: {
        name: 'user',
        displayName: 'User',
        description: 'Standard authenticated user',
        level: 20,
        permissions: ['read:own', 'write:own'],
        cognitoGroup: 'users'
    }
};

// =============================================================================
// TOP 20 RBAC ROLES (Common Patterns)
// =============================================================================

export const STANDARD_ROLES = {
    // -------------------------------------------------------------------------
    // Content & CMS Roles (Static Site Pattern)
    // -------------------------------------------------------------------------

    /**
     * Content Editor - Can create and edit content
     * For static site pattern: pushes updates to static site
     */
    editor: {
        name: 'editor',
        displayName: 'Content Editor',
        description: 'Create and edit content, push to static site',
        level: 40,
        permissions: ['read:content', 'write:content', 'publish:content'],
        cognitoGroup: 'editors',
        pattern: 'static-site'
    },

    /**
     * Content Reviewer - Can review and approve content
     */
    reviewer: {
        name: 'reviewer',
        displayName: 'Content Reviewer',
        description: 'Review and approve content before publishing',
        level: 45,
        permissions: ['read:content', 'approve:content', 'reject:content'],
        cognitoGroup: 'reviewers',
        pattern: 'static-site'
    },

    /**
     * Publisher - Can publish approved content to production
     */
    publisher: {
        name: 'publisher',
        displayName: 'Publisher',
        description: 'Publish approved content to static site',
        level: 50,
        permissions: ['read:content', 'publish:content', 'deploy:static'],
        cognitoGroup: 'publishers',
        pattern: 'static-site'
    },

    // -------------------------------------------------------------------------
    // Multi-User WASM Roles (Game/Collaborative Pattern)
    // -------------------------------------------------------------------------

    /**
     * Player - Basic participant in WASM application
     */
    player: {
        name: 'player',
        displayName: 'Player',
        description: 'Participant in multi-user WASM application',
        level: 20,
        permissions: ['read:game', 'write:own-character', 'join:session'],
        cognitoGroup: 'players',
        pattern: 'wasm-multiuser'
    },

    /**
     * Dungeon Master / Game Master - Session controller
     */
    dm: {
        name: 'dm',
        displayName: 'Dungeon Master',
        description: 'Controls game sessions, manages NPCs and world state',
        level: 60,
        permissions: ['read:game', 'write:game', 'manage:session', 'manage:npcs', 'kick:players'],
        cognitoGroup: 'dms',
        pattern: 'wasm-multiuser'
    },

    /**
     * Moderator - Community moderation
     */
    moderator: {
        name: 'moderator',
        displayName: 'Moderator',
        description: 'Community moderation, can mute/kick users',
        level: 55,
        permissions: ['read:users', 'mute:users', 'kick:users', 'manage:chat'],
        cognitoGroup: 'moderators',
        pattern: 'wasm-multiuser'
    },

    // -------------------------------------------------------------------------
    // API & Developer Roles
    // -------------------------------------------------------------------------

    /**
     * API Consumer - Read-only API access
     */
    apiReader: {
        name: 'api_reader',
        displayName: 'API Reader',
        description: 'Read-only API access for integrations',
        level: 15,
        permissions: ['api:read'],
        cognitoGroup: 'api-readers',
        pattern: 'api'
    },

    /**
     * API Writer - Full API access
     */
    apiWriter: {
        name: 'api_writer',
        displayName: 'API Writer',
        description: 'Full API access for integrations',
        level: 35,
        permissions: ['api:read', 'api:write'],
        cognitoGroup: 'api-writers',
        pattern: 'api'
    },

    /**
     * Developer - Access to dev tools and APIs
     */
    developer: {
        name: 'developer',
        displayName: 'Developer',
        description: 'Access to development tools, logs, and APIs',
        level: 70,
        permissions: ['api:*', 'read:logs', 'read:metrics', 'debug:*'],
        cognitoGroup: 'developers',
        pattern: 'api'
    },

    // -------------------------------------------------------------------------
    // Organization & Team Roles
    // -------------------------------------------------------------------------

    /**
     * Team Member - Basic team access
     */
    teamMember: {
        name: 'team_member',
        displayName: 'Team Member',
        description: 'Basic team member with project access',
        level: 25,
        permissions: ['read:team', 'write:team-content'],
        cognitoGroup: 'team-members',
        pattern: 'organization'
    },

    /**
     * Team Lead - Team management
     */
    teamLead: {
        name: 'team_lead',
        displayName: 'Team Lead',
        description: 'Manage team members and team settings',
        level: 55,
        permissions: ['read:team', 'write:team', 'manage:team-members'],
        cognitoGroup: 'team-leads',
        pattern: 'organization'
    },

    /**
     * Organization Admin - Org-level administration
     */
    orgAdmin: {
        name: 'org_admin',
        displayName: 'Organization Admin',
        description: 'Manage organization settings and teams',
        level: 80,
        permissions: ['read:org', 'write:org', 'manage:teams', 'manage:billing'],
        cognitoGroup: 'org-admins',
        pattern: 'organization'
    },

    // -------------------------------------------------------------------------
    // E-commerce & Customer Roles
    // -------------------------------------------------------------------------

    /**
     * Customer - Standard customer account
     */
    customer: {
        name: 'customer',
        displayName: 'Customer',
        description: 'Standard customer with order history access',
        level: 20,
        permissions: ['read:own-orders', 'write:own-profile', 'read:products'],
        cognitoGroup: 'customers',
        pattern: 'ecommerce'
    },

    /**
     * VIP Customer - Premium customer access
     */
    vipCustomer: {
        name: 'vip_customer',
        displayName: 'VIP Customer',
        description: 'Premium customer with early access and discounts',
        level: 25,
        permissions: ['read:own-orders', 'write:own-profile', 'read:products', 'access:vip'],
        cognitoGroup: 'vip-customers',
        pattern: 'ecommerce'
    },

    /**
     * Support Agent - Customer support access
     */
    supportAgent: {
        name: 'support_agent',
        displayName: 'Support Agent',
        description: 'Handle customer support tickets and inquiries',
        level: 40,
        permissions: ['read:tickets', 'write:tickets', 'read:customers', 'read:orders'],
        cognitoGroup: 'support-agents',
        pattern: 'support'
    },

    // -------------------------------------------------------------------------
    // Analytics & Reporting Roles
    // -------------------------------------------------------------------------

    /**
     * Analyst - Read access to analytics and reports
     */
    analyst: {
        name: 'analyst',
        displayName: 'Analyst',
        description: 'Access to analytics dashboards and reports',
        level: 30,
        permissions: ['read:analytics', 'read:reports', 'export:reports'],
        cognitoGroup: 'analysts',
        pattern: 'analytics'
    },

    /**
     * Auditor - Compliance and audit access
     */
    auditor: {
        name: 'auditor',
        displayName: 'Auditor',
        description: 'Audit logs, compliance reports, and security data',
        level: 65,
        permissions: ['read:audit-logs', 'read:compliance', 'read:security', 'export:audit'],
        cognitoGroup: 'auditors',
        pattern: 'compliance'
    },

    // -------------------------------------------------------------------------
    // Service & System Roles
    // -------------------------------------------------------------------------

    /**
     * Service Account - Automated system access
     */
    serviceAccount: {
        name: 'service_account',
        displayName: 'Service Account',
        description: 'Automated service with specific API access',
        level: 50,
        permissions: ['api:service'],
        cognitoGroup: 'service-accounts',
        pattern: 'system',
        isServiceAccount: true
    },

    /**
     * Billing Admin - Billing and subscription management
     */
    billingAdmin: {
        name: 'billing_admin',
        displayName: 'Billing Admin',
        description: 'Manage billing, subscriptions, and invoices',
        level: 60,
        permissions: ['read:billing', 'write:billing', 'manage:subscriptions'],
        cognitoGroup: 'billing-admins',
        pattern: 'billing'
    }
};

// =============================================================================
// SITE ARCHITECTURE PATTERNS
// =============================================================================

export const SITE_PATTERNS = {
    /**
     * Static Site Pattern
     *
     * Architecture:
     * - site.domain: Public static site with fast CDN delivery
     * - site.domain/auth: Protected area requiring authentication
     * - Admin area: Pushes changes to static site via CI/CD or API
     *
     * Typical flow:
     * 1. Anonymous users see static site
     * 2. Users click "Login" → redirected to /auth
     * 3. After auth, users can access protected content
     * 4. Editors/Publishers push changes that rebuild static site
     */
    staticSite: {
        name: 'static-site',
        displayName: 'Static Site + Auth',
        description: 'Public static site with protected admin area',
        roles: ['readonly', 'user', 'editor', 'reviewer', 'publisher', 'admin'],
        routes: {
            public: ['/', '/about', '/blog/*'],
            protected: ['/auth', '/auth/*', '/dashboard', '/dashboard/*'],
            admin: ['/admin', '/admin/*']
        },
        features: {
            staticGeneration: true,
            cdnCaching: true,
            incrementalBuilds: true,
            contentfulIntegration: 'backlog'  // Future integration
        }
    },

    /**
     * Multi-User WASM Pattern
     *
     * Architecture:
     * - Real-time WebSocket connections
     * - WASM modules for game logic/computation
     * - Player/DM hierarchy for session control
     *
     * Typical roles:
     * 1. Players: Join sessions, control their character
     * 2. DM/GM: Control session, NPCs, world state
     * 3. Moderators: Community management
     * 4. Admin: System configuration
     */
    wasmMultiuser: {
        name: 'wasm-multiuser',
        displayName: 'Multi-User WASM',
        description: 'Real-time multi-user application with WASM',
        roles: ['player', 'dm', 'moderator', 'admin'],
        routes: {
            public: ['/', '/join'],
            protected: ['/game', '/game/*', '/session/*'],
            dm: ['/dm', '/dm/*', '/session/*/control'],
            admin: ['/admin', '/admin/*']
        },
        features: {
            websockets: true,
            wasmModules: true,
            realtimeSync: true,
            sessionManagement: true
        }
    }
};

// =============================================================================
// PERMISSION HELPERS
// =============================================================================

/**
 * Check if a role has a specific permission
 * Supports wildcards: 'read:*' matches 'read:content', 'read:users', etc.
 */
export function hasPermission(role, permission) {
    const roleData = CORE_ROLES[role] || STANDARD_ROLES[role];
    if (!roleData) return false;

    return roleData.permissions.some(p => {
        if (p === '*') return true;  // Admin wildcard
        if (p === permission) return true;  // Exact match

        // Wildcard matching: 'read:*' matches 'read:content'
        if (p.endsWith(':*')) {
            const prefix = p.slice(0, -1);  // 'read:'
            return permission.startsWith(prefix);
        }

        return false;
    });
}

/**
 * Get all roles for a specific site pattern
 */
export function getRolesForPattern(pattern) {
    const patternRoles = Object.values(STANDARD_ROLES)
        .filter(r => r.pattern === pattern)
        .map(r => r.name);

    // Always include core roles
    return [...Object.keys(CORE_ROLES), ...patternRoles];
}

/**
 * Get role hierarchy (for role inheritance)
 */
export function getRoleHierarchy() {
    const allRoles = { ...CORE_ROLES, ...STANDARD_ROLES };
    return Object.values(allRoles)
        .sort((a, b) => b.level - a.level)
        .map(r => ({ name: r.name, level: r.level }));
}

/**
 * Check if user with roleA can manage users with roleB
 * Based on role level hierarchy
 */
export function canManageRole(roleA, roleB) {
    const roleDataA = CORE_ROLES[roleA] || STANDARD_ROLES[roleA];
    const roleDataB = CORE_ROLES[roleB] || STANDARD_ROLES[roleB];

    if (!roleDataA || !roleDataB) return false;
    return roleDataA.level > roleDataB.level;
}

// =============================================================================
// COGNITO GROUP MAPPING
// =============================================================================

/**
 * Generate Cognito group configuration for AWS CDK/CloudFormation
 */
export function getCognitoGroupConfig(roles = Object.keys({ ...CORE_ROLES, ...STANDARD_ROLES })) {
    const allRoles = { ...CORE_ROLES, ...STANDARD_ROLES };

    return roles
        .filter(r => allRoles[r])
        .map(r => ({
            groupName: allRoles[r].cognitoGroup,
            description: allRoles[r].description,
            precedence: 100 - allRoles[r].level  // Lower number = higher precedence
        }));
}

// =============================================================================
// CONTENTFUL INTEGRATION (BACKLOG)
// =============================================================================

/**
 * Contentful role mapping - BACKLOG
 * Maps l42 roles to Contentful space roles
 *
 * TODO: Implement when Contentful integration is prioritized
 */
export const CONTENTFUL_ROLE_MAPPING = {
    // editor: 'Editor',
    // reviewer: 'Content Reviewer',
    // publisher: 'Publisher',
    // admin: 'Admin'
    _status: 'backlog',
    _note: 'Contentful integration planned for future release'
};

// =============================================================================
// EXPORTS
// =============================================================================

export default {
    // Cognito group handling (v0.3.0+)
    COGNITO_GROUPS,
    isInCognitoGroup,
    isInAnyCognitoGroup,
    getCanonicalGroupName,
    // Role definitions
    CORE_ROLES,
    STANDARD_ROLES,
    SITE_PATTERNS,
    // Permission helpers
    hasPermission,
    getRolesForPattern,
    getRoleHierarchy,
    canManageRole,
    getCognitoGroupConfig,
    // Future integrations
    CONTENTFUL_ROLE_MAPPING
};
