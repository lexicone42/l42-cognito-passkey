"""Cedar authorization engine wrapping cedarpy.

Port of examples/backends/express/cedar-engine.js to Python.
Uses cedarpy.is_authorized_batch (single-element list) to get schema
validation parity with the Express backend's validateRequest: true.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import cedarpy

from .cognito import decode_jwt_payload

# Cognito group → Cedar UserGroup entity ID mapping
# Mirrors COGNITO_GROUPS aliases from rbac-roles.js
DEFAULT_GROUP_MAP: dict[str, str] = {
    "admin": "admin", "admins": "admin", "administrators": "admin",
    "readonly": "readonly", "read-only": "readonly", "viewer": "readonly", "viewers": "readonly",
    "user": "users", "users": "users", "member": "users", "members": "users",
    "editor": "editors", "editors": "editors",
    "reviewer": "reviewers", "reviewers": "reviewers",
    "publisher": "publishers", "publishers": "publishers",
    "moderator": "moderators", "moderators": "moderators", "mod": "moderators", "mods": "moderators",
    "developer": "developers", "developers": "developers", "dev": "developers", "devs": "developers",
}

_initialized = False
_schema: dict[str, Any] | None = None
_policy_text: str | None = None
_resolve_group = lambda group: DEFAULT_GROUP_MAP.get(group.lower(), group)


def init_cedar_engine(
    *,
    schema_path: str | None = None,
    policy_dir: str | None = None,
    schema: dict[str, Any] | str | None = None,
    policies: str | None = None,
    resolve_group: Any = None,
) -> None:
    """Initialize the Cedar engine. Call once at server startup.

    Loads and validates the schema and policies.
    """
    global _initialized, _schema, _policy_text, _resolve_group

    # Load schema
    if schema is not None:
        _schema = json.loads(schema) if isinstance(schema, str) else schema
    elif schema_path:
        _schema = json.loads(Path(schema_path).read_text())
    else:
        raise ValueError("init_cedar_engine requires schema or schema_path")

    # Load policies
    if policies is not None:
        _policy_text = policies
    elif policy_dir:
        files = sorted(f for f in os.listdir(policy_dir) if f.endswith(".cedar"))
        if not files:
            raise ValueError(f"No .cedar files found in {policy_dir}")
        _policy_text = "\n\n".join(
            Path(os.path.join(policy_dir, f)).read_text() for f in files
        )
    else:
        raise ValueError("init_cedar_engine requires policies or policy_dir")

    # Validate policies against schema
    result = cedarpy.validate_policies(_policy_text, _schema)
    if not result:
        errors = [str(e) for e in getattr(result, "errors", [])]
        raise ValueError(f"Cedar validation failed: {'; '.join(errors) or 'unknown error'}")

    if resolve_group:
        _resolve_group = resolve_group

    _initialized = True


def is_initialized() -> bool:
    return _initialized


def build_entities(
    claims: dict[str, Any], resource: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Build Cedar entities from JWT claims and a resource descriptor."""
    resource = resource or {}
    groups = claims.get("cognito:groups", [])
    canonical_groups = list({_resolve_group(g) for g in groups})
    entities: list[dict[str, Any]] = []

    # Principal (User) entity
    entities.append({
        "uid": {"type": "App::User", "id": claims["sub"]},
        "attrs": {"email": claims.get("email", ""), "sub": claims["sub"]},
        "parents": [{"type": "App::UserGroup", "id": g} for g in canonical_groups],
    })

    # UserGroup entities — Cedar requires these to exist
    for group in canonical_groups:
        entities.append({
            "uid": {"type": "App::UserGroup", "id": group},
            "attrs": {},
            "parents": [],
        })

    # Resource entity
    resource_id = resource.get("id", "_application")
    resource_attrs: dict[str, Any] = {
        "resourceType": resource.get("type", "application"),
    }
    if resource.get("owner"):
        resource_attrs["owner"] = {
            "__entity": {"type": "App::User", "id": resource["owner"]}
        }
    entities.append({
        "uid": {"type": "App::Resource", "id": resource_id},
        "attrs": resource_attrs,
        "parents": [],
    })

    return entities


def authorize(
    *,
    session: dict[str, Any],
    action: str,
    resource: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a Cedar authorization request.

    Returns: { authorized: bool, reason: str, diagnostics: dict }
    """
    if not _initialized:
        raise RuntimeError("Cedar engine not initialized. Call init_cedar_engine() first.")

    resource = resource or {}
    context = context or {}
    claims = decode_jwt_payload(session["tokens"]["id_token"])
    entities = build_entities(claims, resource)
    resource_id = resource.get("id", "_application")

    request = {
        "principal": f'App::User::"{claims["sub"]}"',
        "action": f'App::Action::"{action}"',
        "resource": f'App::Resource::"{resource_id}"',
        "context": context,
    }

    # Use is_authorized_batch with schema for request validation
    results = cedarpy.is_authorized_batch(
        requests=[request],
        policies=_policy_text,
        entities=entities,
        schema=_schema,
    )

    result = results[0]

    if result.allowed:
        return {
            "authorized": True,
            "reason": "allowed",
            "diagnostics": {},
        }
    else:
        return {
            "authorized": False,
            "reason": "No matching permit policy",
            "diagnostics": {},
        }


def get_schema() -> dict[str, Any] | None:
    return _schema


def get_policies() -> str | None:
    return _policy_text


def get_resolve_group():
    return _resolve_group


def reset_for_testing() -> None:
    """Reset engine state. For testing only."""
    global _initialized, _schema, _policy_text, _resolve_group
    _initialized = False
    _schema = None
    _policy_text = None
    _resolve_group = lambda group: DEFAULT_GROUP_MAP.get(group.lower(), group)
