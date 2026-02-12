"""Tests for Cedar engine (entity building, group aliases, policy eval).

Uses real Cedar schema and policies from the shared cedar/ directory.
"""

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from app.cedar_engine import (
    DEFAULT_GROUP_MAP,
    build_entities,
    init_cedar_engine,
    is_initialized,
    reset_for_testing,
)

CEDAR_DIR = Path(__file__).parent.parent / "cedar"
SCHEMA_PATH = str(CEDAR_DIR / "schema.cedarschema.json")
POLICY_DIR = str(CEDAR_DIR / "policies")


@pytest.fixture(autouse=True)
def reset_cedar():
    """Reset Cedar engine before each test."""
    reset_for_testing()
    yield
    reset_for_testing()


@pytest.fixture
def cedar_engine():
    """Initialize Cedar engine with real schema and policies."""
    init_cedar_engine(schema_path=SCHEMA_PATH, policy_dir=POLICY_DIR)


# ── Initialization ────────────────────────────────────────────────────────

def test_not_initialized_by_default():
    assert not is_initialized()


def test_init_with_schema_and_policies(cedar_engine):
    assert is_initialized()


def test_init_fails_without_schema():
    with pytest.raises(ValueError, match="schema"):
        init_cedar_engine(policy_dir=POLICY_DIR)


def test_init_fails_without_policies():
    with pytest.raises(ValueError, match="policies"):
        init_cedar_engine(schema_path=SCHEMA_PATH)


def test_init_fails_with_invalid_policy():
    with pytest.raises((ValueError, Exception)):
        init_cedar_engine(
            schema_path=SCHEMA_PATH,
            policies="this is not valid cedar",
        )


# ── Entity Building ───────────────────────────────────────────────────────

def test_build_entities_creates_user():
    claims = {"sub": "user-1", "email": "a@b.com", "cognito:groups": ["admin"]}
    entities = build_entities(claims)
    user = next(e for e in entities if e["uid"]["type"] == "App::User")
    assert user["uid"]["id"] == "user-1"
    assert user["attrs"]["email"] == "a@b.com"


def test_build_entities_creates_group_entities():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admin", "editors"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "App::UserGroup"]
    group_ids = {g["uid"]["id"] for g in groups}
    assert "admin" in group_ids
    assert "editors" in group_ids


def test_build_entities_resolves_group_aliases():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admins", "dev"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "App::UserGroup"]
    group_ids = {g["uid"]["id"] for g in groups}
    assert "admin" in group_ids  # admins → admin
    assert "developers" in group_ids  # dev → developers


def test_build_entities_deduplicates_groups():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admin", "admins", "administrators"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "App::UserGroup"]
    assert len(groups) == 1  # All map to "admin"


def test_build_entities_default_resource():
    claims = {"sub": "u", "email": ""}
    entities = build_entities(claims)
    resource = next(e for e in entities if e["uid"]["type"] == "App::Resource")
    assert resource["uid"]["id"] == "_application"
    assert resource["attrs"]["resourceType"] == "application"


def test_build_entities_custom_resource():
    claims = {"sub": "u", "email": ""}
    resource = {"id": "doc-1", "type": "document", "owner": "owner-sub"}
    entities = build_entities(claims, resource)
    res = next(e for e in entities if e["uid"]["type"] == "App::Resource")
    assert res["uid"]["id"] == "doc-1"
    assert res["attrs"]["resourceType"] == "document"
    assert res["attrs"]["owner"] == {"__entity": {"type": "App::User", "id": "owner-sub"}}


def test_build_entities_no_owner():
    claims = {"sub": "u", "email": ""}
    resource = {"id": "doc-1", "type": "document"}
    entities = build_entities(claims, resource)
    res = next(e for e in entities if e["uid"]["type"] == "App::Resource")
    assert "owner" not in res["attrs"]


def test_build_entities_user_parents_linked_to_groups():
    claims = {"sub": "u", "email": "", "cognito:groups": ["editors"]}
    entities = build_entities(claims)
    user = next(e for e in entities if e["uid"]["type"] == "App::User")
    assert any(p["id"] == "editors" for p in user["parents"])


# ── Group Aliases ─────────────────────────────────────────────────────────

def test_all_admin_aliases_resolve():
    for alias in ["admin", "admins", "administrators"]:
        assert DEFAULT_GROUP_MAP[alias] == "admin"


def test_all_readonly_aliases_resolve():
    for alias in ["readonly", "read-only", "viewer", "viewers"]:
        assert DEFAULT_GROUP_MAP[alias] == "readonly"


def test_all_developer_aliases_resolve():
    for alias in ["developer", "developers", "dev", "devs"]:
        assert DEFAULT_GROUP_MAP[alias] == "developers"


def test_unknown_group_passes_through():
    from app.cedar_engine import _resolve_group
    assert _resolve_group("custom-team") == "custom-team"
