"""Tests for DynamoDB session backend.

Uses mocks for aioboto3 since moto doesn't fully support aiobotocore's
async response handling.
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.session.dynamodb import DynamoDBSessionBackend

TABLE_NAME = "test_sessions"


def _make_backend():
    return DynamoDBSessionBackend(
        table_name=TABLE_NAME,
        region_name="us-west-2",
    )


def _mock_table(items=None):
    """Create a mock DynamoDB table backed by a simple dict."""
    store = {}
    if items:
        store.update(items)

    table = AsyncMock()

    async def mock_get_item(Key):
        sid = Key["session_id"]
        if sid in store:
            return {"Item": store[sid]}
        return {}

    async def mock_put_item(Item):
        store[Item["session_id"]] = Item

    async def mock_delete_item(Key):
        store.pop(Key["session_id"], None)

    table.get_item = mock_get_item
    table.put_item = mock_put_item
    table.delete_item = mock_delete_item

    return table, store


def _mock_dynamodb_resource(table):
    """Create a mock aioboto3 resource context manager."""

    class MockResource:
        async def Table(self, name):
            return table

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    return MockResource()


@pytest.mark.asyncio
async def test_save_and_load():
    table, store = _mock_table()
    be = _make_backend()

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        await be.save("sess-1", {"tokens": {"access_token": "abc"}})
        data = await be.load("sess-1")

    assert data is not None
    assert data["tokens"]["access_token"] == "abc"


@pytest.mark.asyncio
async def test_load_nonexistent():
    table, _ = _mock_table()
    be = _make_backend()

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        data = await be.load("nonexistent")

    assert data is None


@pytest.mark.asyncio
async def test_delete():
    table, _ = _mock_table()
    be = _make_backend()

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        await be.save("sess-1", {"key": "val"})
        await be.delete("sess-1")
        data = await be.load("sess-1")

    assert data is None


@pytest.mark.asyncio
async def test_expired_session():
    # Pre-populate with an expired item
    expired_item = {
        "session_id": "sess-1",
        "data": json.dumps({"key": "val"}),
        "created_at": int(time.time() - 100),
        "ttl": int(time.time() - 99),
    }
    table, store = _mock_table({"sess-1": expired_item})
    be = DynamoDBSessionBackend(
        table_name=TABLE_NAME, max_age=1, region_name="us-west-2"
    )

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        data = await be.load("sess-1")

    assert data is None
    # Expired session should be deleted
    assert "sess-1" not in store


@pytest.mark.asyncio
async def test_save_overwrites_existing():
    table, _ = _mock_table()
    be = _make_backend()

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        await be.save("sess-1", {"version": 1})
        await be.save("sess-1", {"version": 2})
        data = await be.load("sess-1")

    assert data["version"] == 2


@pytest.mark.asyncio
async def test_save_sets_ttl():
    table, store = _mock_table()
    be = DynamoDBSessionBackend(
        table_name=TABLE_NAME, max_age=3600, region_name="us-west-2"
    )

    with patch.object(be._session, "resource", return_value=_mock_dynamodb_resource(table)):
        await be.save("sess-1", {"key": "val"})

    item = store["sess-1"]
    assert "ttl" in item
    assert item["ttl"] > time.time()
