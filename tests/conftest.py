"""Shared pytest fixtures. Each test gets an isolated DATA_DIR so DBs/rules don't leak between tests."""
import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("DATA_DIR", d)
        # reset cached sqlite connections in the gateway store between tests
        import gateway.store as store
        store._conn = None
        yield d
        store._conn = None
