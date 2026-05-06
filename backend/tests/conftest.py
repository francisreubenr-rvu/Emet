from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

from services.rate_limit import auth_rate_limiter, scan_rate_limiter


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

TEST_DB_PATH = Path("/tmp/emet_test_suite.sqlite3")
if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["COOKIE_SECURE"] = "false"
os.environ["ALLOW_INTERNAL_SCANNING"] = "false"
os.environ["GEMINI_API_KEY"] = ""
os.environ["INGEST_SCHEDULER_ENABLED"] = "false"
os.environ["INGEST_ALLOWED_ROOT"] = "/tmp"

auth_rate_limiter._store.clear()
scan_rate_limiter._store.clear()


class FakePubSub:
    async def subscribe(self, _channel: str) -> None:
        return None

    async def get_message(self, ignore_subscribe_messages: bool = True, timeout: float = 1.0):
        return None

    async def unsubscribe(self, _channel: str) -> None:
        return None

    async def close(self) -> None:
        return None


class FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self.lists: dict[str, list[str]] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.kv[key] = value

    async def get(self, key: str):
        return self.kv.get(key)

    async def delete(self, key: str) -> None:
        self.kv.pop(key, None)

    async def exists(self, key: str) -> int:
        return 1 if key in self.kv else 0

    async def incr(self, key: str) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def lpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    async def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))

    async def publish(self, _channel: str, _payload: str) -> int:
        return 1

    async def ping(self) -> bool:
        return True

    async def lrange(self, key: str, start: int, stop: int):
        values = self.lists.get(key, [])
        if stop == -1:
            return values[start:]
        return values[start : stop + 1]

    async def rpop(self, key: str):
        values = self.lists.get(key, [])
        if not values:
            return None
        return values.pop()

    async def keys(self, pattern: str):
        if pattern == "worker:heartbeat:*":
            return [key for key in self.kv.keys() if key.startswith("worker:heartbeat:")]
        if pattern == "metrics:worker:*":
            keys = list(self.kv.keys()) + list(self.counters.keys())
            return [key for key in keys if key.startswith("metrics:worker:")]
        return []

    async def incrby(self, key: str, amount: int) -> int:
        self.counters[key] = self.counters.get(key, 0) + amount
        return self.counters[key]

    def pubsub(self) -> FakePubSub:
        return FakePubSub()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    from db.database import Base, engine
    from main import app
    import routers.auth as auth_router
    import routers.scan as scan_router
    import services.progress as progress_service
    import services.redis_bus as redis_bus
    import main as main_module

    fake_redis = FakeRedis()

    monkeypatch.setattr(redis_bus, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(auth_router, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(scan_router, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(progress_service, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(main_module, "get_redis_client", lambda: fake_redis)
    scan_rate_limiter._store.clear()
    auth_rate_limiter._store.clear()

    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_client(client: TestClient) -> TestClient:
    auth_rate_limiter._store.clear()
    response = client.post("/api/auth/login", json={"identifier": "analyst@emet.local", "password": "emet"})
    if response.status_code == 429:
        auth_rate_limiter._store.clear()
        response = client.post("/api/auth/login", json={"identifier": "admin", "password": "emet"})
    assert response.status_code == 200
    return client
