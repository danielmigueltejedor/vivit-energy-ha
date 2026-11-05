"""Retry behavior for provider GET requests."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_COMPONENTS_DIR = ROOT / "custom_components"
COMPONENT_DIR = CUSTOM_COMPONENTS_DIR / "repsol_vivit"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


aiohttp = types.ModuleType("aiohttp")


class ClientSession:
    """Stand-in so the client module can load without Home Assistant."""


aiohttp.ClientSession = ClientSession
sys.modules.setdefault("aiohttp", aiohttp)

custom_components_pkg = sys.modules.setdefault(
    "custom_components", types.ModuleType("custom_components")
)
custom_components_pkg.__path__ = [str(CUSTOM_COMPONENTS_DIR)]
component_pkg = sys.modules.setdefault(
    "custom_components.repsol_vivit",
    types.ModuleType("custom_components.repsol_vivit"),
)
component_pkg.__path__ = [str(COMPONENT_DIR)]

_load_module("custom_components.repsol_vivit.const", COMPONENT_DIR / "const.py")
_load_module("custom_components.repsol_vivit.helpers", COMPONENT_DIR / "helpers.py")
api = _load_module("custom_components.repsol_vivit.api", COMPONENT_DIR / "api.py")


class _Response:
    def __init__(self, status: int, payload: dict | None = None) -> None:
        self.status = status
        self._payload = payload or {}

    async def json(self, content_type: str | None = None) -> dict:
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _Session:
    def __init__(self, responses: list[tuple[int, dict | None]]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def get(self, url: str, headers: dict | None = None, cookies: dict | None = None) -> _Response:
        self.calls += 1
        status, payload = self._responses.pop(0)
        return _Response(status, payload)


class GetJsonRetryTests(unittest.TestCase):
    """Auth refresh must not consume the HTTP retry budget."""

    def setUp(self) -> None:
        api.RETRY_SLEEP_BASE = 0

    def _client(self, responses: list[tuple[int, dict | None]]) -> tuple[object, _Session]:
        session = _Session(responses)
        client = api.RepsolLuzYGasAPI(session, "user", "secret")

        async def _login(reset_cookies: bool = False) -> bool:
            client.signature = "refreshed"
            return True

        client.async_login = _login
        return client, session

    @unittest.skipUnless(hasattr(asyncio, "timeout"), "asyncio.timeout requires Python 3.11")
    def test_relogin_does_not_consume_retry_budget(self) -> None:
        client, session = self._client(
            [
                (401, None),
                (401, None),
                (500, None),
                (500, None),
                (500, None),
                (200, {"ok": True}),
            ]
        )

        result = asyncio.run(client._get_json("https://example.test/houses/h/products/c", {}))

        self.assertEqual(result, {"ok": True})
        self.assertEqual(session.calls, 6)

    @unittest.skipUnless(hasattr(asyncio, "timeout"), "asyncio.timeout requires Python 3.11")
    def test_third_auth_failure_stops_without_backoff(self) -> None:
        client, session = self._client([(401, None), (401, None), (403, None), (200, {"ok": True})])

        with self.assertRaises(api.VivitAPIError) as raised:
            asyncio.run(client._get_json("https://example.test/houses/h/products/c", {}))

        self.assertEqual(str(raised.exception), "http_403")
        self.assertEqual(session.calls, 3)


if __name__ == "__main__":
    unittest.main()
