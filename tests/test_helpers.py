"""Unit tests for pure Vivit helper functions."""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from datetime import timedelta
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


custom_components_pkg = sys.modules.setdefault("custom_components", types.ModuleType("custom_components"))
custom_components_pkg.__path__ = [str(CUSTOM_COMPONENTS_DIR)]

component_pkg = sys.modules.setdefault(
    "custom_components.repsol_vivit",
    types.ModuleType("custom_components.repsol_vivit"),
)
component_pkg.__path__ = [str(COMPONENT_DIR)]

const = _load_module("custom_components.repsol_vivit.const", COMPONENT_DIR / "const.py")
helpers = _load_module("custom_components.repsol_vivit.helpers", COMPONENT_DIR / "helpers.py")


class HelperTests(unittest.TestCase):
    """Tests for pure helpers."""

    def test_build_device_name_for_electricity(self) -> None:
        self.assertEqual(
            helpers.build_device_name(2, "ELECTRICITY"),
            "Contrato 2 (Electricidad)",
        )

    def test_build_device_name_without_index(self) -> None:
        self.assertEqual(helpers.build_device_name(None, "GAS"), "Contrato (Gas)")

    def test_update_interval_defaults_when_missing(self) -> None:
        self.assertEqual(helpers.get_update_interval_minutes({}), 120)
        self.assertEqual(helpers.get_update_interval(None), timedelta(minutes=120))

    def test_update_interval_defaults_when_invalid(self) -> None:
        self.assertEqual(
            helpers.get_update_interval_minutes(
                {const.CONF_UPDATE_INTERVAL_MINUTES: "not-a-number"}
            ),
            120,
        )
        self.assertEqual(
            helpers.get_update_interval_minutes({const.CONF_UPDATE_INTERVAL_MINUTES: 5}),
            120,
        )

    def test_update_interval_uses_valid_option(self) -> None:
        self.assertEqual(
            helpers.get_update_interval_minutes({const.CONF_UPDATE_INTERVAL_MINUTES: 180}),
            180,
        )
        self.assertEqual(
            helpers.get_update_interval({const.CONF_UPDATE_INTERVAL_MINUTES: 180}),
            timedelta(minutes=180),
        )

    def test_virtual_battery_option_defaults_and_overrides(self) -> None:
        self.assertTrue(helpers.is_virtual_battery_enabled({}))
        self.assertFalse(
            helpers.is_virtual_battery_enabled(
                {const.CONF_ENABLE_VIRTUAL_BATTERY_SENSORS: False}
            )
        )

    def test_device_identifier_is_shared_when_house_is_missing(self) -> None:
        self.assertEqual(
            helpers.build_device_identifier(None, "contract-1"),
            "unknown_house_contract-1",
        )

    def test_contract_snapshot_uses_latest_payload(self) -> None:
        data = {
            "contract-1": {
                "contracts": {"status": "ACTIVE"},
                "house_data": {
                    "contracts": [{"code": "contract-1", "power": 3.45}]
                },
            }
        }
        info, house_contract = helpers.get_contract_snapshot(data, "contract-1")
        self.assertEqual(info["status"], "ACTIVE")
        self.assertEqual(house_contract["power"], 3.45)

        data["contract-1"]["house_data"]["contracts"][0]["power"] = 4.6
        _, refreshed_contract = helpers.get_contract_snapshot(data, "contract-1")
        self.assertEqual(refreshed_contract["power"], 4.6)

    def test_latest_invoice_preserves_zero_amount(self) -> None:
        invoice = helpers.get_latest_invoice([{"amount": 0, "totalAmount": 12.5}])
        self.assertEqual(invoice["amount"], 0)

    def test_latest_redemption_tracks_new_data(self) -> None:
        history = {
            "discounts": {
                "data": [
                    {"billingDate": "2026-01-01", "amount": 1},
                    {"billingDate": "2026-02-01", "amount": 2},
                ]
            }
        }
        self.assertEqual(helpers.get_latest_redemption(history)["amount"], 2)

    def test_provider_url_redacts_personal_identifiers(self) -> None:
        url = (
            "https://areacliente.repsol.es/api/proxy/houses/house-secret/"
            "products/contract-secret/invoices?limit=10"
        )
        redacted = helpers.redact_provider_url(url)
        self.assertNotIn("house-secret", redacted)
        self.assertNotIn("contract-secret", redacted)
        self.assertIn("/houses/<house>/products/<contract>/invoices", redacted)


if __name__ == "__main__":
    unittest.main()
