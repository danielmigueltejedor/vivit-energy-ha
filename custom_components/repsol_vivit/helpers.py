"""Pure helpers for Vivit/Repsol integration."""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Mapping

from .const import (
    CONF_ENABLE_VIRTUAL_BATTERY_SENSORS,
    CONF_UPDATE_INTERVAL_MINUTES,
    DEFAULT_ENABLE_VIRTUAL_BATTERY_SENSORS,
    DEFAULT_UPDATE_INTERVAL_MINUTES,
    MAX_UPDATE_INTERVAL_MINUTES,
    MIN_UPDATE_INTERVAL_MINUTES,
)


def build_device_name(contract_index: int | None, contract_type: str | None) -> str:
    """Build a stable device name for a contract entry."""
    normalized_type = (contract_type or "").upper()
    human_contract_type = "Electricidad" if normalized_type == "ELECTRICITY" else "Gas"
    prefix = f"Contrato {contract_index}" if contract_index else "Contrato"
    return f"{prefix} ({human_contract_type})"


def build_device_identifier(house_id: str | None, contract_id: str) -> str:
    """Build the shared device identifier used by every platform."""
    return f"{house_id or 'unknown_house'}_{contract_id}"


def get_contract_snapshot(
    data: Mapping[str, Any] | None, contract_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return current contract summaries from the latest coordinator payload."""
    payload = (data or {}).get(contract_id) or {}
    if not isinstance(payload, Mapping):
        return {}, {}
    contract_info = payload.get("contracts") or {}
    if not isinstance(contract_info, Mapping):
        contract_info = {}
    house_data = payload.get("house_data") or {}
    if not isinstance(house_data, Mapping):
        house_data = {}
    house_contracts = house_data.get("contracts") or []
    house_contract = next(
        (
            contract
            for contract in house_contracts
            if isinstance(contract, Mapping) and contract.get("code") == contract_id
        ),
        {},
    )
    return contract_info, house_contract


def get_latest_invoice(invoices: Any) -> dict[str, Any] | None:
    """Normalize the provider's list/dict invoice response."""
    if isinstance(invoices, list) and invoices and isinstance(invoices[0], dict):
        return invoices[0]
    if isinstance(invoices, dict):
        return invoices
    return None


def get_latest_redemption(virtual_battery: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the latest valid virtual-battery redemption."""
    discounts = (virtual_battery or {}).get("discounts") or {}
    if not isinstance(discounts, Mapping):
        return None
    entries = discounts.get("data") or []
    if not isinstance(entries, list):
        return None
    valid_entries = [entry for entry in entries if isinstance(entry, dict)]
    return max(valid_entries, key=lambda entry: str(entry.get("billingDate") or ""), default=None)


def redact_provider_url(url: str) -> str:
    """Redact house and contract identifiers before writing a provider URL to logs."""
    redacted = re.sub(r"(?<=/houses/)[^/?]+", "<house>", str(url))
    return re.sub(r"(?<=/products/)[^/?]+", "<contract>", redacted)


def get_update_interval_minutes(options: Mapping[str, Any] | None) -> int:
    """Return the configured polling interval in minutes."""
    raw_value = (options or {}).get(CONF_UPDATE_INTERVAL_MINUTES, DEFAULT_UPDATE_INTERVAL_MINUTES)
    try:
        minutes = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_UPDATE_INTERVAL_MINUTES

    if minutes < MIN_UPDATE_INTERVAL_MINUTES or minutes > MAX_UPDATE_INTERVAL_MINUTES:
        return DEFAULT_UPDATE_INTERVAL_MINUTES

    return minutes


def get_update_interval(options: Mapping[str, Any] | None) -> timedelta:
    """Return the configured polling interval as timedelta."""
    return timedelta(minutes=get_update_interval_minutes(options))


def is_virtual_battery_enabled(options: Mapping[str, Any] | None) -> bool:
    """Return whether virtual battery sensors should be created."""
    return bool(
        (options or {}).get(
            CONF_ENABLE_VIRTUAL_BATTERY_SENSORS,
            DEFAULT_ENABLE_VIRTUAL_BATTERY_SENSORS,
        )
    )
