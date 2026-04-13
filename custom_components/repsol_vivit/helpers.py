"""Pure helpers for Vivit/Repsol integration."""
from __future__ import annotations

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
