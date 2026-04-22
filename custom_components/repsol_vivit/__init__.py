"""Integration for Vivit Energy (unofficial)."""
from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed

from .api import RepsolLuzYGasAPI
from .const import DOMAIN, LOGGER
from .helpers import build_device_name, get_update_interval

PLATFORMS: list[str] = ["sensor", "binary_sensor"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """YAML setup (no usado)."""
    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the config entry after options or reauth changes."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Setup por entrada de configuración."""
    session = async_create_clientsession(hass)
    client = RepsolLuzYGasAPI(
        session=session,
        username=entry.data["username"],
        password=entry.data["password"],
        selected_contract_id=entry.data.get("contract_id"),
    )

    hass.data.setdefault(DOMAIN, {})
    store: dict[str, Any] = hass.data[DOMAIN].setdefault(entry.entry_id, {})
    contract_type = (entry.data.get("contract_type") or "ELECTRICITY").upper()
    contract_index = entry.data.get("contract_index")
    device_name = entry.data.get("device_name")

    if not device_name:
        device_name = build_device_name(contract_index, contract_type)

    store.update(
        {
            "api": client,
            "last_data": None,
            "contract_id": entry.data.get("contract_id"),
            "contract_type": contract_type,
            "contract_index": contract_index,
            "house_id": entry.data.get("house_id"),
            "device_name": device_name,
        }
    )

    async def _update():
        """Actualización con caché y tolerancia a errores."""
        try:
            data = await client.fetch_all_data()
            if not data:
                raise Exception("no_contracts")
            store["last_data"] = data
            return data
        except Exception as err:  # noqa: BLE001
            msg = (str(err) or "").lower()
            if "login_failed" in msg:
                raise ConfigEntryAuthFailed("Authentication failed") from err
            if store.get("last_data") is not None:
                if "no_contracts" in msg or "no contracts" in msg:
                    LOGGER.warning(
                        "API devolvió 0 contratos (transitorio). Sirviendo datos en caché."
                    )
                else:
                    LOGGER.warning(
                        "Fallo al actualizar (%s). Sirviendo datos en caché.", err
                    )
                return store["last_data"]
            raise UpdateFailed(f"Error actualizando datos: {err}") from err

    coordinator = DataUpdateCoordinator(
        hass,
        LOGGER,
        name=f"{DOMAIN}-coordinator",
        update_method=_update,
        update_interval=get_update_interval(entry.options),
    )

    store["coordinator"] = coordinator
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    try:
        await coordinator.async_config_entry_first_refresh()
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        raise

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Descarga la entrada."""
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if not hass.data[DOMAIN]:
            hass.data.pop(DOMAIN, None)
    return ok
