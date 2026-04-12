"""Integration for Vivit Energy (unofficial)."""
from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import RepsolLuzYGasAPI
from .const import DOMAIN, LOGGER, UPDATE_INTERVAL

PLATFORMS: list[str] = ["sensor"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """YAML setup (no usado)."""
    return True


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
        human_contract_type = "Electricidad" if contract_type == "ELECTRICITY" else "Gas"
        prefix = f"Contrato {contract_index}" if contract_index else "Contrato"
        device_name = f"{prefix} ({human_contract_type})"

    store.update(
        {
            "api": client,
            "session": session,
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
        update_interval=UPDATE_INTERVAL,
    )

    store["coordinator"] = coordinator
    try:
        await coordinator.async_config_entry_first_refresh()
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        await session.close()
        raise

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Descarga la entrada."""
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        store = hass.data[DOMAIN].pop(entry.entry_id, None)
        if store and (session := store.get("session")):
            await session.close()
        if not hass.data[DOMAIN]:
            hass.data.pop(DOMAIN, None)
    return ok
