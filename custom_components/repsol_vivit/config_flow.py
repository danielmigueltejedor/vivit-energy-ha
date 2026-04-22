"""Config flow for Vivit Energy (unofficial)."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from aiohttp.client_exceptions import ClientConnectorError

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import RepsolLuzYGasAPI
from .const import (
    CONF_ENABLE_VIRTUAL_BATTERY_SENSORS,
    CONF_UPDATE_INTERVAL_MINUTES,
    DOMAIN,
    LOGGER,
    MAX_UPDATE_INTERVAL_MINUTES,
    MIN_UPDATE_INTERVAL_MINUTES,
)
from .helpers import build_device_name, get_update_interval_minutes, is_virtual_battery_enabled


class RepsolConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._creds: dict[str, Any] | None = None
        self._contracts: list[dict[str, Any]] | None = None

    async def _async_fetch_contracts(
        self, username: str, password: str
    ) -> list[dict[str, Any]]:
        """Validate credentials and fetch contracts."""
        session = async_create_clientsession(self.hass)
        client = RepsolLuzYGasAPI(session=session, username=username, password=password)

        await client.async_login()
        data = await client.async_get_contracts()
        return [
            {
                "code": contract.get("contract_id"),
                "cups": contract.get("cups"),
                "type": contract.get("contractType"),
                "house_id": contract.get("house_id"),
            }
            for contract in (data.get("information") or [])
        ]

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial config flow step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                contracts = await self._async_fetch_contracts(
                    user_input["username"],
                    user_input["password"],
                )

                if not contracts:
                    errors["base"] = "no_contracts"
                else:
                    self._creds = {
                        "username": user_input["username"],
                        "password": user_input["password"],
                    }
                    self._contracts = contracts
                    return await self.async_step_contract()
            except (ClientConnectorError, asyncio.TimeoutError):
                errors["base"] = "cannot_connect"
            except Exception as err:  # noqa: BLE001
                msg = (str(err) or "").lower()
                if "login_failed" in msg:
                    errors["base"] = "invalid_auth"
                elif "no_contracts" in msg or "no contracts" in msg:
                    errors["base"] = "no_contracts"
                else:
                    LOGGER.exception("Unexpected flow error: %s", err)
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("username", default=(user_input or {}).get("username", "")): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_contract(self, user_input: dict[str, Any] | None = None):
        """Handle contract selection."""
        assert self._contracts is not None

        opts = {
            contract["code"]: f'{(contract.get("type") or "").upper()} - {contract.get("cups") or ""}'
            for contract in self._contracts
        }

        errors: dict[str, str] = {}

        if user_input is not None:
            code = user_input["contract_code"]
            selected = next(contract for contract in self._contracts if contract["code"] == code)
            idx = next(
                index
                for index, contract in enumerate(self._contracts, start=1)
                if contract["code"] == code
            )
            contract_type = (selected.get("type") or "ELECTRICITY").upper()
            title = f"{contract_type} - {selected.get('cups') or code}"

            data = {
                **(self._creds or {}),
                "contract_id": selected["code"],
                "contract_index": idx,
                "contract_type": contract_type,
                "house_id": selected.get("house_id"),
                "device_name": build_device_name(idx, contract_type),
            }

            await self.async_set_unique_id(f"{DOMAIN}_{selected['code']}")
            self._abort_if_unique_id_configured()

            return self.async_create_entry(title=title, data=data)

        return self.async_show_form(
            step_id="contract",
            data_schema=vol.Schema({vol.Required("contract_code"): vol.In(opts)}),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]):
        """Handle reauthentication start."""
        self._creds = {
            "username": str(entry_data.get("username", "")),
            "password": str(entry_data.get("password", "")),
        }

        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None):
        """Confirm reauthentication with new credentials."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if entry is None:
            return self.async_abort(reason="unknown")

        if user_input is not None:
            try:
                contracts = await self._async_fetch_contracts(
                    user_input["username"],
                    user_input["password"],
                )

                selected = next(
                    (
                        contract
                        for contract in contracts
                        if contract.get("code") == entry.data.get("contract_id")
                    ),
                    None,
                )
                if selected is None:
                    errors["base"] = "contract_not_found"
                else:
                    idx = next(
                        index
                        for index, contract in enumerate(contracts, start=1)
                        if contract.get("code") == entry.data.get("contract_id")
                    )
                    contract_type = (selected.get("type") or "ELECTRICITY").upper()
                    await self.async_set_unique_id(f"{DOMAIN}_{entry.data.get('contract_id')}")
                    self._abort_if_unique_id_mismatch()

                    return self.async_update_reload_and_abort(
                        entry,
                        data_updates={
                        "username": user_input["username"],
                        "password": user_input["password"],
                        "contract_index": idx,
                        "contract_type": contract_type,
                        "house_id": selected.get("house_id"),
                        "device_name": build_device_name(idx, contract_type),
                        },
                    )
            except (ClientConnectorError, asyncio.TimeoutError):
                errors["base"] = "cannot_connect"
            except Exception as err:  # noqa: BLE001
                msg = (str(err) or "").lower()
                if "login_failed" in msg:
                    errors["base"] = "invalid_auth"
                elif "no_contracts" in msg or "no contracts" in msg:
                    errors["base"] = "no_contracts"
                else:
                    LOGGER.exception("Unexpected reauth error: %s", err)
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "username",
                        default=(user_input or self._creds or {}).get("username", entry.data.get("username", "")),
                    ): str,
                    vol.Required("password"): str,
                }
            ),
            description_placeholders={"username": entry.data.get("username", "")},
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry):
        """Create the options flow."""
        return RepsolOptionsFlow()


class RepsolOptionsFlow(config_entries.OptionsFlow):
    """Options flow for Vivit/Repsol."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage the integration options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_UPDATE_INTERVAL_MINUTES,
                        default=get_update_interval_minutes(self.config_entry.options),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(
                            min=MIN_UPDATE_INTERVAL_MINUTES,
                            max=MAX_UPDATE_INTERVAL_MINUTES,
                        ),
                    ),
                    vol.Required(
                        CONF_ENABLE_VIRTUAL_BATTERY_SENSORS,
                        default=is_virtual_battery_enabled(self.config_entry.options),
                    ): bool,
                }
            ),
        )
