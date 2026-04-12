"""Config flow for Vivit Energy (unofficial)."""
from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol
from aiohttp.client_exceptions import ClientConnectorError

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import RepsolLuzYGasAPI
from .const import DOMAIN, LOGGER


def _device_name(contract_index: int, contract_type: str | None) -> str:
    """Devuelve el nombre estable del dispositivo para un contrato."""
    human_contract_type = (
        "Electricidad" if (contract_type or "").upper() == "ELECTRICITY" else "Gas"
    )
    return f"Contrato {contract_index} ({human_contract_type})"


class RepsolConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._creds: dict[str, Any] | None = None
        self._contracts: list[dict[str, Any]] | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_create_clientsession(self.hass)
            client = RepsolLuzYGasAPI(
                session=session,
                username=user_input["username"],
                password=user_input["password"],
            )

            try:
                await client.async_login()
                data = await client.async_get_contracts()
                contracts = [
                    {
                        "code": contract.get("contract_id"),
                        "cups": contract.get("cups"),
                        "type": contract.get("contractType"),
                        "house_id": contract.get("house_id"),
                    }
                    for contract in (data.get("information") or [])
                ]

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
            finally:
                await session.close()

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
                "device_name": _device_name(idx, contract_type),
            }

            await self.async_set_unique_id(f"{DOMAIN}_{selected['code']}")
            self._abort_if_unique_id_configured()

            return self.async_create_entry(title=title, data=data)

        return self.async_show_form(
            step_id="contract",
            data_schema=vol.Schema({vol.Required("contract_code"): vol.In(opts)}),
            errors=errors,
        )
