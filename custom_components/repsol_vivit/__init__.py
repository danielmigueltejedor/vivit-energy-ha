"""Integration for Vivit Energy (unofficial)."""
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any, Dict, Optional, List

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    DOMAIN,
    LOGGER,
    LOGIN_URL,
    CONTRACTS_URL,
    HOUSES_URL,
    INVOICES_URL,
    COSTS_URL,
    NEXT_INVOICE_URL,
    VIRTUAL_BATTERY_HISTORY_URL,
    UPDATE_INTERVAL,
    LOGIN_HEADERS,
    CONTRACTS_HEADERS,
    COOKIES_CONST,
    LOGIN_DATA,
)

PLATFORMS: list[str] = ["sensor"]

# Parámetros de robustez/red
REQ_TIMEOUT = 15            # seg por request
REQUEST_RETRIES = 1         # nº de reintentos adicionales
RETRY_SLEEP_BASE = 1.0      # backoff lineal (1s, 2s, ...)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """YAML setup (no usado)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Setup por entrada de configuración."""
    session = async_get_clientsession(hass)
    client = RepsolLuzYGasAPI(
        session=session,
        username=entry.data["username"],
        password=entry.data["password"],
        selected_contract_id=entry.data.get("contract_id"),
    )

    hass.data.setdefault(DOMAIN, {})
    store: Dict[str, Any] = hass.data[DOMAIN].setdefault(entry.entry_id, {})
    store["api"] = client
    store["last_data"] = None  # caché último dataset válido

    async def _update():
        """Actualización con caché y tolerancia a errores."""
        try:
            data = await client.fetch_all_data()
            if not data:
                raise Exception("no_contracts")
            store["last_data"] = data
            return data
        except Exception as e:
            msg = (str(e) or "").lower()
            if store.get("last_data") is not None:
                if "no_contracts" in msg or "no contracts" in msg:
                    LOGGER.warning("API devolvió 0 contratos (transitorio). Sirviendo datos en caché.")
                else:
                    LOGGER.warning("Fallo al actualizar (%s). Sirviendo datos en caché.", e)
                return store["last_data"]
            raise UpdateFailed(f"Error actualizando datos: {e}") from e

    coordinator = DataUpdateCoordinator(
        hass,
        LOGGER,
        name=f"{DOMAIN}-coordinator",
        update_method=_update,
        update_interval=UPDATE_INTERVAL,
    )

    store["coordinator"] = coordinator
    await coordinator.async_config_entry_first_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Descarga la entrada."""
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok


class RepsolLuzYGasAPI:
    """Cliente API para Vivit/Repsol."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        selected_contract_id: Optional[str] = None,
    ):
        self.session = session
        self.username = username
        self.password = password
        self.selected_contract_id = selected_contract_id

        self.uid: Optional[str] = None
        self.signature: Optional[str] = None
        self.timestamp: Optional[str] = None

        # Cookies por instancia (puede iniciarse vacía)
        self.cookies: Dict[str, str] = dict(COOKIES_CONST) if COOKIES_CONST else {}

    # ---------------- utils HTTP ----------------

    async def _get_json(self, url: str, headers: Dict[str, str]) -> Any:
        """GET con reintentos, re-login en 401/403 y backoff en 429/5xx."""
        last_exc: Optional[Exception] = None
        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as r:
                        if r.status in (401, 403):
                            LOGGER.info("GET %s -> %s. Re-login y reintento.", url, r.status)
                            await self.async_login(reset_cookies=False)
                            headers.update({
                                "UID": self.uid or "",
                                "signature": self.signature or "",
                                "signatureTimestamp": self.timestamp or "",
                            })
                            continue
                        if r.status in (429, 500, 502, 503, 504):
                            body = (await r.text())[:400]
                            LOGGER.warning("GET %s -> %s. Backoff: %s. Body=%s", url, r.status, attempt + 1, body)
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue
                        if r.status != 200:
                            body = (await r.text())[:400]
                            raise Exception(f"HTTP {r.status} {body}")
                        return await r.json(content_type=None)
            except Exception as e:
                last_exc = e
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
        raise last_exc or Exception("request_failed")

    # ---------------- login ----------------

    async def async_login(self, reset_cookies: bool = False) -> bool:
        """Login robusto con retry limpiando cookies si hay bloqueo 400006."""
        if reset_cookies:
            self.cookies = {}

        data = dict(LOGIN_DATA)
        data.update({"loginID": self.username, "password": self.password})
        headers = dict(LOGIN_HEADERS)

        for attempt in range(2):  # intento + 1 retry limpiando cookies
            async with self.session.post(
                LOGIN_URL, headers=headers, cookies=self.cookies, data=data
            ) as resp:
                text = await resp.text()
                if resp.status != 200:
                    if "security issues" in text or "400006" in text:
                        LOGGER.warning("Login bloqueado por seguridad. Reintentamos con cookies nuevas.")
                        self.cookies = {}
                        continue
                    raise Exception(f"login_failed_http {resp.status} {text[:300]}")
                try:
                    payload = await resp.json(content_type=None)
                except Exception:
                    raise Exception(f"login_failed_parse {text[:300]}")

                ui = payload.get("userInfo") or {}
                self.uid = ui.get("UID")
                self.signature = ui.get("UIDSignature")
                self.timestamp = ui.get("signatureTimestamp")
                if not (self.uid and self.signature and self.timestamp):
                    self.cookies = {}
                    if attempt == 0:
                        continue
                    raise Exception("login_failed_tokens")
                return True

        raise Exception("login_failed")

    def _auth_headers(self) -> Dict[str, str]:
        h = dict(CONTRACTS_HEADERS)
        h.update({
            "UID": self.uid or "",
            "signature": self.signature or "",
            "signatureTimestamp": self.timestamp or "",
        })
        return h

    # ---------------- endpoints ----------------

    async def async_get_contracts(self) -> Dict[str, List[Dict[str, Any]]]:
        """Listado de contratos con re-login si la API devuelve 0 transitoriamente."""
        headers = self._auth_headers()
        data = await self._get_json(CONTRACTS_URL, headers)
        parsed: Dict[str, List[Dict[str, Any]]] = {"information": []}
        for house in data or []:
            hid = (house or {}).get("code")
            for c in (house or {}).get("contracts", []):
                parsed["information"].append({
                    "contract_id": c.get("code"),
                    "contractType": c.get("contractType"),
                    "cups": c.get("cups"),
                    "active": c.get("status") == "ACTIVE",
                    "house_id": hid,
                })

        if not parsed["information"]:
            LOGGER.warning("La API devolvió 0 contratos. Re-login y segundo intento…")
            await self.async_login(reset_cookies=True)
            headers = self._auth_headers()
            data = await self._get_json(CONTRACTS_URL, headers)
            parsed2: Dict[str, List[Dict[str, Any]]] = {"information": []}
            for house in data or []:
                hid = (house or {}).get("code")
                for c in (house or {}).get("contracts", []):
                    parsed2["information"].append({
                        "contract_id": c.get("code"),
                        "contractType": c.get("contractType"),
                        "cups": c.get("cups"),
                        "active": c.get("status") == "ACTIVE",
                        "house_id": hid,
                    })
            return parsed2

        return parsed

    async def async_get_invoices(self, house_id: str, contract_id: str):
        headers = self._auth_headers()
        url = INVOICES_URL.format(house_id, contract_id)
        return await self._get_json(url, headers)

    async def async_get_costs(self, house_id: str, contract_id: str):
        headers = self._auth_headers()
        url = COSTS_URL.format(house_id, contract_id)
        resp = await self._get_json(url, headers)
        base = {"totalDays": 0, "consumption": 0, "amount": 0, "amountVariable": 0, "amountFixed": 0, "averageAmount": 0}
        for k in base:
            base[k] = resp.get(k, 0)
        return base

    async def async_get_next_invoice(self, house_id: str, contract_id: str):
        """Próxima factura: tolera estados 'no disponible' devolviendo 0s."""
        headers = self._auth_headers()
        url = NEXT_INVOICE_URL.format(house_id, contract_id)
        base = {"amount": 0, "amountVariable": 0, "amountFixed": 0}
        last_exc: Exception | None = None

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as r:
                        if r.status == 200:
                            resp = await r.json(content_type=None)
                            return {
                                "amount": resp.get("amount", 0),
                                "amountVariable": resp.get("amountVariable", 0),
                                "amountFixed": resp.get("amountFixed", 0),
                            }

                        if r.status in (401, 403):
                            LOGGER.info("Invoice estimate %s -> %s. Re-login y reintento.", url, r.status)
                            await self.async_login(reset_cookies=False)
                            headers = self._auth_headers()
                            continue

                        if r.status in (429, 500, 502, 503, 504):
                            body = (await r.text())[:400]
                            LOGGER.warning("Invoice estimate %s -> %s. Backoff (%s). Body=%s",
                                           url, r.status, attempt + 1, body)
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        # 400/404: estimación no disponible -> devolver 0s
                        if r.status in (400, 404):
                            txt = (await r.text())[:400]
                            if (
                                "InvoiceEstimateNotAvailableException" in txt
                                or "invoice estimate" in txt.lower()
                                or "not available" in txt.lower()
                            ):
                                LOGGER.info("Invoice estimate no disponible para %s/%s. Devolviendo 0s.",
                                            house_id, contract_id)
                                return base
                            LOGGER.info("Invoice estimate %s -> %s. Respuesta=%s. Devolviendo 0s.",
                                        url, r.status, txt)
                            return base

                        txt = (await r.text())[:400]
                        raise Exception(f"HTTP {r.status} {txt}")

            except Exception as e:  # noqa: BLE001
                last_exc = e
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning("Fallo persistente obteniendo invoice estimate %s/%s (%s). Devolviendo 0s.",
                       house_id, contract_id, last_exc)
        return base

    async def async_get_virtual_battery_history(self, house_id: str, contract_id: str):
        """Histórico de batería virtual; 404 conocido -> {}."""
        headers = self._auth_headers()
        url = VIRTUAL_BATTERY_HISTORY_URL.format(house_id, contract_id)
        last_exc: Exception | None = None

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as r:
                        if r.status == 200:
                            return await r.json(content_type=None)

                        if r.status in (401, 403):
                            LOGGER.info("VB history %s -> %s. Re-login y reintento.", url, r.status)
                            await self.async_login(reset_cookies=False)
                            headers = self._auth_headers()
                            continue

                        if r.status in (429, 500, 502, 503, 504):
                            body = (await r.text())[:400]
                            LOGGER.warning("VB history %s -> %s. Backoff (%s). Body=%s",
                                           url, r.status, attempt + 1, body)
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        if r.status in (400, 404):
                            txt = (await r.text())[:400]
                            if (
                                "BatteryHistoryNotFoundException" in txt
                                or "not found" in txt.lower()
                            ):
                                LOGGER.info(
                                    "VB history no disponible para %s/%s. Devolviendo {}.",
                                    house_id, contract_id
                                )
                                return {}
                            LOGGER.info("VB history %s -> %s. Respuesta=%s. Devolviendo {}.",
                                        url, r.status, txt)
                            return {}

                        txt = (await r.text())[:400]
                        raise Exception(f"HTTP {r.status} {txt}")

            except Exception as e:  # noqa: BLE001
                last_exc = e
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning(
            "Fallo persistente obteniendo VB history %s/%s (%s). Devolviendo {}.",
            house_id, contract_id, last_exc
        )
        return {}

    async def async_get_houseDetails(self, house_id: str):
        headers = self._auth_headers()
        url = HOUSES_URL.format(house_id)
        return await self._get_json(url, headers)

    # ---------------- orquestación ----------------

    async def fetch_all_data(self) -> Dict[str, Any]:
        """Carga de todos los datos de contratos (o del seleccionado)."""
        if not (self.uid and self.signature and self.timestamp):
            await self.async_login()

        contracts_data = await self.async_get_contracts()
        contracts_list = (contracts_data or {}).get("information") or []

        if self.selected_contract_id:
            contracts_list = [c for c in contracts_list if c.get("contract_id") == self.selected_contract_id]

        if not contracts_list:
            raise Exception("no_contracts")

        all_data: Dict[str, Any] = {}
        for contract in contracts_list:
            house_id = contract["house_id"]
            contract_id = contract["contract_id"]

            house_data = await self.async_get_houseDetails(house_id)
            invoices_data = await self.async_get_invoices(house_id, contract_id)
            costs_data = await self.async_get_costs(house_id, contract_id)
            next_invoice_data = await self.async_get_next_invoice(house_id, contract_id)

            vb_hist = None
            if (contract.get("contractType") or "").upper() == "ELECTRICITY":
                vb_hist = await self.async_get_virtual_battery_history(house_id, contract_id)

            all_data[contract_id] = {
                "contracts": contract,
                "house_data": house_data,
                "invoices": invoices_data,
                "costs": costs_data,
                "nextInvoice": next_invoice_data,
                "virtual_battery_history": vb_hist,
            }

        return all_data
