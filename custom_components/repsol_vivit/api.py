"""API client for Vivit/Repsol."""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from .const import (
    CONTRACTS_HEADERS,
    CONTRACTS_URL,
    COOKIES_CONST,
    COSTS_URL,
    HOUSES_URL,
    INVOICES_URL,
    LOGIN_DATA,
    LOGIN_HEADERS,
    LOGIN_URL,
    LOGGER,
    NEXT_INVOICE_URL,
    REFERER_BILLING,
    REFERER_PRODUCTS,
    VIRTUAL_BATTERY_HISTORY_URL,
)

REQ_TIMEOUT = 15
REQUEST_RETRIES = 1
RETRY_SLEEP_BASE = 1.0


class RepsolLuzYGasAPI:
    """Cliente API para Vivit/Repsol."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        selected_contract_id: str | None = None,
    ) -> None:
        self.session = session
        self.username = username
        self.password = password
        self.selected_contract_id = selected_contract_id

        self.uid: str | None = None
        self.signature: str | None = None
        self.timestamp: str | None = None
        self.cookies: dict[str, str] = dict(COOKIES_CONST) if COOKIES_CONST else {}
        self._login_lock = asyncio.Lock()

    def _clear_auth(self) -> None:
        """Borra tokens en memoria para forzar relogin limpio."""
        self.uid = None
        self.signature = None
        self.timestamp = None

    def _clear_cookies(self) -> None:
        """Limpia cookies explícitas y las acumuladas por la sesión."""
        self.cookies = {}
        self.session.cookie_jar.clear()

    def _refresh_auth_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Actualiza una copia de headers con las credenciales actuales."""
        headers.update(
            {
                "UID": self.uid or "",
                "signature": self.signature or "",
                "signatureTimestamp": self.timestamp or "",
            }
        )
        return headers

    def _auth_headers(self, referer: str = REFERER_PRODUCTS) -> dict[str, str]:
        """Construye cabeceras autenticadas para el endpoint solicitado."""
        headers = dict(CONTRACTS_HEADERS)
        headers["Referer"] = referer
        return self._refresh_auth_headers(headers)

    def _parse_contracts(self, data: Any) -> dict[str, list[dict[str, Any]]]:
        """Normaliza la respuesta de contratos de la API."""
        parsed: dict[str, list[dict[str, Any]]] = {"information": []}
        for house in data or []:
            house_id = (house or {}).get("code")
            for contract in (house or {}).get("contracts", []):
                parsed["information"].append(
                    {
                        "contract_id": contract.get("code"),
                        "contractType": contract.get("contractType"),
                        "cups": contract.get("cups"),
                        "active": contract.get("status") == "ACTIVE",
                        "house_id": house_id,
                    }
                )
        return parsed

    async def _get_json(self, url: str, headers: dict[str, str]) -> Any:
        """GET con reintentos, re-login en 401/403 y backoff en 429/5xx."""
        last_exc: Exception | None = None
        current_headers = dict(headers)

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(
                        url, headers=current_headers, cookies=self.cookies
                    ) as response:
                        if response.status in (401, 403):
                            LOGGER.info("GET %s -> %s. Re-login y reintento.", url, response.status)
                            await self.async_login(reset_cookies=False)
                            current_headers = self._refresh_auth_headers(current_headers)
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            body = (await response.text())[:400]
                            LOGGER.warning(
                                "GET %s -> %s. Backoff: %s. Body=%s",
                                url,
                                response.status,
                                attempt + 1,
                                body,
                            )
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        if response.status != 200:
                            body = (await response.text())[:400]
                            raise Exception(f"HTTP {response.status} {body}")

                        return await response.json(content_type=None)
            except Exception as err:  # noqa: BLE001
                last_exc = err
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        raise last_exc or Exception("request_failed")

    async def async_login(self, reset_cookies: bool = False) -> bool:
        """Login robusto con retry limpiando cookies si hay bloqueo 400006."""
        async with self._login_lock:
            if reset_cookies:
                self._clear_cookies()
                self._clear_auth()

            data = dict(LOGIN_DATA)
            data.update({"loginID": self.username, "password": self.password})
            headers = dict(LOGIN_HEADERS)

            for attempt in range(2):
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.post(
                        LOGIN_URL, headers=headers, cookies=self.cookies, data=data
                    ) as response:
                        text = await response.text()
                        if response.status != 200:
                            if "security issues" in text or "400006" in text:
                                LOGGER.warning(
                                    "Login bloqueado por seguridad. Reintentamos con cookies nuevas."
                                )
                                self._clear_cookies()
                                self._clear_auth()
                                continue
                            raise Exception(f"login_failed_http {response.status} {text[:300]}")

                        try:
                            payload = await response.json(content_type=None)
                        except Exception as err:  # noqa: BLE001
                            raise Exception(f"login_failed_parse {text[:300]}") from err

                        user_info = payload.get("userInfo") or {}
                        self.uid = user_info.get("UID")
                        self.signature = user_info.get("UIDSignature")
                        self.timestamp = user_info.get("signatureTimestamp")

                        if not (self.uid and self.signature and self.timestamp):
                            self._clear_cookies()
                            self._clear_auth()
                            if attempt == 0:
                                continue
                            raise Exception("login_failed_tokens")

                        return True

        raise Exception("login_failed")

    async def async_get_contracts(self) -> dict[str, list[dict[str, Any]]]:
        """Listado de contratos con re-login si la API devuelve 0 transitoriamente."""
        data = await self._get_json(CONTRACTS_URL, self._auth_headers())
        parsed = self._parse_contracts(data)

        if parsed["information"]:
            return parsed

        LOGGER.warning("La API devolvió 0 contratos. Re-login y segundo intento...")
        await self.async_login(reset_cookies=True)
        data = await self._get_json(CONTRACTS_URL, self._auth_headers())
        return self._parse_contracts(data)

    async def async_get_invoices(self, house_id: str, contract_id: str) -> Any:
        """Obtiene las facturas del contrato."""
        url = INVOICES_URL.format(house_id, contract_id)
        return await self._get_json(url, self._auth_headers(REFERER_BILLING))

    async def async_get_costs(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Obtiene el acumulado de consumo y costes."""
        url = COSTS_URL.format(house_id, contract_id)
        response = await self._get_json(url, self._auth_headers())
        base = {
            "totalDays": 0,
            "consumption": 0,
            "amount": 0,
            "amountVariable": 0,
            "amountFixed": 0,
            "averageAmount": 0,
        }
        for key in base:
            base[key] = response.get(key, 0)
        return base

    async def async_get_next_invoice(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Próxima factura: tolera estados 'no disponible' devolviendo 0s."""
        url = NEXT_INVOICE_URL.format(house_id, contract_id)
        headers = self._auth_headers(REFERER_BILLING)
        base = {"amount": 0, "amountVariable": 0, "amountFixed": 0}
        last_exc: Exception | None = None

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as response:
                        if response.status == 200:
                            payload = await response.json(content_type=None)
                            return {
                                "amount": payload.get("amount", 0),
                                "amountVariable": payload.get("amountVariable", 0),
                                "amountFixed": payload.get("amountFixed", 0),
                            }

                        if response.status in (401, 403):
                            LOGGER.info(
                                "Invoice estimate %s -> %s. Re-login y reintento.",
                                url,
                                response.status,
                            )
                            await self.async_login(reset_cookies=False)
                            headers = self._auth_headers(REFERER_BILLING)
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            body = (await response.text())[:400]
                            LOGGER.warning(
                                "Invoice estimate %s -> %s. Backoff (%s). Body=%s",
                                url,
                                response.status,
                                attempt + 1,
                                body,
                            )
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        if response.status in (400, 404):
                            text = (await response.text())[:400]
                            if (
                                "InvoiceEstimateNotAvailableException" in text
                                or "invoice estimate" in text.lower()
                                or "not available" in text.lower()
                            ):
                                LOGGER.info(
                                    "Invoice estimate no disponible para %s/%s. Devolviendo 0s.",
                                    house_id,
                                    contract_id,
                                )
                                return base

                            LOGGER.info(
                                "Invoice estimate %s -> %s. Respuesta=%s. Devolviendo 0s.",
                                url,
                                response.status,
                                text,
                            )
                            return base

                        text = (await response.text())[:400]
                        raise Exception(f"HTTP {response.status} {text}")
            except Exception as err:  # noqa: BLE001
                last_exc = err
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning(
            "Fallo persistente obteniendo invoice estimate %s/%s (%s). Devolviendo 0s.",
            house_id,
            contract_id,
            last_exc,
        )
        return base

    async def async_get_virtual_battery_history(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Histórico de batería virtual; 404 conocido -> {}."""
        url = VIRTUAL_BATTERY_HISTORY_URL.format(house_id, contract_id)
        headers = self._auth_headers()
        last_exc: Exception | None = None

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as response:
                        if response.status == 200:
                            return await response.json(content_type=None)

                        if response.status in (401, 403):
                            LOGGER.info(
                                "VB history %s -> %s. Re-login y reintento.",
                                url,
                                response.status,
                            )
                            await self.async_login(reset_cookies=False)
                            headers = self._auth_headers()
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            body = (await response.text())[:400]
                            LOGGER.warning(
                                "VB history %s -> %s. Backoff (%s). Body=%s",
                                url,
                                response.status,
                                attempt + 1,
                                body,
                            )
                            await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        if response.status in (400, 404):
                            text = (await response.text())[:400]
                            if (
                                "BatteryHistoryNotFoundException" in text
                                or "not found" in text.lower()
                            ):
                                LOGGER.info(
                                    "VB history no disponible para %s/%s. Devolviendo {}.",
                                    house_id,
                                    contract_id,
                                )
                                return {}

                            LOGGER.info(
                                "VB history %s -> %s. Respuesta=%s. Devolviendo {}.",
                                url,
                                response.status,
                                text,
                            )
                            return {}

                        text = (await response.text())[:400]
                        raise Exception(f"HTTP {response.status} {text}")
            except Exception as err:  # noqa: BLE001
                last_exc = err
                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning(
            "Fallo persistente obteniendo VB history %s/%s (%s). Devolviendo {}.",
            house_id,
            contract_id,
            last_exc,
        )
        return {}

    async def async_get_house_details(self, house_id: str) -> Any:
        """Obtiene el detalle de una vivienda."""
        url = HOUSES_URL.format(house_id)
        return await self._get_json(url, self._auth_headers())

    async def _fetch_contract_data(self, contract: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Carga en paralelo todos los datos de un contrato."""
        house_id = contract["house_id"]
        contract_id = contract["contract_id"]
        tasks = [
            self.async_get_house_details(house_id),
            self.async_get_invoices(house_id, contract_id),
            self.async_get_costs(house_id, contract_id),
            self.async_get_next_invoice(house_id, contract_id),
        ]

        has_virtual_battery = (contract.get("contractType") or "").upper() == "ELECTRICITY"
        if has_virtual_battery:
            tasks.append(self.async_get_virtual_battery_history(house_id, contract_id))

        results = await asyncio.gather(*tasks)
        house_data, invoices_data, costs_data, next_invoice_data, *vb_results = results

        return contract_id, {
            "contracts": contract,
            "house_data": house_data,
            "invoices": invoices_data,
            "costs": costs_data,
            "nextInvoice": next_invoice_data,
            "virtual_battery_history": vb_results[0] if vb_results else None,
        }

    async def fetch_all_data(self) -> dict[str, Any]:
        """Carga de todos los datos de contratos (o del seleccionado)."""
        if not (self.uid and self.signature and self.timestamp):
            await self.async_login()

        contracts_data = await self.async_get_contracts()
        contracts_list = (contracts_data or {}).get("information") or []

        if self.selected_contract_id:
            contracts_list = [
                contract
                for contract in contracts_list
                if contract.get("contract_id") == self.selected_contract_id
            ]

        if not contracts_list:
            raise Exception("no_contracts")

        payloads = await asyncio.gather(
            *(self._fetch_contract_data(contract) for contract in contracts_list)
        )
        return {contract_id: payload for contract_id, payload in payloads}
