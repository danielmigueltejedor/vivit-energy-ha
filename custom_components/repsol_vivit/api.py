"""API client for Vivit/Repsol."""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import aiohttp

from .const import (
    BOOTSTRAP_URL,
    COMMON_HEADERS,
    CONTRACTS_HEADERS,
    CONTRACTS_URL,
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
from .helpers import redact_provider_url

REQ_TIMEOUT = 15
REQUEST_RETRIES = 3
RETRY_SLEEP_BASE = 1.0
MAX_RELOGINS = 2
COOKIE_DOMAINS = ("login.repsol.es", "areacliente.repsol.es", "repsol.es")
# Si el último login falló hace menos de este tiempo, no volvemos a golpear Gigya
# (evita reintentos concurrentes / tras restart ante un bloqueo temporal).
LOGIN_FAILURE_COOLDOWN = 300.0
# Cooldown extendido cuando Gigya devuelve rate-limit explícito.
LOGIN_RATE_LIMIT_COOLDOWN = 900.0
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


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
        self.cookies: dict[str, str] = {}
        self._login_lock = asyncio.Lock()
        self._last_login_fail_at: float = 0.0
        self._last_login_err: str | None = None

    def _validated_id(self, value: str, name: str) -> str:
        """Valida IDs remotos antes de construir URLs."""
        if not isinstance(value, str) or not ID_RE.fullmatch(value):
            raise Exception(f"invalid_{name}")
        return value

    def _clear_auth(self) -> None:
        """Borra tokens en memoria para forzar relogin limpio."""
        self.uid = None
        self.signature = None
        self.timestamp = None

    def _clear_cookies(self) -> None:
        """Limpia cookies explícitas y las del dominio Repsol en la sesión compartida."""
        self.cookies = {}
        jar = self.session.cookie_jar
        for domain in COOKIE_DOMAINS:
            try:
                jar.clear_domain(domain)
            except Exception:  # noqa: BLE001
                pass

    async def _bootstrap_gigya(self) -> None:
        """Obtiene un gmid fresco de Gigya antes de accounts.login.

        Gigya rechaza `accounts.login` con targetEnv=jssdk si las cookies
        bootstrap (gmid/ucid/gig_bootstrap_*) están caducadas o no coinciden
        con la APIKey, devolviendo HTTP 200 + errorCode 400006.
        """
        # Partimos de cookies vacías; el POST de login las rellena desde el bootstrap.
        self.cookies = {}
        params = {
            "apiKey": LOGIN_DATA["APIKey"],
            "format": "json",
            "pageURL": "https://areacliente.repsol.es/",
            "sdk": "js_latest",
        }
        try:
            async with asyncio.timeout(REQ_TIMEOUT):
                async with self.session.get(
                    BOOTSTRAP_URL,
                    params=params,
                    headers=dict(COMMON_HEADERS),
                    cookies={},
                ) as response:
                    # Gigya manda Set-Cookie (gmid, ucid, hasGmid, gig_bootstrap_*).
                    # aiohttp los guarda en el cookie_jar de la sesión; copiamos además
                    # a self.cookies para pasarlos explícitamente en el POST.
                    for key, morsel in response.cookies.items():
                        self.cookies[key] = morsel.value
                    await response.read()
        except Exception as err:  # noqa: BLE001
            LOGGER.debug("Bootstrap Gigya falló (%s). Continuamos con login directo.", err)

    async def _warmup_areacliente(self) -> None:
        """Visita el portal areacliente tras el login para capturar su cookie de sesión.

        Algunos 401 `The user signature provided is not valid` desaparecen si el
        backend ha podido emitir su propia cookie de sesión antes del primer GET
        a la API; GET al portal deja que el BFF set-cookie-ee lo que necesite.
        """
        try:
            async with asyncio.timeout(REQ_TIMEOUT):
                async with self.session.get(
                    REFERER_PRODUCTS,
                    headers=dict(COMMON_HEADERS),
                    cookies=self.cookies,
                    allow_redirects=True,
                ) as response:
                    for key, morsel in response.cookies.items():
                        self.cookies[key] = morsel.value
                    await response.read()
        except Exception as err:  # noqa: BLE001
            LOGGER.debug("Warmup areacliente falló (%s).", err)

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
        if not isinstance(data, list):
            return parsed
        for house in data:
            if not isinstance(house, dict):
                continue
            house_id = house.get("code")
            for contract in house.get("contracts") or []:
                if not isinstance(contract, dict):
                    continue
                contract_id = contract.get("code")
                if (
                    not isinstance(house_id, str)
                    or not ID_RE.fullmatch(house_id)
                    or not isinstance(contract_id, str)
                    or not ID_RE.fullmatch(contract_id)
                ):
                    continue
                parsed["information"].append(
                    {
                        "contract_id": contract_id,
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
        log_url = redact_provider_url(url)
        relogins = 0
        attempt = 0

        while attempt <= REQUEST_RETRIES:
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(
                        url, headers=current_headers, cookies=self.cookies
                    ) as response:
                        if response.status in (401, 403):
                            if relogins >= MAX_RELOGINS:
                                raise Exception(f"http_{response.status}")
                            reset = relogins >= 1
                            LOGGER.info(
                                "GET %s -> %s. Re-login (reset_cookies=%s) y reintento.",
                                log_url,
                                response.status,
                                reset,
                            )
                            await self.async_login(reset_cookies=reset)
                            current_headers = self._refresh_auth_headers(current_headers)
                            relogins += 1
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            if attempt < REQUEST_RETRIES:
                                LOGGER.debug(
                                    "GET %s -> %s. Reintento %s/%s.",
                                    log_url,
                                    response.status,
                                    attempt + 1,
                                    REQUEST_RETRIES + 1,
                                )
                                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            else:
                                LOGGER.warning(
                                    "GET %s -> %s. Sin más reintentos en este ciclo.",
                                    log_url,
                                    response.status,
                                )
                            attempt += 1
                            continue

                        if response.status != 200:
                            raise Exception(f"http_{response.status}")

                        return await response.json(content_type=None)
            except Exception as err:  # noqa: BLE001
                last_exc = err
                if str(err).startswith("http_"):
                    raise
                if attempt < REQUEST_RETRIES:
                    LOGGER.debug(
                        "GET %s excepción (reintento %s/%s): %s",
                        log_url,
                        attempt + 1,
                        REQUEST_RETRIES + 1,
                        err,
                    )
                    await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                else:
                    LOGGER.warning("GET %s agotó reintentos: %s", log_url, err)
                attempt += 1

        raise last_exc or Exception("request_failed")

    async def async_login(self, reset_cookies: bool = False) -> bool:
        """Login robusto con retry limpiando cookies si hay bloqueo 400006."""
        prev_signature = self.signature
        async with self._login_lock:
            # Otra task ya refrescó tokens mientras esperábamos el lock.
            if self.signature is not None and self.signature != prev_signature:
                return True
            # Cooldown: si hace <LOGIN_FAILURE_COOLDOWN que falló, no insistimos.
            # Evita que 5-10 peticiones concurrentes disparen 5-10 logins seguidos
            # cuando Gigya está devolviendo 400006 / rate limit.
            if self._last_login_err is not None:
                since_fail = time.monotonic() - self._last_login_fail_at
                cooldown = (
                    LOGIN_RATE_LIMIT_COOLDOWN
                    if "403048" in self._last_login_err or "rate limit" in self._last_login_err.lower()
                    else LOGIN_FAILURE_COOLDOWN
                )
                if since_fail < cooldown:
                    raise Exception(self._last_login_err)
            if reset_cookies:
                self._clear_cookies()
                self._clear_auth()

            # Fresh gmid/ucid cookies via accounts.webSdkBootstrap para evitar 400006.
            await self._bootstrap_gigya()

            data = dict(LOGIN_DATA)
            data.update({"loginID": self.username, "password": self.password})
            headers = dict(LOGIN_HEADERS)

            try:
                for attempt in range(2):
                    async with asyncio.timeout(REQ_TIMEOUT):
                        async with self.session.post(
                            LOGIN_URL, headers=headers, cookies=self.cookies, data=data
                        ) as response:
                            if response.status != 200:
                                text = await response.text()
                                if "security issues" in text or "400006" in text:
                                    LOGGER.warning(
                                        "Login bloqueado por seguridad (HTTP %s). Reintentamos con cookies nuevas.",
                                        response.status,
                                    )
                                    self._clear_cookies()
                                    self._clear_auth()
                                    if attempt == 0:
                                        await self._bootstrap_gigya()
                                        continue
                                    raise Exception(
                                        f"login_failed_blocked {response.status}"
                                    )
                                raise Exception(f"login_failed_http {response.status}")

                            try:
                                payload = await response.json(content_type=None)
                            except Exception as err:  # noqa: BLE001
                                raise Exception("login_failed_parse") from err

                            # Gigya devuelve HTTP 200 incluso en errores; hay que inspeccionar errorCode.
                            error_code = payload.get("errorCode", 0) or 0
                            if error_code:
                                # 403042: loginID/password incorrectos (reauth real).
                                if error_code == 403042:
                                    raise Exception(f"login_failed_credentials {error_code}")
                                # 400006 y similares: bloqueo temporal de seguridad.
                                if error_code in (400006, 400125, 403047, 500001):
                                    LOGGER.warning(
                                        "Gigya errorCode=%s. Reintento con cookies nuevas.",
                                        error_code,
                                    )
                                    self._clear_cookies()
                                    self._clear_auth()
                                    if attempt == 0:
                                        await self._bootstrap_gigya()
                                        continue
                                    raise Exception(
                                        f"login_failed_blocked {error_code}"
                                    )
                                # Resto: transitorio. Reintento una vez.
                                LOGGER.warning(
                                    "Gigya errorCode=%s. Reintento.",
                                    error_code,
                                )
                                if attempt == 0:
                                    continue
                                raise Exception(
                                    f"login_failed_gigya {error_code}"
                                )

                            user_info = payload.get("userInfo") or {}
                            self.uid = user_info.get("UID")
                            self.signature = user_info.get("UIDSignature")
                            self.timestamp = user_info.get("signatureTimestamp")

                            if not (self.uid and self.signature and self.timestamp):
                                LOGGER.warning(
                                    "Login Gigya 200 sin tokens. errorCode=%s.",
                                    payload.get("errorCode"),
                                )
                                self._clear_cookies()
                                self._clear_auth()
                                if attempt == 0:
                                    continue
                                raise Exception("login_failed_tokens")

                            # Login OK: limpiamos cooldown de error.
                            self._last_login_err = None
                            self._last_login_fail_at = 0.0
                            LOGGER.info("Login Gigya completado correctamente.")
                            await self._warmup_areacliente()
                            return True

                raise Exception("login_failed")
            except Exception as err:
                self._last_login_err = str(err) or "login_failed"
                self._last_login_fail_at = time.monotonic()
                raise

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
        safe_house_id = self._validated_id(house_id, "house_id")
        safe_contract_id = self._validated_id(contract_id, "contract_id")
        url = INVOICES_URL.format(safe_house_id, safe_contract_id)
        return await self._get_json(url, self._auth_headers(REFERER_BILLING))

    async def async_get_costs(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Obtiene el acumulado de consumo y costes."""
        safe_house_id = self._validated_id(house_id, "house_id")
        safe_contract_id = self._validated_id(contract_id, "contract_id")
        url = COSTS_URL.format(safe_house_id, safe_contract_id)
        response = await self._get_json(url, self._auth_headers())
        base = {
            "totalDays": 0,
            "consumption": 0,
            "amount": 0,
            "amountVariable": 0,
            "amountFixed": 0,
            "averageAmount": 0,
        }
        if not isinstance(response, dict):
            return base
        for key in base:
            base[key] = response.get(key, 0)
        return base

    async def async_get_next_invoice(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Próxima factura: tolera estados 'no disponible' devolviendo 0s."""
        safe_house_id = self._validated_id(house_id, "house_id")
        safe_contract_id = self._validated_id(contract_id, "contract_id")
        url = NEXT_INVOICE_URL.format(safe_house_id, safe_contract_id)
        headers = self._auth_headers(REFERER_BILLING)
        log_url = redact_provider_url(url)
        base = {"amount": 0, "amountVariable": 0, "amountFixed": 0}
        last_exc: Exception | None = None
        relogins = 0

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as response:
                        if response.status == 200:
                            payload = await response.json(content_type=None)
                            if not isinstance(payload, dict):
                                raise Exception("invalid_invoice_estimate_response")
                            return {
                                "amount": payload.get("amount", 0),
                                "amountVariable": payload.get("amountVariable", 0),
                                "amountFixed": payload.get("amountFixed", 0),
                            }

                        if response.status in (401, 403):
                            if relogins >= MAX_RELOGINS:
                                raise Exception(f"http_{response.status}")
                            reset = relogins >= 1
                            LOGGER.info(
                                "Invoice estimate %s -> %s. Re-login (reset_cookies=%s) y reintento.",
                                log_url,
                                response.status,
                                reset,
                            )
                            await self.async_login(reset_cookies=reset)
                            headers = self._auth_headers(REFERER_BILLING)
                            relogins += 1
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            LOGGER.debug(
                                "Invoice estimate %s -> %s. Reintento %s.",
                                log_url,
                                response.status,
                                attempt + 1,
                            )
                            if attempt < REQUEST_RETRIES:
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
                                    "Invoice estimate no disponible. Devolviendo 0s.",
                                )
                                return base

                            LOGGER.info(
                                "Invoice estimate %s -> %s. Devolviendo 0s.",
                                log_url,
                                response.status,
                            )
                            return base

                        raise Exception(f"http_{response.status}")
            except Exception as err:  # noqa: BLE001
                last_exc = err
                if str(err) in {"http_401", "http_403"}:
                    break
                if attempt < REQUEST_RETRIES:
                    await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning(
            "Fallo persistente obteniendo invoice estimate (%s). Devolviendo 0s.",
            last_exc,
        )
        return base

    async def async_get_virtual_battery_history(self, house_id: str, contract_id: str) -> dict[str, Any]:
        """Histórico de batería virtual; 404 conocido -> {}."""
        safe_house_id = self._validated_id(house_id, "house_id")
        safe_contract_id = self._validated_id(contract_id, "contract_id")
        url = VIRTUAL_BATTERY_HISTORY_URL.format(safe_house_id, safe_contract_id)
        headers = self._auth_headers()
        log_url = redact_provider_url(url)
        last_exc: Exception | None = None
        relogins = 0

        for attempt in range(REQUEST_RETRIES + 1):
            try:
                async with asyncio.timeout(REQ_TIMEOUT):
                    async with self.session.get(url, headers=headers, cookies=self.cookies) as response:
                        if response.status == 200:
                            payload = await response.json(content_type=None)
                            if not isinstance(payload, dict):
                                raise Exception("invalid_virtual_battery_response")
                            return payload

                        if response.status in (401, 403):
                            if relogins >= MAX_RELOGINS:
                                raise Exception(f"http_{response.status}")
                            reset = relogins >= 1
                            LOGGER.info(
                                "VB history %s -> %s. Re-login (reset_cookies=%s) y reintento.",
                                log_url,
                                response.status,
                                reset,
                            )
                            await self.async_login(reset_cookies=reset)
                            headers = self._auth_headers()
                            relogins += 1
                            continue

                        if response.status in (429, 500, 502, 503, 504):
                            LOGGER.debug(
                                "VB history %s -> %s. Reintento %s.",
                                log_url,
                                response.status,
                                attempt + 1,
                            )
                            if attempt < REQUEST_RETRIES:
                                await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))
                            continue

                        if response.status in (400, 404):
                            text = (await response.text())[:400]
                            if (
                                "BatteryHistoryNotFoundException" in text
                                or "not found" in text.lower()
                            ):
                                LOGGER.info(
                                    "VB history no disponible. Devolviendo {}.",
                                )
                                return {}

                            LOGGER.info(
                                "VB history %s -> %s. Devolviendo {}.",
                                log_url,
                                response.status,
                            )
                            return {}

                        raise Exception(f"http_{response.status}")
            except Exception as err:  # noqa: BLE001
                last_exc = err
                if str(err) in {"http_401", "http_403"}:
                    break
                if attempt < REQUEST_RETRIES:
                    await asyncio.sleep(RETRY_SLEEP_BASE * (attempt + 1))

        LOGGER.warning(
            "Fallo persistente obteniendo VB history (%s). Devolviendo {}.",
            last_exc,
        )
        return {}

    async def async_get_house_details(self, house_id: str) -> Any:
        """Obtiene el detalle de una vivienda."""
        safe_house_id = self._validated_id(house_id, "house_id")
        url = HOUSES_URL.format(safe_house_id)
        return await self._get_json(url, self._auth_headers())

    async def _fetch_contract_data(self, contract: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Carga en paralelo todos los datos de un contrato.

        Si un endpoint falla (p. ej. facturas con HTTP 500), se usan valores por
        defecto y el resto de sensores sigue actualizando (evita 'unavailable'
        en todo el dispositivo tras reset o caída parcial de la API).
        """
        house_id = contract["house_id"]
        contract_id = contract["contract_id"]
        tasks = [
            self.async_get_house_details(house_id),
            self.async_get_invoices(house_id, contract_id),
            self.async_get_costs(house_id, contract_id),
            self.async_get_next_invoice(house_id, contract_id),
        ]

        labels = ("house_details", "invoices", "costs", "next_invoice")
        defaults: list[Any] = [
            {},
            [],
            {
                "totalDays": 0,
                "consumption": 0,
                "amount": 0,
                "amountVariable": 0,
                "amountFixed": 0,
                "averageAmount": 0,
            },
            {"amount": 0, "amountVariable": 0, "amountFixed": 0},
        ]

        has_virtual_battery = (contract.get("contractType") or "").upper() == "ELECTRICITY"
        if has_virtual_battery:
            tasks.append(self.async_get_virtual_battery_history(house_id, contract_id))
            labels = (*labels, "virtual_battery_history")
            defaults.append({})

        results = await asyncio.gather(*tasks, return_exceptions=True)
        resolved: list[Any] = []
        for result, label, default in zip(results, labels, defaults, strict=True):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                LOGGER.warning(
                    "Fallo parcial %s para el contrato seleccionado: %s "
                    "(se usan datos por defecto).",
                    label,
                    result,
                )
                resolved.append(default)
            else:
                resolved.append(result)

        if has_virtual_battery:
            (
                house_data,
                invoices_data,
                costs_data,
                next_invoice_data,
                vb_hist,
            ) = resolved
        else:
            house_data, invoices_data, costs_data, next_invoice_data = resolved
            vb_hist = None

        return contract_id, {
            "contracts": contract,
            "house_data": house_data,
            "invoices": invoices_data,
            "costs": costs_data,
            "nextInvoice": next_invoice_data,
            "virtual_battery_history": vb_hist,
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
