import logging
from datetime import timedelta

LOGGER = logging.getLogger(__name__)

# Dominio del componente
DOMAIN = "repsol_vivit"

# Opciones de configuración
CONF_UPDATE_INTERVAL_MINUTES = "update_interval_minutes"
CONF_ENABLE_VIRTUAL_BATTERY_SENSORS = "enable_virtual_battery_sensors"
DEFAULT_UPDATE_INTERVAL_MINUTES = 120
MIN_UPDATE_INTERVAL_MINUTES = 30
MAX_UPDATE_INTERVAL_MINUTES = 720
DEFAULT_ENABLE_VIRTUAL_BATTERY_SENSORS = True

# Endpoints base
LOGIN_URL = "https://login.repsol.es/accounts.login"
BOOTSTRAP_URL = "https://login.repsol.es/accounts.webSdkBootstrap"
BASE_API_URL = "https://areacliente.repsol.es/api/proxy/"

CONTRACTS_URL = f"{BASE_API_URL}houses"
HOUSES_URL = f"{BASE_API_URL}houses/{{}}"
INVOICES_URL = f"{BASE_API_URL}houses/{{}}/products/{{}}/invoices?limit=10"
COSTS_URL = f"{BASE_API_URL}houses/{{}}/products/{{}}/consumption/accumulated"
NEXT_INVOICE_URL = f"{BASE_API_URL}houses/{{}}/products/{{}}/consumption/invoice-estimate"
VIRTUAL_BATTERY_HISTORY_URL = f"{BASE_API_URL}houses/{{}}/products/{{}}/virtual-battery/history"

# Intervalo de actualización
UPDATE_INTERVAL = timedelta(minutes=DEFAULT_UPDATE_INTERVAL_MINUTES)

# --- Referers canónicos (nuevo) ---
REFERER_PRODUCTS = "https://areacliente.repsol.es/productos-y-servicios"
REFERER_BILLING  = "https://areacliente.repsol.es/mis-facturas"

# Cabeceras comunes
COMMON_HEADERS = {
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "sec-ch-ua": '^\\^Google',
    "sec-ch-ua-mobile": "?0",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Market": "ML",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}

# Cabeceras para login
LOGIN_HEADERS = {
    **COMMON_HEADERS,
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Origin": "https://areacliente.repsol.es",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

# Cabeceras para consultas autenticadas (por defecto Products)
CONTRACTS_HEADERS = {
    **COMMON_HEADERS,
    "Origin": "https://areacliente.repsol.es",
    "Referer": REFERER_PRODUCTS,  # <-- por defecto
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "x-origin": "WEB",
    "Accept": "application/json, text/plain, */*",
}

# Payload base para login Gigya
LOGIN_DATA = {
    "targetEnv": "jssdk",
    "includeUserInfo": "true",
    "include": "profile,data,preferences,",
    "lang": "en",
    "sdk": "js_latest",
    "APIKey": "3_jm2BKK8jIBHi9nXHP8OsQ-HNgJKWxgd1o6kbNqsWvhUy0hhD1eeCpHC-qCrrWe8D",
    "format": "json",
}
