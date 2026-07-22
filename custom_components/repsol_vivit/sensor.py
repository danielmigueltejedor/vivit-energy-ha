"""Sensors for Vivit Energy Portal (Unofficial)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER
from .helpers import (
    build_device_identifier,
    get_contract_snapshot,
    get_latest_invoice,
    get_latest_redemption,
    is_virtual_battery_enabled,
)

# Sensores base (nombres LIMPIOS; el nombre del dispositivo es quien lleva "Contrato N (…)").
SENSOR_DEFS = [
    # Comunes
    {"name": "Consumo", "var": "consumption", "class": SensorDeviceClass.ENERGY},
    {"name": "Días totales", "var": "totalDays", "class": None},
    {"name": "Estado contrato", "var": "status", "class": None},
    {"name": "Importe", "var": "amount", "class": SensorDeviceClass.MONETARY},
    {"name": "Importe fijo", "var": "amountFixed", "class": SensorDeviceClass.MONETARY},
    {"name": "Importe variable", "var": "amountVariable", "class": SensorDeviceClass.MONETARY},
    {"name": "Promedio diario", "var": "averageAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Última factura", "var": "lastInvoiceAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Próxima factura", "var": "nextInvoiceAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Variable próxima factura", "var": "nextInvoiceVariableAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Fijo próxima factura", "var": "nextInvoiceFixedAmount", "class": SensorDeviceClass.MONETARY},

    # Solo electricidad
    {"name": "Potencia contratada", "var": "power", "class": SensorDeviceClass.POWER},
    {"name": "Tarifa", "var": "fee", "class": None},
    {"name": "Precio potencia punta", "var": "pricesPowerPunta", "class": SensorDeviceClass.MONETARY},
    {"name": "Precio potencia valle", "var": "pricesPowerValle", "class": SensorDeviceClass.MONETARY},
    {"name": "Precio energía", "var": "pricesEnergyAmount", "class": SensorDeviceClass.MONETARY},

    # Solo gas
    {"name": "Término fijo gas", "var": "fixedTerm", "class": SensorDeviceClass.MONETARY},
    {"name": "Término variable gas", "var": "variableTerm", "class": SensorDeviceClass.MONETARY},
]

# Sensores de batería virtual (solo electricidad y solo si hay datos)
VB_DEFS = [
    {"name": "Batería virtual — € pendientes", "var": "pendingAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Batería virtual — kWh disponibles", "var": "kwhAvailable", "class": SensorDeviceClass.ENERGY},
    {"name": "Batería virtual — € canjeados", "var": "appliedAmount", "class": SensorDeviceClass.MONETARY},
    {"name": "Batería virtual — kWh canjeados", "var": "kwhRedeemed", "class": SensorDeviceClass.ENERGY},
    {"name": "Batería virtual — kWh totales", "var": "totalKWh", "class": SensorDeviceClass.ENERGY},
    {"name": "Batería virtual — precio excedentes", "var": "excedentsPrice", "class": SensorDeviceClass.MONETARY},
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    """Crea sensores a partir del coordinator."""
    stored = hass.data[DOMAIN][entry.entry_id]
    coordinator = stored["coordinator"]

    contract_id = stored.get("contract_id") or entry.data.get("contract_id")
    contract_type = stored.get("contract_type") or entry.data.get("contract_type")
    device_name = stored.get("device_name") or entry.data.get("device_name")
    enable_virtual_battery = is_virtual_battery_enabled(entry.options)

    data: Dict[str, Dict[str, Any]] = coordinator.data or {}
    entities: List[SensorEntity] = []

    if contract_id and contract_id in data:
        # Creación modo 1-contrato (preferido)
        entities.extend(
            _build_contract_entities(
                data,
                contract_id,
                device_name,
                contract_type,
                coordinator,
                enable_virtual_battery,
            )
        )
    else:
        # Fallback: crear para todos los contratos del payload
        for cid in list(data.keys()):
            payload = data.get(cid) or {}
            cinfo = payload.get("contracts") or {}
            ctype = (cinfo.get("contractType") or "ELECTRICITY").upper()
            dev_name = f"Contrato (Auto) ({'Electricidad' if ctype == 'ELECTRICITY' else 'Gas'})"
            entities.extend(
                _build_contract_entities(
                    data,
                    cid,
                    dev_name,
                    ctype,
                    coordinator,
                    enable_virtual_battery,
                )
            )

    if not entities:
        LOGGER.error("No se han podido crear entidades: datos insuficientes.")
        return

    async_add_entities(entities, True)
    LOGGER.info("Añadidas %s entidades de sensor", len(entities))


def _build_contract_entities(
    full_data: Dict[str, Dict[str, Any]],
    contract_id: str,
    device_name: str | None,
    contract_type: str | None,
    coordinator,
    enable_virtual_battery: bool,
) -> List[SensorEntity]:
    """Construye todas las entidades para un contrato."""
    entities: List[SensorEntity] = []

    payload = full_data.get(contract_id) or {}
    cinfo = payload.get("contracts") or {}
    house_id = cinfo.get("house_id")

    ctype = (contract_type or cinfo.get("contractType") or "ELECTRICITY").upper()
    resolved_device_name = device_name or f"Contrato ({'Electricidad' if ctype == 'ELECTRICITY' else 'Gas'})"

    device = DeviceInfo(
        identifiers={(DOMAIN, build_device_identifier(house_id, contract_id))},
        name=resolved_device_name,
        manufacturer="Vivit Energy (unofficial)",
        model=("Electricidad" if ctype == "ELECTRICITY" else "Gas"),
        serial_number=str(contract_id),
        configuration_url="https://areacliente.repsol.es/productos-y-servicios",
    )

    # Sensores base
    for sd in SENSOR_DEFS:
        var = sd["var"]
        # Filtro tipo
        if ctype == "ELECTRICITY" and var in {"fixedTerm", "variableTerm"}:
            continue
        elif ctype == "GAS" and var in {"power", "fee", "pricesPowerPunta", "pricesPowerValle", "pricesEnergyAmount"}:
            continue  # no aplican a gas

        entities.append(
            VivitSensor(
                coordinator=coordinator,
                name=sd["name"],
                variable=var,
                device_class=sd["class"],
                device=device,
                house_id=house_id,
                contract_id=contract_id,
                contract_type=ctype,
            )
        )

    # Batería virtual (solo electricidad) si hay datos
    if enable_virtual_battery and ctype == "ELECTRICITY":
        vb = payload.get("virtual_battery_history") or {}
        if vb and any(vb.values()):
            for sd in VB_DEFS:
                entities.append(
                    VivitVBSensor(
                        coordinator=coordinator,
                        name=sd["name"],
                        variable=sd["var"],
                        device_class=sd["class"],
                        device=device,
                        house_id=house_id,
                        contract_id=contract_id,
                    )
                )
            # Último canje (si existe)
            last_red = get_latest_redemption(vb)
            if last_red:
                entities.append(
                    VivitVBSensor(
                        coordinator=coordinator,
                        name="Batería virtual — último importe canjeado",
                        variable="amount",
                        device_class=SensorDeviceClass.MONETARY,
                        device=device,
                        house_id=house_id,
                        contract_id=contract_id,
                        latest_redemption=True,
                        unique_id_suffix="last_redemption_amount",
                    )
                )
                entities.append(
                    VivitVBSensor(
                        coordinator=coordinator,
                        name="Batería virtual — últimos kWh canjeados",
                        variable="kWh",
                        device_class=SensorDeviceClass.ENERGY,
                        device=device,
                        house_id=house_id,
                        contract_id=contract_id,
                        latest_redemption=True,
                    )
                )

    return entities


class VivitBase(CoordinatorEntity, SensorEntity):
    """Base común para sensores Vivit."""

    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator,
        name: str,
        variable: str,
        device_class: Optional[SensorDeviceClass],
        device: DeviceInfo,
        house_id: str | None,
        contract_id: str,
        unique_id_suffix: str | None = None,
    ):
        super().__init__(coordinator)
        self._attr_name = name            # nombre visible del sensor (limpio)
        self.variable = variable
        self._attr_device_class = device_class
        self._device = device
        self.house_id = house_id
        self.contract_id = contract_id
        self._unique_id_suffix = unique_id_suffix or variable

    @property
    def unique_id(self) -> str:
        return f"{build_device_identifier(self.house_id, self.contract_id)}_{self._unique_id_suffix}"

    @property
    def device_info(self) -> DeviceInfo:
        return self._device

    @property
    def native_unit_of_measurement(self) -> Optional[str]:
        user_currency = self.hass.config.currency
        if self._attr_device_class == SensorDeviceClass.ENERGY:
            return "kWh"
        if self._attr_device_class == SensorDeviceClass.MONETARY:
            # variables de precio por kWh
            if self.variable in ("pricesEnergyAmount", "excedentsPrice"):
                return f"{user_currency}/kWh"
            return user_currency
        if self._attr_device_class == SensorDeviceClass.POWER:
            return "kW"
        return None


class VivitSensor(VivitBase):
    """Sensor principal (costes/estado/facturas/precios)."""

    def __init__(
        self,
        coordinator,
        name: str,
        variable: str,
        device_class: Optional[SensorDeviceClass],
        device: DeviceInfo,
        house_id: str,
        contract_id: str,
        contract_type: str,
    ):
        super().__init__(coordinator, name, variable, device_class, device, house_id, contract_id)
        self.contract_type = contract_type

    @property
    def native_value(self) -> Any:
        data = (self.coordinator.data or {}).get(self.contract_id) or {}
        contract_info, house_contract = get_contract_snapshot(
            self.coordinator.data, self.contract_id
        )

        # COSTES
        if self.variable in {"amount", "consumption", "totalDays", "amountVariable", "amountFixed", "averageAmount"}:
            return (data.get("costs") or {}).get(self.variable)

        # ÚLTIMA FACTURA
        if self.variable == "lastInvoiceAmount":
            obj = get_latest_invoice(data.get("invoices"))
            if not obj:
                return None
            return obj.get("amount") if "amount" in obj else obj.get("totalAmount")

        # PRÓXIMA FACTURA
        if self.variable in {"nextInvoiceAmount", "nextInvoiceVariableAmount", "nextInvoiceFixedAmount"}:
            nxt = data.get("nextInvoice") or {}
            if self.variable == "nextInvoiceAmount":
                return nxt.get("amount")
            if self.variable == "nextInvoiceVariableAmount":
                return nxt.get("amountVariable")
            if self.variable == "nextInvoiceFixedAmount":
                return nxt.get("amountFixed")

        # CAMPOS DE CONTRATO / PRECIOS
        if self.contract_type == "ELECTRICITY":
            if self.variable in {"status", "power", "fee"}:
                value = house_contract.get(self.variable)
                return value if value is not None else contract_info.get(self.variable)

            prices = house_contract.get("prices") or contract_info.get("prices") or {}
            if self.variable == "pricesPowerPunta":
                return _parse_price_list((prices.get("power") or []), 0)
            if self.variable == "pricesPowerValle":
                return _parse_price_list((prices.get("power") or []), 1)
            if self.variable == "pricesEnergyAmount":
                return _parse_price_list((prices.get("energy") or []), 0)

        if self.contract_type == "GAS":
            if self.variable in {"fixedTerm", "variableTerm", "status"}:
                # status desde house_contract o contract_info
                if self.variable == "status":
                    value = house_contract.get("status")
                    return value if value is not None else contract_info.get("status")
                energy_prices = (house_contract.get("prices") or {}).get("energy") or []
                if self.variable == "fixedTerm":
                    return _extract_gas_price(energy_prices, fixed=True)
                if self.variable == "variableTerm":
                    return _extract_gas_price(energy_prices, fixed=False)

        return None


class VivitVBSensor(VivitBase):
    """Sensores de Batería Virtual."""

    def __init__(
        self,
        coordinator,
        name: str,
        variable: str,
        device_class: Optional[SensorDeviceClass],
        device: DeviceInfo,
        house_id: str,
        contract_id: str,
        latest_redemption: bool = False,
        unique_id_suffix: str | None = None,
    ):
        super().__init__(
            coordinator,
            name,
            variable,
            device_class,
            device,
            house_id,
            contract_id,
            unique_id_suffix,
        )
        self.latest_redemption = latest_redemption

    @property
    def native_value(self) -> Any:
        data = (self.coordinator.data or {}).get(self.contract_id) or {}
        vb = data.get("virtual_battery_history") or {}
        if self.latest_redemption:
            latest = get_latest_redemption(vb)
            return latest.get(self.variable) if latest else None

        discounts = vb.get("discounts") or {}
        excedents = vb.get("excedents") or {}

        if self.variable == "pendingAmount":
            c = next((c for c in (discounts.get("contracts") or []) if c.get("productCode") == self.contract_id), None)
            return c.get("pendingAmount") if c else None

        if self.variable == "kwhAvailable":
            c = next((c for c in (discounts.get("contracts") or []) if c.get("productCode") == self.contract_id), None)
            pending = c.get("pendingAmount") if c else 0
            conv = next((d.get("conversionPrice") for d in (excedents.get("data") or [])), 0)
            try:
                return round(float(pending) / float(conv), 2) if conv else None
            except Exception:
                return None

        if self.variable == "appliedAmount":
            return excedents.get("appliedAmount")

        if self.variable == "kwhRedeemed":
            conv = next((d.get("conversionPrice") for d in (excedents.get("data") or [])), 0)
            try:
                return round(float(excedents.get("appliedAmount", 0)) / float(conv), 2) if conv else None
            except Exception:
                return None

        if self.variable == "totalKWh":
            try:
                return round(float(excedents.get("totalkWh", 0)), 2)
            except Exception:
                return None

        if self.variable == "excedentsPrice":
            return next((d.get("conversionPrice") for d in (excedents.get("data") or [])), None)

        return None


def _parse_price_list(prices: List[str], index: int) -> Any:
    """
    Extrae números tipo '0,1234' o '0.1234' de una lista de strings y devuelve float.
    Ej: ["Punta: 0,1234 €/kWh", "Valle: 0,0987 €/kWh"] -> 0.1234 (index=0)
    """
    parsed: List[str] = []
    for p in prices:
        m = re.search(r"(\d+,\d+|\d+\.\d+)", str(p))
        if m:
            parsed.append(m.group(1).replace(",", "."))
    try:
        return float(parsed[index])
    except Exception:
        return None


def _extract_gas_price(prices: List[str], fixed: bool) -> Any:
    """Busca 'Término Fijo' o 'Término Variable' y devuelve float."""
    key = "Término Fijo" if fixed else "Término Variable"
    for p in prices:
        if key in str(p):
            m = re.search(r"(\d+,\d+|\d+\.\d+)", str(p))
            if m:
                try:
                    return float(m.group(1).replace(",", "."))
                except Exception:
                    return None
    return None
