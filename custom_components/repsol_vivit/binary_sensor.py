"""Binary sensors for Vivit Energy Portal (Unofficial)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER
from .helpers import build_device_name


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    """Create binary sensors from the coordinator."""
    stored = hass.data[DOMAIN][entry.entry_id]
    coordinator = stored["coordinator"]

    contract_id = stored.get("contract_id") or entry.data.get("contract_id")
    contract_type = stored.get("contract_type") or entry.data.get("contract_type")
    device_name = stored.get("device_name") or entry.data.get("device_name")
    contract_index = stored.get("contract_index") or entry.data.get("contract_index")

    data: dict[str, dict[str, Any]] = coordinator.data or {}
    entities: list[BinarySensorEntity] = []

    if contract_id and contract_id in data:
        entities.append(
            VivitLastInvoicePaidBinarySensor(
                coordinator=coordinator,
                house_id=(data.get(contract_id) or {}).get("contracts", {}).get("house_id"),
                contract_id=contract_id,
                device_name=device_name,
                contract_type=contract_type,
                contract_index=contract_index,
            )
        )
    else:
        for cid, payload in data.items():
            contract = payload.get("contracts") or {}
            ctype = (contract.get("contractType") or "ELECTRICITY").upper()
            entities.append(
                VivitLastInvoicePaidBinarySensor(
                    coordinator=coordinator,
                    house_id=contract.get("house_id"),
                    contract_id=cid,
                    device_name=build_device_name(None, ctype),
                    contract_type=ctype,
                    contract_index=None,
                )
            )

    if not entities:
        LOGGER.error("No se han podido crear binary sensors: datos insuficientes.")
        return

    async_add_entities(entities, True)


class VivitLastInvoicePaidBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor indicating whether the last invoice is paid."""

    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator,
        house_id: str | None,
        contract_id: str,
        device_name: str | None,
        contract_type: str | None,
        contract_index: int | None,
    ) -> None:
        super().__init__(coordinator)
        self._attr_name = "Última factura pagada"
        self.house_id = house_id or "unknown_house"
        self.contract_id = contract_id
        self.contract_type = (contract_type or "ELECTRICITY").upper()
        self.device_name = device_name or build_device_name(contract_index, self.contract_type)

    @property
    def unique_id(self) -> str:
        return f"{self.house_id}_{self.contract_id}_lastInvoicePaid"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.house_id}_{self.contract_id}")},
            name=self.device_name,
            manufacturer="Vivit Energy (unofficial)",
            model=("Electricidad" if self.contract_type == "ELECTRICITY" else "Gas"),
            serial_number=str(self.contract_id),
            configuration_url="https://areacliente.repsol.es/productos-y-servicios",
        )

    @property
    def is_on(self) -> bool | None:
        data = (self.coordinator.data or {}).get(self.contract_id) or {}
        invoices = data.get("invoices")
        last_invoice = None

        if isinstance(invoices, list) and invoices:
            last_invoice = invoices[0]
        elif isinstance(invoices, dict):
            last_invoice = invoices

        if not last_invoice:
            return None

        return last_invoice.get("status") == "PAID"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = (self.coordinator.data or {}).get(self.contract_id) or {}
        invoices = data.get("invoices")
        last_invoice = None

        if isinstance(invoices, list) and invoices:
            last_invoice = invoices[0]
        elif isinstance(invoices, dict):
            last_invoice = invoices

        if not last_invoice:
            return {}

        return {
            "status": last_invoice.get("status"),
            "amount": last_invoice.get("amount") or last_invoice.get("totalAmount"),
        }
