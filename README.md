<div align="center">
  <img src="./custom_components/repsol_vivit/brand/logo.png" alt="Vivit Energy Portal logo" width="112">
  <h1>Vivit Energy Portal</h1>
  <p><strong>Repsol electricity, gas, invoices and virtual battery data in Home Assistant.</strong></p>

  <p>
    <a href="https://github.com/danielmigueltejedor/vivit-energy-ha/releases"><img src="https://img.shields.io/github/v/release/danielmigueltejedor/vivit-energy-ha?display_name=tag&sort=semver" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/Home%20Assistant-2025.1%2B-41BDF5?logo=home-assistant&logoColor=white" alt="Home Assistant 2025.1 or newer">
    <img src="https://img.shields.io/badge/HACS-default%20store-41BDF5" alt="Available in the default HACS store">
    <img src="https://img.shields.io/badge/status-stable-2EA44F" alt="Stable status">
    <a href="./LICENSE"><img src="https://img.shields.io/github/license/danielmigueltejedor/vivit-energy-ha" alt="MIT license"></a>
  </p>

  <p>
    <a href="#installation">Installation</a> ·
    <a href="#configuration">Configuration</a> ·
    <a href="#entities">Entities</a> ·
    <a href="https://github.com/danielmigueltejedor/vivit-energy-ha/issues">Support</a>
  </p>
</div>

---

Vivit Energy Portal is an unofficial Home Assistant integration for the Repsol / Vivit Energy customer portal. It brings contract, consumption, cost, invoice and virtual battery information into the same place as the rest of your home energy data.

> [!NOTE]
> Vivit Energy Portal is now available directly from the default HACS catalogue. No custom repository is required.

## Highlights

| Capability | What it provides |
|---|---|
| Electricity and gas | Contract and usage data for both energy services |
| Multiple contracts | Add and monitor more than one eligible contract |
| Cost visibility | Accumulated costs, estimates and power prices |
| Invoices | Latest invoice and next-invoice estimates when available |
| Virtual battery | Optional balance and related sensors for supported accounts |
| Native Home Assistant setup | Config flow, options, reauthentication and coordinator-based updates |

## Important notice

This integration relies on the private API used by the Repsol / Vivit Energy customer portal. Because that API is not public, Repsol may change it without notice. Temporary missing data may also originate from the provider's systems.

This project is not affiliated with, endorsed by or supported by Repsol S.A. It is intended for personal and informational use only.

## Installation

### HACS — recommended

1. Open **HACS → Integrations**.
2. Search for **Vivit Energy Portal**.
3. Select the integration and choose **Download**.
4. Restart Home Assistant.

[![Open Vivit Energy Portal in HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=danielmigueltejedor&repository=vivit-energy-ha&category=Integration)

You do **not** need to add this repository manually.

### Manual installation

1. Download the [latest release](https://github.com/danielmigueltejedor/vivit-energy-ha/releases/latest).
2. Copy `custom_components/repsol_vivit` to `/config/custom_components/repsol_vivit`.
3. Restart Home Assistant.

## Configuration

1. Go to **Settings → Devices & services → Add integration**.
2. Search for **Vivit Energy Portal**.
3. Sign in with your Repsol / Vivit Energy customer-area credentials.
4. Select the contract to add.
5. Repeat the flow for any additional supported contracts.

The integration options let you adjust the update interval and enable virtual battery entities where available. If the provider rejects saved credentials, Home Assistant starts a reauthentication flow.

## Entities

The exact entity IDs depend on your language, contract and entity registry.

| Example entity | Description |
|---|---|
| `sensor.vivit_amount` | Estimated total cost |
| `sensor.vivit_consumption` | Accumulated consumption in kWh |
| `sensor.vivit_last_invoice` | Latest issued invoice |
| `sensor.vivit_next_invoice` | Next invoice estimate |
| `sensor.vivit_power_price_punta` | Peak-period power price |
| `sensor.vivit_virtual_battery_*` | Virtual battery data, when available |

Availability and update frequency ultimately depend on the data exposed by the customer portal.

## Data and privacy

- Credentials are used only to authenticate against the Repsol / Vivit Energy service.
- The integration communicates with the provider using asynchronous Home Assistant networking.
- Do not share usernames, passwords, contract numbers, addresses or unredacted diagnostics in public issues.
- This integration displays provider data for convenience; always use official invoices and contractual documents for billing decisions.

## Support

Before opening an [issue](https://github.com/danielmigueltejedor/vivit-energy-ha/issues):

1. Update to the latest release and restart Home Assistant.
2. Check whether the customer portal itself is operating normally.
3. Search existing issues for the same symptom.
4. Collect relevant logs and remove all personal information.

A useful report includes the Home Assistant version, integration version, installation method, steps to reproduce and sanitized logs. Bug reports and feature requests have dedicated issue templates.

## Technical overview

- Fully asynchronous implementation with `asyncio` and `aiohttp`
- UI configuration through Home Assistant `config_flow`
- Scheduled updates through `DataUpdateCoordinator`
- Dynamic request headers and referers for the relevant portal sections
- Built-in options and reauthentication flows

See the [changelog](./CHANGELOG.md) for release history.

## License and trademarks

Vivit Energy Portal is released under the [MIT License](./LICENSE). Repsol and Vivit are trademarks of their respective owners.

<div align="center">
  <sub>Created and maintained by <a href="https://github.com/danielmigueltejedor">Daniel Miguel Tejedor</a>.</sub>
  <br><br>
  <a href="https://paypal.me/DanielMiguelTejedor"><img src="https://img.shields.io/badge/Support%20the%20project-PayPal-0070BA?logo=paypal&logoColor=white" alt="Support the project with PayPal"></a>
</div>
