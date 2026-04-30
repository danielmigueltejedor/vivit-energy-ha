# ⚡ Vivit Energy Portal for Home Assistant

![Version](https://img.shields.io/badge/version-2.1.10-blue.svg)
![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2025.1%2B-41BDF5?logo=home-assistant)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)
![GitHub](https://img.shields.io/badge/hosted%20on-GitHub-black?logo=github)

**Vivit Energy Portal for Home Assistant** is an unofficial custom integration that connects the **Repsol / Vivit Energy customer portal** with **Home Assistant**.

It allows you to monitor electricity and gas contracts, consumption, estimated costs, invoices and virtual battery data directly from Home Assistant.

> 🟡 This project is **not affiliated with, endorsed by, or supported by Repsol S.A.**  
> It is provided for personal and educational use only.

---

## ✨ Features

- Login using your Repsol / Vivit Energy customer area credentials
- Support for electricity and gas contracts
- Support for multiple contracts
- Automatic updates using Home Assistant's `DataUpdateCoordinator`
- Configurable update interval
- Reauthentication flow when credentials change
- Optional virtual battery sensors
- Entities for:
  - Accumulated consumption
  - Estimated cost
  - Last invoice
  - Next invoice estimate
  - Contract status
  - Power prices
  - Virtual battery data, when available

---

## ⚠️ Important notice

This integration depends on the private Repsol / Vivit Energy web API.

Because this API is not public:

- Repsol may change it at any time
- Some sensors may temporarily stop working after portal changes
- Missing or delayed data may depend on Repsol servers
- The integration may require updates if the customer portal changes

If something stops working, please open an issue and include logs without sharing personal data.

---

## 🧩 Installation

### Option 1 — HACS

If the integration is available in HACS, install it from there.

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=danielmigueltejedor&repository=vivit-energy-ha&category=Integration)

If it is not yet available in the default HACS list, you can add it as a custom repository:

1. Open **HACS**
2. Go to **Integrations**
3. Open the three-dot menu
4. Select **Custom repositories**
5. Add this repository URL:

```text
https://github.com/danielmigueltejedor/vivit-energy-ha
```

6. Category:

```text
Integration
```

7. Install the integration
8. Restart Home Assistant

---

### Option 2 — Manual installation

1. Download this repository from GitHub:

```text
https://github.com/danielmigueltejedor/vivit-energy-ha
```

2. Copy the integration folder:

```text
custom_components/repsol_vivit
```

to:

```text
/config/custom_components/repsol_vivit
```

3. Restart Home Assistant.

---

### Option 3 — Terminal / SSH installation

> Recommended if you use the **Terminal & SSH** add-on in Home Assistant OS or Supervised.

Run these commands in your Home Assistant terminal:

```bash
# 1) Prepare destination
mkdir -p /config/custom_components
rm -rf /config/custom_components/repsol_vivit

# 2) Clone the repository temporarily
cd /config
git clone --depth=1 https://github.com/danielmigueltejedor/vivit-energy-ha.git .vivit-tmp

# 3) Copy only the integration
cp -r .vivit-tmp/custom_components/repsol_vivit /config/custom_components/

# 4) Clean temporary files
rm -rf /config/.vivit-tmp

# 5) Restart Home Assistant
```

After installation, the integration should be located at:

```text
/config/custom_components/repsol_vivit
```

---

## 🔄 Updating

### HACS

If installed through HACS, update it from the HACS interface and restart Home Assistant.

### Manual / SSH update

```bash
# 1) Remove previous version
rm -rf /config/custom_components/repsol_vivit

# 2) Clone latest version
cd /config
git clone --depth=1 https://github.com/danielmigueltejedor/vivit-energy-ha.git .vivit-tmp

# 3) Copy updated integration
cp -r .vivit-tmp/custom_components/repsol_vivit /config/custom_components/

# 4) Clean temporary files
rm -rf /config/.vivit-tmp

# 5) Restart Home Assistant
```

---

## ⚙️ Configuration

1. In Home Assistant, go to:

```text
Settings → Devices & services → Add integration
```

2. Search for:

```text
Vivit Energy Portal (Unofficial)
```

3. Enter your Repsol / Vivit Energy customer area username and password
4. Select the contract you want to add
5. The entities will be created automatically

From the integration options screen you can configure:

- Update interval
- Virtual battery sensors
- Available integration options

---

## 📊 Created entities

Entity names may vary depending on your Home Assistant language, entity registry and contract configuration.

Common entities include:

| Entity | Description |
|---|---|
| `sensor.vivit_amount` | Estimated total cost |
| `sensor.vivit_consumption` | Accumulated consumption in kWh |
| `sensor.vivit_last_invoice` | Last issued invoice |
| `sensor.vivit_next_invoice` | Next invoice estimate |
| `sensor.vivit_power_price_punta` | Peak power price |
| `sensor.vivit_virtual_battery_*` | Virtual battery data, when available |

---

## 🧠 Technical details

- Uses endpoints from the official Repsol customer portal
- Uses dynamic headers and referers depending on the requested section
- Fully asynchronous implementation using `asyncio` and `aiohttp`
- Configuration through Home Assistant `config_flow`
- Data updates handled with `DataUpdateCoordinator`
- Supports reauthentication from Home Assistant

---

## 🐛 Reporting issues

Before opening an issue:

1. Make sure you are using the latest version
2. Restart Home Assistant
3. Check if the issue has already been reported
4. Collect relevant logs

Please include:

- Home Assistant version
- Integration version
- Installation method: HACS or manual
- A clear description of the problem
- Steps to reproduce
- Relevant logs, with personal data removed

⚠️ Never share your Repsol username, password, contract number, address or personal details in public issues.

---

## 🛣️ Roadmap

Possible future improvements:

- Improve error handling when Repsol changes the portal
- Improve diagnostics and logs
- Add more detailed invoice information
- Improve support for edge cases with multiple contracts
- Improve virtual battery sensors
- Add more documentation and examples

---

## 🧑‍💻 Developer

- **Author:** [@danielmigueltejedor](https://github.com/danielmigueltejedor)
- **Repository:** https://github.com/danielmigueltejedor/vivit-energy-ha
- **Version:** 2.1.10
- **Type:** Unofficial custom Home Assistant integration
- **License:** [MIT](./LICENSE)

---

## ⚠️ Legal disclaimer

This project is not affiliated with, endorsed by, or supported by Repsol S.A.

The data obtained through this integration is intended for personal and informational use only.

**Repsol** and **Vivit** are trademarks of their respective owners.

---

## 💰 Donations

If you like this project and want to support its development, you can donate here:

[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/DanielMiguelTejedor)
