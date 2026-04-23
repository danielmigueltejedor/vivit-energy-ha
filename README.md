# ⚡ Vivit Energy Portal for Home Assistant

![Version](https://img.shields.io/badge/version-2.1.6-blue.svg)
![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2025.1%2B-41BDF5?logo=home-assistant)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)
![GitHub](https://img.shields.io/badge/hosted%20on-GitHub-black?logo=github)

Integración **no oficial** para conectar el **portal Vivit Energy (Repsol Luz y Gas)** con **Home Assistant**.  
Permite consultar consumos, costes, facturas y batería virtual directamente desde tu cuenta del área cliente Repsol.

> 🟡 Este proyecto **no está afiliado ni respaldado por Repsol S.A.**  
> Se ofrece únicamente con fines personales y educativos.

---

## ✨ Características

- Inicio de sesión con credenciales del área cliente de **Repsol/Vivit Energy**  
- Compatible con contratos de **electricidad y gas**  
- Soporte para:
  - Coste y consumo acumulado  
  - Facturas emitidas y próximas  
  - Estado del contrato  
  - Batería virtual (si aplica)
- Actualización automática cada 2 horas  
- Compatible con **múltiples contratos**
- Reautenticación desde Home Assistant cuando cambian las credenciales
- Opciones para ajustar el intervalo de actualización y los sensores de batería virtual

---

## 🧩 Instalación

### 🔹 Opción 1 — HACS (Recomendada)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=danielmigueltejedor&repository=vivit-energy-ha&category=Integration)

---

### 🔹 Opción 2 — Manual (descarga directa)

1. Descarga el repositorio desde GitHub:  
   [https://github.com/danielmigueltejedor/vivit-energy-ha](https://github.com/danielmigueltejedor/vivit-energy-ha)

2. Copia la carpeta `repsol_vivit` dentro de:

   ```bash
   config/custom_components/
   ```

3. Reinicia Home Assistant.

---

### 🔹 Opción 3 — Vía Terminal (SSH)

> 💡 Ideal si usas el complemento **Terminal & SSH** en Home Assistant OS o Supervised.

Ejecuta los siguientes comandos en tu terminal de Home Assistant:

```bash
# 1) Prepara destino
mkdir -p /config/custom_components
rm -rf /config/custom_components/repsol_vivit

# 2) Clona temporalmente el repositorio
cd /config
git clone --depth=1 https://github.com/danielmigueltejedor/vivit-energy-ha.git .vivit-tmp

# 3) Copia SOLO la integración
cp -r .vivit-tmp/custom_components/repsol_vivit /config/custom_components/

# 4) Limpia archivos temporales
rm -rf /config/.vivit-tmp

# 5) Reinicia Home Assistant
```

✅ Esto dejará la integración correctamente instalada en:
```
/config/custom_components/repsol_vivit
```

---

## 🔄 Actualización de la integración

Cuando haya una nueva versión disponible, puedes actualizar ejecutando:

```bash
# 1) Elimina versión anterior
rm -rf /config/custom_components/repsol_vivit

# 2) Clona la nueva versión
cd /config
git clone --depth=1 https://github.com/danielmigueltejedor/vivit-energy-ha.git .vivit-tmp

# 3) Copia la integración actualizada
cp -r .vivit-tmp/custom_components/repsol_vivit /config/custom_components/

# 4) Limpia archivos temporales
rm -rf /config/.vivit-tmp

# 5) Reinicia Home Assistant
```

> 💬 Consejo: puedes guardar este bloque como un script bash o comando de automatización en Home Assistant.

---

## ⚙️ Configuración

1. En Home Assistant, ve a  
   **Ajustes → Dispositivos e Integraciones → Añadir integración**
2. Busca **Vivit Energy Portal (Unofficial)**
3. Introduce tu **usuario y contraseña** del área cliente Repsol
4. Selecciona el contrato que quieras vincular
5. ¡Listo! Las entidades se crearán automáticamente.

Desde **Configurar** en la integración puedes cambiar el intervalo de actualización y activar o desactivar los sensores de batería virtual.

---

## 📊 Entidades creadas

| Entidad | Descripción |
|----------|-------------|
| `sensor.vivit_amount` | Coste total estimado |
| `sensor.vivit_consumption` | Consumo acumulado (kWh) |
| `sensor.vivit_last_invoice` | Última factura emitida |
| `sensor.vivit_next_invoice` | Estimación de próxima factura |
| `sensor.vivit_power_price_punta` | Precio potencia punta |
| `sensor.vivit_virtual_battery_*` | Datos de batería virtual (si aplica) |

---

## 🧠 Detalles técnicos

- API obtenida del portal oficial [areacliente.repsol.es](https://areacliente.repsol.es)  
- Uso de `Referer` y cabeceras dinámicas entre *Mis facturas* y *Productos y servicios*  
- Arquitectura **asíncrona completa** (async/await con aiohttp)  
- Configuración mediante `config_flow` y actualización con `DataUpdateCoordinator`

---

## 🧑‍💻 Desarrollador

- **Autor:** [@danielmigueltejedor](https://github.com/danielmigueltejedor)  
- **Versión:** 2.1.6
- **Tipo:** Integración personalizada no oficial  
- **Licencia:** [MIT](./LICENSE)

---

## ⚠️ Aviso Legal

Este proyecto no tiene ninguna relación ni está respaldado por Repsol S.A.  
El uso de esta integración implica aceptar que los datos obtenidos son **informativos y personales**.  
*Repsol* y *Vivit* son marcas registradas de sus respectivos propietarios.

---

## 💰 Donaciones

Si te gusta este proyecto y quieres apoyar su desarrollo, considera hacer una donación:

[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/DanielMiguelTejedor)
