# CHANGELOG
## 2.1.5 — 2026-04-22

### Corregido
- Aviso de Home Assistant `Detected that custom integration 'repsol_vivit' closes the Home Assistant aiohttp session`: la integración ya no cierra la sesión compartida devuelta por `async_create_clientsession` ni en `async_unload_entry` ni en el config flow.

---

## 2.1.4 — 2026-04-22

### Corregido
- Error persistente `HTTP 401 UnauthorizedException: The user signature provided is not valid`: ante firma Gigya caducada, el re-login ahora limpia las cookies de sesión en lugar de reutilizarlas, evitando que la nueva firma se siga rechazando.
- Re-login concurrente redundante cuando varias peticiones fallan a la vez: si otra tarea ya refrescó los tokens mientras se esperaba el lock, se omite un login duplicado.

### Cambiado
- La detección de firma inválida (`signature`/`unauthorized` en el cuerpo 401) fuerza reseteo de cookies en el primer reintento; los demás 401/403 conservan las cookies en el primer intento y escalan al segundo.

---

## 2.1.2 — 2026-04-17

### Corregido
- Errores transitorios `request_failed` al obtener datos de la API: retries subidos de 1 a 3 con backoff progresivo.
- El re-login por 401/403 ya no consume presupuesto de reintentos, evitando fallos tras un único 5xx posterior.
- Se elimina el sleep redundante tras el último intento para reducir latencia.

---

## 2.1.1 — 2026-04-13

### Añadido
- Reautenticación desde Home Assistant cuando cambian las credenciales de acceso.
- Options flow para ajustar el intervalo de actualización y activar o desactivar los sensores de batería virtual.
- Nuevo `binary_sensor` para indicar si la última factura está pagada.
- Base de tests ligeros con `unittest` para helpers, traducciones y coherencia de versión.

### Cambiado
- El estado de “última factura pagada” deja de exponerse como sensor de texto y pasa a `binary_sensor`.
- El intervalo de actualización se calcula por entrada de configuración a partir de sus opciones.

### Corregido
- Se fuerza `reauth` cuando falla la autenticación en lugar de seguir sirviendo caché obsoleta.
- Se mantiene el nombre estable del dispositivo tras reautenticación y cambios de opciones.

---

## 2.0.0 — 2026-04-13

### Corregido
- Se aísla la sesión HTTP por config entry para evitar fugas de cookies entre cuentas o contratos.
- El flujo de configuración reutiliza la misma lógica robusta de login y descubrimiento de contratos que usa la integración en runtime.
- Se propagan `contract_id`, `contract_type`, `contract_index` y `device_name` al runtime para mantener el dispositivo correcto por contrato.
- Se corrige la creación de sensores para no generar términos de gas en contratos de electricidad.
- Se alinean las traducciones en portugués con las claves reales del flujo.
- Se actualizan README y enlaces del repositorio a la versión y ubicación actuales.

### Cambiado
- La carga de datos por contrato ahora se hace en paralelo para reducir el tiempo de refresco cuando hay varios contratos.
- Las peticiones de facturas usan el `Referer` de facturación, en línea con la documentación del proyecto.

---

## 1.1.4 — 2025-12-04

### Cambiado
- Se agregó branding.

  
## 1.1.3 — 2025-12-04

### Cambiado
- Se actualizaron lo metadatos de la integración para redirigir correctamente al nuevo repositorio.


## 1.1.2 — 2025-11-06

### Corregido
-	manifest.json: ajustado documentation, issue_tracker y metadatos para que, si instalas desde GitHub, se muestren los enlaces correctos a GitHub (en Codeberg se mantiene el manifest anterior con sus enlaces propios).

### Notas
-	Sin cambios funcionales en la integración ni en entidades (unique_id intactos).
-	No requiere pasos de migración. Reiniciar Home Assistant tras actualizar es suficiente.

## 1.1.1 — 2025-11-05
### Corregido
- **Caídas nocturnas / sensores en “no disponible”**: si la API devuelve lista de contratos vacía de forma puntual, el coordinador **no borra los datos previos** y reintenta; se mantiene el último estado válido.
- **`InvoiceEstimateNotAvailableException` (HTTP 400, code 5002)**: los sensores de “Próxima factura” pasan a **0** (o `None` donde aplique) sin romper el resto de entidades.
- **`BatteryHistoryNotFoundException` (HTTP 404, code 2317)**: cuando no hay histórico de batería virtual, **no se crean** sensores VB para ese contrato y la integración sigue funcionando.
- Manejo más robusto de **401/403**: renovación del login y nuevo intento antes de marcar error en flujo de configuración o coordinador.

### Cambiado
- **Índice de contrato estable** por entrada de configuración: corrige el caso en el que dos dispositivos aparecían como “Contrato 2”. Cada config‑entry conserva su número (**Contrato N**) de forma consistente tras reinicios/recargas.
- Texto en UI del flujo: de **“Añadir hub”** a **“Añadir contrato”**.
- Limpieza de nombres: los **sensores** ya no incluyen “Contrato N”; el **dispositivo** agrupa por “Contrato N (Electricidad/Gas)”.

### Notas
- Sin cambios en entidades existentes ni `unique_id`. No hay breaking changes.
- Si usas batería virtual y no ves sensores VB, es posible que ese contrato **no tenga histórico** aún: es comportamiento esperado.

---

## 1.1.0 — 2025-11-05
### Añadido
- Soporte completo multi‑contrato mediante **una entrada por contrato** en Home Assistant.
- Sensores de **Batería virtual**: importe pendiente, kWh disponibles, importe/kWh canjeados, kWh totales y precio de excedentes; además de sensores del **último canje** (importe y kWh) cuando existan datos.
- Traducciones **es/en/pt** para formularios y mensajes.

### Cambiado
- Nuevo esquema de nombres: los **sensores tienen nombres limpios** (p. ej. “Consumo”, “Precio energía”) y el **dispositivo** agrupa como **“Contrato N (Electricidad/Gas)”**.
- Unidades consolidadas: `EUR`, `EUR/kWh`, `kWh` y `kW` donde corresponda.
- Mejoras en la obtención de precios (potencia/energía) y términos de **gas** (fijo/variable).

### Corregido
- Robustez ante respuestas de la API: manejo de **401**, **400 InvoiceEstimateNotAvailable**, **404 BatteryHistoryNotFound** sin romper la integración.
- El coordinador conserva datos si una parte del refresco falla y añade **timeouts** y reintentos razonables.
- Registros más claros para diagnosticar problemas de conexión o autenticación.

### Notas de actualización
- Las entidades existentes **conservan su `entity_id`**. En instalaciones nuevas se crean nombres de sensor más limpios; puedes **renombrar** desde la UI si lo deseas.
- Si antes tenías una única entrada para varios contratos, **añade ahora una entrada por cada contrato** desde *Dispositivos e Integraciones → Añadir integración*.

---

## 1.0.0 — 2025-11-04
- Primer lanzamiento estable en Codeberg.
- Inicio de sesión vía **Config Flow** y selección de contrato.
- Sensores básicos de consumo, costes, facturas y batería virtual.
- Actualización automática cada **120 minutos**.
- Documentación inicial e instrucciones de instalación/actualización por **SSH**.

---

## 0.1.0 — 2025-11-04
- Versión preliminar para pruebas internas.
