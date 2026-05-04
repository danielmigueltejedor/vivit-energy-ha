# CHANGELOG
## 2.1.12 — 2026-05-01

### Corregido
- Si un endpoint fallaba con HTTP 5xx (p. ej. facturas `/invoices`) el `asyncio.gather` fallaba entero y el coordinator no devolvía datos: tras un reinicio duro sin caché todas las entidades quedaban **no disponibles**. Ahora cada llamada se gestiona con `return_exceptions=True`: fallos parciales usan valores por defecto (lista de facturas vacía, costes a cero, etc.) y el resto de sensores sigue actualizando.
- Menos ruido en el registro: los reintentos por 429/5xx en `_get_json` (y backoff equivalente en invoice estimate / VB history) pasan a `DEBUG`; un único `WARNING` cuando se agotan reintentos o al registrar un fallo parcial por contrato.

---

## 2.1.11 — 2026-05-01

### Seguridad
- Eliminadas las cookies Gigya hardcodeadas en `const.py` (`COOKIES_CONST`). El flujo ya obtiene cookies frescas vía `accounts.webSdkBootstrap`; no quedan valores de sesión versionados en el repositorio.
- Menos filtrado en logs y excepciones: se dejan de registrar fragmentos de cuerpo HTTP y el payload JSON completo en fallos de login; los errores HTTP usan códigos sin adjuntar el body.
- Validación de `house_id` y `contract_id` (alfanumérico, guiones y guiones bajos, longitud acotada) antes de interpolar en las URLs de la API.

---

## 2.1.10 — 2026-04-24

### Cambiado
- Tras cada `accounts.login` se hace un warmup GET al portal `areacliente.repsol.es` para que el BFF emita su propia cookie de sesión. Intento de mitigar el 401 persistente `The user signature provided is not valid`, que aparece aunque la firma de Gigya se acabe de generar.
- `_bootstrap_gigya` parte de cookies vacías antes de capturar las nuevas desde Gigya.
- Nuevo log `INFO` tras cada login correcto con UID (8 chars), `signatureTimestamp` y longitud de la firma para diagnosticar rechazos posteriores del BFF.

---

## 2.1.9 — 2026-04-23

### Corregido
- Causa real del `Gigya errorCode=400006 (Invalid parameter value)`: el login con `targetEnv=jssdk` necesita cookies bootstrap (`gmid`, `ucid`, `hasGmid`, `gig_bootstrap_*`) emitidas por Gigya para la APIKey activa. Las cookies hard-coded en `COOKIES_CONST` estaban caducadas, por lo que cada login se rechazaba y dejaba a la integración sirviendo sólo caché.
- Antes de cada `accounts.login` se llama a `accounts.webSdkBootstrap` para obtener un `gmid` fresco. Si el login sigue fallando con 400006, se vuelve a bootstrappear antes del reintento.

### Cambiado
- `LOGIN_FAILURE_COOLDOWN` subido de 60 s a 300 s. Nuevo `LOGIN_RATE_LIMIT_COOLDOWN` de 900 s cuando Gigya devuelve `403048 Api rate limit exceeded`, para dar margen a que se relaje el bloqueo.
- Si hay fallo reciente dentro del cooldown, el siguiente `async_login` re-lanza el error cacheado sin tocar Gigya — aunque lo invoquen varios coordinators o reloads seguidos.

---

## 2.1.8 — 2026-04-23

### Corregido
- Cascada de 30+ logs `Gigya errorCode=400006` / `403048 Api rate limit exceeded` en unos pocos segundos: cada una de las peticiones concurrentes de `fetch_all_data` (contratos, facturas, costes, invoice estimate, virtual battery) disparaba su propio `async_login` ante el 401 y reventaba el rate limit de Gigya, retroalimentando el bloqueo.

### Cambiado
- `async_login` deduplica re-logins concurrentes incluso con `reset_cookies=True`: si otra task refrescó la firma mientras estábamos esperando el lock, se reutiliza y se sale.
- Nuevo cooldown `LOGIN_FAILURE_COOLDOWN` (60 s): si el último login falló hace menos de un minuto, los siguientes intentos re-lanzan el error cacheado sin golpear Gigya, permitiendo que el rate limit se recupere.
- Tras un login correcto el cooldown se limpia; tras cualquier fallo se registra `errno` y timestamp para que las peticiones en paralelo del mismo ciclo no lo vuelvan a intentar.

---

## 2.1.7 — 2026-04-23

### Corregido
- Reautenticación forzada que dejaba las entidades no disponibles pese a que las credenciales eran correctas. Gigya devuelve HTTP 200 con `errorCode` ≠ 0 (p.ej. `400006` bloqueo de seguridad, `400125`, `500001`) y sin `userInfo`; el cliente interpretaba ese caso como credenciales inválidas (`login_failed_tokens`) y disparaba `ConfigEntryAuthFailed`.
- Ahora se inspecciona el `errorCode` del payload Gigya:
  - `403042` (loginID/password incorrectos) → `login_failed_credentials`, única ruta que fuerza reauth.
  - `400006 / 400125 / 403047 / 500001` y similares → `login_failed_blocked`, transitorios: se limpian cookies, se reintenta y, si persiste, se sirve la última caché sin tocar las entidades.
  - Cualquier otro `errorCode` → `login_failed_gigya`, tratado como transitorio.
- `login_failed_tokens` (200 sin tokens y sin `errorCode` reconocido) deja de forzar reauth: se sirve caché y se loguea el payload (`errorCode`, fragmento del body) para diagnosticar sin perder entidades.
- Se añade log de advertencia con el `errorCode` y mensaje de Gigya cada vez que el login no devuelve tokens, para poder identificar futuros códigos transitorios.

---

## 2.1.6 — 2026-04-23

### Corregido
- Reautenticación forzada cada ~2 horas tras 2.1.4: el reseteo de cookies usaba `session.cookie_jar.clear()` sobre la sesión compartida de Home Assistant, lo que disparaba el bloqueo de seguridad de Gigya (`400006`) y hacía que el siguiente login fallara con `login_failed_http`, escalando a `ConfigEntryAuthFailed`.
- El reseteo de cookies ahora es específico por dominio (`login.repsol.es`, `areacliente.repsol.es`, `repsol.es`) mediante `cookie_jar.clear_domain`, sin tocar cookies de otras integraciones.
- Se elimina la heurística que reseteaba cookies en el primer 401 cuando el cuerpo contenía `signature`/`unauthorized`: la caducidad natural de la firma Gigya produce ese texto y forzaba el reseteo en cada ciclo de actualización.
- El primer 401/403 sólo hace re-login (sin tocar cookies). Sólo el segundo intento, si sigue fallando, escala a reseteo de cookies Gigya.
- El coordinator sólo lanza `ConfigEntryAuthFailed` si el login devuelve 200 sin tokens (`login_failed_tokens`, credenciales realmente inválidas). El resto de `login_failed_*` (bloqueo de seguridad, 5xx, parse) se tratan como fallo transitorio y no obligan al usuario a reautenticarse.

---

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
