# CHANGELOG
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
