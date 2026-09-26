## Regla(s) incluida(s)

<!-- Ruta del archivo, ej. rules/staging/t1059.001_powershell_encoded_command.yml -->

## Checklist de taxonomía (obligatorio antes de pedir revisión)

- [ ] `id` es un UUID único (no reutilizado de otra regla)
- [ ] `status`, `level`, `logsource`, `falsepositives`, `references` presentes
- [ ] `tags` incluye al menos una técnica (`attack.txxxx`) y su táctica
- [ ] `detectionforge.owner` completado
- [ ] `detectionforge.version` en `0.1.0` (regla nueva) o incrementado según §7 del documento de estándares
- [ ] Nombre de archivo sigue la convención `<tecnica>_<descripcion-corta>.yml`

## Evidencia de validación (si esta PR promueve a `production/`)

<!-- Adjuntar captura o export del evento/alerta generada por el atomic test -->

- Atomic test ejecutado: `detectionforge.atomic_test_id`
- SIEM(s) donde se confirmó la alerta:
- Resultado: PASS / FAIL

## Revisor

<!-- Debe ser el otro integrante del equipo -->
