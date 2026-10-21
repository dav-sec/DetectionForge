# Framework de Validación Empírica — Entregable 3

## Objetivo

Confirmar, con evidencia real (no solo revisión de código), que una regla Sigma
detecta de verdad la técnica ATT&CK que dice detectar. El proceso conecta tres
piezas ya existentes del proyecto:

1. **Atomic Red Team** — genera el comportamiento malicioso real en la VM víctima.
2. **El motor de traducción del Entregable 2** (`sigma convert`, vía pysigma) —
   convierte la regla a una consulta real de Splunk (SPL) y de Elastic (Lucene).
3. **Un runner en Python** (`runner/`) — ejecuta esa consulta contra ambos SIEM
   vía su API y decide PASS/FAIL según si encuentra el evento generado.

## Flujo

```
Analista ejecuta el atomic_test_id de la regla
            en la VM víctima (manual)
                     │
                     ▼
   Sysmon captura el evento → llega a Splunk y Elastic
                     │
                     ▼
     python3 runner.py rules/staging/<regla>.yml
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
  sigma convert -t splunk   sigma convert -t lucene
  (mismo backend del E2)    (mismo backend del E2)
        │                         │
        ▼                         ▼
  Consulta real vía API      Consulta real vía API
  REST de Splunk             de Elasticsearch
        │                         │
        └────────────┬────────────┘
                      ▼
          PASS/FAIL por cada SIEM
```

## Por qué el atomic test se ejecuta manualmente, no desde el runner

El runner **no** controla la VM víctima de forma remota (vía WinRM u otro
mecanismo). Se evaluó, pero se descartó para esta fase: añade una capa de
configuración de red y autenticación remota que no aporta valor directo a lo
que el entregable pide demostrar (que la regla detecta el evento), y sí añade
riesgo de fallas ajenas al objetivo. El analista ejecuta el atomic test a mano
en la VM víctima; el runner se encarga de todo lo que sigue después de eso.

## Por qué se usa `sigma convert` por línea de comandos, no la API de Python

La primera versión del runner llamaba directamente a las clases de `pysigma`
(`SplunkBackend`, `LuceneBackend`, pipelines) desde Python. Se encontró un
problema real durante las pruebas: el solo hecho de **importar** el paquete
`pysigma-pipeline-sysmon` alteraba el comportamiento del pipeline
`ecs_windows()` para Elastic, agregando condiciones (`winlog.channel`,
`winlog.event_data.source`) que no existen en los datos reales indexados por
el Elastic Agent — causando falsos negativos (`FAIL` aunque el evento sí
existiera).

La solución fue invocar `sigma convert` como subproceso — el mismo mecanismo
que usa `scripts/convert_all.sh` del Entregable 2 — en vez de reimplementar la
lógica de pipelines en Python. Esto tiene una ventaja adicional: el runner
queda acoplado a una única fuente de verdad para la traducción (la misma
herramienta de línea de comandos), en vez de mantener dos implementaciones
que podrían divergir con el tiempo.

## Uso

```bash
cd runner
python3 runner.py ../rules/staging/<archivo_de_la_regla>.yml --lookback 15
```

`--lookback` son los minutos hacia atrás que se consultan en ambos SIEM
(default: 60). Usar un valor corto (15-30 min) cuando el atomic test se acaba
de ejecutar; un valor más amplio si ha pasado más tiempo.

Salida esperada en caso de éxito:

```
✅ Regla validada en ambos SIEM — lista para evidencia de promoción a producción.
```

## Casos validados hasta ahora

| Regla | Técnica | atomic_test_id | Splunk | Elastic |
|---|---|---|---|---|
| `t1059.001_powershell_encoded_command.yml` | PowerShell Encoded Command | T1059.001-15 | PASS | PASS |
| `t1053.005_scheduled_task_creation.yml` | Scheduled Task vía schtasks.exe | T1053.005-1 | PASS | PASS |

La evidencia completa de cada corrida (consulta generada + resultado) queda
en `docs/evidencia/`.

## Proceso de promoción a producción

Una regla pasa de `rules/staging/` a `rules/production/` cuando:

1. El runner confirma `PASS` en ambos SIEM.
2. Se actualiza en el YAML de la regla:
   ```yaml
   status: stable                  # antes: experimental
   detectionforge:
     validation_status: passed     # antes: pending
   ```
3. Se abre un PR con la salida del runner como evidencia, siguiendo
   `.github/PULL_REQUEST_TEMPLATE.md`.

Este proceso es incremental: las reglas restantes en `staging/` se irán
promoviendo de la misma forma conforme avance el proyecto, reutilizando el
mismo runner sin cambios adicionales.

## Nota sobre un hallazgo durante la validación

Al validar `t1059.001_powershell_encoded_command.yml`, se detectó que su
campo `detectionforge.atomic_test_id` apuntaba al test incorrecto
(`T1059.001-1`, que corresponde a un atomic test de Mimikatz, no al de
`-EncodedCommand`). Se corrigió a `T1059.001-15`
(`ATHPowerShellCommandLineParameter -EncodedCommand parameter variations`),
que sí coincide con la lógica de detección de la regla. Esto refuerza el
valor del proceso de validación empírica: un `atomic_test_id` mal referenciado
no se detecta con revisión de sintaxis ni con linters — solo ejecutándolo.
