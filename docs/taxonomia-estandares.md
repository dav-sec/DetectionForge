# DetectionForge

Pipeline de *Detection Engineering as Code*: reglas Sigma versionadas en Git,
traducidas automáticamente a Splunk y Elastic, y validadas empíricamente con
Atomic Red Team antes de promoverse a producción. Sentinel queda como fase 2,
sujeta a acceso a un tenant de Azure.

## Estado del proyecto

| Entregable | Contenido | Estado |
|---|---|---|
| 1 | Taxonomía, repositorio, laboratorio (Splunk + Elastic + VM víctima) | ✅ Completo |
| 2 | Motor de traducción Sigma → SPL / Lucene (`pysigma`) | ✅ Completo |
| 3 | Framework de validación empírica con Atomic Red Team | ✅ Completo |
| 4 | Automatización CI/CD | Pendiente |
| 5 | Métricas de cobertura ATT&CK | Pendiente |
| 6 | Piloto end-to-end | Pendiente |

## Quick start

```bash
git clone https://github.com/dav-sec/DetectionForge.git
cd DetectionForge

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pre-commit install

# Validar una regla manualmente contra la taxonomía del proyecto:
python3 scripts/check_taxonomy.py rules/staging/t1059.001_powershell_encoded_command.yml

# Validar y convertir una regla a SPL y Lucene:
sigma check rules/staging/t1059.001_powershell_encoded_command.yml
sigma convert -t splunk -p sysmon -p splunk_windows rules/staging/t1059.001_powershell_encoded_command.yml
sigma convert -t lucene -p ecs_windows rules/staging/t1059.001_powershell_encoded_command.yml
```

## Estructura

```
detectionforge/
├── docs/
│   ├── taxonomia-estandares.md     # Leer primero — gobernanza y taxonomía
│   ├── laboratorio-setup.md        # Guía del laboratorio (Splunk + Elastic)
│   ├── framework-validacion.md     # Cómo funciona la validación empírica (runner)
│   └── evidencia/                  # Salida del runner por cada regla promovida
├── rules/
│   ├── staging/                    # Reglas en desarrollo
│   └── production/                 # Reglas validadas (atomic test PASS en ambos SIEM)
├── runner/                         # Runner de validación empírica (Entregable 3)
│   ├── runner.py                   # Orquestador: traduce la regla y consulta ambos SIEM
│   ├── siem_clients.py             # Conexión vía API a Splunk y Elastic
│   └── config.py                   # Credenciales del laboratorio (NO versionado)
├── pipelines/                      # Mapeos de campos por backend (fase posterior)
├── tests/                          # Vínculo regla ↔ atomic test (fase posterior)
├── scripts/
│   ├── check_taxonomy.py           # Valida campos obligatorios de cada regla
│   ├── convert_all.sh              # Convierte todo rules/staging/ a SPL y Lucene
│   └── strip_custom_fields.py      # Copias de reglas sin el bloque detectionforge (para Chainsaw)
└── .github/                        # Plantilla de PR y CODEOWNERS
```

# Flujo de validación de una regla Sigma

El flujo tiene dos fases: validación estática (rápida, sin laboratorio) y
validación empírica (requiere el laboratorio activo). Una regla solo se
promueve a `rules/production/` tras pasar ambas.

## Fase 1 — Validación estática

### Paso 1: Validar sintaxis Sigma

```bash
sigma check rules/staging/*.yml
```

Confirma que cada archivo sea una regla Sigma válida: YAML correcto, campos
obligatorios del estándar Sigma, tags MITRE ATT&CK válidos. Es la
verificación más barata, por lo que debe ejecutarse primero.

### Paso 2: Validar la taxonomía propia de DetectionForge

```bash
python3 scripts/check_taxonomy.py rules/staging/<regla>.yml
```

`sigma check` valida el estándar Sigma genérico; este script valida las
reglas adicionales del proyecto (ver `docs/taxonomia-estandares.md`) — por
ejemplo, que `references` no contenga enlaces a `attack.mitre.org` (la
técnica va solo en `tags`), que el bloque `detectionforge` esté completo, etc.

### Paso 3: Convertir cada regla a Splunk y Elasticsearch

Instalar los plugins necesarios (incluye los pipelines de Windows/Sysmon,
requeridos además de los backends):

```bash
sigma plugin install splunk elasticsearch sysmon windows
```

```bash
bash scripts/convert_all.sh
```

Comprueba que cada regla pueda traducirse a Splunk SPL y Elasticsearch/Lucene.
Que `sigma check` sea exitoso no garantiza que una regla pueda convertirse a
todos los backends — este paso identifica exactamente cuál regla falla y en
qué plataforma.

### Paso 4: Eliminar campos personalizados incompatibles con Chainsaw

```bash
python scripts/strip_custom_fields.py
```

Chainsaw no tolera el bloque `detectionforge:`. Este script lee las reglas de
`rules/staging/`, elimina ese bloque, y genera copias limpias en
`build/chainsaw-rules/` sin modificar los originales. Omite además las reglas
de correlación (T1046, T1110), ya que Chainsaw no evalúa correlaciones.

### Paso 5: Validar carga de reglas en Chainsaw

```bash
./chainsaw/chainsaw/chainsaw.exe lint --kind sigma rules/staging/
```

### Paso 6: Pre-validación con muestras EVTX públicas

Antes de depender del laboratorio completo, conviene probar las reglas
contra eventos ya existentes — responde rápido a la pregunta "¿la regla
detecta eventos compatibles con el comportamiento esperado?", sin necesidad
de generar tráfico real cada vez.

```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git

./chainsaw/chainsaw/chainsaw.exe hunt EVTX-ATTACK-SAMPLES/ \
  -s build/chainsaw-rules/ \
  --mapping ./chainsaw/chainsaw/mappings/sigma-event-logs-all.yml \
  --json --output results.json
```

## Fase 2 — Validación empírica (requiere laboratorio activo)

Una pre-validación contra EVTX estáticos no prueba que la regla detecte
actividad real en el SIEM del proyecto — para eso existe el runner.

### Paso 7: Ejecutar el atomic test correspondiente

En la VM víctima, con Invoke-AtomicRedTeam instalado:

```powershell
Invoke-AtomicTest <TTP> -TestNumbers <N>
```

El número de test se toma del campo `detectionforge.atomic_test_id` de la
regla — **verifícalo con `-ShowDetails` antes de ejecutar**: ya se encontró
al menos un caso donde ese campo apuntaba al atomic test incorrecto.

### Paso 8: Correr el runner

```bash
cd runner
python3 runner.py ../rules/staging/<regla>.yml --lookback 15
```

El runner traduce la regla (reutilizando `sigma convert`, el mismo mecanismo
del Paso 3) y consulta Splunk y Elastic vía su API en busca del evento
generado por el atomic test. Ver `docs/framework-validacion.md` para el
detalle de diseño.

### Paso 9: Promover la regla

Si el runner confirma `PASS` en ambos SIEM, mover la regla a
`rules/production/`, actualizar `status: stable` y
`detectionforge.validation_status: passed`, y abrir un PR con la salida del
runner como evidencia (guardarla en `docs/evidencia/`).

## Equipo

- dav-sec
- Manzur68
