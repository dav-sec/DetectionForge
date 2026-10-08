# DetectionForge

Pipeline de *Detection Engineering as Code*: reglas Sigma versionadas en Git,
validadas empíricamente contra Splunk y Elastic Security con Atomic Red Team
antes de promoverse a producción. Sentinel queda como fase 2, sujeta a acceso
a un tenant de Azure.

## Quick start

```bash
git init
git add .
git commit -m "chore: estructura inicial y estándares de taxonomía"

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pre-commit install

# Validar una regla manualmente:
python3 scripts/check_taxonomy.py rules/staging/t1059.001_powershell_encoded_command.yml

#Validar y convertir la primera regla
sigma check rules/staging/t1059.001_powershell_encoded_command.yml
sigma convert -t splunk -p sysmon rules/staging/t1059.001_powershell_encoded_command.yml
sigma convert -t elasticsearch -p ecs_windows rules/staging/t1059.001_powershell_encoded_command.yml

```

## Estructura

```
detectionforge/
├── docs/
│   ├── taxonomia-estandares.md   # Leer primero — gobernanza y taxonomía
│   └── laboratorio-setup.md      # Guía del laboratorio (Splunk + Elastic)
├── rules/
│   ├── staging/                  # Reglas en desarrollo
│   └── production/               # Reglas validadas (atomic test PASS)
├── pipelines/                    # Mapeos de campos por backend (fase posterior)
├── tests/                        # Vínculo regla ↔ atomic test (fase posterior)
├── scripts/check_taxonomy.py     # Valida campos obligatorios de cada regla
└── .github/                      # Plantilla de PR y CODEOWNERS
```

# Flujo de Validación de Reglas Sigma

## Paso 1: Validar sintaxis Sigma

```bash
sigma check rules/staging/*.yml
```

Confirma que cada archivo sea una regla Sigma válida:

- YAML correcto.
- Campos obligatorios del estándar Sigma.
- Tags MITRE ATT&CK válidos.

Es la verificación más barata, por lo que debe ejecutarse primero. Si una regla falla aquí, no tiene sentido continuar con las siguientes etapas.

---

## Paso 2: Convertir cada regla a Splunk y Elasticsearch

### Instalar plugins Sigma necesarios

```bash
sigma plugin install splunk elasticsearch sysmon Windows
```

### Convertir todas las reglas

```bash
bash scripts/convert_all.sh
```

Comprueba que cada regla pueda traducirse correctamente a:

- Splunk SPL
- Elasticsearch / Lucene

Que `sigma check` sea exitoso no garantiza que una regla pueda convertirse a todos los backends. Este paso permite identificar exactamente cuál regla falla y en qué plataforma.

---

## Paso 3: Eliminar campos personalizados incompatibles con Chainsaw

```bash
python scripts/strip_custom_fields.py
```

Chainsaw no tolera el bloque:

```yaml
detectionforge:
```

Este script:

1. Lee las reglas desde `rules/staging/`.
2. Elimina el bloque `detectionforge`.
3. Genera copias limpias en:

```text
build/chainsaw-rules/
```

No modifica los archivos originales.

Además:

- Omite las reglas T1046.
- Omite las reglas T1110.

Esto se hace porque Chainsaw no evalúa correlaciones.

---

## Paso 4: Validar carga de reglas en Chainsaw

Instalar Chainsaw

```bash
curl -L -o chainsaw.zip "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip"
unzip chainsaw.zip -d chainsaw
```

```bash
./chainsaw/chainsaw/chainsaw.exe lint --kind sigma rules/staging/
```

Verifica que Chainsaw pueda cargar correctamente las reglas.

Esta es la prueba que anteriormente generaba errores como:

```text
failed to parse
```

Si `lint` reporta un problema, la causa se encuentra en una regla específica y no en el flujo completo de validación.

---

## Paso 5: Pre-validación con muestras EVTX

Antes de depender del laboratorio completo, es recomendable probar las reglas contra eventos ya existentes.

Esto permite verificar rápidamente si una regla dispara correctamente sin necesidad de generar tráfico o ataques reales cada vez.

```bash
# 1. Clonar el repositorio de muestras EVTX
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git

# 2. Ejecutar la cacería con el binario local y las reglas sanitizadas
./chainsaw/chainsaw/chainsaw.exe hunt EVTX-ATTACK-SAMPLES/ \
  -s build/chainsaw-rules/ \
  --mapping mappings/sigma-event-logs-all.yml
```

### Ejecutar Chainsaw sobre muestras EVTX

```bash
./chainsaw/chainsaw/chainsaw.exe hunt EVTX-ATTACK-SAMPLES/ \
  -s build/chainsaw-rules \
  --mapping ./chainsaw/chainsaw/mappings/sigma-event-logs-all.yml \
  --json \
  --output results.json
```

### Objetivo

Realizar una validación preliminar para responder la pregunta:

> ¿La regla detecta eventos compatibles con el comportamiento esperado?

Si la regla funciona con muestras conocidas, se reduce significativamente el tiempo de iteración antes de realizar pruebas en el laboratorio completo.

## Equipo

- dav-sec
- Manzur68
