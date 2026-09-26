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

## Equipo

- dav-sec
- Manzur68
