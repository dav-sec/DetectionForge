# Cobertura ATT&CK — Entregable 5

## Qué es

Un reporte, regenerado por `scripts/generate_coverage.py`, que muestra qué
técnicas MITRE ATT&CK cubren las reglas del proyecto, y en qué estado está
esa cobertura: escrita pero sin probar, o confirmada con evidencia empírica
real (Entregable 3). Se genera en dos formatos:

- **`docs/coverage/attack-navigator-layer.json`** — capa para
  [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/),
  la herramienta estándar de la industria para visualizar cobertura sobre la
  matriz oficial. Se abre arrastrando el archivo ahí.
- **`docs/coverage/coverage-report.md`** — la misma información en una
  tabla, legible directo en GitHub sin abrir ninguna herramienta externa.

## Cómo se mide la cobertura

**Contra las técnicas que el proyecto decidió cubrir, no contra la matriz
completa de ATT&CK.** El denominador es "cuántas técnicas tienen una regla
Sigma en `rules/`" (actualmente 18), no "cuántas de las ~600 técnicas de
ATT&CK existen" — ese segundo número sería una fracción minúscula y no diría
nada sobre el avance real del proyecto en lo que se propuso construir.

## Cómo se interpreta el color en el Navigator

| Color | Significado |
|---|---|
| 🟢 Verde | Técnica con regla que pasó el runner (`detectionforge.validation_status: passed`) en ambos SIEM |
| 🟡 Amarillo | Técnica con regla escrita, aún sin validación empírica (`pending`) |
| 🔴 Rojo | Inconsistencia: regla en `rules/production/` sin `validation_status: passed` — no debería ocurrir si se siguió el proceso de promoción, señal de revisar |

El color de una técnica toma el peor caso entre todas sus reglas asociadas
(si una técnica tiene dos reglas y solo una está `passed`, se muestra en
rojo/amarillo según corresponda, no en verde).

## Qué NO mide este reporte

- No mide calidad de la detección (una regla puede estar `passed` y aun así
  tener falsos positivos altos en producción real — eso es harina de otro
  costal, fuera del alcance de este entregable).
- No incluye las reglas de correlación (T1046, T1110) — son YAML
  multi-documento y el extractor de tags actual no las procesa; quedan fuera
  del conteo tanto en el numerador como en el denominador.
- No es una medición de "qué tan bien protegidos estamos" en sentido
  absoluto — es una medición de avance del propio backlog del proyecto.

## Cómo regenerarlo

```bash
cd DetectionForge
python3 scripts/generate_coverage.py rules/staging rules/production
```

Sobrescribe ambos archivos en `docs/coverage/` con el estado actual del
repositorio. Si el pipeline de CI/CD está configurado para regenerarlo
automáticamente (ver más abajo), no hace falta correrlo a mano salvo para
verificación local antes de un push.

## Integración con CI/CD (Entregable 4)

El job `convert` del pipeline (`.github/workflows/detection_pipeline.yml`)
puede incluir un paso adicional que corra `generate_coverage.py` y suba los
dos archivos como artifact, o los comitee automáticamente de vuelta a
`main` tras un merge — así el reporte nunca queda desactualizado respecto a
las reglas que hay en el repo en cada momento, sin depender de que alguien
se acuerde de correrlo a mano tras cada promoción de regla.
