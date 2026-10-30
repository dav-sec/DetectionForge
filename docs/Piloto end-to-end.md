# Piloto end-to-end


## 1. Qué es (y qué no es)

El Piloto end-toend **no añade componentes nuevos**. Toma **una regla** y la lleva por todo lo
construido en los entregables 1 a 5, documentando el recorrido como una sola narrativa
con evidencia real. Su valor es demostrar que las piezas funcionan *juntas*.


| Etapa del piloto | Entregable que la implementa |
|---|---|
| Regla, taxonomía y repositorio | E1 |
| Traducción Sigma → SPL / Lucene | E2 |
| Validación empírica (atomic test + runner) | E3 |
| CI/CD (lint → convert → deploy) | E4 | 
| Cobertura ATT&CK | E5 |

## 2. Regla piloto

- **Técnica:** `[T1003.001 - LSASS Memory Access via Uncommon Process]`
- **Atomic test:** `Invoke-AtomicTest T1003.001 -TestNumbers 1`, verificado con `-ShowDetails`
- **Estado inicial:** `rules/staging/`, `status: experimental`, `validation_status: pending`

## 3. El recorrido, paso a paso

**3.1 Autoría (E1).** Crear o ajustar la regla en `rules/staging/` con los tags ATT&CK y el
bloque `detectionforge`.

**3.2 Validación estática (E1 + E4).**
```bash
sigma check rules/staging/<regla>.yml
python3 scripts/validate_sigma.py rules/staging/<regla>.yml
python3 scripts/check_taxonomy.py rules/staging/<regla>.yml
```

**3.3 Traducción (E2).**
```bash
sigma convert -t splunk -p sysmon -p splunk_windows rules/staging/<regla>.yml
sigma convert -t lucene -p ecs_windows rules/staging/<regla>.yml
```

<img width="1600" height="237" alt="image" src="https://github.com/user-attachments/assets/feb95ba6-32c9-484d-b541-e7b6189ac13d" />


**3.4 Validación empírica (E3).** En la VM víctima:
```powershell
Invoke-AtomicTest <TTP> -TestNumbers <N> -ShowDetails
Invoke-AtomicTest <TTP> -TestNumbers <N>
```
Después, inmediatamente, en el laboratorio:
```bash
cd runner
python3 runner.py ../rules/staging/<regla>.yml --lookback 15 | tee ../docs/evidencia/evidencia-<ttp>.txt
cd ..
```

<img width="1600" height="719" alt="image" src="https://github.com/user-attachments/assets/dda7ee0b-336d-4077-a12d-f64e891dbb15" />


El archivo sigue el formato de las evidencias existentes (p. ej. `evidencia-t1018.txt`):
cabecera con la regla y el `atomic_test_id`, SPL y Lucene generados, resultado de cada SIEM
y un `RESUMEN` con `Splunk: PASS` y `Elastic: PASS`. Se usa `--lookback 15` para que el
`PASS` corresponda al atomic test recién ejecutado y no a eventos de pruebas anteriores.
Si algún SIEM da `FAIL`, no se promueve.

<img width="1474" height="523" alt="image" src="https://github.com/user-attachments/assets/d8f2b69a-632e-415c-9804-624165fb3095" />


**3.5 Promoción y cobertura (E1 + E3 + E5) — PR A.** En la rama `promote/<ttp>`:
```bash
git mv rules/staging/<regla>.yml rules/production/<regla>.yml
sed -i 's/^status: .*/status: stable/' rules/production/<regla>.yml
sed -i 's/^\(\s*\)validation_status: .*/\1validation_status: passed/' rules/production/<regla>.yml

python3 scripts/validate_sigma.py rules/production
python3 scripts/check_taxonomy.py rules/production/<regla>.yml
python3 scripts/generate_coverage.py rules/staging rules/production
```
La cobertura se regenera **dentro del mismo PR**, así `main` nunca queda con una regla en
producción y un reporte desactualizado. Comprobar en `docs/coverage/coverage-report.md` que
la técnica figura como validada. Commit con la regla movida, `docs/evidencia/evidencia-<ttp>.txt`
y `docs/coverage/`; título del PR: *Promover <ttp> a producción*, con el atomic test, el
`PASS` de ambos SIEM y el cambio de cobertura en la descripción.

**3.6 CI/CD (E4).** Verificar `lint` y `convert` en verde en el PR, hacer merge, aprobar
`deploy` en el entorno `lab-siem` y comprobar la release activa:
```bash
ssh <usuario>@<ip_siem> 'readlink /opt/detectionforge/current'
```

**3.7 Cobertura en `main` (E5).** Tras el merge, abrir `docs/coverage/coverage-report.md`
en GitHub y cargar `docs/coverage/attack-navigator-layer.json` en ATT&CK Navigator para
mostrar la técnica en verde. Estado esperado: de 5 a 6 técnicas validadas sobre las 18 del
proyecto. La cifra mide el avance del backlog del proyecto, no la protección absoluta, y
T1046 y T1110 quedan fuera del conteo (ver E5).

<img width="1600" height="814" alt="image" src="https://github.com/user-attachments/assets/5804e35e-899d-4f34-a05e-0f1cda3f6516" />


## 4. Guion de demostración 

| Min | Escena | Qué se muestra |
|---|---|---|
| 0:00 | Contexto | El problema: reglas sin versionar, sin prueba y distintas por SIEM |
| 1:30 | Regla | El YAML piloto en `staging`, con sus tags y metadatos |
| 2:45 | Validación estática | Los tres chequeos; un fallo provocado a propósito |
| 3:30 | Traducción | SPL y Lucene lado a lado |
| 4:37 | Ataque | `Invoke-AtomicTest` en la VM víctima |
| 5:26 | Evidencia | El evento en Splunk y en Elastic; `PASS` del runner |
| 6:31 | Promoción y CI/CD | PR en verde, merge, aprobación de `deploy`, release en la SIEM |
| 8:30 | Cobertura | El reporte antes y después |
| 9:30 | Cierre | Resultados y limitaciones |



## 5. Limitaciones

- El piloto recorre **una** regla; no prueba la escala del flujo con las 18.
- La validación empírica sigue siendo **manual** (atomic test en la víctima).
- El despliegue **publica y verifica** la release, pero no activa las reglas como alertas
  en los SIEM.
- Prueba la detección, no la **tasa de falsos positivos** con tráfico normal.
