# DetectionForge — Estándares de Gobernanza y Taxonomía de Reglas

**Versión:** 0.1.0 · **Estado:** Vigente · **Alcance actual:** Splunk + Elastic Security (Sentinel en fase 2)

## 1. Objetivo del documento

Este documento define las reglas de gobernanza que todo colaborador del proyecto
DetectionForge debe seguir al escribir, versionar y promover una regla de detección.
Su propósito es que cualquier regla Sigma del repositorio sea **auditable, reproducible
y trazable**: quién la escribió, qué técnica cubre, en qué estado está y qué prueba
demuestra que funciona.

## 2. Alcance del proyecto (fase actual)

Por restricciones de acceso propias de un proyecto universitario, la fase 1 cubre:

| SIEM | Licencia usada | Estado |
|---|---|---|
| Splunk | Free / Developer License (instancia única) | En alcance |
| Elastic Security | Basic (self-managed, gratuita) | En alcance |
| Microsoft Sentinel | Requiere tenant Azure | Fase 2 — pendiente de acceso (Azure for Students) |

Esta tabla debe actualizarse en cuanto cambie el acceso disponible; **no se declara
cobertura "multi-SIEM" en ningún entregable hasta que Sentinel esté realmente probado**.

## 3. Estructura del repositorio

```
detectionforge/
├── docs/                          # Documentación (este archivo, guía de laboratorio, runbooks)
├── rules/
│   ├── staging/                   # Reglas en desarrollo/prueba, aún no validadas
│   └── production/                # Reglas validadas empíricamente (ver §6)
│       └── <tactica>/             # ej. execution/, persistence/, exfiltration/
├── pipelines/                     # Pipelines de mapeo de campos por backend (Splunk CIM, ECS)
├── tests/                         # Vínculo regla ↔ atomic-test-id, resultados de emulación
└── .github/                       # Plantilla de PR y CODEOWNERS
```

Una regla vive primero en `rules/staging/`. Solo se mueve a
`rules/production/<tactica>/` cuando cumple el gate de validación empírica (§6).

## 4. Convención de nombres de archivo

```
<tecnica-attck>_<descripcion-corta-kebab-case>.yml
```

Ejemplos:
- `t1059.001_powershell_encoded_command.yml`
- `t1003.001_lsass_memory_access.yml`

No se usan espacios, mayúsculas ni tildes en el nombre de archivo.

## 5. Taxonomía de metadatos

### 5.0 Criterio metodológico

Esta taxonomía **no se inventa desde cero**: parte de la convención oficial de
reglas que mantiene SigmaHQ, el proyecto dueño del estándar Sigma
(`sigmahq_conventions.md`, en el repositorio `SigmaHQ/sigma-specification`).
Esa convención ya define qué campos son obligatorios y opcionales en cualquier
regla que aspire a integrarse al ecosistema Sigma. DetectionForge adopta esos
campos tal cual, y **declara aparte, en un namespace propio (`detectionforge.*`),
únicamente lo que el estándar no cubre** y que el pipeline de este proyecto sí
necesita (dueño de la regla, evidencia de validación empírica, versión interna).

Separar ambas capas con claridad tiene un motivo concreto: cualquier regla del
repositorio debe poder validarse también con el linter oficial de Sigma
(`sigma-cli check`), no solo con las reglas propias del proyecto. Si mezcláramos
campos inventados dentro del bloque estándar, esa validación externa dejaría de
ser confiable.

### 5.1 Campos del estándar Sigma — obligatorios

Fuente: convención de reglas de SigmaHQ.

| Campo | Descripción | Ejemplo |
|---|---|---|
| `title` | Título en *title case*, corto y descriptivo | "Suspicious Encoded PowerShell Command" |
| `id` | UUID v4 único de la regla | `a1b2c3d4-e5f6-4a5b-8c9d-1234567890ab` |
| `status` | Toda regla **nace** en `experimental` (regla de SigmaHQ) | `experimental` |
| `description` | Debe empezar con "Detects" y explicar qué detecta la regla | "Detects PowerShell execution using the -EncodedCommand parameter…" |
| `references` | Fuente(s) pública(s) que justifican la regla. **No se permiten enlaces a la web de MITRE ATT&CK aquí** — la técnica se declara solo vía `tags` (regla explícita de SigmaHQ) | URL a un blog, informe o repositorio |
| `author` | Persona o equipo autor de la regla | "DetectionForge Team" |
| `date` | Fecha de creación (`YYYY-MM-DD`) | `2026-09-25` |
| `tags` | Mínimo una técnica ATT&CK (`attack.txxxx`) y su táctica (`attack.<tactica>`) | `attack.t1059.001`, `attack.execution` |
| `logsource` | Categoría y producto de origen del log | `category: process_creation, product: windows` |
| `detection` | Lógica Sigma (selección + condición) | — |
| `falsepositives` | Escenarios legítimos que podrían disparar la regla | "Scripts de administración firmados" |
| `level` | `informational` \| `low` \| `medium` \| `high` \| `critical` | `medium` |

### 5.2 Campos del estándar Sigma — opcionales (se usan solo si aplican)

| Campo | Cuándo se usa |
|---|---|
| `related` | La regla deriva de, o reemplaza a, otra regla existente (se referencia por `id` y `type`) |
| `modified` | Fecha de la última modificación relevante, si difiere de `date` |
| `logsource.service` / `logsource.definition` | Cuando la fuente de log necesita más precisión que `category`/`product` |
| `fields` | Lista de campos a mostrar en la alerta, si el backend lo soporta |

### 5.3 Extensiones propias de DetectionForge (namespace `detectionforge.*`)

Cada una existe para resolver una necesidad concreta del pipeline que el
estándar Sigma no cubre — no son campos "porque sí":

| Campo | Obligatorio | Por qué existe |
|---|---|---|
| `detectionforge.owner` | Sí | El estándar Sigma tiene `author`, pero no distingue quién es responsable de mantener la regla frente a quién la escribió originalmente; en un equipo de 2 esto puede coincidir, pero se declara igual para que el criterio escale. |
| `detectionforge.atomic_test_id` | Sí antes de pasar a `production/` | Es la evidencia de validación empírica (§6): sin este campo no hay forma de trazar qué prueba de Atomic Red Team demostró que la regla dispara de verdad. |
| `detectionforge.version` | Sí | El estándar Sigma no define versionado semántico; lo adoptamos de Semantic Versioning (semver.org) y lo adaptamos a reglas de detección (§7). |
| `detectionforge.siem_targets` | Sí | Declara explícitamente en qué SIEM(s) del alcance actual (§2) se probó la regla — evita asumir cobertura que no se validó. |

Una regla **no puede fusionarse a `main`** si le falta alguno de los campos
obligatorios de 5.1 o 5.3 (ver `.pre-commit-config.yaml` y la plantilla de PR).

### 5.4 Nota sobre un framework complementario (opcional, no adoptado en fase 1)

Para reglas de alto valor, algunos equipos documentan además el *porqué* de la
detección (hipótesis, contexto de respuesta) con el framework **Alerting and
Detection Strategy (ADS) de Palantir**, que pide secciones como Goal,
Technical Context, Blind Spots, Validation y Response antes de llevar una
alerta a producción. DetectionForge no lo adopta en esta fase por alcance y
tiempo, pero vale mencionarlo como referencia de buenas prácticas si en la
sustentación preguntan por qué la taxonomía se limita a metadatos técnicos y
no incluye una capa de justificación de negocio.

## 6. Estados de una regla y flujo de promoción

```
experimental → test → stable
   (staging/)         (production/)
```

- **experimental**: recién escrita, lógica sin validar contra el SIEM real.
- **test**: pasó la traducción a los backends en alcance sin error de sintaxis.
- **stable**: además de lo anterior, **se ejecutó el atomic test asociado y se
  confirmó la alerta en el SIEM destino**. Solo una regla `stable` puede vivir en
  `rules/production/`.

Ninguna regla se mueve manualmente de `staging/` a `production/`: el paso ocurre
solo cuando el pipeline de validación (fase posterior del proyecto) confirma el
resultado PASS. Mientras ese pipeline no exista, la promoción se documenta a mano
en el PR con la evidencia de la alerta (captura de pantalla o export del evento).

## 7. Versionado semántico de reglas

Formato `MAJOR.MINOR.PATCH`:

- **MAJOR**: cambia la lógica de detección (qué comportamiento cubre la regla).
- **MINOR**: se agrega cobertura relacionada (nueva sub-técnica, nuevo campo de detección) sin romper la lógica anterior.
- **PATCH**: ajuste de umbral, exclusión de falso positivo, corrección de sintaxis.

Toda regla nace en `0.1.0`.

## 8. Flujo de trabajo en Git

1. Rama nueva desde `main`: `feature/<nombre-regla>`.
2. La regla se escribe en `rules/staging/`.
3. Pull Request contra `main` usando la plantilla (`.github/PULL_REQUEST_TEMPLATE.md`).
4. Revisión por pares obligatoria: el otro integrante del equipo aprueba antes del merge.
5. `main` está protegida: no se permite push directo (ver §9).
6. Al fusionar, la regla queda en `staging/` hasta cumplir el gate de §6.

## 9. Protección de la rama `main` (configuración en GitHub)

Aplicar en **Settings → Branches → Branch protection rules** para `main`:
- Require a pull request before merging (mínimo 1 aprobación).
- Require status checks to pass before merging (una vez exista el workflow de lint).
- No permitir force-push ni borrado de la rama.

Con GitHub CLI, una vez creado el repositorio remoto:

```bash
gh api repos/dav-sec/DetectionForge/branches/main/protection \
  --method PUT \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f enforce_admins=true \
  -f restrictions=null \
  -f required_status_checks=null
```

## 10. Referencias

- Convención de reglas de SigmaHQ (fuente de §5.1 y §5.2): https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq_conventions.md
- Especificación general de Sigma: https://sigmahq.io/
- MITRE ATT&CK (consumido solo vía `tags`, nunca en `references`): https://attack.mitre.org/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Semantic Versioning (base de §7): https://semver.org/
- Alerting and Detection Strategy Framework, Palantir (§5.4, opcional): https://github.com/palantir/alerting-detection-strategy-framework
