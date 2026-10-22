#!/usr/bin/env python3
"""
validate_sigma.py - Linting estático de reglas Sigma para DetectionForge.

Verifica:
  1. YAML válido (soporta archivos multi-documento, p. ej. correlaciones).
  2. Campos obligatorios: title, id (UUID válido), status, description,
     logsource + detection (o correlation).
  3. Tags MITRE ATT&CK: al menos una táctica (attack.<tactic>) y una
     técnica (attack.tNNNN[.NNN]) con formato válido.
  4. Reglas de taxonomía DetectionForge (ver docs/taxonomia-estandares.md):
     - references NO debe contener enlaces a attack.mitre.org.
     - debe existir el bloque `detectionforge` (detalle: check_taxonomy.py).
  5. Reglas en rules/production/ deben tener status: stable y
     detectionforge.validation_status: passed.
  6. IDs duplicados entre reglas.

Uso:
  python3 scripts/validate_sigma.py rules/staging rules/production
  python3 scripts/validate_sigma.py rules/staging/t1059.001_x.yml --warn-as-error

Código de salida: 0 = OK, 1 = errores (o warnings con --warn-as-error), 2 = uso.
En GitHub Actions emite anotaciones (::error file=...::mensaje).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("Falta PyYAML: pip install pyyaml")

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact",
    # ATT&CK v18 (Defense Evasion se dividió en estas dos); se mantiene
    # defense_evasion por compatibilidad con reglas antiguas.
    "stealth", "defense_impairment", "defense_evasion",
}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}
REQUIRED = ("title", "id", "status", "description")
GH = os.getenv("GITHUB_ACTIONS") == "true"


class Report:
    def __init__(self) -> None:
        self.errors = 0
        self.warnings = 0

    def emit(self, level: str, path: Path, msg: str) -> None:
        if level == "error":
            self.errors += 1
        else:
            self.warnings += 1
        if GH:
            print(f"::{level} file={path}::{msg}")
        else:
            print(f"[{level.upper():5}] {path}: {msg}")


def iter_files(targets: list[str]):
    for t in targets:
        p = Path(t)
        if p.is_dir():
            yield from sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
        elif p.is_file():
            yield p
        else:
            print(f"[WARN ] ruta no encontrada: {t}", file=sys.stderr)


def check_doc(doc: dict, path: Path, rep: Report, seen_ids: dict,
              helper: bool = False) -> None:
    # Documentos "global" de Sigma (action: global) no son reglas completas.
    if doc.get("action") in {"global", "reset", "repeat"}:
        return

    is_correlation = "correlation" in doc
    in_production = "production" in path.parts

    for f in REQUIRED:
        if not doc.get(f):
            rep.emit("error", path, f"campo obligatorio ausente: '{f}'")

    # id
    rid = str(doc.get("id", ""))
    if rid:
        try:
            uuid.UUID(rid)
        except ValueError:
            rep.emit("error", path, f"'id' no es un UUID válido: {rid}")
        if rid in seen_ids and seen_ids[rid] != path:
            rep.emit("error", path, f"'id' duplicado con {seen_ids[rid]}")
        seen_ids.setdefault(rid, path)

    # estructura
    if is_correlation:
        if not isinstance(doc["correlation"], dict):
            rep.emit("error", path, "'correlation' debe ser un mapeo")
    else:
        if not doc.get("logsource"):
            rep.emit("error", path, "falta 'logsource'")
        if not isinstance(doc.get("detection"), dict) or \
                "condition" not in (doc.get("detection") or {}):
            rep.emit("error", path, "falta 'detection' con 'condition'")

    # references: aplica siempre (también a reglas auxiliares)
    for ref in doc.get("references") or []:
        if "attack.mitre.org" in str(ref).lower():
            rep.emit("error", path,
                     "references no debe enlazar a attack.mitre.org (usar solo tags)")

    # status / level
    status = doc.get("status")
    if status and status not in VALID_STATUS:
        rep.emit("error", path, f"status inválido: {status}")
    if helper:
        # Regla base referenciada por una correlación: hereda tags/metadatos
        # de la regla de correlación, no se le exigen aquí.
        return
    level = doc.get("level")
    if not level:
        rep.emit("warning", path, "falta 'level'")
    elif level not in VALID_LEVEL:
        rep.emit("error", path, f"level inválido: {level}")

    # tags MITRE ATT&CK
    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        rep.emit("error", path, "'tags' debe ser una lista")
        tags = []
    attack = [str(t).lower() for t in tags if str(t).lower().startswith("attack.")]
    techniques = [t for t in attack if TECHNIQUE_RE.match(t)]
    tactics = [t for t in attack
               if t.split(".", 1)[1].replace("-", "_") in TACTICS]
    bad = [t for t in attack if t not in techniques and t not in tactics]
    if not attack:
        rep.emit("error", path, "sin tags MITRE ATT&CK (attack.<táctica>, attack.tNNNN)")
    else:
        if not techniques:
            rep.emit("error", path, "falta tag de técnica (attack.tNNNN[.NNN])")
        if not tactics:
            rep.emit("error", path, "falta tag de táctica (p. ej. attack.execution)")
        for t in bad:
            rep.emit("error", path, f"tag ATT&CK con formato inválido: {t}")

    # Taxonomía DetectionForge
    df = doc.get("detectionforge")
    if not isinstance(df, dict):
        rep.emit("error", path, "falta el bloque 'detectionforge'")
        df = {}

    # Reglas de producción
    if in_production:
        if status != "stable":
            rep.emit("error", path, "regla en production debe tener status: stable")
        if df.get("validation_status") != "passed":
            rep.emit("error", path,
                     "regla en production requiere detectionforge.validation_status: passed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="archivos o directorios con reglas")
    ap.add_argument("--warn-as-error", action="store_true",
                    help="tratar warnings como errores")
    args = ap.parse_args()

    rep, seen = Report(), {}
    files = list(iter_files(args.paths))
    if not files:
        print("No se encontraron reglas.", file=sys.stderr)
        return 2

    for path in files:
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8"))
                    if d is not None]
        except yaml.YAMLError as exc:
            rep.emit("error", path, f"YAML inválido: {str(exc).splitlines()[0]}")
            continue
        if not docs:
            rep.emit("error", path, "archivo vacío")
            continue
        refd = set()
        for d in docs:
            if isinstance(d, dict) and isinstance(d.get("correlation"), dict):
                refd.update(str(r) for r in d["correlation"].get("rules") or [])
        for doc in docs:
            if not isinstance(doc, dict):
                rep.emit("error", path, "el documento YAML no es un mapeo")
                continue
            helper = "correlation" not in doc and (
                str(doc.get("name", "")) in refd or str(doc.get("id", "")) in refd)
            check_doc(doc, path, rep, seen, helper=helper)

    print(f"\n{len(files)} archivo(s) | {rep.errors} error(es) | {rep.warnings} warning(s)")
    if rep.errors or (args.warn_as_error and rep.warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
