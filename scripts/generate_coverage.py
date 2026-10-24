#!/usr/bin/env python3
"""
generate_coverage.py — Entregable 5: métricas de cobertura ATT&CK.

Recorre todas las reglas en rules/staging/ y rules/production/, extrae sus
tags de técnica MITRE ATT&CK (attack.tNNNN[.NNN]) y su estado de validación
(detectionforge.validation_status), y genera dos artefactos:

  1. docs/coverage/attack-navigator-layer.json
     Capa compatible con MITRE ATT&CK Navigator (v4.5). Se abre arrastrando
     el archivo en https://mitre-attack.github.io/attack-navigator/

  2. docs/coverage/coverage-report.md
     Tabla legible directo en GitHub: técnica, regla, SIEMs, estado.

La cobertura se mide contra las técnicas que el PROYECTO decidió cubrir
(las que aparecen en rules/), no contra la matriz completa de ATT&CK —
el objetivo es "qué % de lo que nos propusimos cubrir ya está validado
empíricamente", no "qué % de las ~600 técnicas de ATT&CK existen reglas".

Uso:
    python3 scripts/generate_coverage.py rules/staging rules/production
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# Colores por estado de validación (hex, sin gradiente — color explícito por técnica)
COLOR_PASSED = "#8ec843"       # verde: validada empíricamente (runner -> PASS en ambos SIEM)
COLOR_PENDING = "#ffe766"      # amarillo: regla escrita, aún sin validación empírica
COLOR_PRODUCTION_NO_VALID = "#ff6666"  # rojo: en production pero sin validation_status=passed (inconsistencia)


def iter_rule_files(targets: list[str]):
    for t in targets:
        p = Path(t)
        if p.is_dir():
            yield from sorted(p.glob("*.yml"))
        elif p.is_file():
            yield p


def load_docs(path: Path):
    try:
        return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    except yaml.YAMLError:
        return []


def extract_techniques(doc: dict) -> list[str]:
    tags = doc.get("tags") or []
    out = []
    for t in tags:
        m = TECHNIQUE_RE.match(str(t).lower())
        if m:
            out.append(m.group(1).upper())
    return out


def collect(targets: list[str]) -> list[dict]:
    """Devuelve una fila por (regla, técnica) — una regla puede cubrir varias técnicas."""
    rows = []
    for path in iter_rule_files(targets):
        in_production = "production" in path.parts
        for doc in load_docs(path):
            if not isinstance(doc, dict) or "correlation" in doc:
                continue  # las reglas de correlación (T1046/T1110 base+corr) se omiten aquí
            techniques = extract_techniques(doc)
            if not techniques:
                continue
            df = doc.get("detectionforge") or {}
            status = df.get("validation_status", "pending")
            siem_targets = df.get("siem_targets") or []
            for tech in techniques:
                rows.append({
                    "technique": tech,
                    "rule_file": path.name,
                    "rule_title": doc.get("title", path.stem),
                    "in_production": in_production,
                    "validation_status": status,
                    "siem_targets": siem_targets,
                })
    return rows


def technique_color(entries: list[dict]) -> str:
    """Una técnica puede tener varias reglas; toma el peor caso."""
    if any(e["in_production"] and e["validation_status"] != "passed" for e in entries):
        return COLOR_PRODUCTION_NO_VALID
    if any(e["validation_status"] == "passed" for e in entries):
        return COLOR_PASSED
    return COLOR_PENDING


def build_navigator_layer(rows: list[dict]) -> dict:
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_technique[r["technique"]].append(r)

    techniques = []
    for tech, entries in sorted(by_technique.items()):
        rule_names = ", ".join(sorted({e["rule_file"] for e in entries}))
        passed = sum(1 for e in entries if e["validation_status"] == "passed")
        techniques.append({
            "techniqueID": tech,
            "color": technique_color(entries),
            "comment": f"Reglas: {rule_names} | Validadas: {passed}/{len(entries)}",
            "enabled": True,
            "showSubtechniques": True,
        })

    return {
        "name": "DetectionForge - Cobertura de reglas",
        "versions": {"attack": "16", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Cobertura de técnicas ATT&CK cubiertas por las reglas Sigma del "
            "proyecto DetectionForge (SOC-06). Verde: validada empíricamente "
            "con atomic test + runner (Splunk y Elastic). Amarillo: regla "
            "escrita, pendiente de validación empírica. Rojo: en production/ "
            "sin validation_status=passed (inconsistencia a corregir)."
        ),
        "techniques": techniques,
        "legendItems": [
            {"label": "Validada (PASS en ambos SIEM)", "color": COLOR_PASSED},
            {"label": "Pendiente de validación empírica", "color": COLOR_PENDING},
            {"label": "Inconsistencia: en production sin validar", "color": COLOR_PRODUCTION_NO_VALID},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def build_markdown_report(rows: list[dict]) -> str:
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_technique[r["technique"]].append(r)

    total = len(by_technique)
    passed = sum(1 for entries in by_technique.values()
                 if any(e["validation_status"] == "passed" for e in entries))

    lines = [
        "# Cobertura ATT&CK — DetectionForge",
        "",
        f"**{passed} de {total} técnicas cubiertas ya validadas empíricamente** "
        f"({round(100 * passed / total) if total else 0}% de lo cubierto por el proyecto).",
        "",
        "> Este porcentaje mide el avance sobre las técnicas que el proyecto "
        "decidió cubrir (las que tienen regla Sigma), no sobre la matriz "
        "completa de MITRE ATT&CK.",
        "",
        "Generado automáticamente por `scripts/generate_coverage.py` — no editar a mano.",
        "",
        "| Técnica | Regla(s) | Estado | SIEMs | Ubicación |",
        "|---|---|---|---|---|",
    ]

    for tech, entries in sorted(by_technique.items()):
        rule_files = ", ".join(f"`{name}`" for name in sorted({e["rule_file"] for e in entries}))
        statuses = {e["validation_status"] for e in entries}
        status_str = "✅ passed" if "passed" in statuses else "⏳ pending"
        siems = sorted({s for e in entries for s in e["siem_targets"]})
        siem_str = ", ".join(siems) if siems else "—"
        location = "production" if any(e["in_production"] for e in entries) else "staging"
        lines.append(f"| {tech} | {rule_files} | {status_str} | {siem_str} | {location} |")

    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(f"Uso: {sys.argv[0]} <dir_staging> [<dir_production> ...]")

    rows = collect(sys.argv[1:])
    if not rows:
        print("No se encontraron reglas con tags de técnica ATT&CK.", file=sys.stderr)
        return 1

    out_dir = Path("docs/coverage")
    out_dir.mkdir(parents=True, exist_ok=True)

    layer = build_navigator_layer(rows)
    (out_dir / "attack-navigator-layer.json").write_text(
        json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    report = build_markdown_report(rows)
    (out_dir / "coverage-report.md").write_text(report, encoding="utf-8")

    by_technique = defaultdict(list)
    for r in rows:
        by_technique[r["technique"]].append(r)
    total = len(by_technique)
    passed = sum(1 for e in by_technique.values() if any(x["validation_status"] == "passed" for x in e))

    print(f"Técnicas cubiertas: {total}")
    print(f"Validadas empíricamente: {passed} ({round(100*passed/total) if total else 0}%)")
    print(f"Escrito: {out_dir / 'attack-navigator-layer.json'}")
    print(f"Escrito: {out_dir / 'coverage-report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
