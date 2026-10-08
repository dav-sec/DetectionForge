#!/usr/bin/env python3
"""
strip_custom_fields.py

Genera, a partir de las reglas Sigma fuente de DetectionForge (rules/staging/
o rules/production/), una copia "limpia" sin el bloque `detectionforge:`
(namespace custom del proyecto), destinada a herramientas que no toleran
campos fuera del spec oficial de Sigma — en este proyecto, Chainsaw.

No modifica ni borra nada en el directorio fuente: el bloque `detectionforge`
es evidencia de gobernanza (owner, atomic_test_id, version, siem_targets) y
debe permanecer intacto en rules/staging/ y rules/production/.

Uso:
    python scripts/strip_custom_fields.py
    python scripts/strip_custom_fields.py --src rules/production --dst build/chainsaw-rules
    python scripts/strip_custom_fields.py --src rules/staging --dst build/chainsaw-rules --clean

Por defecto:
    --src   rules/staging
    --dst   build/chainsaw-rules
"""

import argparse
import shutil
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit(
        "Falta PyYAML. Instala con: pip install pyyaml"
    )

CUSTOM_NAMESPACE = "detectionforge"
CORRELATION = object()  # marcador: omitida a propósito, no es un error


def strip_rule(src_path: Path):
    """Carga una regla Sigma y devuelve su contenido sin el namespace custom.
    Devuelve None (y avisa) si el archivo no es un YAML válido o no tiene
    forma de regla Sigma (sin 'detection' o 'logsource')."""
    try:
        docs = [d for d in yaml.safe_load_all(src_path.read_text(encoding="utf-8")) if d is not None]
    except yaml.YAMLError as e:
        print(f"  [SKIP] {src_path.name}: YAML inválido ({e})")
        return None

    # Las reglas de correlación de Sigma (archivo con varios documentos YAML y
    # una clave `correlation`) no son evaluables por Chainsaw: se omiten.
    if any(isinstance(d, dict) and "correlation" in d for d in docs):
        print(f"  [SKIP] {src_path.name}: regla de correlación (Chainsaw no las soporta)")
        return CORRELATION

    if len(docs) != 1:
        print(f"  [SKIP] {src_path.name}: se esperaba un único documento YAML, hay {len(docs)}")
        return None

    raw = docs[0]

    if not isinstance(raw, dict):
        print(f"  [SKIP] {src_path.name}: no es un mapeo YAML válido")
        return None

    if "detection" not in raw or "logsource" not in raw:
        print(f"  [SKIP] {src_path.name}: no parece una regla Sigma (falta detection/logsource)")
        return None

    had_custom_block = CUSTOM_NAMESPACE in raw
    cleaned = {k: v for k, v in raw.items() if k != CUSTOM_NAMESPACE}

    tag = "[OK]  " if had_custom_block else "[OK*] "
    suffix = "" if had_custom_block else " (no tenía bloque detectionforge, se copió igual)"
    print(f"  {tag}{src_path.name}{suffix}")

    return cleaned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--src", default="rules/staging", help="Carpeta fuente con reglas Sigma (default: rules/staging)")
    parser.add_argument("--dst", default="build/chainsaw-rules", help="Carpeta destino para las reglas sin detectionforge (default: build/chainsaw-rules)")
    parser.add_argument("--clean", action="store_true", help="Borra el contenido previo de --dst antes de generar")
    args = parser.parse_args()

    src_dir = Path(args.src)
    dst_dir = Path(args.dst)

    if not src_dir.is_dir():
        sys.exit(f"Error: la carpeta fuente no existe: {src_dir}")

    if args.clean and dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    rule_files = sorted(src_dir.glob("*.yml")) + sorted(src_dir.glob("*.yaml"))
    if not rule_files:
        sys.exit(f"Error: no se encontraron archivos .yml/.yaml en {src_dir}")

    print(f"Procesando {len(rule_files)} regla(s) desde {src_dir} -> {dst_dir}\n")

    written = 0
    skipped = 0      # errores reales (YAML inválido, no es regla Sigma)
    correlations = 0 # omitidas a propósito
    for rule_file in rule_files:
        cleaned = strip_rule(rule_file)
        if cleaned is CORRELATION:
            correlations += 1
            continue
        if cleaned is None:
            skipped += 1
            continue

        out_path = dst_dir / rule_file.name
        with out_path.open("w", encoding="utf-8") as f:
            yaml.dump(
                cleaned,
                f,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
                width=1000,
            )
        written += 1

    print(f"\nListo: {written} regla(s) escritas en {dst_dir}, {correlations} correlación(es) omitida(s) a propósito, {skipped} con error.")
    if written:
        print(
            "\nEjecuta Chainsaw apuntando a la carpeta generada, no a la fuente, por ejemplo:\n"
            f"  chainsaw hunt <ruta_logs> -s {dst_dir} --mapping mappings/sigma-event-logs-all.yml"
        )
    return 0 if skipped == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())