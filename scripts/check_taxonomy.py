#!/usr/bin/env python3
"""
Valida que cada regla Sigma modificada cumpla la taxonomía obligatoria
definida en docs/taxonomia-estandares.md (seccion 5).

Uso: python3 scripts/check_taxonomy.py <archivo1.yml> <archivo2.yml> ...
(pre-commit invoca este script automáticamente con los archivos en stage)
"""
import sys
import uuid
import yaml

REQUIRED_TOP_LEVEL = [
    "id", "title", "status", "description", "author", "date", "level",
    "logsource", "detection", "falsepositives", "tags", "references",
]
REQUIRED_CUSTOM = ["owner", "version"]
VALID_STATUS = {"experimental", "test", "stable"}
VALID_LEVEL = {"low", "medium", "high", "critical"}


def check_file(path: str) -> list[str]:
    errors = []
    with open(path, "r", encoding="utf-8") as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"{path}: YAML inválido — {e}"]

    if not isinstance(rule, dict):
        return [f"{path}: la regla no es un mapeo YAML válido"]

    for field in REQUIRED_TOP_LEVEL:
        if field not in rule or rule[field] in (None, "", []):
            errors.append(f"{path}: falta el campo obligatorio '{field}'")

    if "id" in rule:
        try:
            uuid.UUID(str(rule["id"]))
        except ValueError:
            errors.append(f"{path}: 'id' no es un UUID válido")

    if rule.get("status") not in VALID_STATUS:
        errors.append(f"{path}: 'status' debe ser uno de {VALID_STATUS}")

    if rule.get("level") not in VALID_LEVEL:
        errors.append(f"{path}: 'level' debe ser uno de {VALID_LEVEL}")

    references = rule.get("references", [])
    if any("attack.mitre.org" in str(r) for r in references):
        errors.append(
            f"{path}: 'references' no debe enlazar attack.mitre.org "
            f"(regla SigmaHQ) — la técnica va solo en 'tags'"
        )

    tags = rule.get("tags", [])
    if not any(str(t).startswith("attack.t") for t in tags):
        errors.append(f"{path}: 'tags' debe incluir al menos una técnica attack.txxxx")
    if not any(
        str(t).startswith("attack.") and not str(t).startswith("attack.t")
        for t in tags
    ):
        errors.append(f"{path}: 'tags' debe incluir la táctica (ej. attack.execution)")

    custom = rule.get("detectionforge", {})
    if not isinstance(custom, dict):
        errors.append(f"{path}: falta el bloque 'detectionforge' con metadatos custom")
    else:
        for field in REQUIRED_CUSTOM:
            if field not in custom or custom[field] in (None, ""):
                errors.append(f"{path}: falta 'detectionforge.{field}'")
        # atomic_test_id solo es obligatorio para reglas en production/
        if "production/" in path.replace("\\", "/") and not custom.get("atomic_test_id"):
            errors.append(
                f"{path}: reglas en production/ requieren 'detectionforge.atomic_test_id'"
            )

    return errors


def main() -> int:
    files = sys.argv[1:]
    if not files:
        print("No se pasaron archivos, nada que validar.")
        return 0

    all_errors = []
    for path in files:
        all_errors.extend(check_file(path))

    if all_errors:
        print("Validación de taxonomía FALLIDA:\n")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    print(f"OK — {len(files)} regla(s) cumplen la taxonomía obligatoria.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
