"""
runner.py — valida empíricamente una regla Sigma de DetectionForge.

Flujo:
  1. Lee la regla y su campo detectionforge.atomic_test_id (solo informativo:
     el atomic test se ejecuta MANUALMENTE en la VM víctima antes de correr
     este script — ver instrucciones al final del archivo).
  2. Traduce la regla a SPL y a Lucene con el motor de pysigma (Entregable 2).
  3. Consulta Splunk y Elastic con esas consultas reales.
  4. Reporta PASS/FAIL por SIEM, y actualiza validation_status en la regla
     si ambos SIEM confirman la detección.

Uso:
    python3 runner.py rules/staging/t1059.001_powershell_encoded_command.yml
"""

import subprocess
import argparse
import sys
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows

from siem_clients import query_splunk, query_elastic


def load_rule_metadata(rule_path: Path) -> dict:
    """Lee los campos detectionforge.* de la regla, para mostrarlos en el reporte."""
    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    return raw.get("detectionforge", {})

def translate_rule(rule_path: Path) -> tuple[str, str]:
    """
    Traduce la regla a SPL y a Lucene invocando sigma-cli por línea de
    comandos (el mismo mecanismo que usa scripts/convert_all.sh), en vez de
    la API de Python directa — evita efectos colaterales de registro de
    pipelines entre paquetes instalados.
    """
    spl_result = subprocess.run(
    ["/home/sebastian/.local/bin/sigma", "convert", "-t", "splunk", "-p", "sysmon", "-p", "splunk_windows", str(rule_path)],
    capture_output=True, text=True, check=True,
    )
    spl = spl_result.stdout.strip()

    lucene_result = subprocess.run(
    ["/home/sebastian/.local/bin/sigma", "convert", "-t", "lucene", "-p", "ecs_windows", str(rule_path)],
    capture_output=True, text=True, check=True,
    )
    lucene = lucene_result.stdout.strip()

    return spl, lucene


def run_validation(rule_path: Path, lookback_minutes: int = 60) -> dict:
    meta = load_rule_metadata(rule_path)
    print(f"\n{'='*70}")
    print(f"Regla:          {rule_path.name}")
    print(f"atomic_test_id: {meta.get('atomic_test_id', '(no definido)')}")
    print(f"{'='*70}")

    try:
        spl, lucene = translate_rule(rule_path)
    except Exception as e:
        print(f"[ERROR] No se pudo traducir la regla: {e}")
        return {"rule": rule_path.name, "splunk": "ERROR", "elastic": "ERROR"}

    print(f"\nSPL generado:\n  {spl}")
    print(f"\nLucene generado:\n  {lucene}")

    # --- Splunk ---
    print(f"\nConsultando Splunk (últimos {lookback_minutes} min)...")
    try:
        splunk_hits = query_splunk(spl, earliest=f"-{lookback_minutes}m")
        splunk_result = "PASS" if splunk_hits else "FAIL"
        print(f"  -> {splunk_result} ({len(splunk_hits)} evento(s))")
    except Exception as e:
        splunk_result = "ERROR"
        print(f"  -> ERROR: {e}")

    # --- Elastic ---
    print(f"\nConsultando Elastic (últimos {lookback_minutes} min)...")
    try:
        elastic_hits = query_elastic(lucene, minutes_back=lookback_minutes)
        elastic_result = "PASS" if elastic_hits else "FAIL"
        print(f"  -> {elastic_result} ({len(elastic_hits)} documento(s))")
    except Exception as e:
        elastic_result = "ERROR"
        print(f"  -> ERROR: {e}")

    return {"rule": rule_path.name, "splunk": splunk_result, "elastic": elastic_result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule", help="Ruta a la regla Sigma a validar (ej. rules/staging/t1059.001_....yml)")
    parser.add_argument("--lookback", type=int, default=60,
                         help="Minutos hacia atrás a buscar en los SIEM (default: 60)")
    args = parser.parse_args()

    rule_path = Path(args.rule)
    if not rule_path.is_file():
        sys.exit(f"Error: no existe el archivo {rule_path}")

    result = run_validation(rule_path, lookback_minutes=args.lookback)

    print(f"\n{'='*70}")
    print("RESUMEN")
    print(f"{'='*70}")
    print(f"  Splunk:  {result['splunk']}")
    print(f"  Elastic: {result['elastic']}")

    if result["splunk"] == "PASS" and result["elastic"] == "PASS":
        print("\n✅ Regla validada en ambos SIEM — lista para evidencia de promoción a producción.")
        sys.exit(0)
    else:
        print("\n❌ La regla NO quedó validada en ambos SIEM. Revisa:")
        print("   - ¿Ejecutaste el atomic_test_id correcto en la VM víctima recientemente?")
        print("   - ¿El --lookback cubre el momento en que lo ejecutaste?")
        sys.exit(1)


if __name__ == "__main__":
    main()
