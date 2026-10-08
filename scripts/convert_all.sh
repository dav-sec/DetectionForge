#!/usr/bin/env bash
# convert_all.sh — convierte todas las reglas Sigma de una carpeta a Splunk (SPL)
# y a Elastic. Las reglas normales van a Lucene; las de correlación (T1046,
# T1110) van a ES|QL, porque el backend Lucene no soporta correlaciones.
#
# Uso (desde la raíz del repo):
#   bash scripts/convert_all.sh                 # usa rules/staging
#   bash scripts/convert_all.sh rules/production
#
# Salida: build/queries/<regla>.splunk.txt y build/queries/<regla>.elastic.txt
# Requisitos: sigma-cli con los plugins splunk, elasticsearch, sysmon y windows
#   sigma plugin install splunk elasticsearch sysmon windows

set -u

SRC="${1:-rules/staging}"
OUT="build/queries"
mkdir -p "$OUT"

ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

ok=0
fail=0

run() {  # run <etiqueta> <archivo_salida> <comando sigma...>
    local label="$1" outfile="$2"; shift 2
    if "$@" -o "$outfile" >/dev/null 2>"$ERR"; then
        ok=$((ok + 1))
    else
        fail=$((fail + 1))
        echo "FALLA $label -> $(grep -v '^[[:space:]]*$' "$ERR" | tail -1 | cut -c1-120)"
    fi
}

for f in "$SRC"/*.yml; do
    n="$(basename "$f" .yml)"

    run "splunk : $n" "$OUT/$n.splunk.txt" \
        sigma convert -t splunk -p sysmon -p splunk_windows "$f"

    if grep -q '^correlation:' "$f"; then
        run "elastic(esql): $n" "$OUT/$n.elastic.txt" \
            sigma convert -t esql -p sysmon -p ecs_windows --disable-pipeline-check "$f"
    else
        run "elastic: $n" "$OUT/$n.elastic.txt" \
            sigma convert -t lucene -p sysmon -p ecs_windows "$f"
    fi
done

echo
echo "Conversiones OK: $ok | con error: $fail | salida en $OUT/"
[ "$fail" -eq 0 ]