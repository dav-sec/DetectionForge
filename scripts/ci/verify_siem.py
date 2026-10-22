#!/usr/bin/env python3
"""
verify_siem.py - Se ejecuta EN la VM SIEM (vía SSH desde el pipeline).

1. Comprueba salud de Elasticsearch y Splunk.
2. Valida sintácticamente cada consulta convertida SIN ejecutarla:
   - Elastic: POST /_all/_validate/query
   - Splunk : POST /services/search/parser (parse_only)

Variables de entorno: ES_URL, ES_USER, ES_PASS, SPLUNK_URL, SPLUNK_USER, SPLUNK_PASS
Uso: python3 verify_siem.py <directorio_converted>   (con subcarpetas splunk/ y lucene/)
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
CTX = ssl.create_default_context()
CTX.check_hostname = False          # Splunk usa certificado autofirmado en el lab
CTX.verify_mode = ssl.CERT_NONE


def auth(user, pwd):
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


def call(url, user, pwd, data=None, headers=None):
    h = {"Authorization": auth(user, pwd)}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:  # conexión rechazada, timeout...
        return 0, str(e)


def es(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    return call(ES_URL + path, os.environ["ES_USER"], os.environ["ES_PASS"], data,
                {"Content-Type": "application/json"})


def splunk(path, form=None):
    data = urllib.parse.urlencode(form).encode() if form else None
    return call(SPLUNK_URL + path, os.environ["SPLUNK_USER"], os.environ["SPLUNK_PASS"], data)


def main(root: Path) -> int:
    failures = 0

    print("== Salud de los SIEM ==")
    code, body = es("/_cluster/health")
    status = json.loads(body).get("status") if code == 200 else None
    print(f"Elasticsearch: HTTP {code} status={status}")
    failures += code != 200 or status == "red"

    code, _ = splunk("/services/server/info?output_mode=json")
    print(f"Splunk (8089): HTTP {code}")
    failures += code != 200

    print("\n== Validación de consultas Lucene (Elastic) ==")
    for f in sorted((root / "lucene").glob("*.txt")):
        q = f.read_text().strip()
        if not q:
            continue
        code, body = es("/_all/_validate/query?allow_no_indices=true",
                        {"query": {"query_string": {"query": q, "analyze_wildcard": True}}})
        ok = code == 200 and json.loads(body).get("valid", False)
        print(f"[{'OK' if ok else 'FAIL'}] {f.name}")
        if not ok:
            print(f"       {body[:300]}")
            failures += 1

    print("\n== Validación de consultas SPL (Splunk) ==")
    for f in sorted((root / "splunk").glob("*.spl")):
        q = f.read_text().strip()
        if not q:
            continue
        if not q.startswith(("|", "search ")):
            q = "search " + q
        code, body = splunk("/services/search/parser?output_mode=json",
                            {"q": q, "parse_only": "true"})
        ok = code == 200
        print(f"[{'OK' if ok else 'FAIL'}] {f.name}")
        if not ok:
            print(f"       {body[:300]}")
            failures += 1

    print(f"\nResultado: {failures} fallo(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
