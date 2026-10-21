"""
siem_clients.py — funciones para consultar Splunk y Elastic vía API,
sin pasar por la interfaz web. Usado por runner.py para validar si una
regla detecta el evento generado por su atomic test correspondiente.
"""

import json
import time
import requests
import urllib3

import config

# Los certificados del laboratorio son autofirmados (igual que con -k en curl)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def query_splunk(spl_query: str, earliest: str = "-15m", timeout: int = 30) -> list[dict]:
    """
    Ejecuta una búsqueda SPL vía la API REST de Splunk y devuelve los eventos
    encontrados como una lista de diccionarios.

    spl_query: la consulta SPL completa (SIN el "search" inicial, se agrega aquí)
    earliest:  ventana de tiempo hacia atrás (ej. "-15m", "-1h")
    """
    url = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}/services/search/jobs/export"
    full_query = spl_query if spl_query.strip().startswith("search") else f"search {spl_query}"

    resp = requests.post(
        url,
        auth=(config.SPLUNK_USER, config.SPLUNK_PASSWORD),
        verify=False,
        timeout=timeout,
        data={
            "search": full_query,
            "earliest_time": earliest,
            "output_mode": "json",
        },
    )
    resp.raise_for_status()

    # /export devuelve un stream de objetos JSON separados por líneas, no un único JSON
    events = []
    for line in resp.text.strip().splitlines():
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "result" in obj:
            events.append(obj["result"])
    return events


def query_elastic(lucene_query: str, index_pattern: str = "logs-windows.sysmon_operational-*",
                   minutes_back: int = 15, timeout: int = 30) -> list[dict]:
    """
    Ejecuta una búsqueda en sintaxis Lucene vía la API de Elasticsearch y
    devuelve los documentos encontrados.
    """
    url = f"http://{config.ELASTIC_HOST}:{config.ELASTIC_PORT}/{index_pattern}/_search"

    body = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": lucene_query}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_back}m"}}},
                ]
            }
        },
        "size": 50,
    }

    resp = requests.post(
        url,
        headers={
            "Authorization": f"ApiKey {config.ELASTIC_API_KEY}",
            "Content-Type": "application/json",
        },
        verify=False,
        timeout=timeout,
        data=json.dumps(body),
    )
    resp.raise_for_status()
    data = resp.json()
    return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]


if __name__ == "__main__":
    # Prueba rápida manual: corre esto directo para confirmar que ambas
    # conexiones funcionan, usando la misma consulta que ya validamos a mano.
    print("=== Probando conexión a Splunk ===")
    try:
        results = query_splunk(
            'source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 '
            'Image="*\\powershell.exe" CommandLine IN ("*-enc *", "*-EncodedCommand*", "*-e *")',
            earliest="-24h",
        )
        print(f"Splunk OK — {len(results)} evento(s) encontrados")
    except Exception as e:
        print(f"Splunk ERROR: {e}")

    print("\n=== Probando conexión a Elastic ===")
    try:
        results = query_elastic(
            'process.executable.caseless:*\\\\powershell.exe AND '
            '(process.command_line:(*\\-enc\\ * OR *\\-EncodedCommand* OR *\\-e\\ *))',
            minutes_back=1440,
        )
        print(f"Elastic OK — {len(results)} evento(s) encontrados")
    except Exception as e:
        print(f"Elastic ERROR: {e}")
