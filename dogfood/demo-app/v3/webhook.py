"""파트너 시스템 연동 (v2 신규)."""

import json
import tempfile

import requests


def fetch_partner_status(host):
    response = requests.get(f"https://{host}/api/status", timeout=5)
    return response.json()


def load_notification(raw):
    return json.loads(raw)


def export_payload(data):
    path = tempfile.mktemp(suffix=".json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(str(data))
    return path
