#!/usr/bin/env bash
set -euo pipefail

echo "=== Tests du Network Sniffer ==="

python3 -m py_compile sniffer.py sniffer_advanced.py sniffer_export.py
python3 sniffer.py --help >/dev/null
python3 sniffer_advanced.py --help >/dev/null
python3 sniffer_export.py --help >/dev/null

python3 - <<'PY'
import csv
import json
import tempfile
from pathlib import Path

from scapy.all import IP, TCP, Raw

from sniffer_advanced import NetworkSniffer
from sniffer_export import SnifferWithExport

packet = IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443) / Raw(load=b"test payload")

sniffer = NetworkSniffer()
sniffer.analyze_packet(packet)
assert sniffer.packet_count == 1
assert sniffer.stats["TCP"] == 1

with tempfile.TemporaryDirectory() as directory:
    output_dir = Path(directory)
    exporter = SnifferWithExport()
    exporter.analyze_packet(packet)
    json_path = output_dir / "capture.json"
    csv_path = output_dir / "capture.csv"
    exporter.export_json(json_path)
    exporter.export_csv(csv_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))[0]["protocol"] == "TCP"
    with csv_path.open(newline="", encoding="utf-8") as capture:
        assert next(csv.DictReader(capture))["dst_port"] == "443"

print("Tests Python: OK")
PY

echo "=== Tests terminés avec succès ==="
