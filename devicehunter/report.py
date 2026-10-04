"""
report.py
Render scan results as a console table (rich) and export to JSON.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

console = Console()


def print_network_report(hosts, vuln_map=None):
    vuln_map = vuln_map or {}
    table = Table(title="Network Devices", show_lines=True)
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Open Ports / Services")
    table.add_column("CVEs Found", style="bold red")

    for h in hosts:
        svc_lines = []
        cve_lines = []
        for s in h.services:
            label = f"{s.port}/{s.protocol} {s.name}"
            if s.product:
                label += f" ({s.product} {s.version})".rstrip()
            svc_lines.append(label)

            key = f"{h.ip}:{s.port}"
            for cve in vuln_map.get(key, []):
                cve_lines.append(f"{cve.cve_id} [{cve.severity} {cve.score}]")

        table.add_row(
            h.ip,
            h.mac or "-",
            h.hostname or "-",
            "\n".join(svc_lines) or "no open ports found",
            "\n".join(cve_lines) or "-",
        )

    console.print(table)


def print_bt_report(devices):
    table = Table(title="Bluetooth / BLE Devices", show_lines=True)
    table.add_column("Address")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("RSSI")
    table.add_column("Service UUIDs")

    for d in devices:
        table.add_row(d.address, d.name, d.kind, str(d.rssi), "\n".join(d.services) or "-")

    console.print(table)


def export_json(hosts, bt_devices, vuln_map, path):
    vuln_map = vuln_map or {}
    data = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "network_hosts": [],
        "bluetooth_devices": [asdict(d) for d in bt_devices],
    }

    for h in hosts:
        h_dict = asdict(h)
        for s in h_dict["services"]:
            key = f"{h.ip}:{s['port']}"
            s["cves"] = [asdict(c) for c in vuln_map.get(key, [])]
        data["network_hosts"].append(h_dict)

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]Report written to {path}[/green]")
