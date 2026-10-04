"""
cli.py
DeviceHunter — scan your surroundings for network + Bluetooth devices
and flag known vulnerabilities in what they're running.

Usage:
  devicehunter network [--subnet 192.168.1.0/24] [--full] [--no-fingerprint] [--json out.json]
  devicehunter bluetooth [--timeout 10] [--no-classic] [--json out.json]
  devicehunter all [--subnet ...] [--json out.json]
"""

import argparse
import sys

from devicehunter import network_scan, bt_scan, vuln_lookup, report


def cmd_network(args):
    report.console.print("[cyan]Discovering hosts on the local network...[/cyan]")
    hosts = network_scan.scan_network(
        subnet=args.subnet,
        fingerprint=not args.no_fingerprint,
        fast=not args.full,
    )
    report.console.print(f"[green]Found {len(hosts)} host(s).[/green]")

    vuln_map = {}
    if not args.no_fingerprint and not args.no_vulns:
        report.console.print("[cyan]Checking services against known CVEs (NVD)...[/cyan]")
        for h in hosts:
            for s in h.services:
                if not s.product:
                    continue
                cves = vuln_lookup.enrich_service_with_cves(s)
                if cves:
                    vuln_map[f"{h.ip}:{s.port}"] = cves

    report.print_network_report(hosts, vuln_map)
    if args.json:
        report.export_json(hosts, [], vuln_map, args.json)


def cmd_bluetooth(args):
    report.console.print("[cyan]Scanning for Bluetooth / BLE devices...[/cyan]")
    devices = bt_scan.scan_bluetooth(include_classic=not args.no_classic, timeout=args.timeout)
    report.console.print(f"[green]Found {len(devices)} device(s).[/green]")
    report.print_bt_report(devices)
    if args.json:
        report.export_json([], devices, {}, args.json)


def cmd_all(args):
    report.console.print("[cyan]Discovering hosts on the local network...[/cyan]")
    hosts = network_scan.scan_network(subnet=args.subnet, fingerprint=True, fast=not args.full)

    vuln_map = {}
    if not args.no_vulns:
        report.console.print("[cyan]Checking services against known CVEs (NVD)...[/cyan]")
        for h in hosts:
            for s in h.services:
                if not s.product:
                    continue
                cves = vuln_lookup.enrich_service_with_cves(s)
                if cves:
                    vuln_map[f"{h.ip}:{s.port}"] = cves

    report.console.print("[cyan]Scanning for Bluetooth / BLE devices...[/cyan]")
    devices = bt_scan.scan_bluetooth(timeout=args.timeout)

    report.print_network_report(hosts, vuln_map)
    report.print_bt_report(devices)
    if args.json:
        report.export_json(hosts, devices, vuln_map, args.json)


def main():
    parser = argparse.ArgumentParser(
        prog="devicehunter",
        description="Scan nearby network + Bluetooth devices and flag known vulnerabilities."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_net = sub.add_parser("network", help="Scan the local network (ARP + nmap)")
    p_net.add_argument("--subnet", help="e.g. 192.168.1.0/24 (auto-detected if omitted)")
    p_net.add_argument("--full", action="store_true", help="Full 1-1024 port scan instead of fast top-100")
    p_net.add_argument("--no-fingerprint", action="store_true", help="Skip nmap service fingerprinting")
    p_net.add_argument("--no-vulns", action="store_true", help="Skip CVE lookups")
    p_net.add_argument("--json", help="Write results to this JSON file")
    p_net.set_defaults(func=cmd_network)

    p_bt = sub.add_parser("bluetooth", help="Scan nearby Bluetooth/BLE devices")
    p_bt.add_argument("--timeout", type=float, default=8.0, help="Scan duration in seconds")
    p_bt.add_argument("--no-classic", action="store_true", help="Skip classic BT (bluetoothctl), BLE only")
    p_bt.add_argument("--json", help="Write results to this JSON file")
    p_bt.set_defaults(func=cmd_bluetooth)

    p_all = sub.add_parser("all", help="Run network + Bluetooth scans together")
    p_all.add_argument("--subnet", help="e.g. 192.168.1.0/24 (auto-detected if omitted)")
    p_all.add_argument("--full", action="store_true", help="Full port scan instead of fast top-100")
    p_all.add_argument("--no-vulns", action="store_true", help="Skip CVE lookups")
    p_all.add_argument("--timeout", type=float, default=8.0, help="Bluetooth scan duration in seconds")
    p_all.add_argument("--json", help="Write results to this JSON file")
    p_all.set_defaults(func=cmd_all)

    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as e:
        report.console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except PermissionError:
        report.console.print("[red]Permission denied — ARP scanning and some nmap scans need root. Try: sudo devicehunter ...[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        report.console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
