"""
network_scan.py
Discover live hosts on the local subnet via ARP, then fingerprint open
ports/services on each host using nmap (via python-nmap).
"""

import ipaddress
import socket
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from scapy.all import ARP, Ether, srp
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

try:
    import nmap
    HAVE_NMAP = True
except Exception:
    HAVE_NMAP = False


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""
    cpe: str = ""


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    services: List[Service] = field(default_factory=list)


def get_local_subnet() -> Optional[str]:
    """Guess the local /24 subnet from the default-route interface IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return None


def arp_scan(subnet: str, timeout: int = 2) -> List[Host]:
    """ARP-sweep a subnet (e.g. '192.168.1.0/24'). Requires scapy + root."""
    if not HAVE_SCAPY:
        raise RuntimeError("scapy not installed — run: pip install scapy")

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=0)[0]
    hosts = []
    for _, received in result:
        host = Host(ip=received.psrc, mac=received.hwsrc)
        try:
            host.hostname = socket.gethostbyaddr(received.psrc)[0]
        except Exception:
            pass
        hosts.append(host)
    return hosts


def ping_sweep_fallback(subnet: str) -> List[Host]:
    """Non-root fallback: ping sweep + ARP table read (Linux/Mac)."""
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = []
    for ip in net.hosts():
        ip_s = str(ip)
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_s],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if res.returncode == 0:
            hosts.append(Host(ip=ip_s))
    return hosts


def fingerprint_host(host: Host, ports: str = "1-1024", fast: bool = True) -> Host:
    """Run nmap -sV against a host to identify open ports and service versions."""
    if not HAVE_NMAP:
        raise RuntimeError("python-nmap not installed — run: pip install python-nmap")

    scanner = nmap.PortScanner()
    args = f"-sV -T4 {'-F' if fast else '-p ' + ports}"
    scanner.scan(hosts=host.ip, arguments=args)

    if host.ip not in scanner.all_hosts():
        return host

    data = scanner[host.ip]
    for proto in data.all_protocols():
        for port, info in data[proto].items():
            svc = Service(
                port=port,
                protocol=proto,
                name=info.get("name", ""),
                product=info.get("product", ""),
                version=info.get("version", ""),
                cpe=info.get("cpe", ""),
            )
            host.services.append(svc)
    return host


def scan_network(subnet: Optional[str] = None, fingerprint: bool = True,
                  fast: bool = True) -> List[Host]:
    subnet = subnet or get_local_subnet()
    if not subnet:
        raise RuntimeError("Could not determine local subnet — pass --subnet explicitly.")

    try:
        hosts = arp_scan(subnet)
    except RuntimeError:
        hosts = ping_sweep_fallback(subnet)

    if fingerprint:
        for h in hosts:
            try:
                fingerprint_host(h, fast=fast)
            except RuntimeError:
                pass  # nmap unavailable — leave host with no services

    return hosts
