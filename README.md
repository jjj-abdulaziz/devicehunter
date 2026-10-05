# DeviceHunter

Scans your surroundings for devices, network hosts and nearby Bluetooth/BLE
devices, fingerprints running services, and checks them against known CVEs
via the NVD API.

**Only run this against networks and devices you own or have explicit
authorization to test.** Unauthorized scanning of networks you don't control
can be illegal in many jurisdictions.

## Install

```bash
# System deps (Linux/Debian example — nmap + bluez for classic BT)
sudo apt install nmap bluez

cd devicehunter
pip install -r requirements.txt
pip install -e .
```

ARP scanning and some nmap scan types need raw sockets, so most commands
should be run with `sudo`.

## Usage

```bash
# Network only: discover hosts, fingerprint services, check CVEs
sudo devicehunter network

# Specify subnet explicitly, full port range, skip CVE lookups
sudo devicehunter network --subnet 192.168.1.0/24 --full --no-vulns

# Bluetooth / BLE only
sudo devicehunter bluetooth --timeout 15

# Both, and save a JSON report
sudo devicehunter all --json report.json
```

## How it works

- **Network discovery**: ARP sweep (scapy) over the local /24, falls back to
  a ping sweep if scapy/root isn't available.
- **Fingerprinting**: `nmap -sV` against each discovered host to identify
  open ports, service names, and product/version strings.
- **Bluetooth**: `bleak` for BLE advertisement scanning (cross-platform),
  `bluetoothctl` for classic Bluetooth device discovery (Linux/BlueZ).
- **Vulnerability lookup**: each identified product/version is queried
  against the NVD CVE 2.0 API (keyword or CPE match), returning CVE ID,
  CVSS severity/score, and a short summary. Lookups are cached and
  throttled to stay under NVD's unauthenticated rate limit.

## Notes / limitations

- NVD keyword matching is approximate — verify any flagged CVE manually
  before treating it as confirmed.
- Classic Bluetooth discovery depends on BlueZ (`bluetoothctl`) and is
  Linux-only; BLE scanning works cross-platform via bleak.
- For heavier use, get a free NVD API key and add it to the request headers
  in `vuln_lookup.py` to raise the rate limit significantly.
