"""
bt_scan.py
Discover nearby Bluetooth Low Energy devices via bleak (cross-platform),
and classic Bluetooth devices via bluetoothctl (Linux).
"""

import asyncio
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict

try:
    from bleak import BleakScanner
    HAVE_BLEAK = True
except Exception:
    HAVE_BLEAK = False


@dataclass
class BTDevice:
    address: str
    name: str = "Unknown"
    rssi: int = 0
    kind: str = "BLE"  # "BLE" or "Classic"
    services: List[str] = field(default_factory=list)


async def _ble_scan_async(timeout: float = 8.0) -> List[BTDevice]:
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    results = []
    for addr, (dev, adv) in devices.items():
        results.append(BTDevice(
            address=addr,
            name=dev.name or "Unknown",
            rssi=adv.rssi if adv.rssi is not None else 0,
            kind="BLE",
            services=list(adv.service_uuids or []),
        ))
    return results


def scan_ble(timeout: float = 8.0) -> List[BTDevice]:
    if not HAVE_BLEAK:
        raise RuntimeError("bleak not installed — run: pip install bleak")
    return asyncio.run(_ble_scan_async(timeout=timeout))


def scan_classic_bt(timeout: int = 10) -> List[BTDevice]:
    """Use bluetoothctl to discover classic Bluetooth devices (Linux only).

    bluetoothctl emits one line per *event*, not one per device — e.g.
    "[NEW] Device AA:BB:.. Some Name" for first sighting, but also
    "[CHG] Device AA:BB:.. RSSI: -49", "[CHG] Device AA:BB:.. ManufacturerData...",
    "[CHG] Device AA:BB:.. Connected: no", etc. for the same device later.
    Only the trailing text on a [NEW] line (or a [CHG] line whose trailing
    text isn't a known metadata field) is treated as a real device name.
    """
    import re
    import time

    MAC_RE = re.compile(r"Device\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*(.*)$")
    METADATA_PREFIXES = (
        "RSSI:", "TxPower:", "ManufacturerData", "ServiceData", "UUIDs:",
        "Paired:", "Trusted:", "Connected:", "LegacyPairing:", "Alias:",
        "ServicesResolved:", "AdvertisingFlags:", "AddressType:",
    )

    devices: Dict[str, BTDevice] = {}
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1
        )
        proc.stdin.write("scan on\n")
        proc.stdin.flush()

        start = time.time()
        while time.time() - start < timeout:
            line = proc.stdout.readline()
            if not line:
                continue

            match = MAC_RE.search(line.strip())
            if not match:
                continue

            addr, trailing = match.group(1), match.group(2).strip()
            is_metadata = any(trailing.startswith(p) for p in METADATA_PREFIXES)

            if addr not in devices:
                name = trailing if (trailing and not is_metadata) else "Unknown"
                devices[addr] = BTDevice(address=addr, name=name, kind="Classic")
            elif devices[addr].name == "Unknown" and trailing and not is_metadata:
                devices[addr].name = trailing

        proc.stdin.write("scan off\n")
        proc.stdin.flush()
        proc.terminate()
    except FileNotFoundError:
        raise RuntimeError("bluetoothctl not found — classic BT scan needs Linux + BlueZ")

    return list(devices.values())


def scan_bluetooth(include_classic: bool = True, timeout: float = 8.0) -> List[BTDevice]:
    results: List[BTDevice] = []
    try:
        results.extend(scan_ble(timeout=timeout))
    except RuntimeError:
        pass

    if include_classic:
        try:
            results.extend(scan_classic_bt(timeout=int(timeout)))
        except RuntimeError:
            pass

    return results
