"""
vuln_lookup.py
Look up known CVEs for a detected product/version using the NVD REST API.
No API key required, but unauthenticated requests are rate-limited
(~5 requests / 30s), so lookups are cached and throttled.
"""

import time
import requests
from dataclasses import dataclass, field
from typing import List, Optional

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_cache = {}
_last_request = 0.0
_MIN_INTERVAL = 6.0  # seconds, stays safely under the public rate limit


@dataclass
class CVEResult:
    cve_id: str
    severity: str
    score: float
    summary: str


def _throttle():
    global _last_request
    elapsed = time.time() - _last_request
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_request = time.time()


def lookup_cves(product: str, version: str = "", cpe: str = "",
                 max_results: int = 5) -> List[CVEResult]:
    """Query NVD by CPE (preferred, precise) or by keyword search."""
    if not product and not cpe:
        return []

    cache_key = cpe or f"{product}:{version}"
    if cache_key in _cache:
        return _cache[cache_key]

    params = {"resultsPerPage": max_results}
    if cpe:
        params["cpeName"] = cpe
    else:
        keyword = f"{product} {version}".strip()
        params["keywordSearch"] = keyword

    _throttle()
    try:
        resp = requests.get(NVD_BASE, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        _cache[cache_key] = []
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score, severity = 0.0, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]
                score = cvss.get("baseScore", 0.0)
                severity = metrics[key][0].get("baseSeverity", cvss.get("baseSeverity", "UNKNOWN"))
                break

        results.append(CVEResult(cve_id=cve_id, severity=severity, score=score, summary=summary[:200]))

    _cache[cache_key] = results
    return results


def enrich_service_with_cves(service) -> List[CVEResult]:
    """Convenience wrapper: given a network_scan.Service, fetch matching CVEs."""
    if not service.product:
        return []
    return lookup_cves(product=service.product, version=service.version, cpe=service.cpe)
