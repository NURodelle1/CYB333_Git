#!/usr/bin/env python3
"""IOC Enrichment (VT + OTX + AbuseIPDB) -> Excel-friendly CSV (+ optional executive summary)

Supported IOC types:
- IPv4
- MD5 / SHA1 / SHA256

Required environment variables:
- VT_API_KEY
- OTX_API_KEY
- ABUSEIPDB_API_KEY
"""

import os
import re
import csv
import time
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import requests

# -------------------------
# Constants
# -------------------------
BLANK = ""  # what we write when a source does not analyze an IOC type OR no-data

# -------------------------
# API Keys
# -------------------------
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY not found in environment variables")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY not found in environment variables")
if not ABUSEIPDB_API_KEY:
    raise RuntimeError("ABUSEIPDB_API_KEY not found in environment variables")

VT_HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}
OTX_HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}
ABUSEIPDB_HEADERS = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

# -------------------------
# IOC Type Detection
# -------------------------
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    ioc = (ioc or "").strip()
    if IPV4_RE.match(ioc):
        return "ip"
    if SHA256_RE.match(ioc):
        return "sha256"
    if SHA1_RE.match(ioc):
        return "sha1"
    if MD5_RE.match(ioc):
        return "md5"
    return "unknown"


# -------------------------
# HTTP Helpers
# -------------------------
def safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"raw_text": (resp.text or "")[:3000]}


def http_get(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
    retries: int = 2,
    backoff: int = 2,
) -> requests.Response:
    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
            if r.status_code in (429, 502, 503, 504) and attempt < retries:
                time.sleep(backoff ** attempt)
                continue
            return r
        except Exception as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
                continue
            raise
    raise last_exc  # pragma: no cover


# -------------------------
# API Lookups
# -------------------------
def vt_lookup_ip(ip: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = http_get(url, VT_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}


def vt_lookup_hash(file_hash: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    r = http_get(url, VT_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}


def otx_lookup_ip(ip: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    r = http_get(url, OTX_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}


def otx_lookup_hash(file_hash: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    r = http_get(url, OTX_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}


def abuseipdb_lookup_ip(ip: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    r = http_get(url, ABUSEIPDB_HEADERS, params=params)
    return {"status_code": r.status_code, "data": safe_json(r)}


# -------------------------
# Helpers
# -------------------------
def epoch_to_iso_utc(epoch_int) -> str:
    try:
        if epoch_int is None or epoch_int == "":
            return BLANK
        return datetime.fromtimestamp(int(epoch_int), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return BLANK


def _to_int(x, default: int = 0) -> int:
    try:
        if x is None or x == "":
            return default
        return int(x)
    except Exception:
        return default


# -------------------------
# Summarizers (blank defaults)
# -------------------------
def summarize_vt(result: Dict[str, Any]) -> Dict[str, Any]:
    """Returns VT fields INCLUDING a correct detection ratio string.

    Detection ratio format used here: (malicious + suspicious) / total
    where total = sum of VT last_analysis_stats values.
    """
    if result.get("status_code") != 200:
        return {"vt_ok": False}

    data = (result.get("data") or {}).get("data") or {}
    attr = data.get("attributes") or {}
    stats = (attr.get("last_analysis_stats") or {})

    malicious = _to_int(stats.get("malicious"), 0)
    suspicious = _to_int(stats.get("suspicious"), 0)

    # total = sum of all numeric buckets in last_analysis_stats
    total = 0
    for v in stats.values():
        total += _to_int(v, 0)

    detection_ratio = BLANK
    if total > 0:
        detection_ratio = f"{malicious + suspicious}/{total}"

    # last_analysis_date is epoch seconds in many VT objects
    last_analysis_utc = epoch_to_iso_utc(attr.get("last_analysis_date"))

    return {
        "vt_ok": True,
        "vt_malicious": stats.get("malicious", BLANK),
        "vt_suspicious": stats.get("suspicious", BLANK),
        "vt_harmless": stats.get("harmless", BLANK),
        "vt_undetected": stats.get("undetected", BLANK),
        "vt_reputation": attr.get("reputation", BLANK),
        # FIX: always a ratio string, never a date
        "vt_detection_ratio": detection_ratio,
        # keep separate so it can't land in the ratio column
        "vt_last_analysis_utc": last_analysis_utc,
    }


def summarize_otx(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("status_code") != 200:
        return {"otx_ok": False}

    d = result.get("data") or {}
    pulse_info = d.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []

    pulse_count = len(pulses)
    names = []
    for p in pulses[:5]:
        name = p.get("name")
        if name:
            names.append(name)

    top_pulses = "; ".join(names).strip()

    return {
        "otx_ok": True,
        "otx_pulse_count": pulse_count,
        "otx_top_pulses": top_pulses,  # blank if none
    }


def summarize_abuseipdb(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("status_code") != 200:
        return {"abuse_ok": False}

    data = (result.get("data") or {}).get("data") or {}

    return {
        "abuse_ok": True,
        "abuse_confidence_score": data.get("abuseConfidenceScore", BLANK),
        "abuse_total_reports": data.get("totalReports", BLANK),
        "abuse_last_reported": data.get("lastReportedAt", BLANK),
        "abuse_country_code": data.get("countryCode", BLANK),
        "abuse_isp": data.get("isp", BLANK),
        "abuse_domain": data.get("domain", BLANK),
        "abuse_usage_type": data.get("usageType", BLANK),
    }


# -------------------------
# Risk scoring (treat blanks as 0)
# -------------------------
def _safe_num(x, default=0.0) -> float:
    try:
        if x is None:
            return default
        s = str(x).strip()
        if s == "":
            return default
        return float(s)
    except Exception:
        return default


def compute_risk_score(row: Dict[str, Any]) -> int:
    vt_m = _safe_num(row.get("vt_malicious"), 0)
    vt_s = _safe_num(row.get("vt_suspicious"), 0)
    otx_c = _safe_num(row.get("otx_pulse_count"), 0)
    abuse = _safe_num(row.get("abuse_confidence_score"), 0)

    score = (vt_m * 15) + (vt_s * 8) + (min(otx_c, 20) * 2) + (abuse * 0.8)
    score = max(0, min(100, score))
    return int(round(score))


def risk_level(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def recommended_action(level: str) -> str:
    if level == "High":
        return "Block + hunt"
    if level == "Medium":
        return "Monitor + targeted hunt"
    return "Document / watchlist"


def evidence_strength(row: Dict[str, Any]) -> str:
    signals = 0
    if _safe_num(row.get("vt_malicious"), 0) > 0 or _safe_num(row.get("vt_suspicious"), 0) > 0:
        signals += 1
    if _safe_num(row.get("otx_pulse_count"), 0) > 0:
        signals += 1
    if _safe_num(row.get("abuse_confidence_score"), 0) > 0:
        signals += 1

    return ["None", "Weak", "Moderate", "Strong"][signals]


# -------------------------
# Output fields
# -------------------------
CSV_FIELDS = [
    "ioc",
    "ioc_type",
    "timestamp",

    "vt_ok",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_reputation",
    "vt_detection_ratio",      # <-- FIXED
    "vt_last_analysis_utc",    # separate column

    "otx_ok",
    "otx_pulse_count",
    "otx_top_pulses",

    "abuse_ok",
    "abuse_confidence_score",
    "abuse_total_reports",
    "abuse_last_reported",
    "abuse_country_code",
    "abuse_isp",
    "abuse_domain",
    "abuse_usage_type",

    "risk_score",
    "risk_level",
    "recommended_action",
    "evidence_strength",

    "error",
]


def stub_for_vt() -> Dict[str, Any]:
    return {
        "vt_ok": BLANK,
        "vt_malicious": BLANK,
        "vt_suspicious": BLANK,
        "vt_harmless": BLANK,
        "vt_undetected": BLANK,
        "vt_reputation": BLANK,
        "vt_detection_ratio": BLANK,
        "vt_last_analysis_utc": BLANK,
    }


def stub_for_otx() -> Dict[str, Any]:
    return {
        "otx_ok": BLANK,
        "otx_pulse_count": BLANK,
        "otx_top_pulses": BLANK,
    }


def stub_for_abuse() -> Dict[str, Any]:
    return {
        "abuse_ok": BLANK,
        "abuse_confidence_score": BLANK,
        "abuse_total_reports": BLANK,
        "abuse_last_reported": BLANK,
        "abuse_country_code": BLANK,
        "abuse_isp": BLANK,
        "abuse_domain": BLANK,
        "abuse_usage_type": BLANK,
    }


def finalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Guarantee all columns exist; leave missing values blank."""
    for k in CSV_FIELDS:
        if k not in row or row[k] is None:
            row[k] = BLANK
    return row


# -------------------------
# Core enrichment
# -------------------------
def enrich_to_row(ioc: str, sleep_s: float = 1.0, verbose: bool = True) -> Dict[str, Any]:
    ioc = (ioc or "").strip()
    ioc_type = detect_ioc_type(ioc)

    row: Dict[str, Any] = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "error": BLANK,
    }

    # Initialize fields to blank so CSV always has the columns
    row.update(stub_for_vt())
    row.update(stub_for_otx())
    row.update(stub_for_abuse())

    try:
        if ioc_type == "ip":
            row.update(summarize_vt(vt_lookup_ip(ioc)))
            time.sleep(sleep_s)

            row.update(summarize_otx(otx_lookup_ip(ioc)))
            time.sleep(sleep_s)

            row.update(summarize_abuseipdb(abuseipdb_lookup_ip(ioc)))

        elif ioc_type in ("md5", "sha1", "sha256"):
            row.update(summarize_vt(vt_lookup_hash(ioc)))
            time.sleep(sleep_s)

            row.update(summarize_otx(otx_lookup_hash(ioc)))
            # AbuseIPDB does NOT analyze hashes -> keep blank stubs

        else:
            row["error"] = "Unsupported or unknown IOC type"

    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"

    # Derived fields (always computed; blanks treated as 0)
    score = compute_risk_score(row)
    lvl = risk_level(score)
    row["risk_score"] = score
    row["risk_level"] = lvl
    row["recommended_action"] = recommended_action(lvl)
    row["evidence_strength"] = evidence_strength(row)

    row = finalize_row(row)

    if verbose:
        print(f"{ioc} ({ioc_type}) -> risk {row['risk_score']} {row['risk_level']}")

    return row


# -------------------------
# CSV + Executive summary
# -------------------------
def export_csv(rows: List[Dict[str, Any]], csv_path: str) -> None:
    rows_sorted = sorted(rows, key=lambda r: int(_safe_num(r.get("risk_score"), 0)), reverse=True)
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows_sorted:
            w.writerow({k: (BLANK if r.get(k) is None else r.get(k)) for k in CSV_FIELDS})


def export_executive_summary(rows: List[Dict[str, Any]], out_path: str) -> None:
    total = len(rows)
    high = sum(1 for r in rows if r.get("risk_level") == "High")
    med = sum(1 for r in rows if r.get("risk_level") == "Medium")
    low = sum(1 for r in rows if r.get("risk_level") == "Low")

    top = sorted(rows, key=lambda r: int(_safe_num(r.get("risk_score"), 0)), reverse=True)[:10]

    lines = []
    lines.append("IOC Enrichment - Executive Summary")
    lines.append("=" * 34)
    lines.append(f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Total indicators: {total}")
    lines.append(f"High: {high} | Medium: {med} | Low: {low}")
    lines.append("")
    lines.append("Top indicators (by risk score):")

    for r in top:
        lines.append(
            f"- {r.get('ioc','')} | {r.get('ioc_type','')} | score {r.get('risk_score','')} ({r.get('risk_level','')}) | "
            f"VT ratio: {r.get('vt_detection_ratio','')} | OTX pulses: {r.get('otx_pulse_count','')} | "
            f"Abuse: {r.get('abuse_confidence_score','')} | Action: {r.get('recommended_action','')}"
        )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# -------------------------
# Input file helpers
# -------------------------
def normalize_powershell_path(raw: str) -> str:
    if raw is None:
        return ""
    s = raw.strip()

    if s.startswith("&"):
        s = s[1:].strip()

    s = s.strip().strip('"').strip()

    if "'" in s:
        parts = s.split("'")
        if len(parts) >= 3:
            s = parts[1].strip()

    s = os.path.expandvars(os.path.expanduser(s))
    return os.path.normpath(s)


def prompt_for_input_file() -> str:
    print("\nEnter the path to your IOC input .txt file (one IOC per line).", flush=True)
    print("Tip: Drag-and-drop the file into the terminal. If it pastes like & 'C:\\\\...\\\\file.txt', that's OK.", flush=True)

    while True:
        raw = input("IOC file path: ").strip()
        path = normalize_powershell_path(raw)
        if not path:
            print("Path was empty. Try again.", flush=True)
            continue
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        if os.path.exists(path) and os.path.isfile(path):
            return path
        print(f"File not found: {path}", flush=True)


def load_iocs_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        iocs = [line.strip() for line in f if line.strip()]

    seen = set()
    out = []
    for x in iocs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# -------------------------
# Menu
# -------------------------
def choose_mode_interactive() -> str:
    print("\nSelect output mode:", flush=True)
    print(" 1) CSV only", flush=True)
    print(" 2) CSV + Executive Summary", flush=True)
    print(" 3) Executive Summary only", flush=True)

    choice = input("Enter choice (1/2/3): ").strip()
    if choice == "1":
        return "csv"
    if choice == "2":
        return "both"
    if choice == "3":
        return "exec"

    print("Invalid choice. Defaulting to CSV only.")
    return "csv"


# -------------------------
# Main
# -------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="IOC Enrichment -> CSV and/or Executive Summary (blank for missing; VT detection ratio fixed)"
    )
    parser.add_argument("--ioc", help="Single IOC (IPv4, MD5, SHA1, SHA256)")
    parser.add_argument("--file", default=None, help="Text file of IOCs. If omitted, you will be prompted.")
    parser.add_argument("--csv", dest="csv_path", default="results.csv", help="Output CSV filename")
    parser.add_argument("--summary", default="executive_summary.txt", help="Executive summary output filename")
    parser.add_argument(
        "--mode",
        choices=["csv", "both", "exec"],
        default=None,
        help="Output mode: csv / both / exec. If omitted, a menu will be shown.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress per-IOC console output")
    parser.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between requests")
    args = parser.parse_args()

    mode = args.mode or choose_mode_interactive()

    if args.ioc:
        iocs = [args.ioc.strip()]
    else:
        path = args.file or prompt_for_input_file()
        iocs = load_iocs_from_file(path)

    if not iocs:
        print("No IOCs provided.")
        return

    rows: List[Dict[str, Any]] = []
    for i, ioc in enumerate(iocs, start=1):
        if not args.quiet:
            print(f"[{i}/{len(iocs)}] Enriching: {ioc}")
        rows.append(enrich_to_row(ioc, sleep_s=args.sleep, verbose=not args.quiet))

    if mode in ("csv", "both"):
        export_csv(rows, args.csv_path)
        print(f"\nWrote CSV: {args.csv_path}")

    if mode in ("exec", "both"):
        export_executive_summary(rows, args.summary)
        print(f"Wrote executive summary: {args.summary}")


if __name__ == "__main__":
    main()