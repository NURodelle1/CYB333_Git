
import os
import re
import json
import csv
import time
import argparse
from datetime import datetime
import requests

# -----------------------------
# Environment Variables (API Keys)
# -----------------------------
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY not found in environment variables")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY not found in environment variables")

VT_HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}
OTX_HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# -----------------------------
# IOC Type Detection
# -----------------------------
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if IPV4_RE.match(ioc):
        return "ip"
    if SHA256_RE.match(ioc):
        return "sha256"
    if SHA1_RE.match(ioc):
        return "sha1"
    if MD5_RE.match(ioc):
        return "md5"
    return "unknown"

# -----------------------------
# HTTP Helpers (basic retry)
# -----------------------------
def safe_json(resp: requests.Response):
    try:
        return resp.json()
    except Exception:
        return {"raw_text": resp.text[:3000]}

def http_get(url, headers, timeout=30, retries=2, backoff=2):
    """
    Basic retry for transient failures / 429 rate limiting.
    Keeps it simple for coursework.
    """
    last = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            # Handle basic rate limit/backoff
            if r.status_code in (429, 503, 502, 504) and attempt < retries:
                time.sleep(backoff ** attempt)
                last = r
                continue
            return r
        except Exception as e:
            last = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
                continue
            raise
    return last

# -----------------------------
# API Lookups
# -----------------------------
def vt_lookup_ip(ip: str) -> dict:
    # VT: GET /api/v3/ip_addresses/{ip}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = http_get(url, VT_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}

def vt_lookup_hash(file_hash: str) -> dict:
    # VT: GET /api/v3/files/{hash}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    r = http_get(url, VT_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}

def otx_lookup_ip(ip: str) -> dict:
    # OTX: general info for IPv4
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    r = http_get(url, OTX_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}

def otx_lookup_hash(file_hash: str) -> dict:
    # OTX uses hash-type in URL path
    if len(file_hash) == 64:
        htype = "SHA256"
    elif len(file_hash) == 40:
        htype = "SHA1"
    else:
        htype = "MD5"

    url = f"https://otx.alienvault.com/api/v1/indicators/file/{htype}/{file_hash}/general"
    r = http_get(url, OTX_HEADERS)
    return {"status_code": r.status_code, "data": safe_json(r)}

# -----------------------------
# Summaries (keep CSV clean)
# -----------------------------
def summarize_vt(result: dict) -> dict:
    if result["status_code"] != 200:
        return {"ok": False, "status_code": result["status_code"]}

    data = result["data"].get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "ok": True,
        "harmless": stats.get("harmless"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "undetected": stats.get("undetected"),
        "timeout": stats.get("timeout"),
        "reputation": attrs.get("reputation"),
    }

def summarize_otx(result: dict) -> dict:
    if result["status_code"] != 200:
        return {"ok": False, "status_code": result["status_code"]}

    d = result["data"]
    pulse_info = d.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) or []

    return {
        "ok": True,
        "pulse_count": len(pulses),
        "top_pulses": [p.get("name") for p in pulses[:5] if p.get("name")],
    }

# -----------------------------
# Enrichment
# -----------------------------
def enrich_single(ioc: str) -> dict:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    out = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sources": {}
    }

    if ioc_type == "ip":
        vt_raw = vt_lookup_ip(ioc)
        otx_raw = otx_lookup_ip(ioc)

        out["sources"]["virustotal"] = {
            "raw_status": vt_raw["status_code"],
            "summary": summarize_vt(vt_raw)
        }
        out["sources"]["otx"] = {
            "raw_status": otx_raw["status_code"],
            "summary": summarize_otx(otx_raw)
        }

    elif ioc_type in ("md5", "sha1", "sha256"):
        vt_raw = vt_lookup_hash(ioc)
        otx_raw = otx_lookup_hash(ioc)

        out["sources"]["virustotal"] = {
            "raw_status": vt_raw["status_code"],
            "summary": summarize_vt(vt_raw)
        }
        out["sources"]["otx"] = {
            "raw_status": otx_raw["status_code"],
            "summary": summarize_otx(otx_raw)
        }

    else:
        out["error"] = "Unsupported IOC type. Provide IPv4, MD5, SHA1, or SHA256."

    return out

# -----------------------------
# Input Handling (fixes your iocs.txt issue)
# -----------------------------
def load_iocs_from_file(path: str):
    """
    Resolves file path relative to script location (not current terminal folder).
    This prevents FileNotFoundError when running script from elsewhere.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # If user passes an absolute path, keep it
    if os.path.isabs(path):
        full_path = path
    else:
        full_path = os.path.join(script_dir, path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"IOC file not found: {full_path}")

    iocs = []
    with open(full_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append(line)
    return iocs

# -----------------------------
# CSV Export
# -----------------------------
def export_csv(results, csv_path):
    fieldnames = [
        "ioc",
        "ioc_type",
        "timestamp",
        "vt_ok",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_undetected",
        "vt_reputation",
        "otx_ok",
        "otx_pulse_count",
        "otx_top_pulses",
        "error"
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            vt_summary = r.get("sources", {}).get("virustotal", {}).get("summary", {})
            otx_summary = r.get("sources", {}).get("otx", {}).get("summary", {})

            row = {
                "ioc": r.get("ioc"),
                "ioc_type": r.get("ioc_type"),
                "timestamp": r.get("timestamp"),

                "vt_ok": vt_summary.get("ok"),
                "vt_malicious": vt_summary.get("malicious"),
                "vt_suspicious": vt_summary.get("suspicious"),
                "vt_harmless": vt_summary.get("harmless"),
                "vt_undetected": vt_summary.get("undetected"),
                "vt_reputation": vt_summary.get("reputation"),

                "otx_ok": otx_summary.get("ok"),
                "otx_pulse_count": otx_summary.get("pulse_count"),
                "otx_top_pulses": "; ".join(otx_summary.get("top_pulses", []) or []),

                "error": r.get("error")
            }

            writer.writerow(row)

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Test (VirusTotal + OTX) -> JSON + CSV")
    parser.add_argument("--ioc", help="Single IOC value (IPv4, MD5, SHA1, SHA256)")
    parser.add_argument("--file", help="Text file containing IOCs (one per line). Relative paths resolve to script directory.")
    parser.add_argument("--out", default="results.json", help="Output JSON filename (default: results.json)")
    parser.add_argument("--csv", default=None, help="Output CSV filename (default: <out>.csv)")
    args = parser.parse_args()

    targets = []
    if args.ioc:
        targets.append(args.ioc)

    if args.file:
        targets.extend(load_iocs_from_file(args.file))

    if not targets:
        print("No input provided. Use --ioc <value> or --file <path>.")
        return

    results = [enrich_single(t) for t in targets]

    # Print quick console summary
    for r in results:
        print(f"\nIOC: {r.get('ioc')}  Type: {r.get('ioc_type')}")
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
            continue

        vt = r.get("sources", {}).get("virustotal", {}).get("summary", {})
        otx = r.get("sources", {}).get("otx", {}).get("summary", {})

        print(f"  VirusTotal Summary: {vt}")
        print(f"  OTX Summary:        {otx}")

    # Write JSON
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved JSON to: {args.out}")

    # Write CSV
    csv_out = args.csv if args.csv else os.path.splitext(args.out)[0] + ".csv"
    export_csv(results, csv_out)
    print(f"Saved CSV to: {csv_out}")

if __name__ == "__main__":
    main()
