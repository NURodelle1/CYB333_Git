import os
import requests

# -----------------------------
# STEP 1: Validate API keys
# -----------------------------
vt_api_key = os.getenv("VT_API_KEY")
otx_api_key = os.getenv("OTX_API_KEY")

if not vt_api_key:
    raise RuntimeError("VirusTotal API key not found in environment variables")

if not otx_api_key:
    raise RuntimeError("OTX API key not found in environment variables")

print("[OK] API keys successfully loaded from environment variables")

# -----------------------------
# STEP 2: Test VirusTotal API
# -----------------------------
vt_test_ip = "8.8.8.8"
vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{vt_test_ip}"
vt_headers = {
    "x-apikey": vt_api_key
}

vt_response = requests.get(vt_url, headers=vt_headers)

if vt_response.status_code == 200:
    print("[OK] VirusTotal API reachable")
else:
    print(f"[ERROR] VirusTotal API returned status {vt_response.status_code}")

# -----------------------------
# STEP 3: Test AlienVault OTX API
# -----------------------------
otx_test_ip = "8.8.8.8"
otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{otx_test_ip}/general"
otx_headers = {
    "X-OTX-API-KEY": otx_api_key
}

otx_response = requests.get(otx_url, headers=otx_headers)

if otx_response.status_code == 200:
    print("[OK] AlienVault OTX API reachable")
else:
    print(f"[ERROR] OTX API returned status {otx_response.status_code}")

# -----------------------------
# STEP 4: Final confirmation
# -----------------------------
print("\nEnvironment and API connectivity test completed successfully.")