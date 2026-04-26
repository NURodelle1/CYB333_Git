import os

vt_key = os.getenv("VT_API_KEY")
otx_key = os.getenv("OTX_API_KEY")

print("VirusTotal key loaded:", bool(vt_key))
print("OTX key loaded:", bool(otx_key))