import os
import requests
import pandas as pd

"""
AbuseIPDB OSINT Lookup
Author: Tomiwa Olanrewaju

Purpose:
Pull real-world threat intelligence from AbuseIPDB
using secure API authentication.
"""

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not API_KEY:
    raise SystemExit("Missing ABUSEIPDB_API_KEY. Check environment variables.")

IPS_TO_CHECK = [
    "185.220.101.1",
    "45.153.160.140",
    "103.85.24.15",
    "109.248.9.67",
]

URL = "https://api.abuseipdb.com/api/v2/check"

results = []

for ip in IPS_TO_CHECK:
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    response = requests.get(URL, headers=headers, params=params, timeout=15)
    response.raise_for_status()

    data = response.json()["data"]

    results.append({
        "ip_address": ip,
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "total_reports": data.get("totalReports"),
        "last_reported": data.get("lastReportedAt"),
    })

df = pd.DataFrame(results)
print("\n=== REAL ABUSEIPDB THREAT INTEL ===")
print(df.to_string(index=False))
