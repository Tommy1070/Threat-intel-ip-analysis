import os
import requests
import pandas as pd

"""
SOC Alerting with Real AbuseIPDB Data
Author: Tomiwa Olanrewaju

Purpose:
Use real OSINT threat intelligence to assign SOC alert severity.
"""

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not API_KEY:
    raise SystemExit("Missing ABUSEIPDB_API_KEY")

IPS_TO_CHECK = [
    "185.220.101.1",
    "45.153.160.140",
    "103.85.24.15",
    "109.248.9.67",
]

URL = "https://api.abuseipdb.com/api/v2/check"

rows = []

for ip in IPS_TO_CHECK:
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(URL, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    d = r.json()["data"]

    rows.append({
        "ip": ip,
        "abuse_score": d.get("abuseConfidenceScore", 0),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "reports": d.get("totalReports", 0)
    })

df = pd.DataFrame(rows)

def soc_severity(row):
    if row["abuse_score"] >= 90:
        return "CRITICAL"
    elif row["abuse_score"] >= 60:
        return "HIGH"
    elif row["abuse_score"] >= 30:
        return "MEDIUM"
    else:
        return "LOW"

df["severity"] = df.apply(soc_severity, axis=1)

alerts = df[df["severity"] != "LOW"].sort_values("abuse_score", ascending=False)

print("\n=== REAL SOC ALERT QUEUE ===")
print(alerts.to_string(index=False))
