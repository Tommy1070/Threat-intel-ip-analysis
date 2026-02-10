import pandas as pd
from io import StringIO

"""
SOC-Style Alerting Script
Author: Tomiwa Olanrewaju

Purpose:
Simulate how a SOC triages threat intelligence indicators by applying rules
to assign severity levels and create a prioritized alert queue.
"""

# -----------------------------
# Threat intelligence dataset
# -----------------------------
data = """
ip_address,country,threat_type,confidence_score,report_count
185.220.101.1,Netherlands,Tor Exit Node,95,320
45.153.160.140,Russia,Brute Force,88,210
103.85.24.15,India,Malware Hosting,92,185
91.240.118.172,Ukraine,Phishing,81,140
109.248.9.67,Russia,DDoS,90,260
51.158.99.12,France,Web Attack,76,98
37.49.230.89,Netherlands,Tor Exit Node,93,310
196.251.72.44,Nigeria,Spam,70,85
162.142.125.45,United States,Scanning Activity,65,120
185.193.88.19,Germany,Malware Hosting,89,200
"""

df = pd.read_csv(StringIO(data))

# -----------------------------
# SOC triage thresholds (simple + realistic)
# -----------------------------
HIGH_CONFIDENCE = 90      # confidence score threshold
HIGH_REPORTS = 200        # report volume threshold

# Threat types that SOC teams often treat as higher priority
HIGH_PRIORITY_THREATS = {"Malware Hosting", "Phishing", "DDoS", "Brute Force"}

def assign_severity(row) -> str:
    """
    Assign severity using simple scoring rules.
    This simulates SOC decision-making:
    - Higher confidence = more likely malicious
    - Higher report volume = repeated/confirmed abuse
    - Certain threat types = higher potential impact
    """
    score = 0

    if row["confidence_score"] >= HIGH_CONFIDENCE:
        score += 2

    if row["report_count"] >= HIGH_REPORTS:
        score += 2

    if row["threat_type"] in HIGH_PRIORITY_THREATS:
        score += 2

    # Convert score into a severity label
    if score >= 5:
        return "CRITICAL"
    elif score >= 3:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"

# Apply severity labeling
df["severity"] = df.apply(assign_severity, axis=1)

# SOCs typically suppress noise and only alert on MEDIUM+
alerts = df[df["severity"].isin(["MEDIUM", "HIGH", "CRITICAL"])].copy()

# Sort alerts so most severe threats appear first
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
alerts["severity_rank"] = alerts["severity"].map(severity_order)
alerts = alerts.sort_values(["severity_rank", "confidence_score", "report_count"], ascending=[True, False, False])

print("\n=== SOC ALERT QUEUE (MEDIUM+) ===")
print(alerts[["severity", "ip_address", "country", "threat_type", "confidence_score", "report_count"]].to_string(index=False))
