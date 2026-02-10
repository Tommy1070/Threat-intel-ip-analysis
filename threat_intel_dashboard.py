import pandas as pd
from io import StringIO
import matplotlib.pyplot as plt

"""
Threat Intelligence Dashboard
Purpose:
Visualize malicious IP indicators for analyst situational awareness
"""

# -----------------------------
# Dataset (same as analysis step)
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
# Chart 1: Malicious IPs by Country
# -----------------------------
country_counts = df["country"].value_counts()

plt.figure()
country_counts.plot(kind="bar")
plt.title("Malicious IPs by Country")
plt.xlabel("Country")
plt.ylabel("Number of IPs")
plt.tight_layout()
plt.show()

# -----------------------------
# Chart 2: Threat Type Frequency
# -----------------------------
threat_counts = df["threat_type"].value_counts()

plt.figure()
threat_counts.plot(kind="bar")
plt.title("Threat Type Frequency")
plt.xlabel("Threat Type")
plt.ylabel("Count")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.show()

# -----------------------------
# Chart 3: Confidence vs Report Count
# -----------------------------
plt.figure()
plt.scatter(df["confidence_score"], df["report_count"])
plt.title("Confidence Score vs Report Volume")
plt.xlabel("Confidence Score")
plt.ylabel("Report Count")
plt.tight_layout()
plt.show()
