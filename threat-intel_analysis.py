"""
Threat Intelligence Analysis Script
Author: Tomiwa Olanrewaju
Description:
Analyzes OSINT-style malicious IP data to identify
high-risk regions, threat vectors, and high-confidence
malicious infrastructure.
"""

import pandas as pd
from io import StringIO

# -----------------------------------------
# Sample dataset of malicious IP addresses
# Columns:
# - ip_address: the IP of the malicious actor
# - country: origin of the IP
# - threat_type: type of attack or malicious activity
# - confidence_score: likelihood that the IP is truly malicious
# - report_count: number of reports in threat feeds
# -----------------------------------------
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

# Load the CSV dataset into a Pandas DataFrame
df = pd.read_csv(StringIO(data))

# -----------------------------------------
# Analysis 1: Count how many IPs per country
# -----------------------------------------
country_counts = df['country'].value_counts()

# -----------------------------------------
# Analysis 2: Count how many IPs per threat type
# -----------------------------------------
threat_counts = df['threat_type'].value_counts()

# -----------------------------------------
# Analysis 3: Filter for high-confidence threats (>=90)
# -----------------------------------------
high_confidence = df[df['confidence_score'] >= 90]

# -----------------------------------------
# Display results
# -----------------------------------------
print("Country Frequency:")
print(country_counts)

print("\nThreat Type Frequency:")
print(threat_counts)

print("\nHigh Confidence Threats:")
print(high_confidence)
