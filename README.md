# Threat Intelligence Analysis of Malicious IP Addresses

## Overview
This project demonstrates a cyber threat intelligence workflow by analyzing
known malicious IP addresses sourced from public OSINT-style threat feeds.
The goal is to identify high-risk regions, common attack vectors, and
high-confidence malicious infrastructure.

## Objectives
- Analyze geographic distribution of malicious IPs
- Identify dominant threat types
- Highlight high-confidence threat actors for prioritization

## Tools & Technologies
- Python
- Pandas
- Basic data analysis techniques
- OSINT-style threat intelligence data

## Key Findings
- Tor Exit Nodes were the most frequent and highest-confidence threat type
- European-based infrastructure showed repeated malicious activity
- High-confidence IPs had significantly higher reporting frequency

## Use Case
This analysis simulates how cyber intelligence analysts assess threat feeds
to support early detection, incident response, and defensive decision-making.

## Scripts
**threat_intel_analysis.py**: Performs initial threat intel analysis (country frequency, threat types, high-confidence threats).
**threat_intel_dashboard.py**: Generates visual dashboards (country distribution, threat type frequency, confidence vs report volume).
**soc_alerts.py**: Simulates SOC triage by assigning severity (MEDIUM/HIGH/CRITICAL) and producing a prioritized alert queue.


