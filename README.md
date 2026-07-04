# 🛡️ Azure-Cloud Cloud-Based Honeypot & Live SOC Monitoring Lab

[![Azure](https://img.shields.io/badge/Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/)
[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)
[![KQL](https://img.shields.io/badge/Query%20Language-KQL-blue)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)

A practical, hands-on implementation of an enterprise-grade cloud Security Operations Center (SOC) lifecycle. This lab features a intentionally misconfigured, high-exposure Windows endpoint acting as a honey-token asset to capture malicious automated footprinting and exploit traffic across the open internet.

---

## 🎯 Core Project Focus
* **Threat Surface Exploitation:** Simulating perimeter exposures on Windows RDP (`Port 3389`).
* **SIEM Log Ingestion Engineering:** Parsing centralized raw pipeline `SecurityEvent` parameters using Azure Log Analytics.
* **Detection Engineering (KQL):** Architecting behavioral analytical criteria to isolate high-confidence brute-force alerts.
* **Threat Intelligence & SOAR Playbooks:** Enriched alert contexts using VirusTotal feeds and malicious geo-IP watchlists.
* **Active Defense Remediation:** Executing immediate incident isolation steps through Cloud Network Security Groups (NSG).

---

## 📊 Lab Telemetry & High-Impact Metrics
Over a continuous **two-week monitoring window**, the environment captured aggressive automated intrusion frameworks:

| Metric Pillar | Operational Data Field |
| :--- | :--- |
| **Monitored Asset** | `CORP-CLIENT-DATABASE-EAST-1` (Windows Server OS) |
| **Deployment Region** | Azure East US |
| **Total Triaged Incidents** | **12 Critical Vector Alerts** |
| **Peak Assault Volume** | **14,738 brute-force password attempts** from a single node |
| **Top Adversary Origin** | China (Huawei Cloud Autonomous Routing Space) |
| **Target Vectors** | Default systemic names (`admin`, `guest`, `user`) |

---

## ⚡ Detection Engineering: KQL Playbook
The core of the detection architecture relies on optimized **Kusto Query Language (KQL)** analytics rules configured to surface high-priority credential access techniques:

### Rule 1: High-Velocity Brute Force Detection
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, TimeGenerated
| where FailedAttempts > 7
