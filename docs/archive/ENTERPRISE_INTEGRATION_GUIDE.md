# 🚀 AI-DTCTM ENTERPRISE INTEGRATION GUIDE

**Version:** 2.0  
**Edition:** Enterprise  
**Date:** June 3, 2026

---

## 📋 TABLE OF CONTENTS

1. [REST API](#rest-api)
2. [SIEM Integration](#siem-integration)
3. [CLI Tool](#cli-tool)
4. [Webhook Alerts](#webhook-alerts)
5. [Configuration](#configuration)
6. [Examples](#examples)

---

## 🌐 REST API

### **Base URL**
```
http://localhost:8000/api/v1
```

### **Authentication**
API keys passed in header:
```
Authorization: Bearer YOUR_API_KEY
```

### **API Documentation**
Auto-generated Swagger UI:
```
http://localhost:8000/docs
```

---

## **SCANNING ENDPOINTS**

### **1. Scan URL**
```bash
POST /api/v1/scan/url

{
  "target": "https://suspicious.com",
  "scan_type": "url",
  "priority": 8,
  "email_notify": "security@company.com"
}

Response:
{
  "scan_id": "SCAN-20260603-001",
  "status": "QUEUED",
  "check_status_url": "/api/v1/scan/SCAN-20260603-001"
}
```

### **2. Upload & Scan File**
```bash
POST /api/v1/scan/file

Content-Type: multipart/form-data
file: <binary file data>

Response:
{
  "scan_id": "SCAN-20260603-002",
  "filename": "malware.exe",
  "status": "PROCESSING"
}
```

### **3. Get Scan Result**
```bash
GET /api/v1/scan/{scan_id}

Response:
{
  "scan_id": "SCAN-20260603-001",
  "status": "COMPLETE",
  "verdict": "🔴 MALICIOUS",
  "threat_score": 9.8,
  "threats_found": 12,
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Keylogger",
      "description": "pynput keystroke logging"
    }
  ],
  "report_url": "/api/v1/scan/SCAN-20260603-001/report"
}
```

### **4. Download Report**
```bash
GET /api/v1/scan/{scan_id}/report

Returns PDF report file
```

### **5. Batch Scan**
```bash
POST /api/v1/scan/batch

{
  "targets": ["https://url1.com", "https://url2.com"],
  "batch_name": "Q2_2026_Sweep",
  "priority": 7
}

Response:
{
  "batch_id": "BATCH-20260603-001",
  "targets_submitted": 2,
  "status": "QUEUED",
  "results_url": "/api/v1/batch/BATCH-20260603-001/results"
}
```

---

## **THREAT INTELLIGENCE ENDPOINTS**

### **1. Search Threats**
```bash
GET /api/v1/threats/search?query=CVE-2022-0492&severity=CRITICAL

Response:
{
  "query": "CVE-2022-0492",
  "results": [
    {
      "cve": "CVE-2022-0492",
      "title": "Linux Kernel Privilege Escalation",
      "severity": "🔴 CRITICAL",
      "cvss_score": 9.8,
      "status": "ACTIVELY EXPLOITED"
    }
  ]
}
```

### **2. Get Critical Threats**
```bash
GET /api/v1/threats/critical

Response:
{
  "total_critical": 47,
  "threats": [...]
}
```

---

## **IOC MANAGEMENT**

### **1. Hunt IOC**
```bash
POST /api/v1/iocs/hunt

{
  "ioc_type": "hash",
  "ioc_value": "5d41402abc4b2a76b9719d911017c592"
}

Response:
{
  "ioc_type": "hash",
  "total_matches": 23,
  "threat_level": "🔴 CRITICAL - WIDESPREAD INFECTION",
  "affected_systems": 23,
  "matches": [
    {"host": "workstation-001", "timestamp": "2026-06-03T10:30:00Z"}
  ]
}
```

### **2. Export IOCs**
```bash
GET /api/v1/iocs/export?format=stix

Formats: json, stix, yara
```

---

## 🖥️ SIEM INTEGRATION

### **Supported Platforms**

#### **1. Splunk (HTTP Event Collector)**
```python
from core.siem_integration import SplunkHECExporter

exporter = SplunkHECExporter(
    hec_url="https://splunk.company.com:8088",
    hec_token="your-hec-token",
    sourcetype="forensic_scanner"
)

# Export single scan
exporter.export_scan(scan_result)

# Check health
exporter.health_check()
```

**Configuration:**
```
Splunk Index: forensic_scanner
Source Type: forensic_scanner
Event Format: JSON with full threat details
Real-time: Immediate push via HEC
```

#### **2. Elasticsearch/ELK**
```python
from core.siem_integration import ElasticExporter

exporter = ElasticExporter(
    es_url="https://elasticsearch:9200",
    index_prefix="forensic-scanner"
)

# Export with automatic index rollover
exporter.export_scan(scan_result)

# Bulk export
exporter.export_batch(batch_results)
```

**Configuration:**
```
Index Template: forensic-scanner-*
Index Pattern: forensic-scanner-2026.06.03
Bulk Ingest: Up to 1000 scans/batch
Real-time: Append mode (no overwrite)
```

#### **3. Syslog (CEF Format)**
```python
from core.siem_integration import SyslogExporter

exporter = SyslogExporter(
    syslog_host="syslog.company.com",
    syslog_port=514  # UDP, or 601 for TCP
)

# Export via RFC 5424 Syslog
exporter.export_scan(scan_result)
```

**CEF Message Format:**
```
<134>CEF:0|AI-DTCTM|ForensicScanner|2.0|12|Malware Detection|10 
case_id=SCAN-20260603-001 file=malware.exe verdict=MALICIOUS threats=12
```

#### **4. Multi-SIEM Export**
```python
from core.siem_integration import MultiSIEMExporter

manager = MultiSIEMExporter()
manager.add_splunk("https://splunk.com:8088", "token")
manager.add_elasticsearch("https://es:9200")
manager.add_syslog("syslog.company.com", 514)

# Export to ALL SIEMs simultaneously
results = manager.export_scan_to_all(scan_result)
# Returns: {"splunk": True, "elasticsearch": True, "syslog": True}

# Health check all SIEMs
health = manager.health_check_all()
```

---

## 🔔 WEBHOOK ALERTS

### **Configuration**
```python
from core.alert_system import AlertSystem

alerts = AlertSystem()

# Configure channels
alerts.configure_slack("https://hooks.slack.com/services/YOUR/WEBHOOK")
alerts.configure_teams("https://outlook.webhook.office.com/...")
alerts.configure_discord("https://discord.com/api/webhooks/...")
alerts.configure_email("smtp.gmail.com", "sender@gmail.com", "password", 
                      ["security@company.com"])

# Check results and send alerts
summary = alerts.check_and_alert(scan_result)
```

### **Alert Triggers**
- ✅ CRITICAL threats detected
- ✅ Batch scan completion
- ✅ IOC matches found
- ✅ System health alerts

### **Example Slack Alert**
```
🔴 CRITICAL: Malware Detected
─────────────────────────────
Case: SCAN-20260603-001
File: malware.exe
Findings: 12 CRITICAL

Action Required: QUARANTINE IMMEDIATELY
```

---

## 🛠️ CLI TOOL

### **Installation**
```bash
# Install dependencies
pip install click requests

# Make CLI executable
chmod +x scripts/dtctm_cli.py

# Create alias (optional)
alias dtctm='python scripts/dtctm_cli.py'
```

### **Commands**

#### **Scan URL**
```bash
dtctm scan --url https://suspicious.com
dtctm scan --url https://example.com --report pdf
dtctm scan --url https://example.com --email security@company.com
```

#### **Scan File**
```bash
dtctm scan --file malware.exe
dtctm scan --file suspicious.zip --report json
```

#### **Batch Scanning**
```bash
# Submit batch
dtctm batch --input urls.txt --batch-name Q2_Sweep --priority high

# Check status
dtctm batch-status --batch-id BATCH-20260603-001

# Get results
dtctm batch-results --batch-id BATCH-20260603-001
```

#### **IOC Threat Hunting**
```bash
dtctm hunt --type hash --value 5d41402abc4b2a76b9719d911017c592
dtctm hunt --type ip --value 192.168.1.100
dtctm hunt --type domain --value evil.com
dtctm hunt --type url --value https://malicious.com/payload
```

#### **Threat Intelligence**
```bash
dtctm threats --query CVE-2022-0492
dtctm threats --query "log4j"
dtctm threats --query "ransomware"
```

#### **System Management**
```bash
dtctm status          # Check system health
dtctm version         # Show version info
dtctm examples        # Show usage examples
dtctm --help          # Show all commands
```

---

## ⚙️ CONFIGURATION

### **Environment Variables**
```bash
# API Configuration
export DTCTM_API_URL="http://localhost:8000/api/v1"
export DTCTM_API_KEY="your-api-key"

# SIEM Configuration
export SPLUNK_HEC_URL="https://splunk:8088"
export SPLUNK_HEC_TOKEN="your-token"

export ELASTICSEARCH_URL="https://elasticsearch:9200"

export SYSLOG_HOST="syslog.company.com"
export SYSLOG_PORT="514"

# Alerting
export SLACK_WEBHOOK="https://hooks.slack.com/..."
export TEAMS_WEBHOOK="https://outlook.webhook.office.com/..."
export EMAIL_SMTP="smtp.gmail.com"
export EMAIL_SENDER="security@company.com"
```

### **Configuration File** (`~/.dtctm/config.yaml`)
```yaml
api:
  url: http://localhost:8000/api/v1
  key: your-api-key

siem:
  splunk:
    enabled: true
    hec_url: https://splunk:8088
    hec_token: token
  elasticsearch:
    enabled: true
    url: https://elasticsearch:9200
  syslog:
    enabled: true
    host: syslog.company.com
    port: 514

alerting:
  slack: true
  teams: true
  discord: true
  email: true
  severity_threshold: HIGH

scanning:
  timeout_seconds: 300
  max_file_size_mb: 500
  default_priority: 5
```

---

## 💡 USAGE EXAMPLES

### **Example 1: API Integration**
```python
import requests

API_URL = "http://localhost:8000/api/v1"

# Scan URL via API
response = requests.post(f"{API_URL}/scan/url", json={
    "target": "https://suspicious.com",
    "scan_type": "url",
    "priority": 8
})

scan_id = response.json()["scan_id"]

# Poll for results
import time
while True:
    result = requests.get(f"{API_URL}/scan/{scan_id}").json()
    if result["status"] == "COMPLETE":
        print(f"Verdict: {result['verdict']}")
        print(f"Threats: {result['threats_found']}")
        break
    time.sleep(2)
```

### **Example 2: SIEM Integration**
```python
from core.siem_integration import MultiSIEMExporter

# Set up all SIEMs
manager = MultiSIEMExporter()
manager.add_splunk("https://splunk:8088", "token")
manager.add_elasticsearch("https://elasticsearch:9200")

# Export scan results to all SIEMs
scan_result = {
    "case_id": "SCAN-001",
    "file": "malware.exe",
    "findings": [...]
}

results = manager.export_scan_to_all(scan_result)
print(results)  # {"splunk": True, "elasticsearch": True}
```

### **Example 3: CLI Batch Processing**
```bash
# Create list of URLs
cat > urls.txt << EOF
https://url1.com
https://url2.com
https://url3.com
EOF

# Submit batch
dtctm batch --input urls.txt --batch-name "Security_Audit_June" --priority high

# Monitor progress
while true; do
    dtctm batch-status --batch-id BATCH-20260603-001
    sleep 5
done

# Get final results
dtctm batch-results --batch-id BATCH-20260603-001
```

### **Example 4: Alert Integration**
```python
from core.alert_system import AlertSystem

alerts = AlertSystem()
alerts.configure_slack("https://hooks.slack.com/services/YOUR/WEBHOOK")
alerts.configure_email("smtp.gmail.com", "security@company.com", "password", 
                      ["team@company.com"])

# Scan file
result = scan_result_with_malware()

# Auto-alert if critical
summary = alerts.check_and_alert(result)
# Sends Slack + Email immediately for CRITICAL threats
```

---

## 📊 DEPLOYMENT ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                   ENTERPRISE DEPLOYMENT                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   CLI    │  │   REST   │  │ Webhooks │  │Batch API │   │
│  │  Tool    │  │   API    │  │ Alerts   │  │Scanning  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│        │            │              │              │         │
│        └────────────┴──────────────┴──────────────┘         │
│                     │                                        │
│        ┌────────────▼────────────┐                          │
│        │  AI-DTCTM Core Engine   │                          │
│        │  - Forensic Scanner     │                          │
│        │  - Threat Intel         │                          │
│        │  - IOC Management       │                          │
│        │  - Reporting            │                          │
│        └────────────┬────────────┘                          │
│                     │                                        │
│  ┌──────────┬──────────────┬──────────┬──────────┐         │
│  │  Splunk  │ Elasticsearch│ Syslog   │CloudWatch│         │
│  │   HEC    │   / ELK      │   CEF    │   Logs   │         │
│  └──────────┴──────────────┴──────────┴──────────┘         │
│                                                              │
│  ┌──────────┬──────────┬──────────┬──────────┐             │
│  │  Slack   │  Teams   │ Discord  │  Email   │             │
│  │ Alerts   │ Alerts   │ Alerts   │Alerts    │             │
│  └──────────┴──────────┴──────────┴──────────┘             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ PRODUCTION CHECKLIST

- [ ] REST API running on port 8000
- [ ] SIEM exporters configured (at least one)
- [ ] Alert channels configured
- [ ] CLI tool installed and tested
- [ ] API documentation reviewed
- [ ] SSL/TLS certificates installed
- [ ] Firewall rules configured
- [ ] Backup systems tested
- [ ] Load testing completed
- [ ] Documentation distributed to teams

---

## 🎯 NEXT STEPS

1. **Deploy REST API** → `python core/api_server.py`
2. **Configure SIEMs** → Edit config files, test health_check()
3. **Set up Alerting** → Configure Slack/Teams/Email channels
4. **Install CLI** → `pip install click && alias dtctm='...'`
5. **Integration Testing** → Test end-to-end workflows
6. **Documentation** → Train team on new capabilities
7. **Monitoring** → Track API usage, SIEM deliveries, alert latency

---

**🚀 ENTERPRISE INTEGRATION COMPLETE!** 

Your AI-DTCTM Forensic Scanner is now ready for enterprise deployment with REST API, SIEM integration, automated alerting, and CLI tool support.

---
