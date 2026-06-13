# 🚀 AI-DTCTM Quick Start Guide

**Status:** ✅ Production-Ready  
**Latest Update:** 2026-06-03  
**Version:** 1.0.0

---

## 📋 What's New

✅ **Batch Scanner** - Process 100+ URLs in one batch job  
✅ **REST API** - 20+ endpoints with WebSocket streaming  
✅ **Python SDK** - Developer-friendly package  
✅ **CLI Tool** - Command-line interface  
✅ **Admin Enhancements** - Professional animations & graphics  

---

## 🎯 Quick Examples

### 1. Scan a Single URL

**Web UI:**
```
1. Navigate to "URL scanner" page
2. Enter URL: https://example.com
3. Click "Scan URL"
4. View results with verdict and score
```

**Python:**
```python
from dtctm import ForensicScanner

scanner = ForensicScanner(api_key="demo")
result = scanner.scan_url("https://example.com")
print(f"Verdict: {result.verdict}")
print(f"Score: {result.score:.2f}")
```

**CLI:**
```bash
dtctm scan --url https://example.com
```

---

### 2. Batch Scan Multiple URLs

**Web UI (Streamlit):**
```
1. Navigate to "Batch scanner" tab
2. Choose "Paste URLs" or "Upload CSV"
3. Enter targets (one per line)
4. Set priority (1-10)
5. Click "Submit Batch"
6. View progress in "Monitor Progress" tab
```

**Python:**
```python
from dtctm import BatchScanner

batch = BatchScanner(api_key="demo")

# Submit batch
targets = ["https://a.com", "https://b.com", "https://c.com"]
batch_id = batch.submit(targets, batch_name="Security Audit")

# Monitor progress
status = batch.get_status(batch_id)
print(f"Progress: {status.progress_pct}%")
print(f"Completed: {status.scans_completed}/{status.total_scans}")
print(f"ETA: {status.eta_seconds}s")

# Get results when complete
results = batch.get_results(batch_id)
for result in results:
    print(f"{result['target']}: {result['verdict']}")

# Stream real-time results
for event in batch.stream_progress(batch_id):
    print(event)
```

**CLI:**
```bash
# Create urls.txt with one URL per line
# https://example1.com
# https://example2.com
# https://example3.com

# Submit and watch
dtctm batch --input urls.txt --watch

# Or submit without watching
dtctm batch --input urls.txt

# Check status later
dtctm batch-status --id batch_20260603_1234

# Export results
dtctm batch --input urls.txt --export results.json
```

---

### 3. REST API Usage

**Get JWT Token:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -d "username=demo&password=demo"

# Response:
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**Submit Batch:**
```bash
curl -X POST "http://localhost:8000/api/v1/scan/batch" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://a.com", "https://b.com"],
    "batch_name": "Audit",
    "priority": 8
  }'

# Response:
{
  "batch_id": "batch_20260603_abc123",
  "status": "queued",
  "total_targets": 2,
  "status_url": "/api/v1/batch/batch_20260603_abc123"
}
```

**Get Batch Status:**
```bash
curl "http://localhost:8000/api/v1/batch/batch_20260603_abc123" \
  -H "Authorization: Bearer $TOKEN"
```

**WebSocket Progress:**
```javascript
// In JavaScript
const ws = new WebSocket("ws://localhost:8000/ws/batch/batch_20260603_abc123");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.event === 'progress') {
    console.log(`Progress: ${data.progress_pct}%`);
  } else if (data.event === 'result') {
    console.log(`${data.target}: ${data.verdict}`);
  }
};
```

---

## 📊 System Health

**Check API Health:**
```bash
dtctm api-health
# Output: ✅ API Status: HEALTHY
```

**Detailed System Status:**
```bash
dtctm system-health
# Shows database, ML model, and API status
```

---

## 📚 API Documentation

**Interactive Swagger UI:**
- URL: `http://localhost:8000/api/docs`
- Try endpoints directly
- View request/response schemas
- Auto-generated from code

**ReDoc Documentation:**
- URL: `http://localhost:8000/api/redoc`
- Three-panel layout
- Reference documentation

---

## 🛠️ Installation & Setup

### 1. Install Dependencies

```bash
pip install fastapi uvicorn click pyjwt requests
```

### 2. Set Environment Variables

```bash
export DTCTM_API_KEY="your-api-key"
export SECRET_KEY="jwt-secret"
```

### 3. Start API Server

```bash
python core/api/fastapi_server.py
# Server runs on http://localhost:8000
```

### 4. Open Web UI (Streamlit)

```bash
streamlit run main_project.py
# Opens on http://localhost:8501
```

---

## 📋 File Input Format

### Text Format (urls.txt)
```
https://example1.com
https://example2.com
https://suspicious.site
```

### CSV Format (targets.csv)
```
target,priority
https://example1.com,5
https://example2.com,8
https://example3.com,10
```

---

## 🎯 Common Workflows

### Workflow 1: Quick Security Audit

```bash
# Create URL list
cat > urls.txt << EOF
https://company-site.com
https://test.company-site.com
https://api.company-site.com
EOF

# Submit batch
dtctm batch --input urls.txt --watch

# Export results
dtctm batch --input urls.txt --export audit_results.json
```

### Workflow 2: Continuous Monitoring

```bash
# Python script to monitor batch
from dtctm import BatchScanner

batch = BatchScanner(api_key="your-key")
targets = ["site1.com", "site2.com", "site3.com"]
batch_id = batch.submit(targets)

# Check every 30 seconds until done
import time
while True:
    status = batch.get_status(batch_id)
    print(f"{status.progress_pct:.0f}% - {status.current_target}")
    if status.is_complete():
        break
    time.sleep(30)

# Download results
results = batch.get_results(batch_id)
```

### Workflow 3: Automated API Integration

```python
# Flask app integrating DTCTM
from flask import Flask, jsonify
from dtctm import ForensicScanner

app = Flask(__name__)
scanner = ForensicScanner(api_key="your-key")

@app.route('/check/<path:url>')
def check_url(url):
    result = scanner.scan_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

---

## 🔍 Troubleshooting

### API Connection Error
```bash
# Check if server is running
curl http://localhost:8000/api/health

# If fails, start server:
python core/api/fastapi_server.py
```

### Rate Limit Exceeded
- Free tier: 60 requests/minute
- Pro tier: 300 requests/minute
- Enterprise tier: 1000 requests/minute
- Wait 1 minute and retry

### Batch Stuck or Slow
```bash
# Check system health
dtctm system-health

# Check batch status
dtctm batch-status --id batch_20260603_1234

# Retry failed scans
# In Python:
batch.retry_failures(batch_id)
```

---

## 📊 Batch Scanner Status Meanings

| Status | Meaning | Action |
|--------|---------|--------|
| queued | Waiting to start | None, will start automatically |
| processing | Currently scanning | Monitor progress |
| complete | Finished | View results |
| cancelled | User cancelled | Check batch-status |

---

## 📈 Performance Tips

1. **Batch Optimization:**
   - Keep batches under 1000 URLs for best performance
   - Use priority levels strategically (high priority = 8-10)
   - Split very large batches

2. **API Usage:**
   - Cache JWT tokens (24-hour expiration)
   - Batch API requests when possible
   - Use WebSocket for real-time monitoring

3. **CLI Usage:**
   - Use CSV files for large target lists
   - Monitor with `--watch` flag for real-time updates
   - Export results to JSON for processing

---

## 🔐 Security Notes

1. **API Keys:**
   - Never commit API keys to Git
   - Use environment variables
   - Rotate keys regularly

2. **JWT Tokens:**
   - Tokens expire in 24 hours
   - Get new token with credentials
   - Include in Authorization header

3. **HTTPS:**
   - Use HTTPS in production
   - Set secure cookies
   - Enable CORS carefully

---

## 📞 Support & Help

**Command Help:**
```bash
dtctm --help              # All commands
dtctm scan --help         # Scan help
dtctm batch --help        # Batch help
dtctm api-health --help   # API health help
```

**API Documentation:**
- Swagger: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

**Code Examples:**
- Check `dtctm_sdk/client.py` docstrings
- Review `scripts/dtctm_cli.py` for CLI patterns
- See `core/api/fastapi_server.py` for API usage

---

## 🎯 Next Steps

1. **Try Web UI:**
   - Open http://localhost:8501
   - Navigate to "Batch scanner"
   - Submit a test batch

2. **Test REST API:**
   - Visit http://localhost:8000/api/docs
   - Get JWT token
   - Try scanning endpoints

3. **Use CLI:**
   - Run `dtctm scan --url https://example.com`
   - Create batch from CSV
   - Monitor with `dtctm batch-status`

4. **Integrate SDK:**
   - Import ForensicScanner
   - Build custom applications
   - Automate threat scanning

---

## 🚀 You're Ready!

The AI-DTCTM platform is fully operational and ready for:
- ✅ Web-based scanning
- ✅ Batch threat analysis
- ✅ REST API integration
- ✅ CLI automation
- ✅ Production deployment

Happy threat hunting! 🎊

---

**Questions?** Check the API docs at http://localhost:8000/api/docs
