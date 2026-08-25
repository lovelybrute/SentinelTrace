# API Testing Guide - SentinelTrace AI

## Quick API Tests

### 1. Health Check
```bash
curl http://localhost:8000/
```

**Expected Response:**
```json
{
  "project": "SentinelTrace AI",
  "problem": "SIH26106",
  "status": "online",
  "module": "Email Forensic Parser"
}
```

---

### 2. Analyze Email (POST /analyze)
Upload and analyze an email file:

```bash
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@samples/phishing_email.eml"
```

**Response includes:**
- Email evidence (from, to, subject, date, message-id)
- Threat assessment (score 0-100, threat level)
- Geolocation intelligence (sender IP location)
- Threat indicators (URLs, IPs, emails, attachments)
- Forensics (DKIM/SPF/DMARC, spoofing detection, header chain)
- Database analysis ID for later retrieval

---

### 3. Get Overall Statistics (GET /stats)
```bash
curl http://localhost:8000/stats
```

**Response:**
```json
{
  "total_emails": 45,
  "flagged_emails": 12,
  "critical_threats": 3,
  "high_threats": 9,
  "average_threat_score": 38.5,
  "flagged_percentage": 26.67
}
```

---

### 4. Get Recent Threats (GET /recent-threats)
```bash
curl "http://localhost:8000/recent-threats?limit=10"
```

**Response:**
List of 10 most recent flagged emails with:
- Email ID, sender, subject
- Threat score and level
- Geolocation (country)
- Analysis timestamp

---

### 5. Get Threat Distribution by Country (GET /threat-by-country)
```bash
curl http://localhost:8000/threat-by-country
```

**Response:**
Top 20 countries with email threat data:
```json
[
  {
    "country": "CN",
    "email_count": 45,
    "average_threat_score": 62.3
  },
  ...
]
```

---

### 6. Get Detailed Analysis (GET /analysis/{id})
```bash
curl http://localhost:8000/analysis/1
```

**Response:**
Complete analysis data for email with ID=1:
- Full evidence, threat assessment
- Geolocation details
- All artifacts (URLs, IPs, attachments)
- Full analysis JSON

---

## Interactive API Documentation

Visit these URLs in your browser:

1. **Swagger UI** (Interactive API Explorer)
   - http://localhost:8000/docs

2. **ReDoc** (API Documentation)
   - http://localhost:8000/redoc

3. **OpenAPI Schema**
   - http://localhost:8000/openapi.json

---

## Testing with Python Requests

```python
import requests
import json

BASE_URL = "http://localhost:8000"

# 1. Health check
response = requests.get(f"{BASE_URL}/")
print(response.json())

# 2. Upload and analyze email
with open("samples/phishing_email.eml", "rb") as f:
    files = {"file": f}
    response = requests.post(f"{BASE_URL}/analyze", files=files)
    result = response.json()
    print(f"Threat Score: {result['threat_assessment']['threat_score']}")

# 3. Get statistics
response = requests.get(f"{BASE_URL}/stats")
print(response.json())

# 4. Get recent threats
response = requests.get(f"{BASE_URL}/recent-threats", params={"limit": 5})
print(response.json())
```

---

## Error Handling

### Common Errors

**400 - Bad Request**
```json
{
  "detail": "No file selected."
}
```

**404 - Not Found**
```json
{
  "detail": "Analysis not found"
}
```

**500 - Internal Server Error**
```json
{
  "detail": "Email analysis failed: [error details]"
}
```

---

## Sample Threat Scores

| Email Type | Typical Score | Threat Level |
|-----------|---------------|--------------|
| Legitimate | 5-15 | LOW |
| Suspicious | 25-50 | MEDIUM |
| Phishing | 60-80 | HIGH |
| Malware | 85-100 | CRITICAL |

---

## Database Queries (Advanced)

Access SQLite database directly:

```bash
sqlite3 backend/sentineltrace.db

# Get all high-threat emails
SELECT filename, threat_score, threat_level FROM email_analysis WHERE threat_level = 'HIGH' ORDER BY analyzed_at DESC;

# Get threat distribution by country
SELECT sender_country, COUNT(*) as count, AVG(threat_score) as avg_score FROM email_analysis GROUP BY sender_country;

# Get top senders
SELECT sender_email, COUNT(*) as email_count, AVG(threat_score) as avg_score FROM email_analysis GROUP BY sender_email ORDER BY email_count DESC LIMIT 10;
```

---

## Bulk Testing

Test with all sample emails:

```bash
for file in samples/*.eml; do
    echo "Testing: $file"
    curl -X POST "http://localhost:8000/analyze" -F "file=@$file"
    echo ""
done
```

---

## Performance Testing

```bash
# Test API response time
time curl http://localhost:8000/stats

# Load testing (requires Apache Bench)
ab -n 100 -c 10 http://localhost:8000/stats
```

---

**Last Updated:** August 24, 2026
