# SentinelTrace AI - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Setup Environment
```bash
# Windows
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Linux/Mac
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Start Backend
```bash
cd backend
python main.py
```
✓ Server running at http://localhost:8000

### Step 3: Open Dashboard
Open `frontend/index.html` in your browser

### Step 4: Analyze Email
1. Click "Select File"
2. Upload a `.eml` email file
3. View threat analysis instantly!

---

## 📊 What You Get

### Email Analysis
- **Threat Score** (0-100)
- **Threat Level** (LOW/MEDIUM/HIGH/CRITICAL)
- **Risk Factors** identified
- **Geolocation** of sender
- **Forensic Intelligence**

### Geolocation Data
- Sender country & city
- IP address lookup
- ISP information
- Threat-level assessment

### Advanced Forensics
- DKIM signature validation
- SPF record verification
- DMARC policy checking
- Email spoofing detection
- Header chain analysis

### Artifacts Extracted
- URLs found
- IP addresses
- Email addresses
- Attachments with hashing

### Analytics Dashboard
- Total emails analyzed
- Flagged emails count
- Threat statistics
- Geographic distribution

---

## 🔧 API Quick Reference

### Analyze Email
```bash
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@email.eml"
```

### Get Statistics
```bash
curl "http://localhost:8000/stats"
```

### Recent High-Threat Emails
```bash
curl "http://localhost:8000/recent-threats"
```

### Threat Distribution by Country
```bash
curl "http://localhost:8000/threat-by-country"
```

### View Detailed Analysis
```bash
curl "http://localhost:8000/analysis/1"
```

---

## 📁 Project Structure

```
SIH26106_SentinelTrace/
├── backend/
│   ├── main.py                 # FastAPI server
│   ├── email_parser.py         # Email parsing
│   ├── geolocation.py          # IP geolocation
│   ├── threat_intelligence.py  # Threat scoring
│   ├── advanced_forensics.py   # Advanced analysis
│   └── database.py             # Database models
├── frontend/
│   └── index.html              # Web dashboard
└── README.md                   # Full documentation
```

---

## ⚙️ Configuration

### Port
Change port in `backend/main.py`:
```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
```

### Database
SQLite database automatically created at `backend/sentineltrace.db`

---

## 🧪 Test Email

Sample .eml file structure:
```
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Thu, 24 Aug 2026 10:00:00 +0000

This is a test email body.
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change port in main.py or kill process
netstat -ano | findstr :8000  # Windows
lsof -i :8000                  # Linux/Mac
```

### Module Not Found
```bash
pip install -r requirements.txt
```

### Database Error
```bash
rm backend/sentineltrace.db
python -c "from database import init_db; init_db()"
```

---

## 📈 Features Overview

| Feature | Status | Details |
|---------|--------|---------|
| Email Analysis | ✅ Active | Real-time threat detection |
| Geolocation | ✅ Active | IP-based location tracking |
| Threat Scoring | ✅ Active | AI-powered assessment |
| Forensics | ✅ Active | DKIM/SPF/DMARC validation |
| Database | ✅ Active | SQLite storage |
| Analytics | ✅ Active | Statistics & reporting |
| Dashboard | ✅ Active | Interactive web UI |
| API | ✅ Active | RESTful endpoints |

---

## 🎯 For SIH Judges

### Technical Excellence
- ✅ Full-stack application (Python + JavaScript)
- ✅ Advanced threat detection algorithms
- ✅ Real-time geolocation intelligence
- ✅ Comprehensive email forensics
- ✅ Production-ready database

### Problem Solving
- ✅ Email threat detection (core problem)
- ✅ Geolocation intelligence (requirement)
- ✅ Forensic analysis (requirement)
- ✅ Historical tracking (scalability)
- ✅ Analytics dashboard (insights)

### Code Quality
- ✅ Modular architecture
- ✅ Clean, documented code
- ✅ Error handling
- ✅ Security best practices
- ✅ Scalable design

---

## 📞 Support

For issues:
1. Check `http://localhost:8000/docs` (API docs)
2. Review console output for errors
3. Verify all dependencies installed
4. Ensure .eml file format is valid

---

**Good Luck at SIH 2026! 🛡️**
