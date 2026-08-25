# SentinelTrace AI - Email Threat Detection Platform

**AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**

*Developed for Smart India Hackathon 2026 - Problem Statement: SIH26106*

---

## 🎯 Overview

SentinelTrace AI is a comprehensive email security platform that combines artificial intelligence, geolocation analysis, and advanced forensic intelligence to detect and analyze email threats in real-time.

### Key Features

✅ **Email Threat Detection**
- Real-time threat scoring (0-100 scale)
- Threat classification: LOW, MEDIUM, HIGH, CRITICAL
- Risk factor identification and analysis
- Malware and phishing detection

✅ **Geolocation Intelligence**
- Sender IP geolocation tracking
- Country and city-level location analysis
- IP reputation scoring
- Threat-level assessment by region

✅ **Advanced Email Forensics**
- DKIM signature validation
- SPF record verification
- DMARC policy analysis
- Email header chain analysis
- Spoofing attempt detection
- Sender authentication validation

✅ **Artifact Extraction**
- URL extraction and analysis
- IP address identification
- Email address discovery
- Attachment analysis and hashing

✅ **Historical Analysis & Analytics**
- Email analysis storage in SQLite database
- Threat statistics and reports
- Threat trends by geography
- Recent high-threat email tracking

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Installation

1. **Activate Virtual Environment**
   ```bash
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   
   # Linux/Mac
   source .venv/bin/activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize Database**
   ```bash
   cd backend
   python -c "from database import init_db; init_db()"
   ```

### Running the Application

#### Start Backend Server
```bash
cd backend
python main.py
```

The API server will start at `http://localhost:8000`

**API Documentation**: `http://localhost:8000/docs` (Interactive Swagger UI)

#### Open Frontend Dashboard
1. Open your web browser
2. Navigate to `frontend/index.html` or serve with a simple HTTP server:
   ```bash
   python -m http.server 8080
   ```
3. Open `http://localhost:8080/frontend/`

---

## 📋 API Endpoints

### Analysis Endpoints

#### **POST /analyze**
Upload and analyze an email file
- **Input**: .eml email file
- **Response**: Comprehensive threat analysis including geolocation, forensics, and threat score

#### **GET /analysis/{analysis_id}**
Retrieve detailed analysis result by ID
- **Parameters**: `analysis_id` (integer)
- **Response**: Full analysis data for specific email

### Analytics & Reporting

#### **GET /stats**
Get overall threat statistics
- **Response**: 
  - Total emails analyzed
  - Flagged emails count
  - Critical threats
  - High threats
  - Average threat score
  - Flagged percentage

#### **GET /recent-threats?limit=10**
Get recent high-threat emails
- **Parameters**: `limit` (optional, default: 10)
- **Response**: List of flagged emails with threat data

#### **GET /threat-by-country**
Get threat distribution by sender country
- **Response**: List of countries with email count and average threat score

### Health Check

#### **GET /**
Health check endpoint
- **Response**: Server status and version information

---

## 🏗️ Project Structure

```
SIH26106_SentinelTrace/
├── backend/
│   ├── main.py                    # FastAPI application & endpoints
│   ├── email_parser.py            # Email parsing & basic forensics
│   ├── geolocation.py             # IP geolocation intelligence
│   ├── threat_intelligence.py     # Threat scoring engine
│   ├── advanced_forensics.py      # Advanced email forensics (DKIM, SPF, DMARC)
│   ├── database.py                # SQLAlchemy database models
│   └── sentineltrace.db           # SQLite database (auto-created)
│
├── frontend/
│   └── index.html                 # Interactive web dashboard
│
├── models/                        # ML models (for future enhancement)
├── data/                          # Sample data
├── samples/                       # Sample emails for testing
│
└── README.md                      # This file
```

---

## 🔍 How It Works

### Email Analysis Pipeline

1. **File Upload** → User uploads .eml file
2. **Email Parsing** → Extract headers, body, attachments
3. **Geolocation** → Identify sender location from IP address
4. **Threat Scoring** → AI-based threat analysis
5. **Forensics** → Validate authentication (DKIM, SPF, DMARC)
6. **Spoofing Check** → Detect impersonation attempts
7. **Database Storage** → Save analysis results
8. **Response** → Return comprehensive threat report

### Threat Scoring Factors

The platform evaluates multiple factors:

- **Phishing Indicators** (up to 30 points)
  - Urgent/action keywords in subject
  - URL shorteners in email body
  - Mismatched sender domains
  
- **Attachment Risk** (up to 30 points)
  - Dangerous file types (.exe, .bat, .zip, etc.)
  - Large file sizes
  - Multiple attachments
  
- **URL Risk** (up to 25 points)
  - IP-based URLs
  - Very long URLs (obfuscation)
  - URL encoding patterns
  
- **Sender Reputation** (up to 25 points)
  - Generic sender names
  - Missing DKIM signatures
  - High-threat sender IP locations

---

## 💾 Database Schema

### EmailAnalysis Table
Stores complete email analysis records
- Email metadata (sender, recipient, subject)
- Threat assessment results
- Geolocation data
- Artifact counts
- Full analysis JSON

### ThreatAlert Table
Tracks identified threats for reporting
- Threat type classification
- Severity levels
- Associated email analysis

### SenderReputation Table
Caches sender reputation scores
- Email address tracking
- Reputation scoring
- Historical data

---

## 🔐 Security Features

✓ **Email Authentication Validation**
- DKIM signature verification
- SPF record checking
- DMARC policy validation

✓ **Spoofing Detection**
- Sender domain verification
- Header chain analysis
- Email address inconsistency detection

✓ **Threat Intelligence**
- Phishing pattern recognition
- Malware indicators
- Suspicious attachment detection

✓ **IP Reputation Scoring**
- Geolocation-based analysis
- Threat level assessment
- Regional threat tracking

---

## 📊 Threat Levels

| Level | Score | Description |
|-------|-------|-------------|
| **LOW** | 0-24 | Safe email, minimal risk |
| **MEDIUM** | 25-49 | Some suspicious indicators present |
| **HIGH** | 50-74 | Multiple threat factors detected |
| **CRITICAL** | 75-100 | Highly suspicious, likely malicious |

---

## 🧪 Testing

### Test with Sample Email

1. Create a test `.eml` file or use a sample
2. Upload via Frontend Dashboard or API:
   ```bash
   curl -X POST "http://localhost:8000/analyze" \
     -F "file=@sample.eml"
   ```

### View Analysis
- Access dashboard at `http://localhost:8080/frontend/`
- Check statistics at `http://localhost:8000/stats`
- View recent threats at `http://localhost:8000/recent-threats`

---

## 🌐 Geolocation Data

The platform uses the IP-API.com service for geolocation:
- Country and region identification
- City-level location data
- ISP/Organization information
- Threat level assessment

*Note: Requires internet connection for IP lookups*

---

## 📈 Analytics & Reporting

Access comprehensive statistics:

1. **Overall Stats** → `/stats`
2. **Recent High-Threat Emails** → `/recent-threats`
3. **Threat Distribution by Country** → `/threat-by-country`
4. **Detailed Analysis** → `/analysis/{id}`

---

## 🛠️ Future Enhancements

- [ ] Machine learning model for threat prediction
- [ ] Real-time email stream processing
- [ ] Multi-language support
- [ ] Advanced visualization dashboard (React)
- [ ] Email server integration (IMAP/POP3)
- [ ] Threat intelligence feed integration
- [ ] Custom threat rules engine
- [ ] API key authentication
- [ ] User authentication & role-based access
- [ ] Bulk email analysis
- [ ] Mobile app

---

## 📝 Dependencies

```
fastapi==0.104.0
uvicorn==0.24.0
python-multipart==0.0.6
sqlalchemy==2.0.0
requests==2.31.0
dnspython==2.4.0
email-validator==2.1.0
geoip2==4.7.0
```

Install all with:
```bash
pip install -r requirements.txt
```

---

## 🤝 Contributing

For Smart India Hackathon 2026 - SIH26106

Submit improvements and enhancements to enhance email security and threat detection capabilities.

---

## 📞 Support

For issues or questions:
1. Check API documentation at `http://localhost:8000/docs`
2. Review error messages in console output
3. Ensure all dependencies are installed correctly
4. Verify .eml file format is valid

---

## 📄 License

Developed for Smart India Hackathon 2026

---

**SentinelTrace AI - Securing Email Communications with Intelligence** 🛡️
