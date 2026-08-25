# Sample Emails for Testing

This folder contains three sample email files (.eml) for testing the SentinelTrace AI threat detection system.

## 📧 Sample Files

### 1. **phishing_email.eml** - HIGH THREAT
**Threat Level:** MEDIUM-HIGH (60-75)
**Characteristics:**
- Urgent action keywords ("Verify", "Immediate", "Act Now", "Suspend")
- Shortened URL (bit.ly) - obfuscation technique
- Spoofed sender (bankingsecure.net instead of legitimate bank)
- Generic greeting ("Hello User")
- Time pressure ("24 hours")
- Requests credential verification

**Expected Analysis:**
- Phishing indicators: ✅ Detected
- Suspicious sender: ✅ Flagged
- Malicious URLs: ✅ Shortened URL detected
- Authentication: ⚠️ DKIM/SPF checks may fail

---

### 2. **malware_email.eml** - CRITICAL THREAT
**Threat Level:** HIGH-CRITICAL (80-95)
**Characteristics:**
- Executable attachment (.exe file)
- Generic subject line
- Suspicious IP in Received header (unlikely origin)
- No proper authentication headers
- Large file reference (> 5MB)
- Multiple risk factors combined

**Expected Analysis:**
- Dangerous attachment: ✅ .exe detected
- Malware indicators: ✅ Critical
- Sender reputation: ✅ Low trust
- Geolocation: ✅ High-threat country/ISP
- Trust score: ⚠️ Very low

---

### 3. **legitimate_email.eml** - LOW THREAT
**Threat Level:** LOW (5-20)
**Characteristics:**
- Professional sender (internal domain)
- Clear subject line
- Proper email formatting
- Valid DKIM signature
- SPF authentication passes
- No suspicious links or attachments
- Standard business communication

**Expected Analysis:**
- Authentication: ✅ DKIM/SPF Pass
- Sender reputation: ✅ Trusted
- Content analysis: ✅ Safe
- No red flags
- Trust score: ✅ High

---

## 🧪 How to Test

### Using the Web Dashboard
1. Open http://localhost:8001 in your browser
2. Click "Choose File" and select one of the .eml files
3. Watch real-time threat analysis display
4. Check threat score, geolocation, and risk factors

### Using the API
```bash
# Analyze phishing email
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@phishing_email.eml"

# Analyze malware email
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@malware_email.eml"

# Analyze legitimate email
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@legitimate_email.eml"
```

### Using Python
```python
import requests

with open('phishing_email.eml', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:8000/analyze', files=files)
    print(response.json())
```

---

## 📊 Expected Threat Scores

| Email | Expected Score | Threat Level | Risk Factors |
|-------|-----------------|--------------|-------------|
| phishing_email.eml | 60-75 | MEDIUM-HIGH | Urgent keywords, shortened URLs, spoofing |
| malware_email.eml | 80-95 | CRITICAL | .exe attachment, low trust, suspicious IP |
| legitimate_email.eml | 5-20 | LOW | Valid authentication, no risks |

---

## 📁 Additional Folders

### `/test-results/`
Store analysis results and test reports here.

### Example Workflow
1. Upload sample emails via dashboard
2. Save JSON responses to `test-results/`
3. Compare threat scores across emails
4. Verify detection accuracy

---

## 🔧 Creating Custom Test Emails

To create your own test emails:

1. Use an email client (Thunderbird, Outlook, etc.)
2. Create test emails with various characteristics
3. Export as .eml format
4. Place in this folder
5. Upload to SentinelTrace for analysis

---

## ✅ Testing Checklist

- [ ] Phishing email detected as HIGH threat
- [ ] Malware email detected as CRITICAL threat
- [ ] Legitimate email detected as LOW threat
- [ ] Threat scores displayed accurately
- [ ] Geolocation analysis working
- [ ] Risk factors listed correctly
- [ ] Database stores analysis results
- [ ] API returns complete JSON response

---

## 📝 Notes

- All sample emails are **fictional** and created for testing purposes
- No real email addresses or credentials are included
- Emails demonstrate various threat patterns for comprehensive testing
- Use these to validate the detection system before production deployment

---

**Last Updated:** August 24, 2026
**SIH Problem:** SIH26106 - Email Threat Detection Platform
