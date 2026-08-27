# 🏆 SENTINELTRACE — Smart India Hackathon 2026 Submission

**Problem Statement ID**: SIH26106  
**Title**: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Organization**: All India Council for Technical Education (AICTE)  
**Department**: Cyber Security Cell  
**Category**: Software  
**Theme**: Blockchain & Cybersecurity  

---

## 🎯 1. Executive Summary & Vision

Email remains the primary initial access vector for advanced persistent threats (APTs), financial fraud, and cyber espionage. Traditional email gateways rely heavily on basic keyword lists or static signatures that attackers easily bypass through lookalike domains, zero-day links, and executive spoofing.

**SENTINELTRACE** is a next-generation **Digital Forensics & AI Threat Intelligence Platform** engineered specifically for SOC analysts, incident response teams, and cybercrime forensic investigators.

Built strictly around foundational Internet RFC standards and modern machine learning architectures, SentinelTrace decomposes raw RFC 5322 MIME messages, performs cryptographic authentication verification, reconstructs multi-hop MTA relay paths, tracks threat actor infrastructure, detects sophisticated BEC attacks, correlates multi-victim campaigns, maps technical findings to the MITRE ATT&CK enterprise matrix, and produces standardized OASIS STIX 2.1 intelligence bundles.

---

## 🔬 2. Core Technical Capabilities

### A. True RFC Email Protocol Verification
- **RFC 7208 SPF Evaluator**: Real mechanism traversal (`ip4`, `ip6`, `include`, `a`, `mx`, `redirect=`, `all`) tested against transmitting IP addresses via strict network boundaries (`ipaddress` module). No false "PASS" when only a record exists.
- **RFC 6376 DKIM Cryptographic Verifier**: Extracts signing domain, selector, canonicalization, algorithms (`rsa-sha256`), body hash (`bh=`), and signature data (`b=`), fetching public keys from DNS `_domainkey` records.
- **RFC 7489 DMARC Policy Analyzer**: Evaluates strict/relaxed identifier alignment between RFC 5322 From, SPF, and DKIM domains, determining true message disposition (`none`, `quarantine`, `reject`).

### B. SMTP Received-Chain Timeline Forensics
- **Chronological Relay Reconstruction**: Parses all top-down `Received:` headers and reverses them into chronological sending order (Hop 1 = Origin).
- **Earliest External Source Identification**: Accurately filters out non-routable RFC 1918 internal subnets to isolate the first public/external Mail Transfer Agent (MTA).
- **Relay Delay & Time Anomaly Detection**: Automatically flags timestamp chronology inversions, missing hops, and suspicious relay delays.

### C. Origin Infrastructure & Geolocation Intelligence
- **Infrastructure Classification**: Identifies whether the transmitting host is a Corporate Mail Server, Cloud Provider (AWS, GCP, Azure), VPS/Hosting Provider, VPN/Tor exit node, or Direct Origin.
- **Responsible Attribution**: Clearly labels IP locations as **Observed Infrastructure Location** with confidence ratings, preventing misleading claims of physical attacker localization.

### D. Advanced Brand Impersonation & Typosquatting
- **Lookalike Domain Engine**: Employs Damerau-Levenshtein distance, character substitutions (`0` for `o`, `1` for `l`, `rn` for `m`), and homoglyphs / IDN punycode to catch deceptive brand spoofing.
- **Deceptive Subdomain Analysis**: Detects multi-level subdomain tricks (e.g. `paypal.security-update.attacker.com`).

### E. Business Email Compromise (BEC) Intelligence
- **7-Category Classifier**: Detects Executive Impersonation, Invoice Fraud, Payment Diversion, Payroll Changes, Wire Transfer Requests, Gift Card Scams, and Credential Harvesting.
- **Urgency, Secrecy & Authority Scoring**: Lexical and NLP pattern analysis combined with `Reply-To` vs `From` address header divergence detection.

### F. Safe Static Attachment & SSRF-Safe URL Inspection
- **Static File Forensics**: Magic-byte MIME verification, executable double-extension detection (`.pdf.exe`), and SHA-256/SHA-512 cryptographic hashing. No dangerous dynamic execution.
- **SSRF-Protected URL Deconstruction**: Resolves link structures while strictly blocking access to internal or private subnets.

### G. Validated ML and Explainable Hybrid Threat Scoring (0-100)
- **Validated Binary Model**: TF-IDF word/bigram features with Logistic Regression, selected against SGD log-loss on a deduplicated stratified holdout.
- **Evaluation Evidence**: 106,159 records, 84,927 training records and 21,232 held-out test records; 98.74% accuracy and 98.73% macro F1 on the supplied corpus.
- **Integrity Enforcement**: The backend loads the model only when its SHA-256 sidecar matches and validation metadata meets minimum held-out support.
- **Honest Scope**: The uploaded MeAJOR release contains TREC-5/6/7 sources; its positive class includes broad unsolicited/malicious email and is disclosed as a phishing-proxy label. Cross-dataset validation remains future work.
- **Subtype Separation**: A small Gradient Boosting prototype estimates the descriptive attack subtype but does not drive the quantitative ML risk contribution when the validated model is available.
- **Multi-Factor Synthesis**:
  $$\text{Final Score} = (\text{Rule Score} \times 0.35) + (\text{ML Score} \times 0.40) + (\text{Reputation} \times 0.15) + (\text{Campaign Correlation} \times 0.10)$$
- **Transparent Factor Weighting**: Every threat signal is explicitly labeled (`STRONG`, `MODERATE`, `WEAK`, `CONTEXTUAL`) with evidence strings.

### H. Threat Sharing, Campaign Correlation & SOC Operations
- **Cross-Email Campaign Correlation**: Automated Jaccard similarity clustering across infrastructure IOCs.
- **MITRE ATT&CK Mapping**: Maps evidence to T1566 (Phishing), T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), and T1598 (Phishing for Information).
- **OASIS STIX 2.1 Bundles**: Instant export for SIEM, SOAR, and threat intelligence platforms.
- **SOC Case Management**: Full investigation lifecycle with chronological analyst notes, evidence tracking, and tamper-evident audit logging.

---

## 🏗️ 3. Architecture & Repository Layout

```
SIH26106_SentinelTrace/
├── backend/
│   ├── main.py                   # FastAPI Application & REST Endpoints
│   ├── config.py                 # Configuration & Environment Management
│   ├── database.py               # SQLAlchemy ORM (Analyses, Cases, IOCs, Campaigns, Audit)
│   ├── email_parser.py           # RFC 5322 Ingestion, MIME & Header Parser
│   ├── advanced_forensics.py     # Forensic Pipeline Orchestrator
│   ├── spf_evaluator.py          # RFC 7208 SPF Engine
│   ├── dkim_verifier.py          # RFC 6376 DKIM Verifier
│   ├── dmarc_analyzer.py         # RFC 7489 DMARC Policy Analyzer
│   ├── received_parser.py        # SMTP Received-Chain Timeline Engine
│   ├── origin_analyzer.py        # Origin Infrastructure Assessment
│   ├── bec_detector.py           # Business Email Compromise Classifier (7 Categories)
│   ├── lookalike_detector.py     # Typosquatting & Homoglyph Detector
│   ├── attachment_analyzer.py    # Static Attachment Security Engine
│   ├── url_analyzer.py           # SSRF-Protected URL Analyzer
│   ├── ml_engine.py              # Gradient Boosting Threat Classifier
│   ├── threat_scorer.py          # Explainable Hybrid Threat Scoring
│   ├── campaign_correlator.py    # Multi-Email Infrastructure Clusterer
│   ├── mitre_mapper.py           # MITRE ATT&CK Enterprise Matrix Mapper
│   ├── stix_exporter.py          # OASIS STIX 2.1 JSON Bundle Generator
│   ├── report_generator.py       # HTML, JSON & PDF Forensic Report Builder
│   └── tests/                    # Unit, API and hybrid-scoring regression tests
│
├── web/                          # Modern React 18 + TypeScript + Tailwind SOC Interface
│   └── src/
│       ├── pages/                # 14 Dedicated SOC Forensic Pages
│       │   ├── Dashboard.tsx            # SOC Overview & Threat Metrics
│       │   ├── EmailAnalyzer.tsx        # Ingestion & Multi-Stage Pipeline View
│       │   ├── RelayChain.tsx           # Interactive MTA Hop Timeline
│       │   ├── HeaderForensics.tsx      # RFC Header & Alignment Matrix
│       │   ├── ThreatIntelligence.tsx   # MITRE ATT&CK & IOC Explorer
│       │   ├── OriginTrace.tsx          # Geolocation & Infrastructure Map
│       │   ├── GraphInvestigation.tsx   # D3 Link Analysis Force Graph
│       │   ├── CaseManagement.tsx       # SOC Case Workflow & Notes
│       │   ├── CampaignIntelligence.tsx # Multi-Email Campaign Clusterer
│       │   └── ForensicReports.tsx      # Exportable Investigation Reports
│       └── services/                    # Typed API Client & Wire Schema Layer
│
├── samples/                      # Forensic demonstration attack vectors (.eml)
├── SIH_REQUIREMENT_MAPPING.md    # Detailed Requirement Traceability Matrix
├── README.md                     # Platform Documentation
└── requirements.txt              # Production Python Dependencies
```

---

## 🧪 4. Test & Quality Assurance Results

SentinelTrace features automated regression testing covering all core cryptographic, network, and forensic parsing components:

- **27 automated backend tests currently collected**, including API, SPF, DKIM/DMARC, relay parsing, BEC/lookalike/attachment, validated-model and hybrid-scoring coverage.
- **25/25 tests passed in the last complete Windows run before the scoring integration; 6 focused ML/scoring tests passed after integration.**
- **TypeScript strict-mode verification and the production Vite build pass.**
- The unrestricted E2E smoke path can perform external IP geolocation lookups; restricted/privacy-sensitive verification should run focused local tests or mock that provider rather than transmitting sample indicators.

To run tests locally:
```bash
python -m pytest backend/tests/ -v
python backend/tests/test_e2e_smoke.py
```

---

## 🚀 5. Quick-Start Guide for Evaluators

### Step 1: Start Backend
```bash
cd backend
python -m uvicorn main:app --reload
# Server runs on http://127.0.0.1:8000
# OpenAPI Docs available at http://localhost:8000/docs
```

### Step 2: Start Modern Frontend
```bash
cd web
npm install
npm run dev
# Frontend runs on http://localhost:5173
```

### Step 3: Test Real Attack Samples
Upload any sample from `samples/` into the platform:
- `invoice_fraud.eml` — Lookalike domain + invoice alteration
- `ceo_impersonation.eml` — Executive BEC spoofing
- `credential_phishing.eml` — Obfuscated URL harvesting
- `multihop_relay.eml` — Multi-hop Received-chain reconstruction
- `suspicious_attachment.eml` — Double-extension static malware analysis
- `legitimate_corporate.eml` — Baseline legitimate scoring

---

## 🎖️ 6. Hackathon Evaluation Checklist

| Category | Criterion | SentinelTrace Implementation |
|----------|-----------|------------------------------|
| **Innovation** | Advanced Multi-Layer Defense | Integrates RFC SPF/DKIM/DMARC with MTA timeline reconstruction, 7-class BEC detection, D3 force graph, and STIX 2.1 export. |
| **Technical Depth** | Cryptographic & Protocol Rigor | Pure RFC compliance with `dnspython` DNS lookups, `ipaddress` network boundary validation, and zero false PASS badges. |
| **User Experience** | Enterprise SOC Dashboard | 14 specialized investigation interfaces, dark-mode SOC aesthetics, interactive D3 force link graph, and TopoJSON geo routing. |
| **Completeness** | SIH Problem Scope | Implements the core detection, forensic, geolocation, explainability and investigation workflow; demonstration-backed views are explicitly labelled. |
| **Feasibility** | Deployable Prototype | Clean separation of concerns, SQLite/PostgreSQL ORM schemas and RESTful APIs. Production rollout still requires real identity management, organization telemetry integrations and deployment-specific monitoring. |
