# 🛡️ SENTINELTRACE — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

> **Smart India Hackathon 2026** — Problem Statement ID: **SIH26106**  
> **Organization**: All India Council for Technical Education (AICTE) — Cyber Security Cell  
> **Category**: Software | **Theme**: Blockchain & Cybersecurity  

---

## 🌐 Live Platform Overview

SentinelTrace is an SIH prototype cyber digital-forensics and threat-intelligence platform built for SOC analysts, incident-response teams, and forensic investigators.

Combining **RFC-compliant protocol verification**, **cryptographic chain-of-custody tracking**, **machine learning classification**, **3D infrastructure visualizations**, and an **AI investigation copilot**, SentinelTrace provides full lifecycle email threat analysis from raw RFC 5322 MIME ingestion to OASIS STIX 2.1 threat intelligence export.

---

## ⚡ Key Highlights & Technical Differentiators

| Forensic Domain | Implementation Details |
|---|---|
| **RFC Authentication** | RFC 7208 SPF evaluation, DKIM DNS-key inspection with cryptographic verification through `dkimpy` when raw bytes and DNS are available, and RFC 7489 DMARC alignment. Unverified signatures never receive a PASS badge. |
| **Relay Timeline** | Top-down SMTP Received: header parsing into reverse chronological order, filtering RFC 1918 internal subnets to find the earliest public external gateway. |
| **Origin Intelligence** | Classifies infrastructure (Corporate, Cloud, VPS, VPN, Open Relay) with **3D Interactive Cyber Globe** and honest ISP datacenter attribution. |
| **Brand Protection** | Damerau-Levenshtein distance, character substitutions (`0` for `o`, `rn` for `m`), and IDN homoglyph punycode detection. |
| **BEC Detection** | 7-category classifier (Executive Impersonation, Invoice Fraud, Payment Diversion, Payroll, Wire Transfers, Gift Cards, Credential Harvesting). |
| **Safe Static Analysis** | Magic-byte MIME checks, executable double-extension detection (`.pdf.exe`), SSRF-protected URL analysis, and SHA-256/SHA-512 evidence hashing. |
| **Explainable risk engine** | Integrity-checked validated binary phishing probability combined with forensic rules, infrastructure and campaign evidence. A clearly labelled Gradient Boosting prototype is used only for descriptive attack-subtype estimation. |
| **Threat Sharing** | Automated MITRE ATT&CK matrix mapping (T1566, T1598) and standardized OASIS STIX 2.1 JSON bundle exporter. |
| **Investigation UX** | 3D Hero Network, 3D Entity Graph, AI Investigation Copilot Drawer, and Universal Command Palette (`Ctrl + K`). |

---

## 🏗️ Architecture

```
                                  [ Incoming .EML File ]
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  EmailForensicParser      │
                               │  - RFC 5322 MIME Parser   │
                               │  - SHA-256 / SHA-512 Hash │
                               └─────────────┬─────────────┘
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
   ┌───────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────┐
   │  RFC Authentication   │   │  MTA Relay Chain Forensics│   │  Artifact Extractors  │
   │  - SPFEvaluator       │   │  - ReceivedHeaderParser   │   │  - AttachmentAnalyzer │
   │  - DKIMVerifier       │   │  - OriginAnalyzer         │   │  - SSRF-Safe URLAnalyzer│
   │  - DMARCAnalyzer      │   │  - 3D Geolocation Globe   │   │  - IOCExtractor (IPv4/6)│
   └───────────┬───────────┘   └─────────────┬─────────────┘   └───────────┬───────────┘
               │                             │                             │
               └─────────────────────────────┼─────────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  Specialized Threat AI    │
                               │  - BECDetector (7 Classes)│
                               │  - LookalikeDetector      │
                               │  - Gradient Boosting ML   │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  Explainable Threat Score │
                               │  - Rule (35%)             │
                               │  - ML Classifier (40%)    │
                               │  - Reputation (15%)       │
                               │  - Campaign Clusters (10%)│
                               └─────────────┬─────────────┘
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
   ┌───────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────┐
   │  MITRE ATT&CK Mapper  │   │  OASIS STIX 2.1 Bundles   │   │  SOC Case Management  │
   │  T1566, T1598, T1204  │   │  Standardized JSON Feed   │   │  Audit Logs & Reports │
   └───────────────────────┘   └───────────────────────────┘   └───────────────────────┘
```

---

## 🚀 Quick-Start Guide

### 1. Prerequisites
- **Python 3.11 or 3.12 recommended** (the pinned Pydantic release is not compatible with this project's Python 3.13 setup)
- **Node.js 18+** & **npm**

### 2. Start Backend API Server
```bash
# Install Python dependencies
pip install -r requirements.txt

# Start FastAPI backend from its module directory
cd backend
python -m uvicorn main:app --reload
# API active on http://127.0.0.1:8000
# Swagger UI Docs: http://127.0.0.1:8000/docs
```

### 3. Start React 18 SOC Dashboard
```bash
cd web
npm install
npm run dev
# Dashboard active on http://localhost:5173
```

---

## 🧪 Test Suite & Quality Assurance

### Run Complete Automated Test Suite
```bash
# Install test-only dependencies and run the backend suite
pip install -r requirements-dev.txt
python -m pytest backend/tests/ -v

# Run End-to-End API smoke test
python backend/tests/test_e2e_smoke.py

# Run frontend TypeScript typecheck
cd web && npm run typecheck

# Run production build
cd web && npm run build
```

### Train the validated phishing model

```bash
python ml/prepare_dataset.py --legitimate-dir data/ham --phishing-dir data/phishing
python ml/train_model.py
```

Parquet corpora are supported as an optional training input:

```bash
pip install -r requirements-ml.txt
python ml/prepare_dataset.py --parquet data/corpus.parquet --output ml/datasets/prepared.jsonl
python ml/train_model.py --dataset ml/datasets/prepared.jsonl
```

Raw corpora, prepared records, and trained artifacts are intentionally excluded
from Git. Record the corpus citation and label taxonomy when training so the UI
does not imply broader validation than the source labels support.

Open **Model Performance** in the dashboard to see held-out precision, recall, macro F1, class support, and validation status. The backend activates the saved classifier only after minimum held-out support is met; smaller experiments remain labeled as prototypes. See `ml/README.md`.

The repository model was trained on 106,159 deduplicated records from the uploaded MeAJOR v2.0 release and achieved 98.74% accuracy / 98.73% macro F1 on a 21,232-record stratified holdout. These results apply only to that corpus. Its TREC-derived positive class includes broad unsolicited/malicious email, so SentinelTrace displays it as phishing-proxy evidence and does not claim phishing-only or real-world production validation.

### Data provenance in the interface

- Uploaded-email parsing, hashing, model inference, scoring, IOC extraction and reporting are functional application logic.
- DNS and geolocation enrichment can degrade when external services are unavailable.
- Analytics, selected campaign views, dashboard fallbacks and demo identities are visibly demonstration-backed; they are not live institutional telemetry.

---

## 📂 Repository Layout

```
SIH26106_SentinelTrace/
├── backend/
│   ├── main.py                   # FastAPI Application & REST Endpoints
│   ├── config.py                 # Central Configuration
│   ├── database.py               # SQLAlchemy ORM (Cases, Evidence, IOCs, Campaigns, Audit)
│   ├── email_parser.py           # RFC 5322 Ingestion, MIME & Header Parser
│   ├── advanced_forensics.py     # Forensic Pipeline Orchestrator
│   ├── spf_evaluator.py          # RFC 7208 SPF Engine
│   ├── dkim_verifier.py          # RFC 6376 DKIM Cryptographic Verifier
│   ├── dmarc_analyzer.py         # RFC 7489 DMARC Policy Alignment Engine
│   ├── received_parser.py        # SMTP Received-Chain Timeline Engine
│   ├── origin_analyzer.py        # Origin Infrastructure Assessment
│   ├── bec_detector.py           # 7-Category Business Email Compromise Classifier
│   ├── lookalike_detector.py     # Typosquatting & Homoglyph Engine
│   ├── attachment_analyzer.py    # Safe Static Attachment Security Engine
│   ├── url_analyzer.py           # SSRF-Protected URL Analyzer
│   ├── ml_engine.py              # Gradient Boosting Threat Classifier
│   ├── threat_scorer.py          # Explainable Hybrid Threat Scoring (0-100)
│   ├── campaign_correlator.py    # Multi-Email Infrastructure Clusterer
│   ├── mitre_mapper.py           # MITRE ATT&CK Matrix Mapper
│   ├── stix_exporter.py          # OASIS STIX 2.1 JSON Bundle Generator
│   ├── report_generator.py       # HTML, JSON & PDF Forensic Report Builder
│   └── tests/                    # Backend unit, API and scoring regression tests
│
├── web/                          # React 18 + TypeScript + Three.js + Tailwind SOC
│   └── src/
│       ├── components/
│       │   ├── 3d/               # Three.js 3D Hero Network, Globe & Threat Graph
│       │   └── shell/            # TopBar, Sidebar, AI Copilot & Command Palette
│       ├── pages/                # 14 Dedicated Forensic Interfaces
│       │   ├── Landing.tsx       # 3D Hero & 7-Phase Storytelling Page
│       │   ├── Dashboard.tsx     # SOC Overview & Live Threat Stream
│       │   ├── EmailAnalyzer.tsx # 14-Stage Ingestion Pipeline & Explainable Scoring
│       │   ├── HeaderForensics.tsx # RFC Header & Identity Divergence Analyzer
│       │   ├── RelayChain.tsx    # Interactive MTA Hop Timeline
│       │   ├── OriginTrace.tsx   # 3D Geolocation Globe & Datacenter Meta
│       │   ├── GraphInvestigation.tsx # 3D / 2D Force-Directed Threat Graph
│       │   ├── CampaignIntelligence.tsx # Multi-Email Campaign Clusterer
│       │   ├── CaseManagement.tsx # SOC Case Workflow & Chain of Custody
│       │   └── ForensicReports.tsx # Exportable Investigation Reports
│       └── services/             # Typed API Client & Wire Schema Layer
│
├── samples/                      # Forensic demonstration attack vectors (.eml)
├── SIH_REQUIREMENT_MAPPING.md    # Judge-Facing Requirement Traceability Matrix
├── SIH_SUBMISSION.md             # Complete Hackathon Submission Document
└── requirements.txt              # Production Python Dependencies
```

---

## ⚖️ Forensic Disclaimer

Geolocation coordinates indicate **observed network mail transfer agents (MTAs) and intermediary proxy infrastructure**. Geolocation data does not establish the physical location of human threat actors. Attribution of human operators requires ISP warrant logs and law enforcement corroboration.
