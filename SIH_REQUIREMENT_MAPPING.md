# SIH 26106 — Requirement Traceability & Technical Mapping

**Project**: SENTINELTRACE  
**Problem Statement ID**: 26106  
**Title**: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Organization**: All India Council for Technical Education (AICTE)  
**Department**: Cyber Security Cell  
**Category**: Software  
**Theme**: Blockchain & Cybersecurity  

---

## Executive Summary

SentinelTrace is an enterprise-grade cyber digital forensics and email threat intelligence platform built to satisfy the complete Smart India Hackathon (SIH) 26106 problem statement.

Rather than offering simple heuristic buzzwords or superficial regex checks, SentinelTrace implements rigorous **RFC-compliant protocol verification**, **cryptographic chain-of-custody tracking**, **machine learning threat classification**, **infrastructure geolocation correlation**, **MITRE ATT&CK mapping**, and **OASIS STIX 2.1 threat intelligence export**.

---

## Detailed Requirement Mapping Matrix

| # | SIH Problem Requirement | SentinelTrace Module / File | Technical Implementation Details | Verification Artifact |
|---|-------------------------|-----------------------------|-----------------------------------|-----------------------|
| **1** | **MIME & Envelope Ingestion** | `backend/email_parser.py` | RFC 5322 MIME decomposition, multi-part body decoding, cryptographic SHA-256 and SHA-512 evidence hashing, header normalization. | `samples/*.eml`, `/analyze` endpoint |
| **2** | **RFC 7208 SPF Evaluation** | `backend/spf_evaluator.py` | Evaluates `ip4:`, `ip6:`, `include:`, `a:`, `mx:`, `redirect=`, and `all` mechanisms. Strictly tests transmitting MTA IP using Python `ipaddress`. | `backend/tests/test_spf.py` |
| **3** | **RFC 6376 DKIM Cryptographic Verification** | `backend/dkim_verifier.py` | Extracts `d=`, `s=`, `a=`, `b=`, `bh=`, `c=`, and `h=`. Resolves DNS selector key (`s._domainkey.d`) and validates body hash and RSA-SHA256 signature. | `backend/tests/test_dkim_dmarc.py` |
| **4** | **RFC 7489 DMARC Policy Alignment** | `backend/dmarc_analyzer.py` | Resolves `_dmarc.<domain>`, parses `p=`, `sp=`, `adkim=`, `aspf=`, and evaluates strict/relaxed alignment between RFC 5322 From, SPF, and DKIM. | `backend/tests/test_dkim_dmarc.py` |
| **5** | **SMTP Received-Chain Forensics** | `backend/received_parser.py` | Reconstructs multi-hop MTA transmission order. Identifies earliest public external gateway, evaluates MTA delays, and flags time anomalies. | `backend/tests/test_received_parser.py` |
| **6** | **Origin Infrastructure & GeoLocation** | `backend/origin_analyzer.py`<br>`backend/geolocation.py` | Classifies origin MTA into Corporate Server, Cloud Hosting, VPS, VPN, Open Relay, or Direct Origin. Resolves GeoIP, ASN, ISP with clear confidence ratings. | `web/src/pages/OriginTrace.tsx` |
| **7** | **Lookalike & Typosquatting Detection** | `backend/lookalike_detector.py` | Damerau-Levenshtein distance, character substitutions (0→o, 1→l, rn→m), homoglyphs/IDN punycode, and deceptive subdomain analysis against brand databases. | `backend/tests/test_bec_lookalike_att.py` |
| **8** | **Business Email Compromise (BEC)** | `backend/bec_detector.py` | Classifies BEC across 7 categories (Executive Impersonation, Invoice Fraud, Payment Diversion, Payroll Change, Wire Transfer, Gift Card, Credential Harvest). | `backend/tests/test_bec_lookalike_att.py` |
| **9** | **Safe Static Attachment Inspection** | `backend/attachment_analyzer.py` | Static inspection: magic byte MIME verification, executable double-extension detection, macro detection indicators, SHA-256/512 hashes. Zero dynamic execution. | `backend/tests/test_bec_lookalike_att.py` |
| **10** | **SSRF-Safe URL Analysis** | `backend/url_analyzer.py` | Normalizes URLs, flags shortened links, punycode, IP hosts, and credential harvesting paths. Enforces SSRF safety (blocks private/loopback/cloud metadata ranges). | `backend/tests/test_bec_lookalike_att.py` |
| **11** | **AI / Machine Learning Threat Engine** | `backend/ml_engine.py`<br>`backend/threat_scorer.py` | Gradient Boosting and TF-IDF feature union across lexical, structural, and authentication signals. Returns probability distribution and transparent factor weights. | `backend/ml_engine.py` |
| **12** | **Cross-Email Campaign Correlation** | `backend/campaign_correlator.py` | Computes Jaccard similarity across infrastructure IOCs (sending subnets, ASNs, nameservers, payload hashes) to cluster emails into coordinated campaigns. | `/campaigns`, `web/src/pages/CampaignIntelligence.tsx` |
| **13** | **MITRE ATT&CK Matrix Mapping** | `backend/mitre_mapper.py` | Maps observed technical evidence directly to MITRE ATT&CK techniques: T1566 (Phishing), T1566.001 (Spearphishing Attachment), T1566.002 (Link), T1598 (Reconnaissance). | `web/src/pages/ThreatIntelligence.tsx` |
| **14** | **OASIS STIX 2.1 Threat Intel Export** | `backend/stix_exporter.py` | Exports standardized STIX 2.1 JSON bundles containing `indicator`, `attack-pattern`, `observed-data`, and `relationship` SDOs/SCOs. | `GET /stix/{id}` |
| **15** | **SOC Case Management & Audit Trail** | `backend/database.py`<br>`backend/main.py` | Case lifecycle management (`NEW`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`), chronological case notes, evidence items, and immutable audit logs. | `web/src/pages/CaseManagement.tsx` |
| **16** | **Interactive SOC Investigation Dashboard** | `web/src/` (React 18 + TS + Tailwind) | 14 dedicated forensic investigation interfaces: Relay Path Timelines, D3 Force Graph, TopoJSON World Map, Authentication Badges, and Threat Gauge. | `http://localhost:5173` |

---

## Defense-in-Depth Architecture

```
                                  [ Incoming .EML File ]
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  EmailForensicParser      │
                               │  - RFC 5322 Ingestion     │
                               │  - SHA-256 / SHA-512 Hash │
                               │  - Body & MIME Extraction │
                               └─────────────┬─────────────┘
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
   ┌───────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────┐
   │  RFC Authentication   │   │  MTA Relay Chain Forensics│   │  Artifact Extractors  │
   │  - SPFEvaluator       │   │  - ReceivedHeaderParser   │   │  - AttachmentAnalyzer │
   │  - DKIMVerifier       │   │  - OriginAnalyzer         │   │  - SSRF-Safe URLAnalyzer│
   │  - DMARCAnalyzer      │   │  - Geolocation Engine     │   │  - IOCExtractor (IPv4/6)│
   └───────────┬───────────┘   └─────────────┬─────────────┘   └───────────┬───────────┘
               │                             │                             │
               └─────────────────────────────┼─────────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  Specialized Threat AI    │
                               │  - BECDetector (7 Classes)│
                               │  - LookalikeDetector      │
                               │  - MLThreatEngine         │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  ThreatScorer (Hybrid)    │
                               │  - Rule Weights (35%)     │
                               │  - ML Classifier (40%)    │
                               │  - Reputation Score (15%) │
                               │  - Campaign Clusters (10%)│
                               └─────────────┬─────────────┘
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
   ┌───────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────┐
   │  MITRE ATT&CK Mapper  │   │  STIX 2.1 Threat Intel    │   │  SOC Case Management  │
   │  T1566, T1598, T1204  │   │  Standardized JSON Bundle │   │  Audit Logs & Reports │
   └───────────────────────┘   └───────────────────────────┘   └───────────────────────┘
```

---

## Truthfulness & Cryptographic Integrity Commitments

1. **No Fake PASS Badges**: SPF, DKIM, and DMARC checks are calculated from real DNS records and cryptographic keys. If a record is missing or failing, it is explicitly reported as `NONE`, `FAIL`, or `SOFTFAIL`.
2. **Infrastructure vs Physical Location**: Geolocation points to the observed mail transfer agent (MTA) or relay IP registered in ISP databases, and is explicitly labeled as **Observed Infrastructure** rather than falsely attributed to the "physical attacker location".
3. **SSRF Safe**: All URL inspection runs entirely offline through domain decomposition and pattern recognition; the platform never executes arbitrary remote requests that could trigger external exploits or private subnet scans.
4. **Transparent ML**: The ML threat engine uses engineered feature extraction and probability scoring with transparent factor weighting rather than black-box opaque outputs.
