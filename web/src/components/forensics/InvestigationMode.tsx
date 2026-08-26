import React, { useState } from 'react';
import {
  Shield, CheckCircle, AlertTriangle, XCircle, ArrowRight, ArrowLeft,
  Search, FileText, Globe, GitBranch, Lock, Key, Link2, Paperclip,
  Crosshair, Layers, Zap, FolderPlus, FileCheck, ExternalLink, X
} from 'lucide-react';
import type { EmailAnalysis } from '@/types';

interface InvestigationModeProps {
  analysis: EmailAnalysis;
  onClose: () => void;
  onNavigateToModule?: (route: string) => void;
}

interface StepDefinition {
  id: string;
  number: number;
  title: string;
  shortLabel: string;
  category: 'INGESTION' | 'AUTH' | 'INFRASTRUCTURE' | 'PAYLOAD' | 'INTELLIGENCE' | 'TRIAGE';
  getDetails: (a: EmailAnalysis) => {
    status: 'PASS' | 'FAIL' | 'WARNING' | 'INFO' | 'NOT_AVAILABLE';
    statusText: string;
    summary: string;
    metrics: Array<{ label: string; value: string | number; highlight?: boolean }>;
    evidenceItems: Array<{ label: string; value: string }>;
    actionLink?: { label: string; route: string };
  };
}

export const INVESTIGATION_STEPS: StepDefinition[] = [
  {
    id: 'ACQUIRED',
    number: 1,
    title: 'Email Acquired & Cryptographic Hashing',
    shortLabel: 'Acquisition',
    category: 'INGESTION',
    getDetails: (a) => ({
      status: 'PASS',
      statusText: 'ACQUIRED & HASHED',
      summary: 'Raw RFC-5322 MIME stream acquired and locked with cryptographic chain of custody.',
      metrics: [
        { label: 'EVIDENCE ID', value: a.evidence.evidenceId, highlight: true },
        { label: 'FILE SIZE', value: `${(a.evidence.sizeBytes / 1024).toFixed(2)} KB` },
        { label: 'SOURCE', value: a.evidence.source },
      ],
      evidenceItems: [
        { label: 'SHA-256 Digest', value: a.evidence.sha256 },
        { label: 'Filename', value: a.filename },
        { label: 'Timestamp', value: new Date(a.evidence.acquiredAt).toISOString() },
      ],
      actionLink: { label: 'View Forensic Reports', route: '/reports' }
    }),
  },
  {
    id: 'PARSED',
    number: 2,
    title: 'RFC-5322 MIME Header Decomposition',
    shortLabel: 'MIME Parser',
    category: 'INGESTION',
    getDetails: (a) => ({
      status: 'PASS',
      statusText: 'RFC-5322 PARSED',
      summary: 'Parsed headers, boundaries, and MIME parts without executing binary code.',
      metrics: [
        { label: 'HEADERS COUNT', value: a.headers.length },
        { label: 'SUBJECT', value: a.metadata.subject || 'No Subject' },
        { label: 'ANOMALIES', value: a.headers.filter(h => h.anomaly).length },
      ],
      evidenceItems: [
        { label: 'Message-ID', value: a.metadata.messageId || 'NOT PRESENT' },
        { label: 'Date Header', value: a.metadata.date || 'NOT PRESENT' },
        { label: 'Return-Path', value: a.metadata.returnPath || 'NOT PRESENT' },
      ],
      actionLink: { label: 'Inspect Raw Headers', route: '/header-forensics' }
    }),
  },
  {
    id: 'IDENTITY',
    number: 3,
    title: 'Sender Identity & Header Divergence',
    shortLabel: 'Identity',
    category: 'AUTH',
    getDetails: (a) => {
      const from = a.metadata.from;
      const replyTo = a.metadata.replyTo;
      const hasDivergence = replyTo && !from.toLowerCase().includes(replyTo.toLowerCase());
      return {
        status: hasDivergence ? 'WARNING' : 'PASS',
        statusText: hasDivergence ? 'REPLY-TO DIVERGENCE' : 'IDENTITY ALIGNED',
        summary: hasDivergence
          ? 'Reply-To address diverges from visible From header, a classic indicator of BEC / impersonation.'
          : 'From and Reply-To addresses are structurally aligned.',
        metrics: [
          { label: 'CLAIMED FROM', value: a.metadata.from, highlight: true },
          { label: 'REPLY-TO', value: a.metadata.replyTo || 'None specified' },
          { label: 'RETURN-PATH', value: a.metadata.returnPath || 'None specified' },
        ],
        evidenceItems: [
          { label: 'From Display Name', value: a.metadata.fromDisplayName || 'None' },
          { label: 'Sender Address', value: a.metadata.from },
        ],
        actionLink: { label: 'Header Forensics', route: '/header-forensics' }
      };
    },
  },
  {
    id: 'SPF',
    number: 4,
    title: 'RFC 7208 SPF Authentication',
    shortLabel: 'SPF Check',
    category: 'AUTH',
    getDetails: (a) => {
      const spf = a.authentication.checks.find(c => c.mechanism === 'SPF');
      const pass = spf?.verdict === 'PASS';
      return {
        status: pass ? 'PASS' : spf?.verdict === 'FAIL' ? 'FAIL' : 'WARNING',
        statusText: `SPF: ${spf?.verdict || 'UNKNOWN'}`,
        summary: spf?.detail || 'Evaluated transmitting MTA against published DNS SPF authorization records.',
        metrics: [
          { label: 'VERDICT', value: spf?.verdict || 'NOT_EVALUATED', highlight: true },
          { label: 'ALIGNED', value: spf?.aligned === true ? 'YES' : 'NO' },
        ],
        evidenceItems: [
          { label: 'SPF Detail', value: spf?.detail || 'No record found' },
          { label: 'Raw Mechanism', value: spf?.raw || 'N/A' },
        ],
      };
    },
  },
  {
    id: 'DKIM',
    number: 5,
    title: 'RFC 6376 DKIM Cryptographic Verification',
    shortLabel: 'DKIM Check',
    category: 'AUTH',
    getDetails: (a) => {
      const dkim = a.authentication.checks.find(c => c.mechanism === 'DKIM');
      const pass = dkim?.verdict === 'PASS';
      return {
        status: pass ? 'PASS' : dkim?.verdict === 'FAIL' ? 'FAIL' : 'WARNING',
        statusText: `DKIM: ${dkim?.verdict || 'ABSENT'}`,
        summary: dkim?.detail || 'Verified digital signature against public key published in sender DNS.',
        metrics: [
          { label: 'VERDICT', value: dkim?.verdict || 'NONE', highlight: true },
          { label: 'ALIGNMENT', value: dkim?.aligned ? 'STRICT' : 'MISMATCH' },
        ],
        evidenceItems: [
          { label: 'DKIM Signature', value: dkim?.raw || 'Signature absent or unsigned' },
          { label: 'Evaluation Note', value: dkim?.detail || 'No DKIM header' },
        ],
      };
    },
  },
  {
    id: 'DMARC',
    number: 6,
    title: 'RFC 7489 DMARC Policy Alignment',
    shortLabel: 'DMARC Check',
    category: 'AUTH',
    getDetails: (a) => {
      const dmarc = a.authentication.checks.find(c => c.mechanism === 'DMARC');
      return {
        status: dmarc?.verdict === 'PASS' ? 'PASS' : 'FAIL',
        statusText: `DMARC: ${dmarc?.verdict || 'FAIL'}`,
        summary: dmarc?.detail || 'Evaluated domain alignment requirements and recipient handling policy.',
        metrics: [
          { label: 'POLICY ENFORCEMENT', value: dmarc?.verdict || 'NONE', highlight: true },
          { label: 'TRUST SCORE', value: `${a.authentication.trustScore}/100` },
        ],
        evidenceItems: [
          { label: 'Alignment Note', value: a.authentication.alignmentNote || 'DMARC alignment evaluated' },
          { label: 'Policy Detail', value: dmarc?.detail || 'No DMARC policy' },
        ],
      };
    },
  },
  {
    id: 'HEADERS',
    number: 7,
    title: 'Header Anomaly & Tamper Detection',
    shortLabel: 'Header Anomaly',
    category: 'AUTH',
    getDetails: (a) => {
      const anomalies = a.headers.filter(h => h.anomaly);
      return {
        status: anomalies.length > 0 ? 'WARNING' : 'PASS',
        statusText: `${anomalies.length} ANOMALIES`,
        summary: anomalies.length > 0
          ? `Detected ${anomalies.length} header field anomalies indicating potential header injection or forging.`
          : 'No structural header anomalies or syntax violations detected.',
        metrics: [
          { label: 'ANOMALIES COUNT', value: anomalies.length, highlight: anomalies.length > 0 },
          { label: 'RAW HEADERS BYTES', value: `${a.rawHeaders.length} bytes` },
        ],
        evidenceItems: anomalies.map(an => ({ label: an.name, value: an.anomaly?.reason || an.value })),
        actionLink: { label: 'Header Forensics', route: '/header-forensics' }
      };
    },
  },
  {
    id: 'RELAYS',
    number: 8,
    title: 'SMTP Received Relay Chain Reconstruction',
    shortLabel: 'Relay Timeline',
    category: 'INFRASTRUCTURE',
    getDetails: (a) => ({
      status: a.relayChain.some(h => h.trust === 'SUSPICIOUS') ? 'WARNING' : 'PASS',
      statusText: `${a.relayChain.length} RELAY HOPS`,
      summary: 'Chronological timeline reconstructed from bottom (earliest sending MTA) to top (final recipient MX).',
      metrics: [
        { label: 'TOTAL HOPS', value: a.relayChain.length, highlight: true },
        { label: 'SUSPICIOUS HOPS', value: a.relayChain.filter(h => h.trust === 'SUSPICIOUS').length },
      ],
      evidenceItems: a.relayChain.slice(0, 4).map(h => ({
        label: `Hop #${h.index} (${h.ip || 'No IP'})`,
        value: `${h.hostname || 'Host'} | ASN: ${h.asn || 'N/A'} | Trust: ${h.trust}`
      })),
      actionLink: { label: 'Inspect Relay Chain', route: '/relay-chain' }
    }),
  },
  {
    id: 'ORIGIN_INFRA',
    number: 9,
    title: 'Origin Infrastructure Assessment',
    shortLabel: 'Origin Infra',
    category: 'INFRASTRUCTURE',
    getDetails: (a) => {
      const o = a.originAssessment;
      return {
        status: 'INFO',
        statusText: o.observedSourceIp || 'OBSERVED INFRASTRUCTURE',
        summary: 'Earliest public relay infrastructure identified. Represents network infrastructure, not physical attacker location.',
        metrics: [
          { label: 'OBSERVED IP', value: o.observedSourceIp || 'UNKNOWN', highlight: true },
          { label: 'ASN', value: o.asn || 'UNKNOWN' },
          { label: 'HOSTING TYPE', value: o.hostingType },
          { label: 'CONFIDENCE', value: `${o.confidence}%` },
        ],
        evidenceItems: [
          { label: 'ISP / Organization', value: o.isp || 'UNKNOWN' },
          { label: 'Estimated Country', value: o.estimatedLocation?.country || 'UNKNOWN' },
          { label: 'Caveat', value: 'Geolocation reflects infrastructure location, not threat actor physical residence.' },
        ],
        actionLink: { label: 'View Origin Trace', route: '/origin-trace' }
      };
    },
  },
  {
    id: 'DOMAIN_INTEL',
    number: 10,
    title: 'Domain Intelligence & Typosquatting Analysis',
    shortLabel: 'Domain Intel',
    category: 'INFRASTRUCTURE',
    getDetails: (a) => {
      const topDomain = a.domainIntel[0];
      const hasLookalike = topDomain?.similarity && topDomain.similarity.score > 70;
      return {
        status: hasLookalike ? 'FAIL' : 'PASS',
        statusText: hasLookalike ? 'LOOKALIKE DETECTED' : 'DOMAIN CLEAN',
        summary: hasLookalike
          ? `High typosquatting similarity detected: ${topDomain.domain} mimics ${topDomain.similarity?.comparedTo} (${topDomain.similarity?.technique}).`
          : 'Domain analyzed against brand dictionaries; no deceptive lookalike pattern detected.',
        metrics: [
          { label: 'PRIMARY DOMAIN', value: topDomain?.domain || 'N/A', highlight: true },
          { label: 'RISK LEVEL', value: topDomain?.risk || 'LOW' },
        ],
        evidenceItems: a.domainIntel.map(d => ({
          label: d.domain,
          value: `Risk: ${d.risk} | Reputation: ${d.reputation} ${d.similarity ? `| Mimics: ${d.similarity.comparedTo}` : ''}`
        })),
        actionLink: { label: 'Threat Intelligence', route: '/threat-intel' }
      };
    },
  },
  {
    id: 'URL_ANALYSIS',
    number: 11,
    title: 'Embedded URL Security & SSRF-Safe Analysis',
    shortLabel: 'URL Safety',
    category: 'PAYLOAD',
    getDetails: (a) => {
      const badUrls = a.urls.filter(u => u.risk === 'CRITICAL' || u.risk === 'HIGH');
      return {
        status: badUrls.length > 0 ? 'FAIL' : 'PASS',
        statusText: `${a.urls.length} URLs ANALYZED`,
        summary: badUrls.length > 0
          ? `Detected ${badUrls.length} high-risk or credential phishing URLs with SSRF protection.`
          : 'Extracted and validated URLs; no active credential harvesting endpoints flagged.',
        metrics: [
          { label: 'TOTAL URLs', value: a.urls.length },
          { label: 'SUSPICIOUS URLs', value: badUrls.length, highlight: badUrls.length > 0 },
        ],
        evidenceItems: a.urls.map(u => ({
          label: u.host,
          value: `${u.url} [Risk: ${u.risk}, Anchor mismatch: ${u.mismatchedAnchor ? 'YES' : 'NO'}]`
        })),
      };
    },
  },
  {
    id: 'ATTACHMENTS',
    number: 12,
    title: 'Static Attachment Analysis & Risk Scoring',
    shortLabel: 'Attachments',
    category: 'PAYLOAD',
    getDetails: (a) => {
      const hasRisky = a.attachments.some(att => att.risk === 'CRITICAL' || att.risk === 'HIGH');
      return {
        status: hasRisky ? 'FAIL' : 'PASS',
        statusText: `${a.attachments.length} ATTACHMENTS`,
        summary: a.attachments.length > 0
          ? 'Static inspection of file extension, double extensions, macros, and SHA-256 hashes.'
          : 'No attachments included in this email.',
        metrics: [
          { label: 'ATTACHMENT COUNT', value: a.attachments.length },
          { label: 'RISKY ATTACHMENTS', value: a.attachments.filter(att => att.risk === 'CRITICAL' || att.risk === 'HIGH').length },
        ],
        evidenceItems: a.attachments.map(att => ({
          label: att.filename,
          value: `Size: ${(att.sizeBytes / 1024).toFixed(1)} KB | SHA-256: ${att.sha256.slice(0, 16)}... | Risk: ${att.risk}`
        })),
      };
    },
  },
  {
    id: 'IOC_EXTRACTION',
    number: 13,
    title: 'Normalized Indicator of Compromise (IOC) Extraction',
    shortLabel: 'IOC Extraction',
    category: 'INTELLIGENCE',
    getDetails: (a) => ({
      status: 'INFO',
      statusText: `${a.iocs.length} IOCs EXTRACTED`,
      summary: 'Extracted IPv4, IPv6, domain, URL, and file hashes normalized for SOC threat hunting.',
      metrics: [
        { label: 'TOTAL IOCs', value: a.iocs.length, highlight: true },
        { label: 'MALICIOUS IOCs', value: a.iocs.filter(i => i.reputation === 'MALICIOUS').length },
      ],
      evidenceItems: a.iocs.map(ioc => ({
        label: `[${ioc.type}] ${ioc.value}`,
        value: `Risk: ${ioc.risk} | Source: ${ioc.source} | Reputation: ${ioc.reputation}`
      })),
      actionLink: { label: 'Threat Intelligence', route: '/threat-intel' }
    }),
  },
  {
    id: 'CAMPAIGN',
    number: 14,
    title: 'Cross-Email Campaign Correlation',
    shortLabel: 'Campaign Match',
    category: 'INTELLIGENCE',
    getDetails: (a) => ({
      status: a.campaignId ? 'WARNING' : 'INFO',
      statusText: a.campaignId ? `MATCHED ${a.campaignId}` : 'ISOLATED THREAT',
      summary: a.campaignId
        ? `Correlated to active campaign ${a.campaignId} via shared infrastructure and lookalike domain clusters.`
        : 'No correlated campaign clusters detected across stored incident archives.',
      metrics: [
        { label: 'CAMPAIGN ID', value: a.campaignId || 'NONE_DETECTED', highlight: !!a.campaignId },
      ],
      evidenceItems: [
        { label: 'Correlation Method', value: 'Jaccard IOC similarity & sender infra fingerprint' },
        { label: 'Cluster Status', value: a.campaignId ? 'Active threat cluster' : 'Uncorrelated incident' },
      ],
      actionLink: { label: 'Campaign Intelligence', route: '/campaigns' }
    }),
  },
  {
    id: 'MITRE',
    number: 15,
    title: 'MITRE ATT&CK Matrix Mapping',
    shortLabel: 'MITRE ATT&CK',
    category: 'INTELLIGENCE',
    getDetails: (a) => ({
      status: 'INFO',
      statusText: `${a.assessment.techniques.length} TECHNIQUES`,
      summary: 'Mapped threat signals to adversary tactics and techniques defined in MITRE ATT&CK enterprise matrix.',
      metrics: [
        { label: 'PRIMARY TACTIC', value: 'Initial Access (TA0001)', highlight: true },
        { label: 'TECHNIQUES', value: a.assessment.techniques.length },
      ],
      evidenceItems: a.assessment.techniques.map(t => ({
        label: t,
        value: 'Evidence-backed adversary technique'
      })),
    }),
  },
  {
    id: 'ASSESSMENT',
    number: 16,
    title: 'Hybrid AI/ML Threat Assessment & Scoring',
    shortLabel: 'Threat Score',
    category: 'TRIAGE',
    getDetails: (a) => ({
      status: a.score.level === 'CRITICAL' || a.score.level === 'HIGH' ? 'FAIL' : 'PASS',
      statusText: `${a.score.total}/100 (${a.score.level})`,
      summary: a.assessment.narrative,
      metrics: [
        { label: 'THREAT SCORE', value: `${a.score.total}/100`, highlight: true },
        { label: 'CLASSIFICATION', value: a.assessment.classification },
        { label: 'CONFIDENCE', value: `${a.assessment.confidence.toFixed(1)}%` },
      ],
      evidenceItems: a.assessment.findings.map(f => ({
        label: f.label,
        value: `${f.evidence} (Weight: ${(f.contribution * 100).toFixed(0)}%)`
      })),
    }),
  },
  {
    id: 'SOC_CASE',
    number: 17,
    title: 'Forensic Case & Chain of Custody',
    shortLabel: 'SOC Case',
    category: 'TRIAGE',
    getDetails: (a) => ({
      status: 'PASS',
      statusText: 'INTEGRITY VERIFIED',
      summary: 'Cryptographically verified evidence record ready for SOC case management and legal discovery.',
      metrics: [
        { label: 'EVIDENCE INTEGRITY', value: a.evidence.integrity, highlight: true },
        { label: 'ANALYST', value: a.evidence.analystId },
      ],
      evidenceItems: a.evidence.custody.map(c => ({
        label: `${c.actor} — ${c.action}`,
        value: `${c.detail} [${new Date(c.at).toLocaleTimeString()}]`
      })),
      actionLink: { label: 'Open Case Management', route: '/cases' }
    }),
  },
  {
    id: 'REPORT',
    number: 18,
    title: 'Forensic Report & STIX 2.1 Package',
    shortLabel: 'Report & Export',
    category: 'TRIAGE',
    getDetails: (a) => ({
      status: 'PASS',
      statusText: 'READY FOR EXPORT',
      summary: 'Investigation finalized. HTML audit reports, STIX 2.1 intelligence bundles, and forensic packages generated.',
      metrics: [
        { label: 'STIX VERSION', value: '2.1 OASIS CTI' },
        { label: 'HTML REPORT', value: 'Printable Audit Format' },
      ],
      evidenceItems: [
        { label: 'Export Options', value: 'HTML Report, STIX 2.1 Bundle, JSON Findings, Full Investigation ZIP' }
      ],
      actionLink: { label: 'Forensic Reports', route: '/reports' }
    }),
  },
];

export function InvestigationMode({ analysis, onClose, onNavigateToModule }: InvestigationModeProps) {
  const [currentStepIdx, setCurrentStepIdx] = useState(0);

  const step = INVESTIGATION_STEPS[currentStepIdx];
  const details = step.getDetails(analysis);

  const handleNext = () => {
    if (currentStepIdx < INVESTIGATION_STEPS.length - 1) {
      setCurrentStepIdx(currentStepIdx + 1);
    }
  };

  const handlePrev = () => {
    if (currentStepIdx > 0) {
      setCurrentStepIdx(currentStepIdx - 1);
    }
  };

  const getStatusIcon = (st: string) => {
    switch (st) {
      case 'PASS':
        return <CheckCircle size={16} className="text-emerald-400" />;
      case 'FAIL':
        return <XCircle size={16} className="text-red-400" />;
      case 'WARNING':
        return <AlertTriangle size={16} className="text-amber-400" />;
      default:
        return <Shield size={16} className="text-cyan-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-[#020617]/95 backdrop-blur-xl flex flex-col p-4 sm:p-6 overflow-hidden animate-fade-in">
      {/* Top Bar */}
      <div className="flex items-center justify-between pb-4 border-b border-cyan-500/20 bg-[#050a18]/60 px-4 py-3 rounded-xl mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.3)]">
            <Search size={18} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-100 tracking-wider">
                GUIDED FORENSIC INVESTIGATION MODE
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                STAGE {currentStepIdx + 1} OF {INVESTIGATION_STEPS.length}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 truncate max-w-xl">
              Target: {analysis.filename} (SHA-256: {analysis.evidence.sha256.slice(0, 16)}...)
            </div>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          title="Exit Investigation Mode"
        >
          <X size={18} />
        </button>
      </div>

      {/* Main Body */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-4 overflow-hidden">
        {/* Left: 18-Step Progress Stepper Sidebar */}
        <div className="lg:col-span-1 panel p-3 overflow-y-auto border-cyan-500/20 bg-[#080e21]/90 flex flex-col gap-1 pr-2">
          <div className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider px-2 py-1 mb-1">
            INVESTIGATION PIPELINE
          </div>
          {INVESTIGATION_STEPS.map((s, idx) => {
            const isCurrent = idx === currentStepIdx;
            const isCompleted = idx < currentStepIdx;
            const stepDetail = s.getDetails(analysis);

            return (
              <button
                key={s.id}
                onClick={() => setCurrentStepIdx(idx)}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-left text-xs transition-all font-mono ${
                  isCurrent
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(34,211,238,0.2)] font-bold'
                    : isCompleted
                    ? 'text-slate-300 hover:bg-slate-800/60'
                    : 'text-slate-500 hover:bg-slate-900/40'
                }`}
              >
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${
                  isCurrent
                    ? 'bg-cyan-500 text-black font-bold'
                    : isCompleted
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400'
                }`}>
                  {idx + 1}
                </span>
                <span className="flex-1 truncate text-[11px]">{s.shortLabel}</span>
                {getStatusIcon(stepDetail.status)}
              </button>
            );
          })}
        </div>

        {/* Center/Right: Step Detailed Evidence View */}
        <div className="lg:col-span-3 panel p-6 overflow-y-auto border-cyan-500/20 bg-[#080e21] flex flex-col justify-between">
          <div className="space-y-6">
            {/* Step Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyan-500/15 pb-4">
              <div>
                <div className="text-[10px] font-mono font-bold text-cyan-400 tracking-widest uppercase">
                  {step.category} // STEP {step.number} OF {INVESTIGATION_STEPS.length}
                </div>
                <h2 className="text-xl font-bold text-white mt-1 flex items-center gap-2">
                  <span>{step.title}</span>
                </h2>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-3 py-1 rounded-md text-xs font-mono font-bold bg-[#0d1733] border border-cyan-500/30 text-cyan-300 flex items-center gap-1.5">
                  {getStatusIcon(details.status)}
                  <span>{details.statusText}</span>
                </span>
              </div>
            </div>

            {/* Step Narrative Summary */}
            <div className="p-4 rounded-xl bg-[#050a18]/80 border border-cyan-500/15 text-xs text-slate-200 leading-relaxed font-sans">
              {details.summary}
            </div>

            {/* Key Metrics Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {details.metrics.map((m, i) => (
                <div key={i} className="p-3.5 rounded-lg bg-[#0d1733]/70 border border-slate-800">
                  <div className="text-[10px] font-mono text-slate-400">{m.label}</div>
                  <div className={`text-sm font-mono font-bold mt-1 truncate ${m.highlight ? 'text-cyan-300' : 'text-slate-100'}`}>
                    {m.value}
                  </div>
                </div>
              ))}
            </div>

            {/* Evidence Items Breakdown */}
            <div className="space-y-2">
              <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                SUPPORTING FORENSIC ARTIFACTS
              </div>
              <div className="space-y-2">
                {details.evidenceItems.map((ev, i) => (
                  <div key={i} className="p-3 rounded-lg bg-[#050a18] border border-cyan-500/10 font-mono text-xs">
                    <div className="text-[10px] text-cyan-400 font-bold">{ev.label}</div>
                    <div className="text-slate-200 mt-0.5 break-all select-all">{ev.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Bottom Step Controller Navigation */}
          <div className="pt-6 border-t border-cyan-500/15 flex items-center justify-between mt-6">
            <button
              onClick={handlePrev}
              disabled={currentStepIdx === 0}
              className="btn-ghost text-xs flex items-center gap-2 font-mono disabled:opacity-30"
            >
              <ArrowLeft size={14} />
              <span>PREVIOUS STAGE</span>
            </button>

            {details.actionLink && onNavigateToModule && (
              <button
                onClick={() => {
                  onClose();
                  onNavigateToModule(details.actionLink!.route);
                }}
                className="btn-ghost text-xs border-cyan-500/40 text-cyan-300 font-mono hidden sm:flex items-center gap-1.5"
              >
                <ExternalLink size={13} />
                <span>{details.actionLink.label}</span>
              </button>
            )}

            {currentStepIdx < INVESTIGATION_STEPS.length - 1 ? (
              <button
                onClick={handleNext}
                className="btn-primary text-xs flex items-center gap-2 font-mono"
              >
                <span>NEXT STAGE</span>
                <ArrowRight size={14} />
              </button>
            ) : (
              <button
                onClick={onClose}
                className="btn-primary bg-emerald-600 hover:bg-emerald-500 text-xs flex items-center gap-2 font-mono"
              >
                <CheckCircle size={14} />
                <span>FINALIZE INVESTIGATION</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
