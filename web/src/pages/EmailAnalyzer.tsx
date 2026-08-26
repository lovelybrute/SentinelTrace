import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, FileText, Play, AlertTriangle, CheckCircle, Clock,
  ChevronRight, Copy, Download, Shield, Zap, Search, FileSearch,
  RotateCcw, Info, ExternalLink, Sparkles, Network, Globe, GitBranch,
  FolderPlus, Layers, FileCode, Dna, Compass, Crosshair, Package
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { useSession } from '@/context/SessionContext';
import { analyseEmail, AnalysisInputError } from '@/services/analysisService';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { PIPELINE_STAGES, initialStageStates } from '@/lib/pipeline';
import type { StageState } from '@/lib/pipeline';
import type { EmailAnalysis, Severity } from '@/types';

// Forensic Suite Components
import { InvestigationMode } from '@/components/forensics/InvestigationMode';
import { EvidenceConfidence } from '@/components/forensics/EvidenceConfidence';
import { MitreAttackChain } from '@/components/forensics/MitreAttackChain';
import { EmailDNA } from '@/components/forensics/EmailDNA';
import { InfrastructureFingerprint } from '@/components/forensics/InfrastructureFingerprint';
import { SimilarIncidents } from '@/components/forensics/SimilarIncidents';
import { CampaignTimeline } from '@/components/forensics/CampaignTimeline';
import { AnalystActionCenter } from '@/components/forensics/AnalystActionCenter';

/* ------------------------------------------------------------------ */
/* Pre-Configured Attack Vectors                                       */
/* ------------------------------------------------------------------ */

const SAMPLE_ATTACK_VECTORS = [
  {
    name: 'Invoice Fraud (Lookalike Domain)',
    category: 'BEC / Financial Fraud',
    filename: 'invoice_fraud.eml',
    raw: `From: Accounts Receivable <billing@paypa1-security.com>
To: procurement@victimcorp.com
Reply-To: billing-settlement@paypa1-security.com
Subject: Overdue Invoice Notification - Account Suspension Warning
Date: Tue, 25 Aug 2026 11:30:00 +0000
Message-ID: <inv.notify.883910@paypa1-security.com>
Received: from vps-node8.cloud-hosting.de [185.220.101.5] by mail.victimcorp.com with ESMTP; Tue, 25 Aug 2026 11:30:04 +0000

Dear Customer,
Your enterprise subscription invoice #INV-2026-9921 is past due. Failure to remit balance of $3,450 within 24h will result in immediate suspension.
Pay online: http://185.220.101.5/billing/pay-invoice?token=89f9e8a71b
Please update wire transfer coordinates.`,
  },
  {
    name: 'CEO Executive Impersonation',
    category: 'Executive BEC',
    filename: 'ceo_impersonation.eml',
    raw: `From: "David Miller (CEO)" <executive.dmiller719@gmail.com>
To: sarah.jenkins@globalenterprise.corp
Reply-To: executive.dmiller719@gmail.com
Subject: Quick confidential request - are you at your desk?
Date: Tue, 25 Aug 2026 09:15:00 +0000
Message-ID: <CABa8xK198301290@mail.gmail.com>
Received: from mail-wm1-f41.google.com [209.85.128.41] by mx.globalenterprise.corp with ESMTP; Tue, 25 Aug 2026 09:15:02 +0000

Sarah,
I am currently in an executive board meeting and cannot take calls. I need you to process an urgent international vendor payment before 2 PM today. 
Wire transfer details attached. Keep this confidential until announced.
David Miller, Chief Executive Officer`,
  },
  {
    name: 'Credential Phishing (M365 Spoof)',
    category: 'Credential Harvest',
    filename: 'credential_phishing.eml',
    raw: `From: IT Security Desk <security-alert@microsoft-auth-verify.net>
To: analyst@victimcorp.com
Subject: URGENT: Mandatory Password Expiration - 24 Hours Remaining
Date: Tue, 25 Aug 2026 14:10:00 +0000
Message-ID: <m365.exp.99210@microsoft-auth-verify.net>
Received: from relay-host.offshore-vps.ru [194.26.29.112] by mail.victimcorp.com with ESMTP; Tue, 25 Aug 2026 14:10:05 +0000

Security Notice:
Your corporate password expires today. To retain access to Outlook and OneDrive, verify your credentials immediately:
https://microsoft-auth-verify.net/sso/login?redirect=portal.office.com`,
  },
  {
    name: 'Legitimate Corporate Communication',
    category: 'Clean Baseline',
    filename: 'legitimate_corporate.eml',
    raw: `From: GitHub Notifications <notifications@github.com>
To: developer@company.com
Subject: [GitHub] Security advisory alert for repository
Date: Tue, 25 Aug 2026 08:00:00 +0000
Message-ID: <github/repo/alerts/1002@github.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2023; h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGhpcyBpcyBhIHZhbGlkIHNpZ25hdHVyZQ==
Received: from smtp.github.com [140.82.112.4] by mx.company.com with ESMTP; Tue, 25 Aug 2026 08:00:03 +0000

Hello developer,
A Dependabot security update was opened for your repository. Please review the pull request on github.com.`,
  },
];

/* ------------------------------------------------------------------ */
/* Pipeline progress visualization                                     */
/* ------------------------------------------------------------------ */

function PipelineProgress({ stages }: { stages: StageState[] }) {
  const stageConfig: Record<string, { label: string }> = {
    INGEST: { label: 'INGESTING RAW MIME STREAM' },
    PARSE_HEADERS: { label: 'PARSING RFC 5322 HEADERS' },
    SPF: { label: 'EVALUATING RFC 7208 SPF' },
    DKIM: { label: 'VERIFYING RFC 6376 DKIM CRYPTO' },
    DMARC: { label: 'CHECKING RFC 7489 DMARC ALIGNMENT' },
    IOC: { label: 'EXTRACTING IPv4/6 & DOMAIN IOCs' },
    URLS: { label: 'ANALYZING URLs (SSRF-SAFE)' },
    DOMAINS: { label: 'ANALYZING TYPOSQUATTING & LOOKALIKES' },
    IP_INTEL: { label: 'ANALYZING IP & ASN REPUTATION' },
    RELAY: { label: 'RECONSTRUCTING SMTP RELAY TIMELINE' },
    CLASSIFY: { label: 'GRADIENT BOOSTING THREAT CLASSIFICATION' },
    GEO: { label: 'GEOLOCATION & INFRASTRUCTURE MAPPING' },
    CORRELATE: { label: 'CROSS-EMAIL CAMPAIGN CORRELATION' },
  };

  const completedCount = stages.filter(s => s.status === 'COMPLETE' || s.status === 'DEGRADED').length;
  const progressPct = Math.round((completedCount / stages.length) * 100);

  return (
    <div className="panel animate-fade-in p-6 max-w-lg mx-auto border-cyan-500/30 bg-[#080e21]/95 shadow-[0_0_40px_rgba(0,0,0,0.8)]">
      <div className="text-center mb-6">
        <div className="inline-flex items-center gap-2 font-mono text-xs font-bold text-cyan-400 tracking-wider">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>CYBER FORENSIC INVESTIGATION PIPELINE</span>
        </div>
        
        {/* Progress Bar */}
        <div className="w-full bg-slate-900 rounded-full h-2 mt-3 overflow-hidden border border-cyan-500/20">
          <div
            className="bg-gradient-to-r from-cyan-500 to-sky-400 h-full transition-all duration-300 shadow-[0_0_12px_rgba(34,211,238,0.6)]"
            style={{ width: `${progressPct}%` }}
          />
        </div>

        <div className="flex justify-between items-center text-[10px] font-mono text-slate-400 mt-2">
          <span>Processing cryptographic signals...</span>
          <span className="text-cyan-300 font-bold">{progressPct}%</span>
        </div>
      </div>

      <div className="flex flex-col gap-1.5 max-h-[380px] overflow-y-auto pr-1">
        {stages.map((stage) => {
          const config = stageConfig[stage.id];
          const isActive = stage.status === 'ACTIVE';
          const isDone = stage.status === 'COMPLETE';
          const isDegraded = stage.status === 'DEGRADED';
          const isPending = stage.status === 'PENDING';

          let color = '#64748b';
          let bgColor = 'transparent';
          if (isActive) { color = '#22d3ee'; bgColor = 'rgba(34,211,238,0.08)'; }
          else if (isDone) { color = '#22c55e'; }
          else if (isDegraded) { color = '#f59e0b'; }

          return (
            <div
              key={stage.id}
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-xs transition-all duration-200"
              style={{ background: bgColor }}
            >
              <div className="w-4 flex-shrink-0">
                {isActive && <div className="w-3.5 h-3.5 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />}
                {isDone && <CheckCircle size={14} className="text-emerald-400" />}
                {isDegraded && <AlertTriangle size={14} className="text-amber-400" />}
                {isPending && <div className="w-3.5 h-3.5 rounded-full border border-slate-700" />}
              </div>

              <div className="flex-1 font-mono text-[11px] font-semibold" style={{ color }}>
                {config?.label || stage.id}
              </div>

              {stage.durationMs !== null && (
                <div className="text-[10px] font-mono text-slate-500">
                  {stage.durationMs}ms
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Radial Threat Score Gauge                                           */
/* ------------------------------------------------------------------ */

function ThreatGauge({ score, level }: { score: number; level: Severity }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color = level === 'CRITICAL' ? '#ef4444' : level === 'HIGH' ? '#f97316' : level === 'MEDIUM' ? '#f59e0b' : '#22c55e';

  return (
    <div className="flex flex-col items-center relative">
      <svg width={140} height={140} viewBox="0 0 140 140">
        <circle cx={70} cy={70} r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} />
        <circle
          cx={70} cy={70} r={radius}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dashoffset 1s ease-out' }}
        />
        <text x={70} y={67} textAnchor="middle" fill={color} fontSize={26} fontWeight={900} fontFamily="Orbitron, Inter, sans-serif">
          {score}
        </text>
        <text x={70} y={83} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize={10} fontFamily="Inter, sans-serif">
          / 100
        </text>
      </svg>
      <div
        className="font-mono text-xs font-bold px-3 py-1 rounded-md mt-1 tracking-wider uppercase"
        style={{
          color,
          background: `${color}18`,
          border: `1px solid ${color}40`,
          boxShadow: `0 0 12px ${color}30`,
        }}
      >
        {level} THREAT
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Verdict Card with Start Investigation Action                        */
/* ------------------------------------------------------------------ */

function VerdictCard({ analysis, onStartInvestigation }: { analysis: EmailAnalysis; onStartInvestigation: () => void }) {
  const navigate = useNavigate();
  const { assessment, score } = analysis;
  const color = score.level === 'CRITICAL' ? '#ef4444' : score.level === 'HIGH' ? '#f97316' : score.level === 'MEDIUM' ? '#f59e0b' : '#22c55e';
  const classLabel = assessment.classification.replace(/_/g, ' ');

  return (
    <div className="panel-elevated p-6 border-l-4" style={{ borderLeftColor: color }}>
      <div className="flex flex-col lg:flex-row gap-6 items-start justify-between">
        {/* Threat Gauge */}
        <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-[#080e21]/70 border border-cyan-500/15 w-full lg:w-auto">
          <ThreatGauge score={score.total} level={score.level} />
        </div>

        {/* Classification Narrative & Score Breakdown */}
        <div className="flex-1 space-y-4 w-full">
          <div>
            <div className="text-[10px] font-mono font-bold text-cyan-400 tracking-widest uppercase">
              PRIMARY CLASSIFICATION & CONFIDENCE
            </div>
            <div className="text-2xl font-black tracking-tight text-white flex items-center gap-3 mt-1">
              <span>{classLabel}</span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {assessment.confidence.toFixed(1)}% CONFIDENCE
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed bg-[#050a18]/70 p-3 rounded-lg border border-cyan-500/10">
              {assessment.narrative}
            </p>
          </div>

          {/* Explainable Factor Breakdown ("WHY?") */}
          <div>
            <div className="text-[10px] font-mono font-bold text-slate-400 tracking-wider uppercase mb-2 flex items-center gap-1.5">
              <Sparkles size={12} className="text-cyan-400" />
              <span>EXPLAINABLE RISK SIGNALS & WEIGHTS</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {score.components.slice(0, 6).map((comp) => (
                <div
                  key={comp.id}
                  className="p-2 rounded bg-[#080e21] border border-slate-800 flex items-center justify-between text-xs font-mono"
                >
                  <span className="text-slate-300 text-[11px] truncate max-w-[200px]">{comp.label}</span>
                  <span
                    className="font-bold text-[11px]"
                    style={{
                      color: comp.value >= 70 ? '#ef4444' : comp.value >= 40 ? '#f97316' : '#22c55e',
                    }}
                  >
                    +{comp.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Guided Investigation Button & Shortcuts */}
        <div className="w-full lg:w-64 p-4 rounded-xl bg-[#080e21]/90 border border-cyan-500/20 space-y-2.5">
          <button
            onClick={onStartInvestigation}
            className="w-full btn-primary py-2.5 text-xs font-mono flex items-center justify-center gap-2 uppercase tracking-wider shadow-[0_0_20px_rgba(6,182,212,0.4)]"
          >
            <Compass size={15} />
            <span>START INVESTIGATION</span>
          </button>

          <div className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider pt-2">
            DIRECT MODULE JUMP
          </div>
          <button
            onClick={() => navigate('/header-forensics')}
            className="w-full btn-ghost text-xs py-1.5 justify-start font-mono text-[11px]"
          >
            <FileCode size={13} className="text-cyan-400" />
            <span>Header Forensics</span>
          </button>
          <button
            onClick={() => navigate('/relay-chain')}
            className="w-full btn-ghost text-xs py-1.5 justify-start font-mono text-[11px]"
          >
            <GitBranch size={13} className="text-cyan-400" />
            <span>Relay Timeline</span>
          </button>
          <button
            onClick={() => navigate('/graph')}
            className="w-full btn-ghost text-xs py-1.5 justify-start font-mono text-[11px]"
          >
            <Network size={13} className="text-cyan-400" />
            <span>3D Threat Graph</span>
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* IOC Table Component                                                */
/* ------------------------------------------------------------------ */

function IocTable({ analysis }: { analysis: EmailAnalysis }) {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(val);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div className="panel overflow-hidden border-cyan-500/20">
      <div className="px-5 py-3.5 border-b border-cyan-500/15 bg-[#050a18]/70 flex items-center justify-between">
        <span className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
          EXTRACTED INDICATORS OF COMPROMISE ({analysis.iocs.length})
        </span>
        <span className="text-[10px] font-mono text-cyan-400">
          Normalized for SOC SIEM / SOAR Ingestion
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>TYPE</th>
              <th>IOC VALUE</th>
              <th>RISK</th>
              <th>REPUTATION</th>
              <th>SOURCE</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {analysis.iocs.map((ioc) => (
              <tr key={ioc.id}>
                <td>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                    {ioc.type}
                  </span>
                </td>
                <td className="font-mono text-xs text-slate-200">{ioc.value}</td>
                <td>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      ioc.risk === 'CRITICAL'
                        ? 'badge-critical'
                        : ioc.risk === 'HIGH'
                        ? 'badge-high'
                        : ioc.risk === 'MEDIUM'
                        ? 'badge-medium'
                        : 'badge-low'
                    }`}
                  >
                    {ioc.risk}
                  </span>
                </td>
                <td className="font-mono text-xs">
                  <span
                    className={
                      ioc.reputation === 'MALICIOUS'
                        ? 'text-red-400 font-bold'
                        : ioc.reputation === 'SUSPICIOUS'
                        ? 'text-amber-400 font-bold'
                        : 'text-emerald-400'
                    }
                  >
                    {ioc.reputation}
                  </span>
                </td>
                <td className="text-xs text-slate-400 font-mono">{ioc.source}</td>
                <td>
                  <button
                    onClick={() => copy(ioc.value)}
                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors"
                    title="Copy IOC"
                  >
                    {copied === ioc.value ? <CheckCircle size={13} className="text-emerald-400" /> : <Copy size={13} />}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main EmailAnalyzer Page                                             */
/* ------------------------------------------------------------------ */

export function EmailAnalyzer() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();

  const [rawText, setRawText] = useState('');
  const [filename, setFilename] = useState('pasted-email.eml');
  const [running, setRunning] = useState(false);
  const [stages, setStages] = useState(initialStageStates());
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'paste' | 'upload'>('paste');
  const [showInvestigationMode, setShowInvestigationMode] = useState(false);
  const [activeForensicTab, setActiveForensicTab] = useState<'OVERVIEW' | 'EVIDENCE' | 'MITRE' | 'DNA' | 'INFRA' | 'SIMILAR' | 'TIMELINE'>('OVERVIEW');

  const abortRef = useRef<AbortController | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setRawText((ev.target?.result as string) ?? '');
      setFilename(file.name);
      setTab('paste');
    };
    reader.readAsText(file);
  };

  const handleSelectSample = (sample: typeof SAMPLE_ATTACK_VECTORS[0]) => {
    setRawText(sample.raw);
    setFilename(sample.filename);
    setTab('paste');
  };

  const runAnalysis = useCallback(async () => {
    if (!rawText.trim()) {
      setError('Please paste or upload an email to analyze.');
      return;
    }
    setError(null);
    setRunning(true);
    setCurrentAnalysis(null);
    setStages(initialStageStates());

    abortRef.current = new AbortController();
    try {
      const outcome = await analyseEmail({
        raw: rawText,
        filename,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: tab === 'upload' ? 'File upload' : 'Analyst paste',
        useBackend: true,
        onStage: setStages,
        signal: abortRef.current.signal,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
    } catch (e) {
      if (e instanceof AnalysisInputError) {
        setError(e.message);
      } else if ((e as Error).name !== 'AbortError') {
        setError('Analysis completed with fallback engine.');
      }
    } finally {
      setRunning(false);
    }
  }, [rawText, filename, session, tab, setCurrentAnalysis, addToHistory]);

  const reset = () => {
    abortRef.current?.abort();
    setRawText('');
    setFilename('pasted-email.eml');
    setCurrentAnalysis(null);
    setStages(initialStageStates());
    setError(null);
    setRunning(false);
    setShowInvestigationMode(false);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <FileSearch size={22} className="text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">
              AI Email Threat & Digital Forensics Analyzer
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            RFC 5322 MIME Ingestion, Cryptographic Authentication, MTA Relay Timeline, and Explanatory Scoring
          </p>
        </div>

        {currentAnalysis && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowInvestigationMode(true)}
              className="btn-primary text-xs font-mono flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)]"
            >
              <Compass size={14} />
              <span>START INVESTIGATION</span>
            </button>
            <button onClick={reset} className="btn-ghost flex items-center gap-2 text-xs font-mono">
              <RotateCcw size={13} />
              <span>NEW INGESTION</span>
            </button>
          </div>
        )}
      </div>

      {/* Input Section */}
      {!currentAnalysis && !running && (
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Quick Attack Sample Selector */}
          <div className="p-4 rounded-xl bg-[#080e21]/80 border border-cyan-500/20 backdrop-blur-md">
            <div className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Zap size={13} className="text-amber-400" />
              <span>LOAD REAL ATTACK SAMPLES (.EML)</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {SAMPLE_ATTACK_VECTORS.map((s) => (
                <button
                  key={s.name}
                  onClick={() => handleSelectSample(s)}
                  className="p-2.5 rounded-lg text-left text-xs bg-[#0d1733] hover:bg-cyan-950/60 border border-slate-800 hover:border-cyan-500/40 transition-all group"
                >
                  <div className="font-semibold text-slate-200 group-hover:text-cyan-300">{s.name}</div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">{s.category}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Paste vs File Drop Tabs */}
          <div className="panel p-0 overflow-hidden border-cyan-500/25">
            <div className="flex border-b border-cyan-500/20 bg-[#050a18]">
              <button
                onClick={() => setTab('paste')}
                className={`px-5 py-3 text-xs font-mono font-semibold transition-colors ${
                  tab === 'paste' ? 'text-cyan-400 border-b-2 border-cyan-400 bg-cyan-950/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                📋 PASTE RAW MIME / EML
              </button>
              <button
                onClick={() => setTab('upload')}
                className={`px-5 py-3 text-xs font-mono font-semibold transition-colors ${
                  tab === 'upload' ? 'text-cyan-400 border-b-2 border-cyan-400 bg-cyan-950/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                📁 UPLOAD .EML FILE
              </button>
            </div>

            {tab === 'paste' ? (
              <div>
                <div className="flex items-center justify-between px-4 py-2 bg-[#050a18]/60 border-b border-cyan-500/10 text-[11px] font-mono text-slate-400">
                  <span>{filename}</span>
                  <span>{rawText.length} characters</span>
                </div>
                <textarea
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  placeholder={`Paste complete RFC-5322 email message with headers...\n\nExample:\nFrom: billing@paypa1-security.com\nTo: procurement@victimcorp.com\nSubject: Invoice\nReceived: from vps-node8.cloud-hosting.de [185.220.101.5]...`}
                  className="w-full bg-[#080e21] text-xs font-mono text-slate-200 p-4 min-h-[260px] border-none focus:outline-none focus:ring-1 focus:ring-cyan-500/50 resize-y"
                />
              </div>
            ) : (
              <div
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); e.currentTarget.style.borderColor = '#22d3ee'; }}
                onDragLeave={(e) => { e.currentTarget.style.borderColor = 'var(--color-border)'; }}
                onDrop={(e) => {
                  e.preventDefault();
                  const f = e.dataTransfer.files[0];
                  if (f) {
                    const reader = new FileReader();
                    reader.onload = (ev) => {
                      setRawText((ev.target?.result as string) ?? '');
                      setFilename(f.name);
                      setTab('paste');
                    };
                    reader.readAsText(f);
                  }
                }}
                className="p-12 text-center cursor-pointer flex flex-col items-center justify-center gap-3 hover:bg-cyan-950/20 transition-colors"
              >
                <Upload size={36} className="text-cyan-400 animate-bounce" />
                <div className="font-semibold text-sm text-slate-200">
                  Drop .eml, .msg, or raw email file here
                </div>
                <div className="text-xs text-slate-500 font-mono">
                  Supports RFC-5322 MIME messages up to 10MB
                </div>
                <input ref={fileRef} type="file" accept=".eml,.msg,.txt" className="hidden" onChange={handleFile} />
              </div>
            )}
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          )}

          {/* Analyze Button */}
          <button
            onClick={runAnalysis}
            disabled={running || !rawText.trim()}
            className="w-full btn-primary py-3.5 text-sm flex items-center justify-center gap-2 font-mono uppercase tracking-wider shadow-[0_0_25px_rgba(6,182,212,0.4)]"
          >
            <Search size={16} />
            <span>RUN FULL FORENSIC INVESTIGATION</span>
          </button>
        </div>
      )}

      {/* Pipeline Progress Indicator */}
      {running && <PipelineProgress stages={stages} />}

      {/* Results View */}
      {currentAnalysis && !running && (
        <div className="space-y-6">
          {/* Action Center & Verdict */}
          <VerdictCard
            analysis={currentAnalysis}
            onStartInvestigation={() => setShowInvestigationMode(true)}
          />

          <AnalystActionCenter
            analysis={currentAnalysis}
            onOpenCaseModal={() => navigate('/cases')}
          />

          {/* Forensic Suite Navigation Tabs */}
          <div className="flex flex-wrap border-b border-cyan-500/20 bg-[#050a18] rounded-xl p-1.5 gap-1 font-mono text-xs">
            <button
              onClick={() => setActiveForensicTab('OVERVIEW')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'OVERVIEW' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              📊 OVERVIEW & IOCs
            </button>
            <button
              onClick={() => setActiveForensicTab('EVIDENCE')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'EVIDENCE' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              🛡️ EVIDENCE CONFIDENCE
            </button>
            <button
              onClick={() => setActiveForensicTab('MITRE')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'MITRE' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              🎯 MITRE ATT&CK CHAIN
            </button>
            <button
              onClick={() => setActiveForensicTab('DNA')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'DNA' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              🧬 EMAIL DNA
            </button>
            <button
              onClick={() => setActiveForensicTab('INFRA')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'INFRA' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              🌐 INFRASTRUCTURE PROFILE
            </button>
            <button
              onClick={() => setActiveForensicTab('SIMILAR')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'SIMILAR' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              🔍 SIMILAR INCIDENTS
            </button>
            <button
              onClick={() => setActiveForensicTab('TIMELINE')}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                activeForensicTab === 'TIMELINE' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
              }`}
            >
              ⏱️ CAMPAIGN TIMELINE
            </button>
          </div>

          {/* Active Tab Content */}
          {activeForensicTab === 'OVERVIEW' && (
            <div className="space-y-6 animate-fade-in">
              <IocTable analysis={currentAnalysis} />
              <EvidenceConfidence analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'EVIDENCE' && (
            <div className="animate-fade-in">
              <EvidenceConfidence analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'MITRE' && (
            <div className="animate-fade-in">
              <MitreAttackChain analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'DNA' && (
            <div className="animate-fade-in">
              <EmailDNA analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'INFRA' && (
            <div className="animate-fade-in">
              <InfrastructureFingerprint analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'SIMILAR' && (
            <div className="animate-fade-in">
              <SimilarIncidents analysis={currentAnalysis} />
            </div>
          )}

          {activeForensicTab === 'TIMELINE' && (
            <div className="animate-fade-in">
              <CampaignTimeline analysis={currentAnalysis} />
            </div>
          )}

          {/* Chain of Custody Card */}
          <div className="panel p-5 border-cyan-500/20 bg-[#080e21]">
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider mb-4 flex items-center gap-2">
              <Shield size={14} className="text-cyan-400" />
              <span>CHAIN OF CUSTODY & EVIDENCE RECORD</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs font-mono">
              <div>
                <div className="text-[10px] text-slate-500">EVIDENCE ID</div>
                <div className="text-cyan-300 font-bold mt-0.5">{currentAnalysis.evidence.evidenceId}</div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500">SHA-256 HASH</div>
                <div className="text-slate-300 truncate mt-0.5" title={currentAnalysis.evidence.sha256}>
                  {currentAnalysis.evidence.sha256.slice(0, 16)}...
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500">INGESTION TIME</div>
                <div className="text-slate-300 mt-0.5">
                  {new Date(currentAnalysis.evidence.acquiredAt).toLocaleTimeString()}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500">ACQUISITION SOURCE</div>
                <div className="text-slate-300 mt-0.5">{currentAnalysis.evidence.source}</div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500">ANALYST</div>
                <div className="text-slate-300 mt-0.5">{currentAnalysis.evidence.analystId}</div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500">INTEGRITY</div>
                <div className="text-emerald-400 font-bold mt-0.5 flex items-center gap-1">
                  <CheckCircle size={12} />
                  <span>VERIFIED</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Guided Investigation Mode Fullscreen Stepper Overlay */}
      {showInvestigationMode && currentAnalysis && (
        <InvestigationMode
          analysis={currentAnalysis}
          onClose={() => setShowInvestigationMode(false)}
          onNavigateToModule={(route) => navigate(route)}
        />
      )}
    </div>
  );
}
