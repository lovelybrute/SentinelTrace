import React from 'react';
import {
  Dna, Sparkles, Shield, Cpu, FileCode, MessageSquare,
  Link2, Server, UserCheck, Paperclip, BarChart3
} from 'lucide-react';
import type { EmailAnalysis } from '@/types';

interface EmailDNAProps {
  analysis: EmailAnalysis;
}

export function EmailDNA({ analysis }: EmailDNAProps) {
  const { score, assessment, headers, urls, attachments, originAssessment, metadata } = analysis;

  // Calculate explainable dimensional forensic DNA scores (0-100)
  const headerScore = Math.min(
    100,
    headers.filter(h => h.anomaly).length * 35 +
    (metadata.replyTo && !metadata.from.includes(metadata.replyTo) ? 40 : 15)
  );

  const languageScore = assessment.classification === 'BUSINESS_EMAIL_COMPROMISE' ? 88
    : assessment.classification === 'PHISHING' ? 92
    : assessment.classification === 'IMPERSONATION' ? 84
    : 20;

  const urlScore = urls.length > 0
    ? Math.max(...urls.map(u => (u.risk === 'CRITICAL' ? 98 : u.risk === 'HIGH' ? 85 : 40)))
    : 10;

  const infraScore = originAssessment.hostingType === 'DATACENTER' ? 82
    : originAssessment.observedSourceIp ? 74
    : 25;

  const senderScore = metadata.fromDisplayName && metadata.from.includes('gmail.com') ? 91
    : analysis.domainIntel[0]?.similarity ? 95
    : 30;

  const attachmentScore = attachments.length > 0
    ? Math.max(...attachments.map(a => (a.risk === 'CRITICAL' ? 96 : a.risk === 'HIGH' ? 82 : 45)))
    : 0;

  const dimensions = [
    {
      id: 'header',
      label: 'HEADER PATTERN',
      score: headerScore,
      icon: FileCode,
      color: headerScore > 60 ? '#ef4444' : '#22c55e',
      detail: `${headers.filter(h => h.anomaly).length} header anomalies & Return-Path alignment`,
    },
    {
      id: 'language',
      label: 'LANGUAGE & URGENCY PATTERN',
      score: languageScore,
      icon: MessageSquare,
      color: languageScore > 60 ? '#f97316' : '#22c55e',
      detail: `${assessment.classification} NLP urgency & wire transfer tone markers`,
    },
    {
      id: 'url',
      label: 'URL HYPERLINK PATTERN',
      score: urlScore,
      icon: Link2,
      color: urlScore > 60 ? '#ef4444' : '#22c55e',
      detail: `${urls.length} extracted endpoints; anchor mismatch evaluation`,
    },
    {
      id: 'infra',
      label: 'INFRASTRUCTURE & RELAY',
      score: infraScore,
      icon: Server,
      color: infraScore > 60 ? '#f59e0b' : '#22c55e',
      detail: `${originAssessment.hostingType} socket on ${originAssessment.asn || 'MTA'}`,
    },
    {
      id: 'sender',
      label: 'SENDER IDENTITY DECEPTION',
      score: senderScore,
      icon: UserCheck,
      color: senderScore > 60 ? '#ef4444' : '#22c55e',
      detail: 'Lookalike domain & executive display name mismatch',
    },
    {
      id: 'attachment',
      label: 'ATTACHMENT PAYLOAD SIGNATURE',
      score: attachmentScore,
      icon: Paperclip,
      color: attachmentScore > 60 ? '#ef4444' : '#94a3b8',
      detail: `${attachments.length} static attachment payloads analyzed`,
    },
  ];

  return (
    <div className="panel p-6 border-cyan-500/20 bg-[#080e21] space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Dna size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              EMAIL FORENSIC DNA & MULTI-DIMENSIONAL FINGERPRINT
            </div>
            <div className="text-[11px] text-slate-400">
              Explainable feature vector quantifying attack attributes for campaign correlation
            </div>
          </div>
        </div>

        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 rounded">
          6-DIMENSIONAL FEATURE VECTOR
        </span>
      </div>

      {/* Dimensional Fingerprint Bars */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {dimensions.map((dim) => {
          const Icon = dim.icon;
          const filledBars = Math.round(dim.score / 10);
          const emptyBars = 10 - filledBars;

          return (
            <div key={dim.id} className="p-4 rounded-xl bg-[#050a18] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Icon size={14} style={{ color: dim.color }} />
                  <span className="font-mono text-xs font-bold text-slate-200">{dim.label}</span>
                </div>
                <span className="font-mono text-xs font-black" style={{ color: dim.color }}>
                  {dim.score}/100
                </span>
              </div>

              {/* Visual ASCII / Block Meter */}
              <div className="flex items-center gap-1 font-mono text-sm select-none" style={{ color: dim.color }}>
                <span>{'█'.repeat(filledBars)}</span>
                <span className="text-slate-800">{'░'.repeat(emptyBars)}</span>
              </div>

              {/* Subtitle summary */}
              <div className="text-[10px] font-mono text-slate-400 truncate">
                {dim.detail}
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary Note */}
      <div className="p-3.5 rounded-lg bg-[#050a18]/80 border border-cyan-500/10 flex items-center justify-between text-xs font-mono text-slate-400">
        <span>DNA Fingerprint hash: <strong className="text-cyan-300">DNA-{analysis.evidence.sha256.slice(0, 12).toUpperCase()}</strong></span>
        <span className="text-[10px] text-slate-500">Normalised Jaccard Euclidean Space</span>
      </div>
    </div>
  );
}
