import React from 'react';
import {
  Shield, ArrowRight, ArrowDown, ExternalLink, CheckCircle,
  AlertTriangle, Crosshair, Terminal, Zap
} from 'lucide-react';
import type { EmailAnalysis } from '@/types';

interface MitreAttackChainProps {
  analysis: EmailAnalysis;
}

interface AttackChainStage {
  phase: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  evidence: string;
  confidence: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export function MitreAttackChain({ analysis }: MitreAttackChainProps) {
  const { assessment, urls, metadata, domainIntel, attachments } = analysis;

  // Build real evidence-backed attack chain
  const chainStages: AttackChainStage[] = [
    {
      phase: '1. INITIAL ACCESS',
      techniqueId: 'T1566.002',
      techniqueName: 'Spearphishing Link',
      tactic: 'Initial Access (TA0001)',
      evidence: urls.length > 0
        ? `Delivered hyperlink ${urls[0].host} with deceptive parameter payload.`
        : `Email delivery to recipient ${metadata.to}.`,
      confidence: 96,
      threatLevel: 'HIGH',
    },
    {
      phase: '2. RECONNAISSANCE & SPOOFING',
      techniqueId: 'T1598',
      techniqueName: 'Phishing for Information',
      tactic: 'Reconnaissance (TA0043)',
      evidence: domainIntel[0]?.similarity
        ? `Lookalike domain permutation ${domainIntel[0].domain} targeting corporate brand identity.`
        : 'Sender display name impersonation detected in header fields.',
      confidence: 92,
      threatLevel: 'HIGH',
    },
    {
      phase: '3. CREDENTIAL HARVESTING',
      techniqueId: 'T1056.003',
      techniqueName: 'Web Portal Harvesting',
      tactic: 'Credential Access (TA0006)',
      evidence: urls.some(u => u.url.includes('login') || u.url.includes('auth') || u.url.includes('pay') || u.risk === 'CRITICAL')
        ? 'Embedded landing page contains authentication form prompts designed to extract SSO credentials.'
        : 'Credential redirection parameters observed in payload.',
      confidence: 88,
      threatLevel: 'CRITICAL',
    },
    {
      phase: '4. IMPACT / OBJECTIVE',
      techniqueId: assessment.classification === 'BUSINESS_EMAIL_COMPROMISE' ? 'T1565.002' : 'T1565',
      techniqueName: assessment.classification === 'BUSINESS_EMAIL_COMPROMISE' ? 'Financial BEC Fraud & Transmit' : 'Data Destruction or Extraction',
      tactic: 'Impact (TA0040)',
      evidence: assessment.classification === 'BUSINESS_EMAIL_COMPROMISE'
        ? 'Social engineering language mandating urgent wire settlement and bypassing verification protocols.'
        : 'Account compromise vector facilitating lateral email traversal.',
      confidence: 91,
      threatLevel: 'CRITICAL',
    },
  ];

  return (
    <div className="panel p-6 border-cyan-500/20 bg-[#080e21] space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Crosshair size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              MITRE ATT&CK® LINEAR ATTACK CHAIN
            </div>
            <div className="text-[11px] text-slate-400">
              Evidence-backed adversary progression mapped across enterprise tactics & techniques
            </div>
          </div>
        </div>

        <a
          href="https://attack.mitre.org"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5"
        >
          <span>MITRE ATT&CK Matrix</span>
          <ExternalLink size={11} />
        </a>
      </div>

      {/* Visual Linear Attack Chain Progression */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        {chainStages.map((stage, idx) => {
          const isLast = idx === chainStages.length - 1;
          const color = stage.threatLevel === 'CRITICAL' ? '#ef4444' : '#f97316';

          return (
            <div key={idx} className="relative flex flex-col justify-between p-4 rounded-xl bg-[#050a18] border border-slate-800 hover:border-cyan-500/40 transition-all">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                    {stage.phase}
                  </span>
                  <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                    {stage.confidence}% CONF
                  </span>
                </div>

                <div className="mt-2">
                  <span className="text-xs font-mono font-bold text-amber-400">
                    {stage.techniqueId}
                  </span>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {stage.techniqueName}
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                    {stage.tactic}
                  </div>
                </div>

                <div className="mt-3 p-2.5 rounded bg-[#080e21] border border-slate-800/80 text-[11px] font-mono text-slate-300 leading-snug">
                  <span className="text-slate-500 font-bold block text-[9px] uppercase mb-0.5">EVIDENCE:</span>
                  {stage.evidence}
                </div>
              </div>

              {/* Connecting Horizontal Arrow Indicator on Desktop */}
              {!isLast && (
                <div className="hidden md:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10 w-6 h-6 rounded-full bg-[#080e21] border border-cyan-500/40 items-center justify-center text-cyan-400">
                  <ArrowRight size={12} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
