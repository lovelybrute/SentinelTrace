import React from 'react';
import {
  ShieldAlert, TrendingUp, Users, Globe, Cpu, Layers,
  Activity, ArrowUpRight, BarChart2, CheckCircle2
} from 'lucide-react';

interface ThreatPostureData {
  categoryDistribution: Array<{ name: string; count: number; percentage: number; color: string }>;
  topTargetedIdentities: Array<{ email: string; department: string; threatCount: number }>;
  topDomains: Array<{ domain: string; classification: string; observedCount: number }>;
  topIps: Array<{ ip: string; asn: string; country: string; score: number }>;
  topCampaigns: Array<{ id: string; name: string; risk: string; emails: number }>;
}

export function SocThreatPosture({ customData }: { customData?: ThreatPostureData }) {
  const data: ThreatPostureData = customData || {
    categoryDistribution: [
      { name: 'PHISHING & CREDENTIAL THEFT', count: 142, percentage: 48, color: '#ef4444' },
      { name: 'BUSINESS EMAIL COMPROMISE (BEC)', count: 68, percentage: 23, color: '#f97316' },
      { name: 'EXECUTIVE IMPERSONATION', count: 44, percentage: 15, color: '#f59e0b' },
      { name: 'MALWARE / SUSPICIOUS ATTACHMENT', count: 28, percentage: 9, color: '#a855f7' },
      { name: 'ACCOUNT RECONNAISSANCE', count: 15, percentage: 5, color: '#38bdf8' },
    ],
    topTargetedIdentities: [
      { email: 'procurement@victimcorp.com', department: 'Finance / Accounts Payable', threatCount: 24 },
      { email: 'cfo.office@victimcorp.com', department: 'Executive Leadership', threatCount: 18 },
      { email: 'analyst.soc@victimcorp.com', department: 'Security Operations', threatCount: 12 },
      { email: 'hr-benefits@victimcorp.com', department: 'Human Resources', threatCount: 9 },
    ],
    topDomains: [
      { domain: 'paypa1-security.com', classification: 'Typosquatting Lookalike', observedCount: 38 },
      { domain: 'microsoft-auth-verify.net', classification: 'Credential Phish', observedCount: 29 },
      { domain: 'executive-urgent-desk.com', classification: 'Executive BEC Spoof', observedCount: 17 },
      { domain: 'docusign-secure-portal.org', classification: 'Document Fraud', observedCount: 14 },
    ],
    topIps: [
      { ip: '185.220.101.5', asn: 'AS60729 (Offshore VPS)', country: 'Germany', score: 96 },
      { ip: '194.26.29.112', asn: 'AS44050 (Bulletproof Hosting)', country: 'Russia', score: 92 },
      { ip: '45.154.255.89', asn: 'AS200019 (Cloud Transit)', country: 'Netherlands', score: 88 },
      { ip: '209.85.128.41', asn: 'AS15169 (Google MTA Relay)', country: 'United States', score: 15 },
    ],
    topCampaigns: [
      { id: 'ST-CAMP-0042', name: 'Global Invoice Lookalike Wave', risk: 'CRITICAL', emails: 48 },
      { id: 'ST-CAMP-0031', name: 'CEO Confidential Wire Request', risk: 'HIGH', emails: 27 },
      { id: 'ST-CAMP-0017', name: 'M365 OAuth Token Harvest', risk: 'HIGH', emails: 19 },
    ],
  };

  return (
    <div className="panel p-6 border-cyan-500/20 bg-[#080e21] space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <ShieldAlert size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              ORGANIZATION-LEVEL SOC THREAT POSTURE
            </div>
            <div className="text-[11px] text-slate-400">
              Aggregated attack telemetry across Phishing, BEC, Credential Theft, and Impersonation
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-[10px] text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-3 py-1.5 rounded">
          <Activity size={12} className="text-cyan-400 animate-pulse" />
          <span>ACTIVE MONITORING // 297 INGESTED THREAT SIGNALS</span>
        </div>
      </div>

      {/* Category Distribution Bars */}
      <div className="space-y-3">
        <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
          ATTACK CATEGORY BREAKDOWN
        </div>
        <div className="space-y-2">
          {data.categoryDistribution.map((cat, i) => (
            <div key={i} className="p-3 rounded-lg bg-[#050a18] border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-slate-200">{cat.name}</span>
                <span className="font-bold" style={{ color: cat.color }}>
                  {cat.count} Incidents ({cat.percentage}%)
                </span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${cat.percentage}%`, backgroundColor: cat.color }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 2x2 Telemetry Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top Targeted Identities */}
        <div className="p-4 rounded-xl bg-[#050a18] border border-cyan-500/15 space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300">
            <Users size={14} className="text-cyan-400" />
            <span>TOP TARGETED IDENTITIES</span>
          </div>
          <div className="space-y-2">
            {data.topTargetedIdentities.map((t, i) => (
              <div key={i} className="p-2.5 rounded bg-[#080e21] border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div>
                  <div className="text-slate-200 font-bold truncate max-w-[200px]">{t.email}</div>
                  <div className="text-[10px] text-slate-500">{t.department}</div>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-500/30">
                  {t.threatCount} attacks
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Lookalike Domains */}
        <div className="p-4 rounded-xl bg-[#050a18] border border-cyan-500/15 space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300">
            <Globe size={14} className="text-cyan-400" />
            <span>TOP OBSERVED THREAT DOMAINS</span>
          </div>
          <div className="space-y-2">
            {data.topDomains.map((d, i) => (
              <div key={i} className="p-2.5 rounded bg-[#080e21] border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div>
                  <div className="text-slate-200 font-bold truncate max-w-[200px]">{d.domain}</div>
                  <div className="text-[10px] text-amber-400">{d.classification}</div>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                  {d.observedCount} hits
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Observed Infrastructure IPs */}
        <div className="p-4 rounded-xl bg-[#050a18] border border-cyan-500/15 space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300">
            <Cpu size={14} className="text-cyan-400" />
            <span>OBSERVED INFRASTRUCTURE RELAYS</span>
          </div>
          <div className="space-y-2">
            {data.topIps.map((ip, i) => (
              <div key={i} className="p-2.5 rounded bg-[#080e21] border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div>
                  <div className="text-slate-200 font-bold">{ip.ip} ({ip.country})</div>
                  <div className="text-[10px] text-slate-500">{ip.asn}</div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${ip.score >= 80 ? 'text-red-400 bg-red-950/80 border border-red-500/30' : 'text-emerald-400'}`}>
                  Score {ip.score}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Active Campaigns */}
        <div className="p-4 rounded-xl bg-[#050a18] border border-cyan-500/15 space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300">
            <Layers size={14} className="text-cyan-400" />
            <span>CORRELATED THREAT CAMPAIGNS</span>
          </div>
          <div className="space-y-2">
            {data.topCampaigns.map((c, i) => (
              <div key={i} className="p-2.5 rounded bg-[#080e21] border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div>
                  <div className="text-cyan-300 font-bold">#{c.id}</div>
                  <div className="text-[10px] text-slate-300 truncate max-w-[200px]">{c.name}</div>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-500/30">
                  {c.emails} messages
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
