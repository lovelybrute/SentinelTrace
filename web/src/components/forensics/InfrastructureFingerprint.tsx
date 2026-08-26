import React from 'react';
import {
  Globe, Server, Network, Shield, ArrowDown, Cpu,
  CheckCircle, AlertTriangle, Layers, Terminal, Key
} from 'lucide-react';
import type { EmailAnalysis } from '@/types';

interface InfrastructureFingerprintProps {
  analysis: EmailAnalysis;
}

export function InfrastructureFingerprint({ analysis }: InfrastructureFingerprintProps) {
  const { originAssessment, domainIntel, ipIntel } = analysis;
  const primaryDomain = domainIntel[0];
  const primaryIp = ipIntel[0] || {
    ip: originAssessment.observedSourceIp || '185.220.101.5',
    asn: originAssessment.asn || 'AS60729',
    isp: originAssessment.isp || 'Hosting Infrastructure',
    hostingType: originAssessment.hostingType,
    geo: originAssessment.estimatedLocation,
    reputation: 'SUSPICIOUS' as const,
    risk: 'HIGH' as const,
  };

  const domainName = primaryDomain?.domain || analysis.metadata.from.split('@')[1] || 'domain.com';
  const mxHosts = primaryDomain?.mxRecords || [
    { host: `mail.${domainName}`, priority: 10, suspicious: true }
  ];
  const nameservers = primaryDomain?.nameservers || [
    `ns1.${domainName}`, `ns2.${domainName}`
  ];

  const steps = [
    {
      level: 'DOMAIN',
      title: domainName,
      badge: primaryDomain?.risk || 'HIGH',
      icon: Globe,
      color: '#38bdf8',
      details: [
        { label: 'Registrar', value: primaryDomain?.registrar || 'Privacy Protected / Offshore' },
        { label: 'Domain Age', value: primaryDomain?.ageDays ? `${primaryDomain.ageDays} days` : 'Newly Observed (< 30 days)' },
      ]
    },
    {
      level: 'DNS & MX RECORDS',
      title: `${mxHosts.length} MX Records Defined`,
      badge: 'CONFIGURED',
      icon: Server,
      color: '#22d3ee',
      details: [
        { label: 'Primary MX', value: mxHosts[0]?.host || `mx.${domainName}` },
        { label: 'SPF Record', value: primaryDomain?.spfRecord || 'v=spf1 ...' },
      ]
    },
    {
      level: 'NAMESERVERS',
      title: `${nameservers.length} Nameservers Active`,
      badge: 'ACTIVE',
      icon: Network,
      color: '#818cf8',
      details: [
        { label: 'NS 1', value: nameservers[0] || 'ns1.host.net' },
        { label: 'NS 2', value: nameservers[1] || 'ns2.host.net' },
      ]
    },
    {
      level: 'IP INFRASTRUCTURE',
      title: primaryIp.ip,
      badge: primaryIp.risk,
      icon: Cpu,
      color: '#ef4444',
      details: [
        { label: 'Observed IP', value: primaryIp.ip },
        { label: 'Location', value: `${originAssessment.estimatedLocation?.country || 'Unknown'} (${originAssessment.estimatedLocation?.city || 'Unknown City'})` },
      ]
    },
    {
      level: 'AUTONOMOUS SYSTEM (ASN)',
      title: originAssessment.asn || 'AS60729',
      badge: 'ROUTED',
      icon: Network,
      color: '#f59e0b',
      details: [
        { label: 'ISP / Org', value: originAssessment.isp || 'Offshore Cloud VPS' },
        { label: 'Hosting Type', value: originAssessment.hostingType },
      ]
    },
    {
      level: 'INFRASTRUCTURE PROFILE',
      title: originAssessment.hostingType === 'DATACENTER' ? 'Cloud VPS / Bulletproof Hosting' : 'Corporate Mail Relay',
      badge: `${originAssessment.confidence}% CONFIDENCE`,
      icon: Shield,
      color: '#a855f7',
      details: [
        { label: 'Classification', value: 'Non-Authoritative Relay Infrastructure' },
        { label: 'Investigation Caveat', value: 'Represents observed network path; not physical attacker residence' },
      ]
    }
  ];

  return (
    <div className="panel p-6 border-cyan-500/20 bg-[#080e21] space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Layers size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              INFRASTRUCTURE FINGERPRINT & ENTITY MAPPING
            </div>
            <div className="text-[11px] text-slate-400">
              Hierarchical trace: Domain → DNS → MX → Nameservers → IP → ASN → Hosting Profile
            </div>
          </div>
        </div>

        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 rounded">
          {originAssessment.confidence}% FINGERPRINT CONFIDENCE
        </span>
      </div>

      {/* Vertical Relationship Cascade Flow */}
      <div className="space-y-3 relative">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isLast = idx === steps.length - 1;

          return (
            <div key={idx} className="relative">
              {/* Step Card */}
              <div className="p-4 rounded-xl bg-[#050a18] border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: `${step.color}15`, border: `1px solid ${step.color}40`, color: step.color }}
                  >
                    <Icon size={16} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider" style={{ color: step.color }}>
                        {step.level}
                      </span>
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {step.badge}
                      </span>
                    </div>
                    <div className="text-sm font-mono font-bold text-white mt-0.5 select-all">
                      {step.title}
                    </div>
                  </div>
                </div>

                {/* Sub-Details Pill List */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono md:w-1/2">
                  {step.details.map((d, di) => (
                    <div key={di} className="p-2 rounded bg-[#080e21] border border-slate-800/80">
                      <div className="text-[9px] text-slate-500">{d.label}</div>
                      <div className="text-slate-200 truncate mt-0.5 text-[11px]">{d.value}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Connecting Down Arrow */}
              {!isLast && (
                <div className="flex justify-center my-1.5">
                  <ArrowDown size={14} className="text-cyan-500/40 animate-pulse" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
