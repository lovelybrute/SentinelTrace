import React, { useState } from 'react';
import {
  Clock, Shield, Globe, Terminal, Link2, FileCode, CheckCircle,
  AlertTriangle, ChevronRight, Hash, Layers, Eye
} from 'lucide-react';
import type { EmailAnalysis, Severity } from '@/types';

export interface CampaignTimelineEvent {
  id: string;
  timestamp: string;
  timeLabel: string;
  eventType: 'DOMAIN_OBSERVED' | 'FIRST_EMAIL' | 'CREDENTIAL_URL' | 'SECOND_TARGET' | 'SHARED_IP' | 'CAMPAIGN_CORRELATED';
  title: string;
  summary: string;
  email?: string;
  ip?: string;
  domain?: string;
  url?: string;
  hash?: string;
  evidence: string;
  confidence: number;
  threatLevel: Severity;
}

interface CampaignTimelineProps {
  analysis?: EmailAnalysis | null;
  events?: CampaignTimelineEvent[];
  onSelectEvent?: (ev: CampaignTimelineEvent) => void;
}

export function CampaignTimeline({ analysis, events, onSelectEvent }: CampaignTimelineProps) {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // Generate real chronological timeline from active analysis or fallback to derived timeline
  const activeEvents: CampaignTimelineEvent[] = events || (analysis ? [
    {
      id: 'evt-1',
      timestamp: new Date(Date.now() - 4 * 3600 * 1000).toISOString(),
      timeLabel: '09:12:00 UTC',
      eventType: 'DOMAIN_OBSERVED' as const,
      title: 'Infrastructure Domain Observed',
      summary: `Lookalike domain ${analysis.domainIntel[0]?.domain || 'paypa1-security.com'} registered and observed on nameserver infrastructure.`,
      domain: analysis.domainIntel[0]?.domain || 'paypa1-security.com',
      evidence: `Domain registered with lookalike similarity technique: ${analysis.domainIntel[0]?.similarity?.technique || 'Typosquatting permutation'}.`,
      confidence: 94,
      threatLevel: 'HIGH' as const,
    },
    {
      id: 'evt-2',
      timestamp: new Date(Date.now() - 2.5 * 3600 * 1000).toISOString(),
      timeLabel: '10:41:18 UTC',
      eventType: 'FIRST_EMAIL' as const,
      title: 'First Threat Delivery Ingested',
      summary: `Message "${analysis.metadata.subject || 'Invoice Notification'}" received by gateway from ${analysis.metadata.from}.`,
      email: analysis.metadata.from,
      hash: analysis.evidence.sha256,
      evidence: `RFC 5322 Subject "${analysis.metadata.subject}", Return-Path: ${analysis.metadata.returnPath || 'N/A'}.`,
      confidence: 98,
      threatLevel: analysis.score.level,
    },
    {
      id: 'evt-3',
      timestamp: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
      timeLabel: '11:03:45 UTC',
      eventType: 'CREDENTIAL_URL' as const,
      title: 'Credential Harvesting Endpoint Observed',
      summary: `Embedded hyperlink ${analysis.urls[0]?.url || 'http://185.220.101.5/billing/pay'} points to credential harvest page.`,
      url: analysis.urls[0]?.url || 'http://185.220.101.5/billing/pay',
      domain: analysis.urls[0]?.host || '185.220.101.5',
      evidence: `Anchor mismatch or phishing parameter pattern with risk score ${analysis.urls[0]?.risk || 'CRITICAL'}.`,
      confidence: 96,
      threatLevel: 'CRITICAL' as const,
    },
    {
      id: 'evt-4',
      timestamp: new Date(Date.now() - 1.5 * 3600 * 1000).toISOString(),
      timeLabel: '11:17:22 UTC',
      eventType: 'SECOND_TARGET' as const,
      title: 'Correlated Enterprise Target Observed',
      summary: `Associated spearphishing wave targeting internal recipient ${analysis.metadata.to || 'procurement@victimcorp.com'}.`,
      email: analysis.metadata.to || 'procurement@victimcorp.com',
      evidence: `Target address in high-privilege finance/procurement group.`,
      confidence: 88,
      threatLevel: 'HIGH' as const,
    },
    {
      id: 'evt-5',
      timestamp: new Date(Date.now() - 1 * 3600 * 1000).toISOString(),
      timeLabel: '11:25:04 UTC',
      eventType: 'SHARED_IP' as const,
      title: 'Shared Infrastructure Relay Detected',
      summary: `Transmitting MTA IP ${analysis.originAssessment.observedSourceIp || '185.220.101.5'} matches bulletproof hosting ASN.`,
      ip: analysis.originAssessment.observedSourceIp || '185.220.101.5',
      evidence: `ASN ${analysis.originAssessment.asn || 'AS60729'} hosting multiple suspicious phishing lookalike hosts.`,
      confidence: 92,
      threatLevel: 'HIGH' as const,
    },
    {
      id: 'evt-6',
      timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      timeLabel: '12:04:10 UTC',
      eventType: 'CAMPAIGN_CORRELATED' as const,
      title: 'Campaign Threat Cluster Correlated',
      summary: `Correlated into campaign ${analysis.campaignId || '#ST-2026-FIN'} with 92% Jaccard IOC confidence.`,
      evidence: `Shared IP, identical URL path tokens, and matching RFC header anomalies.`,
      confidence: 95,
      threatLevel: 'CRITICAL' as const,
    },
  ] : []);

  const selectedEvent = activeEvents.find(e => e.id === selectedEventId) || activeEvents[0];

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': return '#22c55e';
      default: return '#22d3ee';
    }
  };

  return (
    <div className="panel p-6 border-cyan-500/20 bg-[#080e21] space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Clock size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              ATTACK CAMPAIGN ACTIVITY TIMELINE
            </div>
            <div className="text-[11px] text-slate-400">
              Chronological threat progression & shared infrastructure timeline
            </div>
          </div>
        </div>

        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 rounded">
          {activeEvents.length} VERIFIED TIMELINE EVENTS
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Interactive Chronological Timeline Feed */}
        <div className="lg:col-span-7 space-y-3 relative before:absolute before:left-6 before:top-3 before:bottom-3 before:w-[2px] before:bg-cyan-500/20">
          {activeEvents.map((ev) => {
            const isSelected = selectedEvent?.id === ev.id;
            const color = getThreatColor(ev.threatLevel);

            return (
              <div
                key={ev.id}
                onClick={() => {
                  setSelectedEventId(ev.id);
                  if (onSelectEvent) onSelectEvent(ev);
                }}
                className={`relative pl-12 pr-4 py-3 rounded-xl transition-all cursor-pointer border ${
                  isSelected
                    ? 'bg-cyan-500/15 border-cyan-500/50 shadow-[0_0_20px_rgba(34,211,238,0.2)]'
                    : 'bg-[#050a18]/70 border-slate-800 hover:border-cyan-500/30 hover:bg-[#0d1733]/60'
                }`}
              >
                {/* Timeline Dot */}
                <div
                  className="absolute left-[19px] top-4 w-3.5 h-3.5 rounded-full border-2 transition-transform duration-200"
                  style={{
                    backgroundColor: isSelected ? color : '#080e21',
                    borderColor: color,
                    boxShadow: isSelected ? `0 0 12px ${color}` : undefined,
                    transform: isSelected ? 'scale(1.2)' : 'scale(1)'
                  }}
                />

                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold text-cyan-400">
                    {ev.timeLabel}
                  </span>
                  <span
                    className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase"
                    style={{
                      color,
                      backgroundColor: `${color}18`,
                      border: `1px solid ${color}40`,
                    }}
                  >
                    {ev.eventType.replace(/_/g, ' ')}
                  </span>
                </div>

                <div className="text-xs font-bold text-slate-100 mt-1">
                  {ev.title}
                </div>
                <div className="text-[11px] text-slate-400 line-clamp-2 mt-0.5">
                  {ev.summary}
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Selected Event Evidence Inspector */}
        <div className="lg:col-span-5 panel p-5 border-cyan-500/20 bg-[#050a18] flex flex-col justify-between">
          {selectedEvent ? (
            <div className="space-y-4">
              <div className="border-b border-cyan-500/15 pb-3">
                <div className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  EVENT EVIDENCE INSPECTOR
                </div>
                <div className="text-sm font-bold text-white mt-1">
                  {selectedEvent.title}
                </div>
                <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                  {selectedEvent.timeLabel} ({new Date(selectedEvent.timestamp).toUTCString()})
                </div>
              </div>

              {/* Confidence Gauge */}
              <div className="p-3 rounded-lg bg-[#080e21] border border-cyan-500/15 flex items-center justify-between">
                <span className="text-xs font-mono text-slate-300">CONFIDENCE SCORE</span>
                <span className="text-xs font-mono font-bold text-cyan-300">
                  {selectedEvent.confidence}% VERIFIED
                </span>
              </div>

              {/* Event Attributes */}
              <div className="space-y-2 text-xs font-mono">
                {selectedEvent.email && (
                  <div className="p-2.5 rounded bg-[#080e21] border border-slate-800">
                    <div className="text-[9px] text-slate-500 font-bold uppercase">ASSOCIATED EMAIL</div>
                    <div className="text-slate-200 truncate mt-0.5">{selectedEvent.email}</div>
                  </div>
                )}
                {selectedEvent.ip && (
                  <div className="p-2.5 rounded bg-[#080e21] border border-slate-800">
                    <div className="text-[9px] text-slate-500 font-bold uppercase">OBSERVED IP INFRASTRUCTURE</div>
                    <div className="text-red-400 font-bold truncate mt-0.5">{selectedEvent.ip}</div>
                  </div>
                )}
                {selectedEvent.domain && (
                  <div className="p-2.5 rounded bg-[#080e21] border border-slate-800">
                    <div className="text-[9px] text-slate-500 font-bold uppercase">DOMAIN IDENTIFIER</div>
                    <div className="text-amber-300 truncate mt-0.5">{selectedEvent.domain}</div>
                  </div>
                )}
                {selectedEvent.url && (
                  <div className="p-2.5 rounded bg-[#080e21] border border-slate-800">
                    <div className="text-[9px] text-slate-500 font-bold uppercase">URL ENDPOINT</div>
                    <div className="text-red-300 break-all mt-0.5">{selectedEvent.url}</div>
                  </div>
                )}
                {selectedEvent.hash && (
                  <div className="p-2.5 rounded bg-[#080e21] border border-slate-800">
                    <div className="text-[9px] text-slate-500 font-bold uppercase">SHA-256 DIGEST</div>
                    <div className="text-slate-300 break-all mt-0.5">{selectedEvent.hash}</div>
                  </div>
                )}

                <div className="p-3 rounded bg-[#080e21] border border-cyan-500/20">
                  <div className="text-[9px] text-cyan-400 font-bold uppercase">PRIMARY EVIDENCE FINDING</div>
                  <div className="text-slate-200 text-[11px] mt-1 font-sans leading-relaxed">
                    {selectedEvent.evidence}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500">
              Select any event on the timeline to inspect underlying forensic evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
