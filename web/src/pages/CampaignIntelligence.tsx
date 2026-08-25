import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Layers, Shield, AlertTriangle, Users, Globe,
  Wifi, Calendar, ChevronRight, Activity, Search, Filter
} from 'lucide-react';
import { MOCK_CAMPAIGNS } from '@/services/mockDataService';
import type { Campaign, Severity } from '@/types';

export function CampaignIntelligence() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState<Campaign[]>(MOCK_CAMPAIGNS);
  const [selectedId, setSelectedId] = useState<string>(MOCK_CAMPAIGNS[0].id);
  const [searchQuery, setSearchQuery] = useState('');

  const selectedCampaign = campaigns.find(c => c.id === selectedId) || campaigns[0];

  const filteredCampaigns = campaigns.filter(c =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.topDomains.some(d => d.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const getRiskBadge = (risk: Severity) => {
    switch (risk) {
      case 'CRITICAL': return { color: '#ef4444', bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.3)' };
      case 'HIGH': return { color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.3)' };
      case 'MEDIUM': return { color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.3)' };
      default: return { color: '#22c55e', bg: 'rgba(34,197,94,0.15)', border: 'rgba(34,197,94,0.3)' };
    }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Campaign Intelligence & Threat Clusters
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Correlated email wave detection grouped by shared infrastructure, lookalike patterns, and delivery cadence
          </div>
        </div>

        <div className="relative">
          <Search size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            placeholder="Search campaigns or domains..."
            className="st-input text-xs"
            style={{ paddingLeft: 34, width: 260 }}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Grid: Left Campaign Cards + Right Campaign Inspector */}
      <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(350px, 1.2fr) minmax(360px, 1.8fr)' }}>
        {/* Campaign List */}
        <div className="flex flex-col gap-4">
          <div className="section-title">Active Campaign Clusters ({filteredCampaigns.length})</div>

          {filteredCampaigns.map(camp => {
            const isSelected = selectedId === camp.id;
            const badge = getRiskBadge(camp.risk);

            return (
              <div
                key={camp.id}
                onClick={() => setSelectedId(camp.id)}
                className={`panel-elevated transition-all-fast cursor-pointer ${isSelected ? 'glow-cyan' : ''}`}
                style={{
                  padding: 18,
                  borderLeft: `4px solid ${badge.color}`,
                  background: isSelected ? 'rgba(34,211,238,0.06)' : 'var(--color-surface-2)',
                  borderColor: isSelected ? 'rgba(34,211,238,0.4)' : undefined,
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#22d3ee', fontWeight: 700 }}>
                      CAMPAIGN #{camp.id}
                    </span>
                    <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--color-text)', marginTop: 2 }}>
                      {camp.name}
                    </div>
                  </div>

                  <span
                    style={{
                      fontSize: 10, fontWeight: 800,
                      color: badge.color, background: badge.bg,
                      border: `1px solid ${badge.border}`,
                      borderRadius: 4, padding: '2px 8px',
                    }}
                  >
                    {camp.risk}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--color-text-dim)', marginTop: 6, lineClamp: 2 }}>
                  {camp.summary}
                </div>

                <div className="grid grid-cols-4 gap-2 mt-4 pt-3" style={{ borderTop: '1px solid var(--color-border)' }}>
                  <div>
                    <div className="label">EMAILS</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--color-text)' }}>{camp.emailCount}</div>
                  </div>
                  <div>
                    <div className="label">DOMAINS</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: '#22d3ee' }}>{camp.domainCount}</div>
                  </div>
                  <div>
                    <div className="label">IPS</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: '#f59e0b' }}>{camp.ipCount}</div>
                  </div>
                  <div>
                    <div className="label">VICTIMS</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: '#ef4444' }}>{camp.victimCount}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Campaign Detailed Inspector */}
        {selectedCampaign && (
          <div className="panel" style={{ padding: 24 }}>
            <div className="flex items-start justify-between pb-4 mb-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
              <div>
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: '#22d3ee', fontWeight: 800 }}>
                  CAMPAIGN #{selectedCampaign.id}
                </span>
                <h2 style={{ fontSize: 20, fontWeight: 900, color: 'var(--color-text)', marginTop: 2 }}>
                  {selectedCampaign.name}
                </h2>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
                  Classification: <strong>{selectedCampaign.classification.replace(/_/g, ' ')}</strong> · Status: <span style={{ color: '#22c55e', fontWeight: 700 }}>{selectedCampaign.status}</span>
                </div>
              </div>

              <button
                onClick={() => navigate('/cases')}
                className="btn-primary flex items-center gap-1.5 text-xs"
              >
                <span>Open Incident Case</span>
                <ChevronRight size={13} />
              </button>
            </div>

            {/* Campaign Metrics */}
            <div className="grid grid-cols-4 gap-3 mb-6">
              {[
                { label: 'Related Emails', val: selectedCampaign.emailCount, col: '#22d3ee' },
                { label: 'Observed Domains', val: selectedCampaign.domainCount, col: '#ef4444' },
                { label: 'Relay IPs', val: selectedCampaign.ipCount, col: '#f59e0b' },
                { label: 'Target Organizations', val: selectedCampaign.victimCount, col: '#fca5a5' },
              ].map(m => (
                <div key={m.label} className="panel-elevated" style={{ padding: 12, textAlign: 'center' }}>
                  <div className="label">{m.label}</div>
                  <div style={{ fontSize: 20, fontWeight: 900, color: m.col, marginTop: 4 }}>{m.val}</div>
                </div>
              ))}
            </div>

            {/* Narrative Summary */}
            <div className="mb-6">
              <div className="label mb-1">Threat Actor & Modus Operandi</div>
              <div style={{ fontSize: 13, color: 'var(--color-text-dim)', lineHeight: 1.6, background: 'rgba(0,0,0,0.2)', padding: 14, borderRadius: 8, border: '1px solid var(--color-border)' }}>
                {selectedCampaign.summary}
              </div>
            </div>

            {/* Clustering Basis */}
            <div className="mb-6">
              <div className="label mb-2">Cluster Correlation Basis</div>
              <div className="flex flex-wrap gap-2">
                {selectedCampaign.clusterBasis.map((b, i) => (
                  <span
                    key={i}
                    style={{
                      fontSize: 11,
                      padding: '4px 10px',
                      borderRadius: 4,
                      background: 'rgba(34,211,238,0.1)',
                      border: '1px solid rgba(34,211,238,0.25)',
                      color: '#22d3ee',
                      fontWeight: 600,
                    }}
                  >
                    ✓ {b}
                  </span>
                ))}
              </div>
            </div>

            {/* Correlated Domains & IPs */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div>
                <div className="label mb-2">Associated Lookalike Domains</div>
                <div className="flex flex-col gap-1.5">
                  {selectedCampaign.topDomains.map(d => (
                    <div key={d} className="p-2 rounded flex items-center justify-between" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--color-border)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: '#fca5a5' }}>{d}</span>
                      <span style={{ fontSize: 9, color: '#ef4444', fontWeight: 700 }}>MALICIOUS</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="label mb-2">Associated Ingress IPs</div>
                <div className="flex flex-col gap-1.5">
                  {selectedCampaign.topIps.map(ip => (
                    <div key={ip} className="p-2 rounded flex items-center justify-between" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--color-border)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: '#22d3ee' }}>{ip}</span>
                      <span style={{ fontSize: 9, color: '#f59e0b', fontWeight: 700 }}>RELAY</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Timeline */}
            <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--color-border)' }}>
              <div>
                <div className="label">First Observed</div>
                <div style={{ fontSize: 12, color: 'var(--color-text)', marginTop: 2 }}>
                  {new Date(selectedCampaign.firstObserved).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}
                </div>
              </div>
              <div className="text-right">
                <div className="label">Last Activity</div>
                <div style={{ fontSize: 12, color: '#ef4444', fontWeight: 700, marginTop: 2 }}>
                  {new Date(selectedCampaign.lastObserved).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })} (Active)
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
