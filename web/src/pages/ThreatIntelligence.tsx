import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Globe, Wifi, AlertTriangle, CheckCircle,
  Copy, ExternalLink, RefreshCw, Search, Database, Layers
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
import { InteractiveGlobe3D } from '@/components/3d/InteractiveGlobe3D';
import type { Severity, DomainIntelligence, IpIntelligence } from '@/types';

export function ThreatIntelligence() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [analyzingDemo, setAnalyzingDemo] = useState(false);

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Threat Intelligence Demo Load',
        useBackend: true,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
    } catch (e) {
      console.error(e);
    } finally {
      setAnalyzingDemo(false);
    }
  };

  const analysis = currentAnalysis;

  if (!analysis) {
    return (
      <div style={{ padding: 32, maxWidth: 800, margin: '40px auto', textAlign: 'center' }}>
        <div className="panel" style={{ padding: 48 }}>
          <Shield size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No Threat Intelligence Records</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            Analyze an email to extract associated domains, lookalikes, IP nodes, ASNs, and reputation blacklists.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load BEC Threat Intel Demo'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const { domainIntel, ipIntel } = analysis;

  const activeDomain = selectedDomain
    ? domainIntel.find(d => d.domain === selectedDomain) || domainIntel[0]
    : domainIntel[0];

  const activeIp = selectedIp
    ? ipIntel.find(i => i.ip === selectedIp) || ipIntel[0]
    : ipIntel[0];

  const getRiskColor = (risk: Severity) => {
    switch (risk) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': return '#22c55e';
      case 'INFO':
      default: return '#22d3ee';
    }
  };

  // Build Globe Location Points from analyzed IPs
  const globePoints = ipIntel.map(ip => ({
    ip: ip.ip,
    country: ip.geo?.country || 'Unknown',
    city: ip.geo?.city || undefined,
    lat: ip.geo?.latitude || 50.1109,
    lng: ip.geo?.longitude || 8.6821,
    isp: ip.isp || undefined,
    asn: ip.asn || undefined,
    isThreat: ip.risk === 'CRITICAL' || ip.risk === 'HIGH',
    threatScore: ip.risk === 'CRITICAL' ? 95 : ip.risk === 'HIGH' ? 80 : 30,
  }));

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }} className="space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Domain & IP Threat Intelligence
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Infrastructure attribution, lookalike typosquatting scores, WHOIS age, MX telemetry, and blacklist correlation
          </div>
        </div>
      </div>

      {/* Global 3D Observed Infrastructure Globe */}
      <div>
        <div className="section-title mb-2">Global 3D Infrastructure Map</div>
        <InteractiveGlobe3D locations={globePoints} highlightIp={activeIp?.ip} />
      </div>

      {/* Section 1: Domain Intelligence */}
      <div className="mb-6">
        <div className="section-title">Domain Intelligence & Typosquatting Analysis</div>

        <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(280px, 1fr) minmax(360px, 2fr)' }}>
          {/* Domain List */}
          <div className="panel" style={{ padding: 16 }}>
            <div className="label mb-3">Extracted Domains ({domainIntel.length})</div>
            <div className="flex flex-col gap-2">
              {domainIntel.map(d => {
                const isSelected = activeDomain?.domain === d.domain;
                const riskColor = getRiskColor(d.risk);
                return (
                  <div
                    key={d.domain}
                    onClick={() => setSelectedDomain(d.domain)}
                    className="panel-elevated transition-all-fast cursor-pointer flex items-center justify-between"
                    style={{
                      padding: '12px 14px',
                      borderLeft: `3px solid ${riskColor}`,
                      background: isSelected ? 'rgba(34,211,238,0.08)' : 'var(--color-surface-2)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)', color: isSelected ? '#22d3ee' : 'var(--color-text)' }}>
                        {d.domain}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--color-text-muted)', marginTop: 2 }}>
                        {d.similarity ? `Mimics ${d.similarity.comparedTo} (${d.similarity.score}%)` : d.registrar || 'Standard registration'}
                      </div>
                    </div>
                    <span
                      style={{
                        fontSize: 9, fontWeight: 800,
                        color: riskColor, background: `${riskColor}15`,
                        border: `1px solid ${riskColor}30`,
                        borderRadius: 3, padding: '2px 6px',
                      }}
                    >
                      {d.risk}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Domain Inspector Details */}
          {activeDomain && (
            <div className="panel-elevated" style={{ padding: 24, borderLeft: `4px solid ${getRiskColor(activeDomain.risk)}` }}>
              <div className="flex items-start justify-between mb-4 pb-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#22d3ee' }}>
                    {activeDomain.domain}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-dim)', marginTop: 2 }}>
                    Registrar: <strong>{activeDomain.registrar || 'Privacy Protected / Redacted'}</strong>
                  </div>
                </div>

                <span
                  style={{
                    fontSize: 11, fontWeight: 800,
                    color: getRiskColor(activeDomain.risk),
                    background: `${getRiskColor(activeDomain.risk)}15`,
                    border: `1px solid ${getRiskColor(activeDomain.risk)}30`,
                    borderRadius: 4, padding: '4px 10px',
                  }}
                >
                  {activeDomain.reputation} ({activeDomain.risk})
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="label">Domain Age</div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: (activeDomain.ageDays ?? 999) < 30 ? '#ef4444' : 'var(--color-text)', marginTop: 2 }}>
                    {activeDomain.ageDays !== null ? `${activeDomain.ageDays} Days Old` : 'Unknown'}
                  </div>
                  {(activeDomain.ageDays ?? 999) < 30 && (
                    <div style={{ fontSize: 10, color: '#ef4444', marginTop: 1 }}>
                      ⚠ Newly registered domain (frequent in phishing)
                    </div>
                  )}
                </div>

                <div>
                  <div className="label">Creation Date</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', marginTop: 2 }}>
                    {activeDomain.createdAt || 'Not returned in WHOIS'}
                  </div>
                </div>
              </div>

              {/* Lookalike Details */}
              {activeDomain.similarity && (
                <div className="p-3 rounded-lg mb-4" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
                  <div className="label" style={{ color: '#ef4444' }}>Typosquatting & Brand Impersonation</div>
                  <div className="flex items-center justify-between mt-1">
                    <span style={{ fontSize: 12, color: 'var(--color-text)' }}>
                      Target Brand: <strong style={{ color: '#22d3ee' }}>{activeDomain.similarity.comparedTo}</strong>
                    </span>
                    <span style={{ fontSize: 12, fontWeight: 800, color: '#ef4444' }}>
                      {activeDomain.similarity.score}% Match
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                    Technique: {activeDomain.similarity.technique}
                  </div>
                </div>
              )}

              {/* MX Records */}
              <div className="mb-4">
                <div className="label mb-1">Mail Exchange (MX) Configuration</div>
                <div className="flex flex-col gap-1.5">
                  {activeDomain.mxRecords.map((mx, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 rounded" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--color-border)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: mx.suspicious ? '#ef4444' : 'var(--color-text)' }}>
                        {mx.host} (Priority: {mx.priority})
                      </span>
                      {mx.suspicious && (
                        <span style={{ fontSize: 9, color: '#ef4444', fontWeight: 700 }}>SUSPICIOUS MX</span>
                      )}
                    </div>
                  ))}
                  {activeDomain.mxRecords.length === 0 && (
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>No MX records published</div>
                  )}
                </div>
              </div>

              {/* Blacklists */}
              <div>
                <div className="label mb-2">Threat Intelligence Blacklists</div>
                <div className="flex flex-wrap gap-2">
                  {activeDomain.blacklists.map((bl, i) => (
                    <span
                      key={i}
                      style={{
                        fontSize: 11,
                        padding: '3px 8px',
                        borderRadius: 4,
                        background: bl.listed ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.1)',
                        border: `1px solid ${bl.listed ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.25)'}`,
                        color: bl.listed ? '#ef4444' : '#22c55e',
                        fontWeight: 600,
                      }}
                    >
                      {bl.source}: {bl.listed ? 'LISTED (MALICIOUS)' : 'CLEAN'}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Section 2: IP Intelligence */}
      <div>
        <div className="section-title">IP Intelligence & ASN Attribution</div>

        <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(280px, 1fr) minmax(360px, 2fr)' }}>
          {/* IP List */}
          <div className="panel" style={{ padding: 16 }}>
            <div className="label mb-3">Extracted IP Infrastructure ({ipIntel.length})</div>
            <div className="flex flex-col gap-2">
              {ipIntel.map(ip => {
                const isSelected = activeIp?.ip === ip.ip;
                const riskColor = getRiskColor(ip.risk);
                return (
                  <div
                    key={ip.ip}
                    onClick={() => setSelectedIp(ip.ip)}
                    className="panel-elevated transition-all-fast cursor-pointer flex items-center justify-between"
                    style={{
                      padding: '12px 14px',
                      borderLeft: `3px solid ${riskColor}`,
                      background: isSelected ? 'rgba(34,211,238,0.08)' : 'var(--color-surface-2)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)', color: isSelected ? '#22d3ee' : 'var(--color-text)' }}>
                        {ip.ip}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--color-text-muted)', marginTop: 2 }}>
                        {ip.geo ? `${ip.geo.city || ''} ${ip.geo.country}` : 'Location unknown'} · {ip.asn || 'No ASN'}
                      </div>
                    </div>
                    <span
                      style={{
                        fontSize: 9, fontWeight: 800,
                        color: riskColor, background: `${riskColor}15`,
                        border: `1px solid ${riskColor}30`,
                        borderRadius: 3, padding: '2px 6px',
                      }}
                    >
                      {ip.risk}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* IP Inspector Details */}
          {activeIp && (
            <div className="panel-elevated" style={{ padding: 24, borderLeft: `4px solid ${getRiskColor(activeIp.risk)}` }}>
              <div className="flex items-start justify-between mb-4 pb-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#22d3ee' }}>
                    {activeIp.ip}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-dim)', marginTop: 2 }}>
                    Hostname: <strong>{activeIp.hostname || 'Unresolved PTR'}</strong>
                  </div>
                </div>

                <span
                  style={{
                    fontSize: 11, fontWeight: 800,
                    color: getRiskColor(activeIp.risk),
                    background: `${getRiskColor(activeIp.risk)}15`,
                    border: `1px solid ${getRiskColor(activeIp.risk)}30`,
                    borderRadius: 4, padding: '4px 10px',
                  }}
                >
                  {activeIp.reputation} ({activeIp.risk})
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="label">Location & Country</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)', marginTop: 2 }}>
                    {activeIp.geo ? `${activeIp.geo.city ? `${activeIp.geo.city}, ` : ''}${activeIp.geo.country} (${activeIp.geo.countryCode})` : 'Geocoding unavailable'}
                  </div>
                </div>

                <div>
                  <div className="label">Hosting Classification</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: activeIp.hostingType === 'DATACENTER' ? '#f59e0b' : 'var(--color-text)', marginTop: 2 }}>
                    {activeIp.hostingType}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="label">ISP / Organization</div>
                  <div style={{ fontSize: 13, color: 'var(--color-text)', marginTop: 2 }}>
                    {activeIp.isp || activeIp.organization || 'Unknown'}
                  </div>
                </div>

                <div>
                  <div className="label">Autonomous System (ASN)</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: '#22d3ee', marginTop: 2 }}>
                    {activeIp.asn ? `${activeIp.asn} (${activeIp.asnOwner || ''})` : 'Unassigned'}
                  </div>
                </div>
              </div>

              {/* IP Blacklists */}
              <div>
                <div className="label mb-2">IP Reputation Blacklist Feeds</div>
                <div className="flex flex-wrap gap-2">
                  {activeIp.blacklists.map((bl, i) => (
                    <span
                      key={i}
                      style={{
                        fontSize: 11,
                        padding: '3px 8px',
                        borderRadius: 4,
                        background: bl.listed ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.1)',
                        border: `1px solid ${bl.listed ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.25)'}`,
                        color: bl.listed ? '#ef4444' : '#22c55e',
                        fontWeight: 600,
                      }}
                    >
                      {bl.source}: {bl.listed ? 'LISTED' : 'CLEAN'}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
