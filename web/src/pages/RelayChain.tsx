import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GitBranch, Server, Globe, Shield, AlertTriangle, CheckCircle,
  Clock, MapPin, Copy, ArrowDown, ChevronRight, Eye, Network, Info
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
import type { RelayHop, HopTrust } from '@/types';

export function RelayChain() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const [selectedHopIndex, setSelectedHopIndex] = useState<number | null>(null);
  const [analyzingDemo, setAnalyzingDemo] = useState(false);

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Relay Chain Demo Load',
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

  if (!analysis || analysis.relayChain.length === 0) {
    return (
      <div style={{ padding: 32, maxWidth: 800, margin: '40px auto', textAlign: 'center' }}>
        <div className="panel" style={{ padding: 48 }}>
          <GitBranch size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No SMTP Relay Path Available</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            Reconstructing the SMTP relay timeline requires an analyzed email with Received: transport headers.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load Multi-Hop Demo Email'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const { relayChain, originAssessment } = analysis;
  const selectedHop = selectedHopIndex !== null ? relayChain[selectedHopIndex] : relayChain[0];

  const getTrustBadge = (trust: HopTrust) => {
    switch (trust) {
      case 'TRUSTED':
        return { label: 'TRUSTED HOP', color: '#22c55e', bg: 'rgba(34,197,94,0.15)', border: 'rgba(34,197,94,0.3)' };
      case 'SUSPICIOUS':
        return { label: 'SUSPICIOUS HOP', color: '#ef4444', bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.3)' };
      case 'UNKNOWN':
      default:
        return { label: 'UNKNOWN / UNVERIFIED', color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.3)' };
    }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <GitBranch size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              SMTP Relay Infrastructure & Hop Timeline
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Reverse chronological Mail Transfer Agent (MTA) traversal reconstructed from envelope Received: stamps
          </div>
        </div>

        <button onClick={() => navigate('/origin-trace')} className="btn-primary flex items-center gap-2 text-xs">
          <Globe size={14} />
          <span>View Geolocation Route Map</span>
          <ChevronRight size={14} />
        </button>
      </div>

      {/* Origin Infrastructure Summary Banner */}
      <div
        className="panel mb-6"
        style={{
          padding: 20,
          background: 'linear-gradient(135deg, rgba(34,211,238,0.06) 0%, rgba(10,15,26,0.95) 60%)',
          borderLeft: '4px solid #22d3ee',
        }}
      >
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div
              style={{
                width: 44, height: 44, borderRadius: 10,
                background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.25)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
            >
              <Server size={20} color="#22d3ee" />
            </div>
            <div>
              <div className="label">Observed Earliest Reliable MTA</div>
              <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>
                {originAssessment.observedSourceIp || 'Unknown IP'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                Estimated Infrastructure: <strong style={{ color: '#22d3ee' }}>{originAssessment.estimatedLocation?.country || 'Unknown'}</strong> · ISP: <strong>{originAssessment.isp || 'Unknown'}</strong> (ASN: {originAssessment.asn || 'N/A'})
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="label">Origin Confidence</div>
              <div style={{ fontSize: 18, fontWeight: 800, color: '#22d3ee' }}>
                {originAssessment.confidence}%
              </div>
            </div>
            <div className="text-right">
              <div className="label">Proxy / VPN Indicator</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: originAssessment.proxyOrVpnIndicator === 'DETECTED' ? '#ef4444' : '#22c55e' }}>
                {originAssessment.proxyOrVpnIndicator}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Left Timeline + Right Hop Inspector */}
      <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(350px, 1.2fr) minmax(300px, 1fr)' }}>
        {/* Left: Relay Timeline */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Reconstructed MTA Hops (Sender → Recipient)</div>
          
          <div className="relative mt-4 flex flex-col gap-4">
            {relayChain.map((hop, idx) => {
              const badge = getTrustBadge(hop.trust);
              const isSelected = selectedHop?.index === hop.index;
              const isEarliest = idx === relayChain.length - 1 || hop.index === originAssessment.earliestReliableHopIndex;

              return (
                <div key={hop.index} className="relative">
                  {/* Timeline connector line */}
                  {idx < relayChain.length - 1 && (
                    <div
                      style={{
                        position: 'absolute',
                        left: 20,
                        top: 44,
                        bottom: -16,
                        width: 2,
                        background: 'linear-gradient(to bottom, rgba(34,211,238,0.4), rgba(34,211,238,0.1))',
                        zIndex: 1,
                      }}
                    />
                  )}

                  {/* Hop Card */}
                  <div
                    onClick={() => setSelectedHopIndex(idx)}
                    className={`panel-elevated transition-all-fast cursor-pointer ${isSelected ? 'glow-cyan' : ''}`}
                    style={{
                      padding: 16,
                      borderLeft: `4px solid ${badge.color}`,
                      background: isSelected ? 'rgba(34,211,238,0.06)' : 'var(--color-surface-2)',
                      borderColor: isSelected ? 'rgba(34,211,238,0.4)' : undefined,
                    }}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        {/* Hop Index Marker */}
                        <div
                          style={{
                            width: 28, height: 28, borderRadius: '50%',
                            background: badge.bg, border: `1px solid ${badge.border}`,
                            color: badge.color, fontWeight: 800, fontSize: 12,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            flexShrink: 0,
                          }}
                        >
                          #{hop.index}
                        </div>

                        <div>
                          <div className="flex items-center gap-2">
                            <span style={{ fontSize: 13, fontWeight: 800, color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>
                              {hop.ip || 'Hostname only'}
                            </span>
                            {hop.isDestination && (
                              <span style={{ fontSize: 9, fontWeight: 700, background: 'rgba(34,211,238,0.2)', color: '#22d3ee', padding: '1px 5px', borderRadius: 3 }}>
                                RECIPIENT MX
                              </span>
                            )}
                            {isEarliest && !hop.isDestination && (
                              <span style={{ fontSize: 9, fontWeight: 700, background: 'rgba(239,68,68,0.2)', color: '#ef4444', padding: '1px 5px', borderRadius: 3 }}>
                                EARLIEST RELIABLE
                              </span>
                            )}
                          </div>

                          <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2, wordBreak: 'break-all' }}>
                            {hop.hostname || '(No hostname banner)'}
                          </div>

                          <div className="flex items-center gap-3 mt-2" style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                            {hop.geo && (
                              <div className="flex items-center gap-1">
                                <MapPin size={11} color="#22d3ee" />
                                <span>{hop.geo.city ? `${hop.geo.city}, ` : ''}{hop.geo.country}</span>
                              </div>
                            )}
                            {hop.timestamp && (
                              <div className="flex items-center gap-1">
                                <Clock size={11} />
                                <span>{new Date(hop.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      <span
                        style={{
                          fontSize: 9, fontWeight: 800,
                          color: badge.color,
                          background: badge.bg,
                          border: `1px solid ${badge.border}`,
                          borderRadius: 4, padding: '2px 6px',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {badge.label}
                      </span>
                    </div>

                    {hop.notes.length > 0 && (
                      <div className="mt-3 pt-2" style={{ borderTop: '1px solid var(--color-border)', fontSize: 11, color: '#fca5a5' }}>
                        {hop.notes.map((n, ni) => (
                          <div key={ni} className="flex items-center gap-1.5">
                            <AlertTriangle size={11} color="#ef4444" />
                            <span>{n}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Hop Inspector Detail Panel */}
        <div className="flex flex-col gap-4">
          <div className="panel" style={{ padding: 20 }}>
            <div className="flex items-center justify-between mb-3">
              <div className="section-title mb-0">Hop #{selectedHop.index} Forensic Details</div>
              <span
                style={{
                  fontSize: 10, fontWeight: 800,
                  ...getTrustBadge(selectedHop.trust),
                  padding: '2px 8px', borderRadius: 4,
                }}
              >
                {selectedHop.trust}
              </span>
            </div>

            <div className="flex flex-col gap-3">
              <div>
                <div className="label">IP Address</div>
                <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#22d3ee', marginTop: 2 }}>
                  {selectedHop.ip || 'None (Internal / Hostname Resolution Only)'}
                </div>
              </div>

              <div>
                <div className="label">MTA Hostname (Reported in Header)</div>
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', marginTop: 2, wordBreak: 'break-all' }}>
                  {selectedHop.hostname || 'None'}
                </div>
              </div>

              <div>
                <div className="label">Geographic Location</div>
                <div style={{ fontSize: 13, color: 'var(--color-text)', marginTop: 2 }}>
                  {selectedHop.geo ? `${selectedHop.geo.city || 'Unknown City'}, ${selectedHop.geo.country} (${selectedHop.geo.countryCode})` : 'Geocoding unavailable'}
                </div>
                {selectedHop.geo && (
                  <div style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                    Lat: {selectedHop.geo.latitude.toFixed(4)}, Lon: {selectedHop.geo.longitude.toFixed(4)}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="label">ISP / Carrier</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text)', marginTop: 2 }}>
                    {selectedHop.isp || 'Unknown'}
                  </div>
                </div>
                <div>
                  <div className="label">Autonomous System</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text)', marginTop: 2 }}>
                    {selectedHop.asn || 'N/A'}
                  </div>
                </div>
              </div>

              <div>
                <div className="label">Hop Timestamp</div>
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', marginTop: 2 }}>
                  {selectedHop.timestamp || 'Not explicitly timestamped'}
                </div>
              </div>

              <div>
                <div className="label">Hop Resolution Confidence</div>
                <div className="flex items-center gap-3 mt-1">
                  <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${selectedHop.confidence}%`, height: '100%', background: '#22d3ee', borderRadius: 3 }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#22d3ee' }}>{selectedHop.confidence}%</span>
                </div>
              </div>

              <div>
                <div className="label">Raw Received Header Segment</div>
                <div className="code-block mt-2" style={{ fontSize: 10, maxHeight: 150, overflowY: 'auto' }}>
                  {selectedHop.raw}
                </div>
              </div>
            </div>
          </div>

          <div
            className="p-3 rounded-lg flex items-start gap-2.5"
            style={{ background: 'rgba(34,211,238,0.04)', border: '1px solid var(--color-border)', fontSize: 11, color: 'var(--color-text-muted)' }}
          >
            <Info size={13} color="#22d3ee" style={{ marginTop: 2, flexShrink: 0 }} />
            <div>
              <strong>Relay Security Standard:</strong> Intermediate hops outside trusted corporate boundary MTAs can be forged by attackers. The earliest reliable hop is determined after validating against the recipient MX ingress boundary.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
