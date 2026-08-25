import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  MapPin, Globe, Shield, AlertTriangle, Info,
  Navigation, Server, ExternalLink, RefreshCw, ChevronRight
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
import type { RelayHop } from '@/types';

// Simple Geo to SVG Coordinate Projection for World View (Equirectangular)
function project(lat: number, lon: number, width: number, height: number): [number, number] {
  const x = ((lon + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return [x, y];
}

export function OriginTrace() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const [analyzingDemo, setAnalyzingDemo] = useState(false);
  const [selectedHop, setSelectedHop] = useState<RelayHop | null>(null);

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Origin Trace Demo Load',
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
          <Globe size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No Geolocation Trace Available</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            Analyze an email with network hops to project the relay route across global jurisdictions.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load Multi-Country Demo Email'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const { originAssessment, relayChain } = analysis;
  const hopsWithGeo = relayChain.filter(h => h.geo !== null);

  const mapWidth = 900;
  const mapHeight = 450;

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <MapPin size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Geographic Route & Origin Trace
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Estimated infrastructure location, intermediate server traversal, and network anonymity indicators
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/threat-intel')} className="btn-primary flex items-center gap-2 text-xs">
            <Shield size={14} />
            <span>Domain & IP Intelligence</span>
            <ChevronRight size={14} />
          </button>
        </div>
      </div>

      {/* Main Map + Side Panel Grid */}
      <div className="grid gap-6 mb-6" style={{ gridTemplateColumns: 'minmax(400px, 1.7fr) minmax(320px, 1fr)' }}>
        {/* World Map SVG Canvas */}
        <div className="panel" style={{ padding: 20, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div className="flex items-center justify-between mb-3">
            <div className="section-title mb-0">Global Relay Traversal Path</div>
            <div className="flex items-center gap-2">
              <span className="status-dot online" />
              <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{hopsWithGeo.length} Geocoded MTAs</span>
            </div>
          </div>

          <div
            style={{
              position: 'relative',
              width: '100%',
              background: '#030712',
              borderRadius: 8,
              border: '1px solid var(--color-border)',
              padding: 8,
              overflow: 'hidden',
            }}
          >
            <svg
              viewBox={`0 0 ${mapWidth} ${mapHeight}`}
              style={{ width: '100%', height: 'auto', display: 'block' }}
            >
              {/* Graticule Grid */}
              <defs>
                <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
                  <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(34, 211, 238, 0.05)" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect width={mapWidth} height={mapHeight} fill="url(#grid)" />

              {/* Continents Outline approximation */}
              <path
                d="M 120 100 Q 180 80 250 110 T 320 180 T 260 300 T 210 380 Q 180 280 150 200 Z
                   M 420 80 Q 550 50 620 90 T 780 140 T 700 280 T 580 220 T 480 160 Z
                   M 480 200 Q 560 210 570 290 T 520 380 T 450 300 Z
                   M 720 300 Q 820 280 840 360 T 750 400 Z"
                fill="#0a1224"
                stroke="rgba(34, 211, 238, 0.12)"
                strokeWidth="1"
              />

              {/* Connecting Relay Path Curve */}
              {hopsWithGeo.length > 1 && (
                <path
                  d={hopsWithGeo.map((h, i) => {
                    const [x, y] = project(h.geo!.latitude, h.geo!.longitude, mapWidth, mapHeight);
                    return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
                  }).join(' ')}
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="2"
                  strokeDasharray="4 3"
                  style={{ filter: 'drop-shadow(0 0 4px #22d3ee)' }}
                />
              )}

              {/* Hop Markers */}
              {hopsWithGeo.map((hop, idx) => {
                const [x, y] = project(hop.geo!.latitude, hop.geo!.longitude, mapWidth, mapHeight);
                const isOrigin = idx === hopsWithGeo.length - 1;
                const isSelected = selectedHop?.index === hop.index;
                const color = isOrigin ? '#ef4444' : idx === 0 ? '#22c55e' : '#f59e0b';

                return (
                  <g
                    key={hop.index}
                    transform={`translate(${x}, ${y})`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedHop(hop)}
                  >
                    {/* Animated Pulse for Origin */}
                    {isOrigin && (
                      <circle r="16" fill="none" stroke="#ef4444" strokeWidth="1.5" opacity="0.6">
                        <animate attributeName="r" values="8;20" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.8;0" dur="2s" repeatCount="indefinite" />
                      </circle>
                    )}

                    <circle
                      r={isSelected ? 9 : 6}
                      fill={color}
                      stroke="#030712"
                      strokeWidth="2"
                      style={{ filter: `drop-shadow(0 0 6px ${color})` }}
                    />

                    {/* Label */}
                    <text
                      x={0}
                      y={-12}
                      textAnchor="middle"
                      fill="#e2e8f0"
                      fontSize="10"
                      fontWeight="700"
                      fontFamily="var(--font-mono)"
                      style={{ filter: 'drop-shadow(0 1px 2px #000)' }}
                    >
                      {hop.geo?.country} ({isOrigin ? 'ORIGIN' : `#${hop.index}`})
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Quick Route Summary */}
          <div className="flex items-center gap-2 mt-4 overflow-x-auto pb-2">
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
              TRAVERSAL ROUTE:
            </span>
            {hopsWithGeo.map((h, i) => (
              <React.Fragment key={h.index}>
                <span
                  onClick={() => setSelectedHop(h)}
                  className="cursor-pointer"
                  style={{
                    fontSize: 11, fontWeight: 600,
                    color: h.index === originAssessment.earliestReliableHopIndex ? '#ef4444' : '#22d3ee',
                    background: selectedHop?.index === h.index ? 'rgba(34,211,238,0.2)' : 'rgba(255,255,255,0.05)',
                    padding: '2px 8px', borderRadius: 4, whiteSpace: 'nowrap',
                  }}
                >
                  {h.geo?.country}
                </span>
                {i < hopsWithGeo.length - 1 && (
                  <span style={{ color: 'var(--color-text-muted)' }}>→</span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Right: Origin Intelligence Assessment Panel */}
        <div className="panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div className="section-title">Origin Attribution Analysis</div>

            <div className="flex flex-col gap-3">
              <div>
                <div className="label">Earliest Reliable Node</div>
                <div style={{ fontSize: 15, fontFamily: 'var(--font-mono)', fontWeight: 800, color: '#ef4444', marginTop: 2 }}>
                  {originAssessment.observedSourceIp || 'Unknown IP'}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="label">Estimated Location</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)', marginTop: 2 }}>
                    {originAssessment.estimatedLocation ? `${originAssessment.estimatedLocation.city || ''} ${originAssessment.estimatedLocation.country}` : 'Unknown'}
                  </div>
                </div>
                <div>
                  <div className="label">Attribution Confidence</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: '#22d3ee', marginTop: 2 }}>
                    {originAssessment.confidence}%
                  </div>
                </div>
              </div>

              <div>
                <div className="label">ISP & Hosting Provider</div>
                <div style={{ fontSize: 13, color: 'var(--color-text)', marginTop: 2 }}>
                  {originAssessment.isp || 'Hosting provider not identified'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 1 }}>
                  ASN: {originAssessment.asn || 'N/A'} · Hosting Type: {originAssessment.hostingType}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2" style={{ borderTop: '1px solid var(--color-border)' }}>
                <div>
                  <div className="label">Proxy / VPN Indicator</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: originAssessment.proxyOrVpnIndicator === 'DETECTED' ? '#ef4444' : '#22c55e', marginTop: 2 }}>
                    {originAssessment.proxyOrVpnIndicator}
                  </div>
                </div>
                <div>
                  <div className="label">TOR Exit Node</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: originAssessment.torIndicator === 'DETECTED' ? '#ef4444' : '#22c55e', marginTop: 2 }}>
                    {originAssessment.torIndicator}
                  </div>
                </div>
              </div>

              {/* Caveats & Legal Framing */}
              <div className="mt-3">
                <div className="label mb-1">Investigative Caveats</div>
                <div className="flex flex-col gap-1.5">
                  {originAssessment.caveats.map((c, i) => (
                    <div key={i} className="flex items-start gap-1.5" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                      <span style={{ color: '#f59e0b', flexShrink: 0 }}>•</span>
                      <span>{c}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Legal disclaimer */}
          <div
            className="p-3 rounded-lg flex items-start gap-2.5 mt-4"
            style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', fontSize: 11, color: '#fde68a' }}
          >
            <AlertTriangle size={14} color="#f59e0b" style={{ marginTop: 2, flexShrink: 0 }} />
            <div>
              <strong>Forensic Standard Disclaimer:</strong> Geolocation estimates designate observed network infrastructure, not the physical location of the human perpetrator. Used as attribution leads and corroborative forensic evidence.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
