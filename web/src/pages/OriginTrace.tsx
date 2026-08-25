import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  MapPin, Globe, Shield, AlertTriangle, Info,
  Navigation, Server, ExternalLink, RefreshCw, ChevronRight,
  Radio, Cpu
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
import { InteractiveGlobe3D } from '@/components/3d/InteractiveGlobe3D';
import type { RelayHop } from '@/types';

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
      <div className="p-8 max-w-2xl mx-auto my-12 text-center animate-fade-in">
        <div className="panel p-10 border-cyan-500/20 bg-[#080e21]">
          <Globe size={48} className="text-cyan-400 mx-auto mb-4 animate-pulse" />
          <h2 className="text-lg font-bold text-slate-100 mb-2">No Active Geolocation Trace</h2>
          <p className="text-xs text-slate-400 mb-6 leading-relaxed">
            Ingest an email with Received transport headers to project the relay route across global datacenter infrastructure.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary text-xs">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost text-xs border-amber-500/40 text-amber-400">
              {analyzingDemo ? 'Analyzing...' : '⚡ Load Multi-Country Demo'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const { originAssessment, relayChain } = analysis;
  const hopsWithGeo = relayChain.filter((h) => h.geo !== null);

  const globeLocations = hopsWithGeo.map((h) => ({
    ip: h.ip || 'Unknown',
    country: h.geo?.country || 'Unknown',
    city: h.geo?.city || '',
    lat: h.geo?.latitude || 0,
    lng: h.geo?.longitude || 0,
    isp: h.isp || '',
    isThreat: h.trust === 'SUSPICIOUS',
  }));

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <MapPin size={22} className="text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">
              Origin Infrastructure & Geolocation Trace
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Observed MTA Relay Coordinates, Autonomous System Numbers (ASN), and Datacenter Hosting Providers
          </p>
        </div>

        <button
          onClick={() => navigate('/threat-intel')}
          className="btn-primary text-xs flex items-center gap-2"
        >
          <Shield size={14} />
          <span>Domain & Threat Intel</span>
          <ChevronRight size={14} />
        </button>
      </div>

      {/* Main 3D Globe + Origin Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 3D Interactive Cyber Globe (2 cols) */}
        <div className="lg:col-span-2 panel p-0 overflow-hidden border-cyan-500/25 relative flex flex-col">
          <div className="px-5 py-3 border-b border-cyan-500/15 bg-[#050a18] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                3D INFRASTRUCTURE ROUTING GLOBE
              </span>
            </div>
            <span className="text-[10px] font-mono text-cyan-400">
              Drag to rotate // Great-Circle Arcs
            </span>
          </div>

          <div className="flex-1 min-h-[420px]">
            <InteractiveGlobe3D locations={globeLocations} />
          </div>
        </div>

        {/* Probable Source Infrastructure Card (1 col) */}
        <div className="panel p-5 border-cyan-500/25 bg-[#080e21] flex flex-col justify-between space-y-4">
          <div>
            <div className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider mb-2">
              PROBABLE SOURCE INFRASTRUCTURE
            </div>
            <div className="text-lg font-bold text-white mb-1">
              {originAssessment.hostingType} HOSTING
            </div>
            <div className="text-xs font-mono text-cyan-300">
              Confidence: {originAssessment.confidence}%
            </div>

            <div className="mt-4 p-3 rounded-lg bg-[#050a18] border border-cyan-500/15 text-xs text-slate-300 leading-relaxed">
              {originAssessment.caveats[0] || 'Infrastructure verified through envelope Received: hops and reverse DNS.'}
            </div>
          </div>

          {/* ASN & Datacenter Meta */}
          <div className="space-y-2 border-t border-cyan-500/15 pt-4 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-500">COUNTRY:</span>
              <span className="text-slate-200 font-semibold">{originAssessment.estimatedLocation?.country || 'Unknown'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">OBSERVED IP:</span>
              <span className="text-cyan-300 font-semibold">{originAssessment.observedSourceIp || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ASN / ISP:</span>
              <span className="text-slate-200 truncate max-w-[140px]">{originAssessment.asn || originAssessment.isp || 'Unavailable'}</span>
            </div>
          </div>

          {/* Honest Attribution Disclaimer */}
          <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/20 text-[11px] text-slate-400">
            <div className="flex items-center gap-1.5 text-cyan-300 font-bold text-[10px] uppercase mb-1">
              <Info size={12} />
              <span>FORENSIC ATTRIBUTION NOTICE</span>
            </div>
            Coordinates describe observed mail transfer agents and proxy relays. Physical human attribution requires ISP warrant logs.
          </div>
        </div>
      </div>

      {/* Hop By Hop Relay Jurisdiction Table */}
      <div className="panel overflow-hidden border-cyan-500/20">
        <div className="px-5 py-3.5 border-b border-cyan-500/15 bg-[#050a18] flex items-center justify-between">
          <span className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
            MTA RELAY INFRASTRUCTURE HOPS ({relayChain.length})
          </span>
          <span className="text-[10px] font-mono text-cyan-400">
            Chronological Transmission Sequence
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>HOP</th>
                <th>MTA HOSTNAME</th>
                <th>OBSERVED IP</th>
                <th>GEOLOCATION</th>
                <th>ASN / PROVIDER</th>
                <th>TRUST STATUS</th>
              </tr>
            </thead>
            <tbody>
              {relayChain.map((hop, idx) => (
                <tr key={idx}>
                  <td>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300">
                      HOP {idx + 1}
                    </span>
                  </td>
                  <td className="font-mono text-xs text-slate-200">{hop.hostname || 'Unknown MTA'}</td>
                  <td className="font-mono text-xs text-cyan-300">{hop.ip || 'Internal'}</td>
                  <td className="text-xs text-slate-300">
                    {hop.geo?.country ? `${hop.geo.city ? hop.geo.city + ', ' : ''}${hop.geo.country}` : 'Internal / Private'}
                  </td>
                  <td className="font-mono text-xs text-slate-400">{hop.isp || hop.asn || 'Private Relay'}</td>
                  <td>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        hop.trust === 'SUSPICIOUS'
                          ? 'badge-critical'
                          : hop.trust === 'TRUSTED'
                          ? 'badge-low'
                          : 'badge-medium'
                      }`}
                    >
                      {hop.trust}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
