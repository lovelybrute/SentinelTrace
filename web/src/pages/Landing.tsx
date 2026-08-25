import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  FileSearch,
  Zap,
  Globe,
  GitBranch,
  Network,
  Layers,
  FileText,
  Lock,
  ArrowRight,
  CheckCircle,
  AlertTriangle,
  Upload,
  Cpu,
  Terminal,
  Activity,
} from 'lucide-react';
import { HeroNetwork3D } from '@/components/3d/HeroNetwork3D';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useAnalysis } from '@/context/AnalysisContext';

export function Landing() {
  const navigate = useNavigate();
  const { setCurrentAnalysis, addToHistory } = useAnalysis();
  const [isIngestingDemo, setIsIngestingDemo] = useState(false);

  const handleLaunchDemo = async () => {
    setIsIngestingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: 'HERO_DEMO',
        acquisitionSource: 'Hero Landing Page Ingest',
        useBackend: true,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
      navigate('/analyzer');
    } catch (e) {
      console.error(e);
      navigate('/analyzer');
    } finally {
      setIsIngestingDemo(false);
    }
  };

  return (
    <div className="relative min-h-screen bg-[#020617] text-slate-100 overflow-x-hidden selection:bg-cyan-500 selection:text-black">
      {/* Top Cyber Navigation Bar */}
      <header className="fixed top-0 inset-x-0 z-40 h-16 px-6 sm:px-12 flex items-center justify-between border-b border-cyan-500/15 bg-[#020617]/80 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-sky-400 p-0.5 shadow-[0_0_15px_rgba(34,211,238,0.5)]">
            <div className="w-full h-full bg-[#020617] rounded-[6px] flex items-center justify-center">
              <Shield size={16} className="text-cyan-400" />
            </div>
          </div>
          <div>
            <span className="font-mono font-bold text-sm tracking-wider text-slate-100">
              SENTINELTRACE
            </span>
            <span className="text-[10px] font-mono text-cyan-400 ml-2 border border-cyan-500/30 px-1.5 py-0.2 rounded bg-cyan-950/40">
              SIH 26106
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-xs font-mono font-medium text-slate-300 hover:text-cyan-300 transition-colors hidden sm:block"
          >
            SOC DASHBOARD
          </button>
          <button
            onClick={() => navigate('/analyzer')}
            className="btn-primary text-xs"
          >
            <span>ANALYZE EMAIL</span>
            <ArrowRight size={13} />
          </button>
        </div>
      </header>

      {/* ── SECTION 1: HERO & 3D CYBER NETWORK ── */}
      <section className="relative pt-32 pb-20 px-6 sm:px-12 min-h-[92vh] flex flex-col justify-center items-center text-center">
        {/* Glow backdrop */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[700px] h-[450px] bg-gradient-to-tr from-cyan-600/15 to-blue-600/10 blur-[130px] rounded-full pointer-events-none" />

        <div className="max-w-4xl z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 font-mono text-xs mb-6 shadow-[0_0_20px_rgba(34,211,238,0.2)]">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span>AI-POWERED DIGITAL FORENSICS & THREAT INTELLIGENCE</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight">
            THE FUTURE OF <br />
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 bg-clip-text text-transparent drop-shadow-[0_0_35px_rgba(34,211,238,0.4)]">
              EMAIL FORENSICS
            </span>
          </h1>

          <p className="text-base sm:text-lg text-slate-300 max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
            Drop an email. SentinelTrace investigates it. Reconstruct multi-hop MTA relay chains, verify RFC 7208/6376/7489 cryptographic authentications, and correlate threat actor infrastructure in real time.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={() => navigate('/analyzer')}
              className="btn-primary px-7 py-3 text-sm flex items-center gap-2 shadow-[0_0_25px_rgba(6,182,212,0.4)]"
            >
              <FileSearch size={16} />
              <span>ANALYZE EMAIL (.EML)</span>
            </button>
            <button
              onClick={handleLaunchDemo}
              disabled={isIngestingDemo}
              className="btn-ghost px-6 py-3 text-sm flex items-center gap-2 border-cyan-500/40 text-cyan-300 hover:bg-cyan-950/40"
            >
              <Zap size={16} className="text-amber-400" />
              <span>{isIngestingDemo ? 'INGESTING DEMO...' : 'LOAD LIVE ATTACK DEMO'}</span>
            </button>
            <button
              onClick={() => navigate('/dashboard')}
              className="btn-ghost px-6 py-3 text-sm flex items-center gap-2"
            >
              <Shield size={16} />
              <span>OPEN SOC DASHBOARD</span>
            </button>
          </div>
        </div>

        {/* 3D Cyber Network Canvas */}
        <div className="w-full max-w-5xl h-[480px] mt-12 z-10 rounded-2xl border border-cyan-500/20 bg-[#080e21]/40 backdrop-blur-md shadow-[0_0_50px_rgba(0,0,0,0.8)] overflow-hidden">
          <HeroNetwork3D onSelectNode={(label) => console.log('Node selected:', label)} />
        </div>
      </section>

      {/* ── SECTION 2: "EMAIL IS THE ATTACK SURFACE" ── */}
      <section className="py-24 px-6 sm:px-12 border-t border-cyan-500/10 bg-[#050a18]/60 relative">
        <div className="max-w-5xl mx-auto">
          <div className="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-2">
            PHASE 01 // VULNERABILITY MATRIX
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-6">
            "EMAIL IS THE ATTACK SURFACE."
          </h2>
          <p className="text-slate-400 max-w-2xl mb-12">
            91% of modern cyber attacks originate with deceptive email communications. Attackers exploit trust through typosquatting, invoice fraud, and spoofed headers.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            <div className="panel p-6 border-cyan-500/20 bg-[#080e21]/80">
              <AlertTriangle size={24} className="text-red-400 mb-4" />
              <h3 className="font-bold text-slate-100 mb-2">Executive Impersonation</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Deceptive display names masking divergent Reply-To addresses to initiate unauthorized wire transfers.
              </p>
            </div>
            <div className="panel p-6 border-cyan-500/20 bg-[#080e21]/80">
              <Network size={24} className="text-amber-400 mb-4" />
              <h3 className="font-bold text-slate-100 mb-2">Lookalike Typosquatting</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Character substitutions and homoglyph punycode domains (e.g. <code>paypa1-security.com</code>) evading basic heuristics.
              </p>
            </div>
            <div className="panel p-6 border-cyan-500/20 bg-[#080e21]/80">
              <Zap size={24} className="text-cyan-400 mb-4" />
              <h3 className="font-bold text-slate-100 mb-2">Multi-Hop Obfuscation</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Routing traffic through multiple open relays and compromised cloud VPS nodes to disguise origin infrastructure.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── SECTION 3: "BUT THE HEADER TELLS THE STORY" ── */}
      <section className="py-24 px-6 sm:px-12 border-t border-cyan-500/10 bg-[#020617] relative">
        <div className="max-w-5xl mx-auto">
          <div className="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-2">
            PHASE 02 // CRYPTOGRAPHIC VERIFICATION
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-6">
            "BUT THE HEADER TELLS THE STORY."
          </h2>
          <p className="text-slate-400 max-w-2xl mb-12">
            SentinelTrace performs rigorous RFC protocol decomposition to expose cryptographic mismatches and identity divergence.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            <div className="panel p-6 border-cyan-500/25 bg-[#080e21]">
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-xs font-bold text-cyan-400">RFC 7208</span>
                <span className="badge-pass text-[10px] px-2 py-0.5 rounded font-mono font-bold">SPF ENGINE</span>
              </div>
              <p className="text-xs text-slate-400">
                Traverses <code>ip4</code>, <code>ip6</code>, <code>include</code>, and <code>redirect</code> mechanisms against transmitting MTA IP boundaries.
              </p>
            </div>

            <div className="panel p-6 border-cyan-500/25 bg-[#080e21]">
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-xs font-bold text-cyan-400">RFC 6376</span>
                <span className="badge-pass text-[10px] px-2 py-0.5 rounded font-mono font-bold">DKIM VERIFIER</span>
              </div>
              <p className="text-xs text-slate-400">
                Queries DNS selector keys (<code>s._domainkey.d</code>) and validates body hash (<code>bh=</code>) and RSA signatures.
              </p>
            </div>

            <div className="panel p-6 border-cyan-500/25 bg-[#080e21]">
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-xs font-bold text-cyan-400">RFC 7489</span>
                <span className="badge-pass text-[10px] px-2 py-0.5 rounded font-mono font-bold">DMARC POLICY</span>
              </div>
              <p className="text-xs text-slate-400">
                Enforces strict/relaxed identifier alignment between RFC 5322 From, SPF, and DKIM domains.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── SECTION 4: "FOLLOW THE RELAYS" ── */}
      <section className="py-24 px-6 sm:px-12 border-t border-cyan-500/10 bg-[#050a18]/60 relative">
        <div className="max-w-5xl mx-auto">
          <div className="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-2">
            PHASE 03 // TRANSMISSION TIMELINE
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-6">
            "FOLLOW THE RELAYS."
          </h2>
          <p className="text-slate-400 max-w-2xl mb-10">
            Reconstructing envelope Received: stamps into reverse chronological transmission hops to isolate the earliest reliable external gateway.
          </p>

          <div className="panel p-6 border-cyan-500/30 bg-[#080e21]/90">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 w-full sm:w-1/3">
                <div className="font-bold text-[10px] uppercase text-red-400">HOP 1 // SENDER MTA</div>
                <div className="mt-1">185.220.101.5</div>
                <div className="text-[10px] text-slate-400">vps-node8.cloud-hosting.de</div>
              </div>

              <div className="text-cyan-400">➔</div>

              <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 w-full sm:w-1/3">
                <div className="font-bold text-[10px] uppercase text-cyan-400">HOP 2 // EXTERNAL GATEWAY</div>
                <div className="mt-1">209.85.128.41</div>
                <div className="text-[10px] text-slate-400">mail-wm1-f41.google.com</div>
              </div>

              <div className="text-cyan-400">➔</div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 w-full sm:w-1/3">
                <div className="font-bold text-[10px] uppercase text-slate-400">HOP 3 // DESTINATION MX</div>
                <div className="mt-1">10.0.0.1 (INTERNAL)</div>
                <div className="text-[10px] text-slate-400">mx.victimcorp.com</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── SECTION 5: "CONNECT THE CAMPAIGN" ── */}
      <section className="py-24 px-6 sm:px-12 border-t border-cyan-500/10 bg-[#020617] relative">
        <div className="max-w-5xl mx-auto">
          <div className="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-2">
            PHASE 04 // THREAT CLUSTERING
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-6">
            "CONNECT THE CAMPAIGN."
          </h2>
          <p className="text-slate-400 max-w-2xl mb-10">
            Jaccard similarity correlation over shared subnets, registrant nameservers, and payload hashes links isolated emails into active threat campaigns.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="panel p-6 border-cyan-500/25 bg-[#080e21]">
              <h3 className="font-bold text-slate-100 mb-2 flex items-center gap-2">
                <Layers size={18} className="text-purple-400" />
                <span>Campaign #ST-2026-FIN</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Correlated 12 financial phishing emails across 3 victim organizations sharing identical hosting ASN (AS60729) and credential harvesting paths.
              </p>
              <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">12 Emails</span>
                <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">4 Lookalike Domains</span>
                <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">7 Shared IOCs</span>
              </div>
            </div>

            <div className="panel p-6 border-cyan-500/25 bg-[#080e21]">
              <h3 className="font-bold text-slate-100 mb-2 flex items-center gap-2">
                <Shield size={18} className="text-cyan-400" />
                <span>MITRE ATT&CK & STIX 2.1 Export</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Automated mapping to T1566, T1566.001, T1566.002, and T1598 with instant OASIS STIX 2.1 JSON bundle export for SIEM/SOAR integration.
              </p>
              <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">T1566 (Phishing)</span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">STIX 2.1 Bundle</span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">Chain of Custody</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── SECTION 6: "INVESTIGATE WITH SENTINELTRACE" ── */}
      <section className="py-24 px-6 sm:px-12 border-t border-cyan-500/10 bg-[#050a18] text-center relative">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white mb-6">
            INVESTIGATE WITH SENTINELTRACE
          </h2>
          <p className="text-slate-400 mb-10 text-sm sm:text-base">
            Start investigating live phishing, BEC, invoice fraud, and malware delivery emails in the dedicated cyber forensic laboratory.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={() => navigate('/analyzer')}
              className="btn-primary px-8 py-3.5 text-sm flex items-center gap-2 shadow-[0_0_30px_rgba(6,182,212,0.5)]"
            >
              <FileSearch size={16} />
              <span>START FORENSIC ANALYSIS</span>
              <ArrowRight size={16} />
            </button>
            <button
              onClick={() => navigate('/dashboard')}
              className="btn-ghost px-8 py-3.5 text-sm flex items-center gap-2"
            >
              <Shield size={16} />
              <span>OPEN SOC DASHBOARD</span>
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 sm:px-12 border-t border-cyan-500/15 bg-[#020617] text-slate-500 font-mono text-xs flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>SENTINELTRACE — Smart India Hackathon (SIH 26106)</div>
        <div>All India Council for Technical Education (AICTE) Cyber Security Cell</div>
      </footer>
    </div>
  );
}
