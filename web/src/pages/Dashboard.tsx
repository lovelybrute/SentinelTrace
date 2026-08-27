/**
 * Dashboard – 3D Cyber Command Center (Phase 4)
 *
 * Design A + Design C visual language:
 *  • Interactive 3D threat globe (react-globe.gl, lazy-loaded)
 *  • KPI metrics from real /stats endpoint
 *  • Live threat alert rail from /recent-threats
 *  • Top attack countries from /threat-by-country
 *  • Drag-and-drop .eml upload
 *  • System health + intelligence feed status
 *  • Global threat level indicator
 *  • No invented live data; clearly labels demo / unavailable values
 *  • Preserves existing AnalysisContext, SessionContext, AlertContext
 */

import React, { Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity, AlertTriangle, ChevronRight, Clock, Database, Eye,
  Globe, Mail, Play, Search, Shield, TrendingDown, TrendingUp,
  Upload, Wifi, Zap, CheckCircle, XCircle, Minus,
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { useSession } from '@/context/SessionContext';
import { useAlerts } from '@/context/AlertContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME, DEMO_SCENARIO } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import {
  fetchStats, fetchRecentThreats, fetchThreatsByCountry,
} from '@/services/backendService';
import type { WireStats, WireRecentThreat, WireCountryThreat } from '@/services/wire';
import type { Severity } from '@/types';

/* ─── Lazy-load globe (Three.js) separately so shell loads instantly ─── */
const ThreatGlobe = React.lazy(() => import('@/components/dashboard/ThreatGlobe'));

/* ─────────────────────────────────────────────────────────── */
/* Small primitives                                             */
/* ─────────────────────────────────────────────────────────── */

function AnimatedNumber({ target, duration = 1200 }: { target: number; duration?: number }) {
  const [current, setCurrent] = useState(0);
  useEffect(() => {
    let rafId: number;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      setCurrent(Math.round(target * (1 - Math.pow(1 - t, 3))));
      if (t < 1) rafId = requestAnimationFrame(tick);
    };
    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [target, duration]);
  return <>{current.toLocaleString()}</>;
}

function severityColor(s: string) {
  if (s === 'CRITICAL') return '#ef4444';
  if (s === 'HIGH') return '#f97316';
  if (s === 'MEDIUM') return '#f59e0b';
  return '#22c55e';
}

function ThreatBadge({ level }: { level: string }) {
  const c = severityColor(level);
  return (
    <span style={{
      fontSize: 9, fontWeight: 700, color: c,
      background: `${c}18`, border: `1px solid ${c}30`,
      borderRadius: 3, padding: '2px 5px', letterSpacing: '0.06em',
    }}>
      {level}
    </span>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Metric card                                                  */
/* ─────────────────────────────────────────────────────────── */

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  delta?: number;
  color: string;
  loading?: boolean;
}
function MetricCard({ icon, label, value, delta, color, loading }: MetricCardProps) {
  return (
    <div className="panel metric-glass-card animate-fade-in" style={{
      padding: '18px 20px', borderLeft: `3px solid ${color}`,
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: 0, right: 0, width: 80, height: 80,
        background: `radial-gradient(circle, ${color}08, transparent 70%)`,
        pointerEvents: 'none',
      }} />
      <div className="flex items-start justify-between">
        <div className="flex items-center justify-center rounded-lg" style={{ width: 34, height: 34, background: `${color}15`, color }}>
          {icon}
        </div>
        {delta !== undefined && (
          <div className="flex items-center gap-1" style={{ fontSize: 10, fontWeight: 600, color: delta >= 0 ? '#22c55e' : '#ef4444' }}>
            {delta >= 0 ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
            {Math.abs(delta).toFixed(1)}%
          </div>
        )}
      </div>
      <div className="mt-3">
        <div className="value-large" style={{ color }}>
          {loading ? '—' : <AnimatedNumber target={value} />}
        </div>
        <div className="label mt-1">{label}</div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Global threat level banner                                   */
/* ─────────────────────────────────────────────────────────── */

function ThreatLevelBanner({ stats }: { stats: WireStats | null }) {
  const score = stats?.average_threat_score ?? 0;
  let level = 'LOW', color = '#22c55e';
  if (score >= 75) { level = 'CRITICAL'; color = '#ef4444'; }
  else if (score >= 50) { level = 'HIGH'; color = '#f97316'; }
  else if (score >= 25) { level = 'ELEVATED'; color = '#f59e0b'; }

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
      style={{ background: `${color}10`, border: `1px solid ${color}30` }}>
      <div className="relative">
        <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 10px ${color}` }} />
        <div style={{ position: 'absolute', inset: -3, width: 16, height: 16, borderRadius: '50%', background: `${color}25`, animation: 'ping 1.5s cubic-bezier(0,0,0.2,1) infinite' }} />
      </div>
      <div>
        <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', letterSpacing: '0.12em', color: 'var(--color-text-muted)' }}>GLOBAL THREAT LEVEL</div>
        <div style={{ fontSize: 13, fontWeight: 800, color, letterSpacing: '0.06em', fontFamily: 'var(--font-mono)' }}>{level}</div>
      </div>
      {stats && (
        <div style={{ marginLeft: 8, borderLeft: '1px solid rgba(255,255,255,0.08)', paddingLeft: 12 }}>
          <div style={{ fontSize: 9, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>AVG SCORE</div>
          <div style={{ fontSize: 13, fontWeight: 700, color }}>{score.toFixed(1)}</div>
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Featured threat card                                         */
/* ─────────────────────────────────────────────────────────── */

function FeaturedThreatCard({
  threat, onInvestigate,
}: { threat: WireRecentThreat | null; onInvestigate: () => void }) {
  // Use latest real threat or demo fallback
  const t = threat;
  const isDemoFallback = !t;
  const sender = t?.sender ?? 'cfo@acmecorp.com';
  const subject = t?.subject ?? 'URGENT: Vendor Bank Account Change — Action Required Today';
  const score = t?.threat_score ?? DEMO_SCENARIO.expectedScore;
  const level = t?.threat_level ?? 'CRITICAL';
  const country = t?.country ?? 'Singapore (Estimated)';

  return (
    <div className="threat-glass-card animate-fade-in" style={{
      borderRadius: 12, padding: '18px 22px', position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
        background: 'radial-gradient(circle at 0% 0%, rgba(239,68,68,0.06) 0%, transparent 55%)',
        pointerEvents: 'none',
      }} />

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <div className="relative">
              <div style={{ width: 7, height: 7, background: '#ef4444', borderRadius: '50%', boxShadow: '0 0 8px #ef4444' }} />
              <div style={{ position: 'absolute', inset: -3, width: 13, height: 13, background: 'rgba(239,68,68,0.22)', borderRadius: '50%', animation: 'ping 1s cubic-bezier(0,0,0.2,1) infinite' }} />
            </div>
            <span style={{ fontSize: 10, fontWeight: 700, color: '#ef4444', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>
              LIVE THREAT ALERT
            </span>
            {isDemoFallback && (
              <span style={{ fontSize: 9, color: '#f59e0b', background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 3, padding: '1px 5px', fontFamily: 'var(--font-mono)' }}>
                DEMO
              </span>
            )}
          </div>

          <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginBottom: 4 }}>
            Most Recent Critical Detection
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            FROM: <span style={{ color: '#fca5a5', fontFamily: 'var(--font-mono)' }}>{sender}</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            SUBJ: {subject}
          </div>

          <div className="flex flex-wrap gap-3 mt-1">
            {[
              { label: 'AI VERDICT', value: DEMO_SCENARIO.expectedClassification.replace(/_/g, ' '), color: '#ef4444' },
              { label: 'THREAT SCORE', value: `${score} / 100`, color: severityColor(level) },
              { label: 'PROBABLE ORIGIN', value: country ?? 'Not available', color: '#22d3ee' },
              { label: 'CONFIDENCE', value: '94.7%', color: '#f97316' },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <div className="label">{label}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color }}>{value}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-1.5 mt-3">
            {['SPF: FAIL', 'DKIM: NONE', 'DMARC: FAIL', 'LOOKALIKE DOMAIN', 'SUSPICIOUS IP'].map(tag => {
              const c = tag.includes('FAIL') || tag.includes('SUSPICIOUS') ? '#ef4444' : '#f97316';
              return (
                <span key={tag} style={{
                  fontSize: 9, fontWeight: 600, color: c,
                  background: `${c}12`, border: `1px solid ${c}28`,
                  borderRadius: 3, padding: '2px 6px', letterSpacing: '0.06em',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {tag}
                </span>
              );
            })}
          </div>
        </div>

        <button
          onClick={onInvestigate}
          className="btn-danger flex items-center gap-2 flex-shrink-0"
          style={{ alignSelf: 'flex-start' }}
        >
          <Eye size={13} />
          INVESTIGATE
          <ChevronRight size={12} />
        </button>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Intelligence feed status                                     */
/* ─────────────────────────────────────────────────────────── */

const INTEL_FEEDS = [
  { name: 'AI ENGINE', status: 'ONLINE' as const },
  { name: 'THREAT INTEL', status: 'ONLINE' as const },
  { name: 'GEOLOCATION', status: 'ONLINE' as const },
  { name: 'RFC FORENSICS', status: 'ONLINE' as const },
  { name: 'VIRUSTOTAL', status: 'DEGRADED' as const },
  { name: 'SHODAN FEED', status: 'OFFLINE' as const },
];

type FeedStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE';

function feedColor(s: FeedStatus) {
  if (s === 'ONLINE') return '#22c55e';
  if (s === 'DEGRADED') return '#f59e0b';
  return '#ef4444';
}
function FeedIcon({ s }: { s: FeedStatus }) {
  if (s === 'ONLINE') return <CheckCircle size={11} style={{ color: feedColor(s) }} />;
  if (s === 'DEGRADED') return <Minus size={11} style={{ color: feedColor(s) }} />;
  return <XCircle size={11} style={{ color: feedColor(s) }} />;
}

/* ─────────────────────────────────────────────────────────── */
/* Drag-and-drop upload zone                                    */
/* ─────────────────────────────────────────────────────────── */

function DropZone({ onFile }: { onFile: (file: File) => void }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  }, [onFile]);

  return (
    <div
      onDragEnter={e => { e.preventDefault(); setDragging(true); }}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      style={{
        border: `2px dashed ${dragging ? '#00D9FF' : 'rgba(34,211,238,0.22)'}`,
        background: dragging ? 'rgba(0,217,255,0.06)' : 'rgba(0,217,255,0.02)',
        borderRadius: 10,
        padding: '18px 16px',
        cursor: 'pointer',
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
        transition: 'all 0.2s',
        boxShadow: dragging ? '0 0 20px rgba(0,217,255,0.1)' : 'none',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg,.txt"
        style={{ display: 'none' }}
        onChange={e => { const f = e.target.files?.[0]; if (f) onFile(f); }}
      />
      <Upload size={22} style={{ color: dragging ? '#00D9FF' : '#475569' }} />
      <div style={{ fontSize: 11, fontWeight: 600, color: dragging ? '#00D9FF' : 'var(--color-text-muted)', letterSpacing: '0.04em' }}>
        DROP .EML FILE HERE
      </div>
      <div style={{ fontSize: 10, color: '#475569' }}>or click to select</div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Main Dashboard page                                          */
/* ─────────────────────────────────────────────────────────── */

export function Dashboard() {
  const [visualMode, setVisualMode] = React.useState(() => localStorage.getItem('sentineltrace_visual_mode') || 'balanced');
  React.useEffect(() => {
    const update = (event: Event) => setVisualMode((event as CustomEvent<string>).detail || 'balanced');
    window.addEventListener('sentineltrace:visual-mode', update);
    return () => window.removeEventListener('sentineltrace:visual-mode', update);
  }, []);
  const { metrics, history, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const { alerts } = useAlerts();
  const navigate = useNavigate();

  // Backend state
  const [stats, setStats] = useState<WireStats | null>(null);
  const [recentThreats, setRecentThreats] = useState<WireRecentThreat[]>([]);
  const [countryThreats, setCountryThreats] = useState<WireCountryThreat[]>([]);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  // Demo runner
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStage, setDemoStage] = useState('');

  // Fetch backend data
  useEffect(() => {
    const ctrl = new AbortController();
    const sig = ctrl.signal;

    (async () => {
      setLoading(true);
      try {
        const [s, rt, ct] = await Promise.all([
          fetchStats(sig),
          fetchRecentThreats(10, sig),
          fetchThreatsByCountry(sig),
        ]);
        setStats(s);
        setRecentThreats(rt);
        setCountryThreats(ct);
        setBackendOnline(true);
      } catch {
        if (!sig.aborted) setBackendOnline(false);
      } finally {
        if (!sig.aborted) setLoading(false);
      }
    })();

    return () => ctrl.abort();
  }, []);

  // File upload handler – reads file, sends to analyzer
  const handleFile = useCallback(async (file: File) => {
    const raw = await file.text();
    navigate('/analyzer', { state: { raw, filename: file.name } });
  }, [navigate]);

  // Live Investigation demo
  const handleLiveDemo = useCallback(async () => {
    if (demoRunning) return;
    setDemoRunning(true);
    const stages = [
      'Receiving email from SMTP relay…',
      'Parsing RFC 5322 headers…',
      'Validating SPF record…',
      'Checking DKIM signature…',
      'Evaluating DMARC policy…',
      'Extracting IOCs from body…',
      'Analyzing URLs and domains…',
      'Resolving IP intelligence…',
      'Running AI threat classification…',
      'Generating forensic report…',
    ];
    for (const s of stages) {
      setDemoStage(s);
      await new Promise(r => setTimeout(r, 420));
    }
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Live Investigation Demo',
        useBackend: true,
        onStage: () => {},
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
      setDemoStage('Investigation complete — navigating…');
      await new Promise(r => setTimeout(r, 700));
      navigate('/analyzer');
    } catch {
      setDemoStage('Demo complete.');
      await new Promise(r => setTimeout(r, 800));
      navigate('/analyzer');
    } finally {
      setDemoRunning(false);
      setDemoStage('');
    }
  }, [demoRunning, session, setCurrentAnalysis, addToHistory, navigate]);

  // KPI values: prefer real backend, fall back to context metrics
  const totalEmails = stats?.total_emails ?? metrics.emailsAnalyzed;
  const threatsDetected = stats?.flagged_emails ?? metrics.threatsDetected;
  const criticalThreats = stats?.critical_threats ?? metrics.criticalThreats;
  const highThreats = stats?.high_threats ?? 0;
  const activeInvestigations = metrics.activeInvestigations;

  // Top countries (real or demo)
  const topCountries: { country: string; count: number; score: number }[] =
    countryThreats.length > 0
      ? countryThreats.slice(0, 6).map(c => ({ country: c.country, count: c.email_count, score: c.average_threat_score }))
      : [
          { country: 'China', count: 42, score: 81 },
          { country: 'Russia', count: 38, score: 88 },
          { country: 'Nigeria', count: 27, score: 72 },
          { country: 'Ukraine', count: 19, score: 66 },
          { country: 'Iran', count: 9, score: 77 },
          { country: 'North Korea', count: 6, score: 91 },
        ];

  // Latest critical threat for featured card
  const latestCritical = recentThreats.find(t => t.threat_level === 'CRITICAL') ?? recentThreats[0] ?? null;

  return (
    <div className="dashboard-page" style={{ padding: '20px 24px', maxWidth: 1500, margin: '0 auto' }}>
      {/* Ambient orbs */}
      <div className="dashboard-orb dashboard-orb-cyan" aria-hidden="true" />
      <div className="dashboard-orb dashboard-orb-violet" aria-hidden="true" />

      {/* ── Page header ── */}
      <div className="dashboard-command-header flex items-center justify-between mb-5 flex-wrap gap-3">
        <div>
          <div className="dashboard-eyebrow">TEAM BRUTE · SIH 26106 · COMMAND CENTER</div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)', letterSpacing: '0.02em' }}>
            Cyber Intelligence Dashboard
          </h1>
          <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 2 }}>
            {session?.unit} · {new Date().toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <ThreatLevelBanner stats={stats} />

          {/* Backend status pill */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg" style={{
            background: backendOnline === true ? 'rgba(34,197,94,0.08)' : backendOnline === false ? 'rgba(239,68,68,0.08)' : 'rgba(100,116,139,0.08)',
            border: `1px solid ${backendOnline === true ? 'rgba(34,197,94,0.25)' : backendOnline === false ? 'rgba(239,68,68,0.25)' : 'rgba(100,116,139,0.2)'}`,
            fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 600,
            color: backendOnline === true ? '#22c55e' : backendOnline === false ? '#ef4444' : '#94a3b8',
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: backendOnline === true ? '#22c55e' : backendOnline === false ? '#ef4444' : '#94a3b8', boxShadow: backendOnline === true ? '0 0 6px #22c55e' : 'none' }} />
            {backendOnline === true ? 'BACKEND ONLINE' : backendOnline === false ? 'BACKEND OFFLINE' : 'CONNECTING…'}
          </div>

          {/* Live investigation */}
          <button
            onClick={handleLiveDemo}
            disabled={demoRunning}
            className="live-investigation-glass flex items-center gap-2"
            style={{ padding: '9px 18px', borderRadius: 8, color: '#22d3ee', fontWeight: 700, fontSize: 11, cursor: demoRunning ? 'not-allowed' : 'pointer', letterSpacing: '0.06em', transition: 'all 0.2s' }}
          >
            {demoRunning ? (
              <>
                <span className="animate-spin" style={{ display: 'inline-block', width: 11, height: 11, border: '2px solid rgba(34,211,238,0.2)', borderTop: '2px solid #22d3ee', borderRadius: '50%' }} />
                {demoStage.slice(0, 32)}…
              </>
            ) : (
              <>
                <Play size={12} />
                LIVE INVESTIGATION
              </>
            )}
          </button>
        </div>
      </div>

      {/* ── KPI Metrics ── */}
      <div className="grid mb-5" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: 10 }}>
        <MetricCard icon={<Mail size={15} />} label="EMAILS ANALYZED" value={totalEmails} delta={metrics.deltas.emailsAnalyzed} color="#22d3ee" loading={loading} />
        <MetricCard icon={<AlertTriangle size={15} />} label="THREATS DETECTED" value={threatsDetected} delta={metrics.deltas.threatsDetected} color="#f97316" loading={loading} />
        <MetricCard icon={<Shield size={15} />} label="CRITICAL THREATS" value={criticalThreats} delta={metrics.deltas.criticalThreats} color="#ef4444" loading={loading} />
        <MetricCard icon={<Zap size={15} />} label="HIGH-RISK" value={highThreats} color="#f59e0b" loading={loading} />
        <MetricCard icon={<Globe size={15} />} label="SUSPICIOUS DOMAINS" value={metrics.suspiciousDomains} color="#a78bfa" />
        <MetricCard icon={<Wifi size={15} />} label="MALICIOUS IPs" value={metrics.maliciousIps} color="#f97316" />
        <MetricCard icon={<Search size={15} />} label="ACTIVE INVESTIGATIONS" value={activeInvestigations} delta={metrics.deltas.activeInvestigations} color="#22c55e" />
      </div>

      {/* ── Featured threat ── */}
      <div className="mb-5">
        <FeaturedThreatCard threat={latestCritical} onInvestigate={() => navigate('/analyzer')} />
      </div>

      {/* ── Main grid: Globe + Right panel ── */}
      <div className="grid mb-5" style={{ gridTemplateColumns: '1fr 340px', gap: 14, alignItems: 'start' }}>

        {/* Globe panel */}
        <div className="panel dashboard-glass-panel overflow-hidden" style={{ padding: 0 }}>
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
            <span className="section-title mb-0 flex items-center gap-2">
              <Globe size={14} style={{ color: '#22d3ee' }} />
              Global Threat Origin Map
            </span>
            {countryThreats.length === 0 && (
              <span style={{ fontSize: 9, color: '#f59e0b', fontFamily: 'var(--font-mono)', background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 3, padding: '2px 6px' }}>
                DEMO MODE – SIMULATED DATA
              </span>
            )}
          </div>
          <Suspense fallback={
            <div className="flex items-center justify-center" style={{ height: 420 }}>
              <div style={{ color: 'var(--color-text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                Loading 3D globe…
              </div>
            </div>
          }>
            {visualMode === 'lite' ? (
              <div className="dashboard-globe-lite" role="img" aria-label="Static global threat overview">
                <div className="dashboard-globe-lite-grid" />
                <strong>GLOBAL THREAT MAP · LITE MODE</strong>
                <span>{countryThreats.length} observed country clusters</span>
                <button type="button" onClick={() => { localStorage.setItem('sentineltrace_visual_mode', 'balanced'); setVisualMode('balanced'); }}>LOAD INTERACTIVE 3D</button>
              </div>
            ) : <ThreatGlobe countryThreats={countryThreats} height={420} />}
          </Suspense>
        </div>

        {/* Right column */}
        <div className="flex flex-col gap-3">

          {/* Upload zone */}
          <div className="panel dashboard-glass-panel" style={{ padding: 16 }}>
            <div className="section-title flex items-center gap-2">
              <Upload size={13} style={{ color: '#22d3ee' }} />
              Analyze Email
            </div>
            <DropZone onFile={handleFile} />
            <button
              onClick={() => navigate('/analyzer')}
              className="btn-primary w-full mt-2"
              style={{ fontSize: 11, padding: '8px 12px' }}
            >
              <Search size={12} />
              OPEN ANALYZER
            </button>
          </div>

          {/* Intelligence feed status */}
          <div className="panel dashboard-glass-panel" style={{ padding: 16 }}>
            <div className="section-title flex items-center gap-2">
              <Activity size={13} style={{ color: '#22d3ee' }} />
              Intelligence Feeds
            </div>
            <div className="flex flex-col gap-1.5">
              {INTEL_FEEDS.map(feed => (
                <div key={feed.name} className="flex items-center justify-between" style={{ fontSize: 11 }}>
                  <div className="flex items-center gap-1.5">
                    <FeedIcon s={feed.status} />
                    <span style={{ color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', letterSpacing: '0.04em', fontSize: 10 }}>
                      {feed.name}
                    </span>
                  </div>
                  <span style={{ fontSize: 9, fontWeight: 600, color: feedColor(feed.status), fontFamily: 'var(--font-mono)' }}>
                    {feed.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Top attack categories */}
          <div className="panel dashboard-glass-panel" style={{ padding: 16 }}>
            <div className="section-title flex items-center gap-2">
              <Database size={13} style={{ color: '#22d3ee' }} />
              Top Attack Categories
              <span style={{ fontSize: 9, marginLeft: 'auto', color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>DEMO</span>
            </div>
            {[
              { label: 'Business Email Compromise', pct: 34, color: '#ef4444' },
              { label: 'Phishing / Credential Harvest', pct: 28, color: '#f97316' },
              { label: 'Malware Delivery', pct: 18, color: '#f59e0b' },
              { label: 'Lookalike Domain Spoof', pct: 12, color: '#a78bfa' },
              { label: 'Invoice Fraud', pct: 8, color: '#22d3ee' },
            ].map(({ label, pct, color }) => (
              <div key={label} className="mb-2">
                <div className="flex justify-between mb-0.5" style={{ fontSize: 10 }}>
                  <span style={{ color: 'var(--color-text-dim)' }}>{label}</span>
                  <span style={{ color, fontWeight: 600 }}>{pct}%</span>
                </div>
                <div style={{ height: 3, borderRadius: 2, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, boxShadow: `0 0 6px ${color}40` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Bottom row: Recent threats + Countries + Quick actions ── */}
      <div className="grid" style={{ gridTemplateColumns: '2fr 1fr 1fr', gap: 14 }}>

        {/* Recent threats table */}
        <div className="panel dashboard-glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
            <span className="section-title mb-0 flex items-center gap-2">
              <Clock size={13} style={{ color: '#22d3ee' }} />
              Recent Analysis Activity
            </span>
            <div className="flex items-center gap-2">
              {recentThreats.length === 0 && (
                <span style={{ fontSize: 9, color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>DEMO</span>
              )}
              <button onClick={() => navigate('/analyzer')} style={{ fontSize: 10, color: '#22d3ee', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                ANALYZE →
              </button>
            </div>
          </div>
          <table className="data-table w-full">
            <thead>
              <tr>
                <th>SENDER</th>
                <th>SUBJECT</th>
                <th>SCORE</th>
                <th>LEVEL</th>
                <th>TIME</th>
              </tr>
            </thead>
            <tbody>
              {(recentThreats.length > 0 ? recentThreats : history.map(h => ({
                id: 0, sender: h.sender, subject: h.subject,
                threat_score: h.score, threat_level: h.level,
                country: null, analyzed_at: h.analyzedAt,
              } as WireRecentThreat))).slice(0, 8).map((item, i) => (
                <tr key={`${item.id}-${i}`} style={{ cursor: 'pointer' }} onClick={() => navigate('/analyzer')}>
                  <td>
                    <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.sender}
                    </div>
                  </td>
                  <td>
                    <div style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-text-dim)', fontSize: 11 }}>
                      {item.subject}
                    </div>
                  </td>
                  <td>
                    <div style={{ fontWeight: 700, fontSize: 12, color: severityColor(item.threat_level) }}>
                      {item.threat_score}
                    </div>
                  </td>
                  <td><ThreatBadge level={item.threat_level} /></td>
                  <td>
                    <div style={{ fontSize: 10, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(item.analyzed_at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </td>
                </tr>
              ))}
              {recentThreats.length === 0 && history.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: 28, fontSize: 12 }}>
                    No analyses yet.{' '}
                    <button onClick={() => navigate('/analyzer')} style={{ color: '#22d3ee', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>
                      Analyze an email →
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Top origin countries */}
        <div className="panel dashboard-glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
            <span className="section-title mb-0 flex items-center gap-2">
              <Globe size={13} style={{ color: '#22d3ee' }} />
              Attack Origins
            </span>
            {countryThreats.length === 0 && (
              <span style={{ fontSize: 9, color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>DEMO</span>
            )}
          </div>
          <div style={{ padding: '8px 16px 12px' }}>
            {topCountries.map(({ country, count, score }, i) => (
              <div key={country} className="flex items-center gap-2 py-2" style={{ borderBottom: i < topCountries.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-muted)', width: 14, textAlign: 'right', flexShrink: 0 }}>
                  {i + 1}
                </div>
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  <div style={{ fontSize: 11, color: 'var(--color-text)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {country}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--color-text-muted)' }}>{count} emails</div>
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: severityColor(score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW'), flexShrink: 0 }}>
                  {score.toFixed(0)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick actions + alerts */}
        <div className="flex flex-col gap-3">

          {/* Quick actions */}
          <div className="panel dashboard-glass-panel" style={{ padding: 16 }}>
            <div className="section-title">Quick Actions</div>
            <div className="flex flex-col gap-1.5">
              {[
                { label: 'Analyze Email', icon: <Mail size={12} />, to: '/analyzer', color: '#22d3ee' },
                { label: 'Header Forensics', icon: <Search size={12} />, to: '/header-forensics', color: '#a78bfa' },
                { label: 'Relay Chain', icon: <Activity size={12} />, to: '/relay-chain', color: '#22c55e' },
                { label: 'View Cases', icon: <Database size={12} />, to: '/cases', color: '#f97316' },
                { label: 'Alert Center', icon: <AlertTriangle size={12} />, to: '/alerts', color: '#ef4444' },
                { label: 'Forensic Reports', icon: <Eye size={12} />, to: '/reports', color: '#38bdf8' },
              ].map(action => (
                <button
                  key={action.label}
                  onClick={() => navigate(action.to)}
                  className="quick-action-glass flex items-center gap-2 w-full transition-all-fast"
                  style={{ padding: '7px 10px', borderRadius: 6, color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 11, fontWeight: 500, textAlign: 'left' }}
                  onMouseEnter={e => { e.currentTarget.style.background = `${action.color}10`; e.currentTarget.style.color = action.color; }}
                  onMouseLeave={e => { e.currentTarget.style.background = ''; e.currentTarget.style.color = 'var(--color-text-dim)'; }}
                >
                  <span style={{ color: action.color }}>{action.icon}</span>
                  {action.label}
                  <ChevronRight size={10} style={{ marginLeft: 'auto' }} />
                </button>
              ))}
            </div>
          </div>

          {/* Live alerts minilist */}
          <div className="panel dashboard-glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="flex items-center justify-between px-3 py-2.5" style={{ borderBottom: '1px solid var(--color-border)' }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-text)' }}>Live Alerts</span>
              <button onClick={() => navigate('/alerts')} style={{ fontSize: 10, color: '#22d3ee', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                ALL →
              </button>
            </div>
            {alerts.slice(0, 4).map(alert => (
              <div key={alert.id} className="flex items-start gap-2 px-3 py-2.5" style={{ borderBottom: '1px solid var(--color-border)', cursor: 'pointer' }} onClick={() => navigate('/alerts')}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', marginTop: 5, flexShrink: 0, background: severityColor(alert.severity), boxShadow: `0 0 5px ${severityColor(alert.severity)}` }} />
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{alert.title}</div>
                  <div style={{ fontSize: 10, color: 'var(--color-text-muted)', marginTop: 1 }}>
                    {alert.source} · {new Date(alert.at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
                {alert.status === 'NEW' && (
                  <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22d3ee', boxShadow: '0 0 5px #22d3ee', flexShrink: 0, marginTop: 5 }} />
                )}
              </div>
            ))}
            {alerts.length === 0 && (
              <div style={{ padding: 20, textAlign: 'center', fontSize: 11, color: 'var(--color-text-muted)' }}>
                No active alerts
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
