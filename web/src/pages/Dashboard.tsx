import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail, AlertTriangle, Shield, Globe, Wifi, Search,
  TrendingUp, TrendingDown, ChevronRight, Play, Clock,
  Activity, Eye, Zap, Database
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { useSession } from '@/context/SessionContext';
import { useAlerts } from '@/context/AlertContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME, DEMO_SCENARIO } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import type { Severity } from '@/types';

/* ------------------------------------------------------------------ */
/* Animated counter                                                    */
/* ------------------------------------------------------------------ */

function AnimatedNumber({ target, duration = 1200 }: { target: number; duration?: number }) {
  const [current, setCurrent] = useState(0);
  useEffect(() => {
    const start = Date.now();
    const step = () => {
      const elapsed = Date.now() - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(Math.round(target * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration]);
  return <>{current.toLocaleString()}</>;
}

/* ------------------------------------------------------------------ */
/* Metric card                                                         */
/* ------------------------------------------------------------------ */

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  delta?: number;
  color: string;
  accent?: string;
}

function MetricCard({ icon, label, value, delta, color, accent }: MetricCardProps) {
  return (
    <div
      className="panel metric-glass-card animate-fade-in"
      style={{
        padding: '20px',
        borderLeft: `3px solid ${color}`,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: 0, right: 0,
          width: 80, height: 80,
          background: `radial-gradient(circle, ${color}08, transparent 70%)`,
          pointerEvents: 'none',
        }}
      />
      <div className="flex items-start justify-between">
        <div
          className="flex items-center justify-center rounded-lg"
          style={{ width: 36, height: 36, background: `${color}15`, color }}
        >
          {icon}
        </div>
        {delta !== undefined && (
          <div
            className="flex items-center gap-1"
            style={{ fontSize: 11, fontWeight: 600, color: delta >= 0 ? '#22c55e' : '#ef4444' }}
          >
            {delta >= 0 ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
            {Math.abs(delta).toFixed(1)}%
          </div>
        )}
      </div>
      <div className="mt-3">
        <div className="value-large" style={{ color }}>
          <AnimatedNumber target={value} />
        </div>
        <div className="label mt-1">{label}</div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Threat level badge                                                  */
/* ------------------------------------------------------------------ */

function ThreatBadge({ level }: { level: Severity }) {
  const colors: Record<Severity, string> = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#f59e0b',
    LOW: '#22c55e',
    INFO: '#22d3ee',
  };
  return (
    <span
      style={{
        fontSize: 10,
        fontWeight: 700,
        color: colors[level],
        background: `${colors[level]}18`,
        border: `1px solid ${colors[level]}30`,
        borderRadius: 4,
        padding: '2px 6px',
        letterSpacing: '0.04em',
      }}
    >
      {level}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Featured threat card (top of page)                                  */
/* ------------------------------------------------------------------ */

function FeaturedThreatCard({ onInvestigate }: { onInvestigate: () => void }) {
  return (
    <div
      className="threat-glass-card animate-fade-in"
      style={{
        borderRadius: 12,
        padding: '20px 24px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Glow */}
      <div
        style={{
          position: 'absolute',
          top: 0, left: 0,
          width: '100%', height: '100%',
          background: 'radial-gradient(circle at 0% 0%, rgba(239,68,68,0.08) 0%, transparent 60%)',
          pointerEvents: 'none',
        }}
      />

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="relative">
              <div style={{ width: 8, height: 8, background: '#ef4444', borderRadius: '50%', boxShadow: '0 0 8px #ef4444' }} />
              <div
                style={{
                  position: 'absolute', inset: -3,
                  width: 14, height: 14, background: 'rgba(239,68,68,0.25)',
                  borderRadius: '50%', animation: 'ping 1s cubic-bezier(0,0,0.2,1) infinite',
                }}
              />
            </div>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', letterSpacing: '0.08em' }}>
              LIVE THREAT ALERT
            </span>
          </div>

          <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginBottom: 4 }}>
            Most Recent Critical Detection
          </div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-text)', marginBottom: 8 }}>
            EMAIL: <span style={{ color: '#fca5a5', fontFamily: 'var(--font-mono)' }}>finance@paypa1-security.com</span>
          </div>

          <div className="flex flex-wrap gap-3 mt-2">
            <div>
              <div className="label">AI VERDICT</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#ef4444' }}>BUSINESS EMAIL COMPROMISE</div>
            </div>
            <div>
              <div className="label">CONFIDENCE</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#f97316' }}>94.7%</div>
            </div>
            <div>
              <div className="label">THREAT SCORE</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#ef4444' }}>87 / 100</div>
            </div>
            <div>
              <div className="label">PROBABLE ORIGIN</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#22d3ee' }}>Singapore (Estimated)</div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 mt-3">
            {[
              { label: 'SPF: FAIL', color: '#ef4444' },
              { label: 'DKIM: NONE', color: '#ef4444' },
              { label: 'DMARC: FAIL', color: '#ef4444' },
              { label: 'LOOKALIKE DOMAIN', color: '#f97316' },
              { label: 'SUSPICIOUS IP', color: '#f59e0b' },
            ].map(tag => (
              <span
                key={tag.label}
                style={{
                  fontSize: 10, fontWeight: 600,
                  color: tag.color,
                  background: `${tag.color}15`,
                  border: `1px solid ${tag.color}30`,
                  borderRadius: 4,
                  padding: '2px 7px',
                  letterSpacing: '0.04em',
                }}
              >
                {tag.label}
              </span>
            ))}
          </div>
        </div>

        <button
          onClick={onInvestigate}
          className="flex items-center gap-2"
          style={{
            padding: '10px 18px',
            background: 'rgba(239,68,68,0.15)',
            border: '1px solid rgba(239,68,68,0.35)',
            borderRadius: 8,
            color: '#fca5a5',
            fontWeight: 700,
            fontSize: 12,
            cursor: 'pointer',
            letterSpacing: '0.04em',
            transition: 'all 0.2s',
            flexShrink: 0,
            whiteSpace: 'nowrap',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = 'rgba(239,68,68,0.25)';
            e.currentTarget.style.boxShadow = '0 0 20px rgba(239,68,68,0.3)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = 'rgba(239,68,68,0.15)';
            e.currentTarget.style.boxShadow = 'none';
          }}
        >
          <Eye size={14} />
          VIEW FORENSIC INVESTIGATION
          <ChevronRight size={13} />
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sparkline chart                                                      */
/* ------------------------------------------------------------------ */

function MiniSparkline({ data }: { data: { analyzed: number; threats: number }[] }) {
  const w = 100, h = 30;
  const maxA = Math.max(...data.map(d => d.analyzed));
  const pts = data.map((d, i) => `${(i / (data.length - 1)) * w},${h - (d.analyzed / maxA) * h}`).join(' ');
  const tpts = data.map((d, i) => `${(i / (data.length - 1)) * w},${h - (d.threats / maxA) * h}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: '100%', height: 36 }}>
      <polyline points={pts} fill="none" stroke="rgba(34,211,238,0.5)" strokeWidth="1.5" />
      <polyline points={tpts} fill="none" stroke="rgba(239,68,68,0.5)" strokeWidth="1" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/* Dashboard                                                           */
/* ------------------------------------------------------------------ */

export function Dashboard() {
  const { metrics, history, currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const { alerts } = useAlerts();
  const navigate = useNavigate();
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStage, setDemoStage] = useState('');

  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'NEW');

  const handleInvestigate = () => {
    navigate('/analyzer');
  };

  const handleLiveDemo = async () => {
    if (demoRunning) return;
    setDemoRunning(true);

    const stages = [
      'Receiving email from SMTP relay...',
      'Parsing RFC 5322 headers...',
      'Validating SPF record...',
      'Checking DKIM signature...',
      'Evaluating DMARC policy...',
      'Extracting IOCs from body...',
      'Analyzing URLs and domains...',
      'Resolving IP intelligence...',
      'Reconstructing relay path...',
      'Running AI threat classification...',
      'Correlating geolocation data...',
      'Generating forensic report...',
    ];

    for (const stage of stages) {
      setDemoStage(stage);
      await new Promise(r => setTimeout(r, 500));
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
      setDemoStage('Investigation complete — navigating to results...');
      await new Promise(r => setTimeout(r, 800));
      navigate('/analyzer');
    } catch {
      setDemoStage('Demo analysis complete.');
      await new Promise(r => setTimeout(r, 1000));
      navigate('/analyzer');
    } finally {
      setDemoRunning(false);
    }
  };

  return (
    <div className="dashboard-page" style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <div className="dashboard-orb dashboard-orb-cyan" aria-hidden="true" />
      <div className="dashboard-orb dashboard-orb-violet" aria-hidden="true" />

      {/* Page header */}
      <div className="dashboard-command-header flex items-center justify-between mb-6 flex-wrap gap-3">
        <div>
          <div className="dashboard-eyebrow">TEAM BRUTE · SIH 26106</div>
          <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--color-text)', letterSpacing: '0.02em' }}>
            Command Center
          </h1>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            {session?.unit} · {new Date().toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </div>
        </div>

        {/* Live demo button */}
        <button
          onClick={handleLiveDemo}
          disabled={demoRunning}
          className="live-investigation-glass flex items-center gap-2"
          style={{
            padding: '10px 20px',
            borderRadius: 8,
            color: '#22d3ee',
            fontWeight: 700,
            fontSize: 12,
            cursor: demoRunning ? 'not-allowed' : 'pointer',
            letterSpacing: '0.05em',
            transition: 'all 0.2s',
          }}
        >
          {demoRunning ? (
            <>
              <span className="animate-spin" style={{ display: 'inline-block', width: 12, height: 12, border: '2px solid rgba(34,211,238,0.2)', borderTop: '2px solid #22d3ee', borderRadius: '50%' }} />
              {demoStage.slice(0, 35)}...
            </>
          ) : (
            <>
              <Play size={13} />
              START LIVE INVESTIGATION
            </>
          )}
        </button>
      </div>

      {/* Featured threat */}
      <FeaturedThreatCard onInvestigate={handleInvestigate} />

      {/* Metrics grid */}
      <div
        className="grid mt-5"
        style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 12 }}
      >
        <MetricCard
          icon={<Mail size={16} />}
          label="EMAILS ANALYZED"
          value={metrics.emailsAnalyzed}
          delta={metrics.deltas.emailsAnalyzed}
          color="#22d3ee"
        />
        <MetricCard
          icon={<AlertTriangle size={16} />}
          label="THREATS DETECTED"
          value={metrics.threatsDetected}
          delta={metrics.deltas.threatsDetected}
          color="#f97316"
        />
        <MetricCard
          icon={<Shield size={16} />}
          label="CRITICAL THREATS"
          value={metrics.criticalThreats}
          delta={metrics.deltas.criticalThreats}
          color="#ef4444"
        />
        <MetricCard
          icon={<Globe size={16} />}
          label="SUSPICIOUS DOMAINS"
          value={metrics.suspiciousDomains}
          color="#a78bfa"
        />
        <MetricCard
          icon={<Wifi size={16} />}
          label="MALICIOUS IPs"
          value={metrics.maliciousIps}
          color="#f59e0b"
        />
        <MetricCard
          icon={<Search size={16} />}
          label="ACTIVE INVESTIGATIONS"
          value={metrics.activeInvestigations}
          delta={metrics.deltas.activeInvestigations}
          color="#22c55e"
        />
      </div>

      {/* Lower grid */}
      <div
        className="grid mt-5"
        style={{ gridTemplateColumns: '2fr 1fr', gap: 16 }}
      >
        {/* Recent threats table */}
        <div className="panel dashboard-glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            className="flex items-center justify-between px-4 py-3"
            style={{ borderBottom: '1px solid var(--color-border)' }}
          >
            <span className="section-title mb-0">Recent Threats</span>
            <button
              onClick={() => navigate('/analyzer')}
              style={{ fontSize: 11, color: 'var(--color-cyan)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}
            >
              ANALYZE EMAIL →
            </button>
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
              {history.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: 32 }}>
                    No analyses yet. <button onClick={() => navigate('/analyzer')} style={{ color: '#22d3ee', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>Analyze an email →</button>
                  </td>
                </tr>
              ) : (
                history.slice(0, 8).map(item => (
                  <tr key={item.id} style={{ cursor: 'pointer' }}>
                    <td>
                      <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.sender}
                      </div>
                    </td>
                    <td>
                      <div style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-text-dim)' }}>
                        {item.subject}
                      </div>
                    </td>
                    <td>
                      <div style={{
                        fontWeight: 700,
                        fontSize: 13,
                        color: item.score >= 75 ? '#ef4444' : item.score >= 50 ? '#f97316' : item.score >= 25 ? '#f59e0b' : '#22c55e',
                      }}>
                        {item.score}
                      </div>
                    </td>
                    <td><ThreatBadge level={item.level} /></td>
                    <td>
                      <div style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
                        {new Date(item.analyzedAt).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Right column */}
        <div className="flex flex-col gap-4">
          {/* Trend sparkline */}
          <div className="panel dashboard-glass-panel" style={{ padding: '16px' }}>
            <div className="section-title">14-Day Trend</div>
            <MiniSparkline data={metrics.trend} />
            <div className="flex items-center gap-4 mt-2">
              <div className="flex items-center gap-1.5">
                <div style={{ width: 10, height: 2, background: 'rgba(34,211,238,0.5)', borderRadius: 1 }} />
                <span style={{ fontSize: 10, color: 'var(--color-text-muted)' }}>Analyzed</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div style={{ width: 10, height: 2, background: 'rgba(239,68,68,0.5)', borderRadius: 1 }} />
                <span style={{ fontSize: 10, color: 'var(--color-text-muted)' }}>Threats</span>
              </div>
            </div>
          </div>

          {/* Live alerts */}
          <div className="panel dashboard-glass-panel" style={{ padding: 0, overflow: 'hidden', flex: 1 }}>
            <div
              className="flex items-center justify-between px-4 py-3"
              style={{ borderBottom: '1px solid var(--color-border)' }}
            >
              <span className="section-title mb-0">Live Alerts</span>
              <button
                onClick={() => navigate('/alerts')}
                style={{ fontSize: 11, color: 'var(--color-cyan)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}
              >
                VIEW ALL →
              </button>
            </div>
            <div style={{ overflow: 'hidden' }}>
              {alerts.slice(0, 4).map(alert => (
                <div
                  key={alert.id}
                  className="flex items-start gap-3 px-4 py-3"
                  style={{ borderBottom: '1px solid var(--color-border)', cursor: 'pointer' }}
                >
                  <div
                    style={{
                      width: 6, height: 6, borderRadius: '50%', marginTop: 6, flexShrink: 0,
                      background: alert.severity === 'CRITICAL' ? '#ef4444' : alert.severity === 'HIGH' ? '#f97316' : '#f59e0b',
                      boxShadow: `0 0 6px ${alert.severity === 'CRITICAL' ? '#ef4444' : alert.severity === 'HIGH' ? '#f97316' : '#f59e0b'}`,
                    }}
                  />
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {alert.title}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 2 }}>
                      {alert.source} · {new Date(alert.at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>
                  {alert.status === 'NEW' && (
                    <div
                      style={{
                        width: 6, height: 6, borderRadius: '50%',
                        background: '#22d3ee', boxShadow: '0 0 6px #22d3ee',
                        flexShrink: 0, marginTop: 6,
                      }}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Quick actions */}
          <div className="panel dashboard-glass-panel" style={{ padding: '16px' }}>
            <div className="section-title">Quick Actions</div>
            <div className="flex flex-col gap-2">
              {[
                { label: 'Analyze Email', icon: <Mail size={13} />, to: '/analyzer', color: '#22d3ee' },
                { label: 'View Campaigns', icon: <Activity size={13} />, to: '/campaigns', color: '#a78bfa' },
                { label: 'Open Cases', icon: <Database size={13} />, to: '/cases', color: '#22c55e' },
              ].map(action => (
                <button
                  key={action.label}
                  onClick={() => navigate(action.to)}
                  className="quick-action-glass flex items-center gap-2 w-full transition-all-fast"
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    color: 'var(--color-text-dim)',
                    cursor: 'pointer',
                    fontSize: 12,
                    fontWeight: 500,
                    textAlign: 'left',
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.background = `${action.color}10`;
                    e.currentTarget.style.borderColor = `${action.color}30`;
                    e.currentTarget.style.color = action.color;
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = '';
                    e.currentTarget.style.borderColor = 'var(--color-border)';
                    e.currentTarget.style.color = 'var(--color-text-dim)';
                  }}
                >
                  <span style={{ color: action.color }}>{action.icon}</span>
                  {action.label}
                  <ChevronRight size={11} style={{ marginLeft: 'auto' }} />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
