import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, FileText, Play, AlertTriangle, CheckCircle, Clock,
  ChevronRight, Copy, Download, Shield, Zap, Search,
  RotateCcw, Info, ExternalLink
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { useSession } from '@/context/SessionContext';
import { analyseEmail, AnalysisInputError } from '@/services/analysisService';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { PIPELINE_STAGES, initialStageStates } from '@/lib/pipeline';
import type { StageState } from '@/lib/pipeline';
import type { EmailAnalysis, Severity } from '@/types';

/* ------------------------------------------------------------------ */
/* Pipeline progress visualization                                     */
/* ------------------------------------------------------------------ */

function PipelineProgress({ stages }: { stages: StageState[] }) {
  const stageConfig: Record<string, { label: string }> = {
    INGEST: { label: 'INGESTING EMAIL' },
    PARSE_HEADERS: { label: 'PARSING HEADERS' },
    SPF: { label: 'VALIDATING SPF' },
    DKIM: { label: 'VALIDATING DKIM' },
    DMARC: { label: 'VALIDATING DMARC' },
    IOC: { label: 'EXTRACTING IOCs' },
    URLS: { label: 'ANALYZING URLS' },
    DOMAINS: { label: 'ANALYZING DOMAINS' },
    IP_INTEL: { label: 'ANALYZING IP INTELLIGENCE' },
    RELAY: { label: 'RECONSTRUCTING RELAY PATH' },
    CLASSIFY: { label: 'AI THREAT CLASSIFICATION' },
    GEO: { label: 'GEOLOCATION ANALYSIS' },
    CORRELATE: { label: 'FORENSIC CORRELATION' },
  };

  return (
    <div
      className="panel animate-fade-in"
      style={{ padding: 24, maxWidth: 500, margin: '0 auto' }}
    >
      <div className="text-center mb-6">
        <div style={{ fontSize: 12, fontWeight: 700, color: '#22d3ee', letterSpacing: '0.1em' }}>
          FORENSIC ANALYSIS PIPELINE
        </div>
        <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 4 }}>
          {stages.filter(s => s.status === 'COMPLETE' || s.status === 'DEGRADED').length} / {stages.length} stages complete
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {stages.map((stage, idx) => {
          const config = stageConfig[stage.id];
          const isActive = stage.status === 'ACTIVE';
          const isDone = stage.status === 'COMPLETE';
          const isDegraded = stage.status === 'DEGRADED';
          const isPending = stage.status === 'PENDING';

          let color = 'var(--color-text-muted)';
          let bgColor = 'transparent';
          if (isActive) { color = '#22d3ee'; bgColor = 'rgba(34,211,238,0.06)'; }
          else if (isDone) { color = '#22c55e'; }
          else if (isDegraded) { color = '#f59e0b'; }

          return (
            <div
              key={stage.id}
              className="flex items-center gap-3 rounded-lg px-3 py-2"
              style={{ background: bgColor, transition: 'all 0.3s' }}
            >
              {/* Status icon */}
              <div style={{ width: 18, flexShrink: 0 }}>
                {isActive && (
                  <div className="animate-spin" style={{ width: 14, height: 14, border: '2px solid rgba(34,211,238,0.2)', borderTop: '2px solid #22d3ee', borderRadius: '50%' }} />
                )}
                {isDone && <CheckCircle size={14} color="#22c55e" />}
                {isDegraded && <AlertTriangle size={14} color="#f59e0b" />}
                {isPending && (
                  <div style={{ width: 14, height: 14, borderRadius: '50%', border: '1px solid rgba(255,255,255,0.1)' }} />
                )}
              </div>

              {/* Connector line */}
              {idx < stages.length - 1 && (
                <div
                  style={{
                    position: 'absolute',
                    left: 28,
                    top: '50%',
                    width: 1,
                    height: 20,
                    background: isDone ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.05)',
                    transform: 'translateY(8px)',
                    zIndex: 0,
                  }}
                />
              )}

              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color, letterSpacing: '0.06em', fontFamily: 'var(--font-mono)' }}>
                  {config?.label || stage.id}
                </div>
                {stage.note && (
                  <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 1 }}>
                    ⚠ {stage.note}
                  </div>
                )}
              </div>

              {stage.durationMs !== null && (
                <div style={{ fontSize: 10, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {stage.durationMs}ms
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Threat gauge (circular)                                             */
/* ------------------------------------------------------------------ */

function ThreatGauge({ score, level }: { score: number; level: Severity }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color = level === 'CRITICAL' ? '#ef4444' : level === 'HIGH' ? '#f97316' : level === 'MEDIUM' ? '#f59e0b' : '#22c55e';

  return (
    <div className="flex flex-col items-center" style={{ position: 'relative' }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        {/* Background track */}
        <circle cx={65} cy={65} r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} />
        {/* Score arc */}
        <circle
          cx={65} cy={65} r={radius}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 65 65)"
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dashoffset 1s ease-out' }}
        />
        {/* Score text */}
        <text x={65} y={62} textAnchor="middle" fill={color} fontSize={24} fontWeight={800} fontFamily="Inter, sans-serif">
          {score}
        </text>
        <text x={65} y={77} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize={10} fontFamily="Inter, sans-serif">
          / 100
        </text>
      </svg>
      <div
        style={{
          fontSize: 12,
          fontWeight: 800,
          color,
          letterSpacing: '0.12em',
          marginTop: -4,
          background: `${color}15`,
          border: `1px solid ${color}30`,
          borderRadius: 4,
          padding: '3px 10px',
        }}
      >
        {level}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Verdict card                                                        */
/* ------------------------------------------------------------------ */

function VerdictCard({ analysis }: { analysis: EmailAnalysis }) {
  const { assessment, score } = analysis;
  const color = score.level === 'CRITICAL' ? '#ef4444' : score.level === 'HIGH' ? '#f97316' : score.level === 'MEDIUM' ? '#f59e0b' : '#22c55e';

  const classLabel = assessment.classification.replace(/_/g, ' ');

  return (
    <div
      className="panel-elevated animate-fade-in"
      style={{
        padding: 24,
        borderLeft: `3px solid ${color}`,
        background: `linear-gradient(135deg, ${color}08, var(--color-surface-2) 60%)`,
      }}
    >
      <div className="flex flex-wrap gap-6 items-start">
        {/* Gauge */}
        <ThreatGauge score={score.total} level={score.level} />

        {/* Verdict text */}
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', marginBottom: 4 }}>
            AI CLASSIFICATION
          </div>
          <div style={{ fontSize: 20, fontWeight: 900, color, letterSpacing: '0.04em', lineHeight: 1 }}>
            {classLabel}
          </div>
          <div style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 4 }}>
            Confidence: <span style={{ color: 'var(--color-text)', fontWeight: 600 }}>{assessment.confidence.toFixed(1)}%</span>
          </div>

          <div
            className="mt-4 p-3 rounded-lg"
            style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--color-border)', fontSize: 12, color: 'var(--color-text-dim)', lineHeight: 1.6 }}
          >
            {assessment.narrative}
          </div>

          {/* Component scores */}
          <div className="mt-4 flex flex-col gap-2">
            {score.components.slice(0, 5).map(comp => (
              <div key={comp.id} className="flex items-center gap-3">
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)', width: 140, flexShrink: 0 }}>{comp.label}</div>
                <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                  <div
                    style={{
                      width: `${comp.value}%`,
                      height: '100%',
                      background: comp.value >= 75 ? '#ef4444' : comp.value >= 50 ? '#f97316' : comp.value >= 25 ? '#f59e0b' : '#22c55e',
                      borderRadius: 2,
                      transition: 'width 1s ease-out',
                    }}
                  />
                </div>
                <div style={{ fontSize: 11, fontWeight: 600, width: 36, textAlign: 'right', color: 'var(--color-text-dim)' }}>
                  {comp.value}%
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Auth results */}
        <div style={{ minWidth: 140 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', marginBottom: 8 }}>
            AUTHENTICATION
          </div>
          {analysis.authentication.checks.map(check => {
            const pass = check.verdict === 'PASS';
            const col = pass ? '#22c55e' : check.verdict === 'SOFTFAIL' ? '#f59e0b' : '#ef4444';
            return (
              <div key={check.mechanism} className="flex items-center justify-between mb-2">
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-dim)', width: 50 }}>{check.mechanism}</span>
                <span
                  style={{
                    fontSize: 10, fontWeight: 700, color: col,
                    background: `${col}15`, border: `1px solid ${col}30`,
                    borderRadius: 3, padding: '2px 6px',
                  }}
                >
                  {check.verdict}
                </span>
              </div>
            );
          })}

          <div className="mt-3" style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
            Origin:
          </div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#22d3ee' }}>
            {analysis.originAssessment.estimatedLocation?.country ?? 'Unknown'}
            {analysis.originAssessment.confidence > 0 && (
              <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>
                {' '}({analysis.originAssessment.confidence}% conf.)
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* IOC Table                                                           */
/* ------------------------------------------------------------------ */

function IocTable({ analysis }: { analysis: EmailAnalysis }) {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(val);
    setTimeout(() => setCopied(null), 1500);
  };

  const riskColor = (r: string) => {
    if (r === 'CRITICAL') return '#ef4444';
    if (r === 'HIGH') return '#f97316';
    if (r === 'MEDIUM') return '#f59e0b';
    if (r === 'LOW') return '#22c55e';
    return '#22d3ee';
  };

  return (
    <div className="panel" style={{ overflow: 'hidden' }}>
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
        <span className="section-title mb-0">Indicators of Compromise ({analysis.iocs.length})</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table w-full">
          <thead>
            <tr>
              <th>TYPE</th>
              <th>VALUE</th>
              <th>RISK</th>
              <th>REPUTATION</th>
              <th>SOURCE</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {analysis.iocs.map(ioc => (
              <tr key={ioc.id}>
                <td>
                  <span
                    style={{
                      fontSize: 10, fontWeight: 700,
                      color: '#22d3ee',
                      background: 'rgba(34,211,238,0.08)',
                      border: '1px solid rgba(34,211,238,0.2)',
                      borderRadius: 3, padding: '2px 6px',
                    }}
                  >
                    {ioc.type}
                  </span>
                </td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text)', maxWidth: 250, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ioc.value}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 10, fontWeight: 700, color: riskColor(ioc.risk), background: `${riskColor(ioc.risk)}15`, border: `1px solid ${riskColor(ioc.risk)}30`, borderRadius: 3, padding: '2px 6px' }}>
                    {ioc.risk}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 11, color: ioc.reputation === 'MALICIOUS' ? '#ef4444' : ioc.reputation === 'SUSPICIOUS' ? '#f97316' : ioc.reputation === 'CLEAN' ? '#22c55e' : 'var(--color-text-muted)' }}>
                    {ioc.reputation}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{ioc.source}</span>
                </td>
                <td>
                  <button
                    onClick={() => copy(ioc.value)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === ioc.value ? '#22c55e' : 'var(--color-text-muted)' }}
                  >
                    {copied === ioc.value ? <CheckCircle size={12} /> : <Copy size={12} />}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* AI Assessment Panel                                                 */
/* ------------------------------------------------------------------ */

function AiPanel({ analysis }: { analysis: EmailAnalysis }) {
  const navigate = useNavigate();
  return (
    <div className="panel" style={{ padding: 20 }}>
      <div className="section-title">AI Forensic Assessment</div>

      <div className="flex flex-col gap-2 mb-4">
        {analysis.assessment.findings.map(f => {
          const sev = f.severity;
          const col = sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f97316' : sev === 'MEDIUM' ? '#f59e0b' : '#22c55e';
          return (
            <div key={f.id} className="flex items-start gap-2">
              <span style={{ color: col, fontSize: 14, marginTop: 1, flexShrink: 0 }}>✓</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)' }}>{f.label}</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 1 }}>{f.evidence}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="divider" />

      <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', marginBottom: 8 }}>
        RECOMMENDED ANALYST ACTIONS
      </div>
      <div className="flex flex-col gap-2">
        {analysis.assessment.recommendedActions.map(a => {
          const col = a.priority === 'CRITICAL' ? '#ef4444' : a.priority === 'HIGH' ? '#f97316' : a.priority === 'MEDIUM' ? '#f59e0b' : '#22c55e';
          return (
            <div
              key={a.kind}
              className="flex items-center gap-2 p-2 rounded-lg"
              style={{ background: `${col}08`, border: `1px solid ${col}20` }}
            >
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: col, flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)' }}>{a.label}</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{a.rationale}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex flex-wrap gap-2 mt-4">
        <button onClick={() => navigate('/header-forensics')} className="btn-ghost text-xs" style={{ fontSize: 11 }}>
          Header Analysis →
        </button>
        <button onClick={() => navigate('/relay-chain')} className="btn-ghost text-xs" style={{ fontSize: 11 }}>
          Relay Chain →
        </button>
        <button onClick={() => navigate('/origin-trace')} className="btn-ghost text-xs" style={{ fontSize: 11 }}>
          Origin Map →
        </button>
        <button onClick={() => navigate('/graph')} className="btn-ghost text-xs" style={{ fontSize: 11 }}>
          Graph Investigation →
        </button>
        <button onClick={() => navigate('/reports')} className="btn-ghost text-xs" style={{ fontSize: 11 }}>
          Generate Report →
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main EmailAnalyzer page                                             */
/* ------------------------------------------------------------------ */

export function EmailAnalyzer() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();

  const [rawText, setRawText] = useState('');
  const [filename, setFilename] = useState('pasted-email.eml');
  const [running, setRunning] = useState(false);
  const [stages, setStages] = useState(initialStageStates());
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'paste' | 'upload'>('paste');
  const abortRef = useRef<AbortController | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      setRawText(ev.target?.result as string ?? '');
      setFilename(file.name);
      setTab('paste');
    };
    reader.readAsText(file);
  };

  const loadDemo = () => {
    setRawText(DEMO_EMAIL_RAW);
    setFilename(DEMO_EMAIL_FILENAME);
    setTab('paste');
  };

  const runAnalysis = useCallback(async () => {
    if (!rawText.trim()) { setError('Paste or upload an email to analyze.'); return; }
    setError(null);
    setRunning(true);
    setCurrentAnalysis(null);
    setStages(initialStageStates());

    abortRef.current = new AbortController();
    try {
      const outcome = await analyseEmail({
        raw: rawText,
        filename,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: tab === 'upload' ? 'File upload' : 'Analyst paste',
        useBackend: true,
        onStage: setStages,
        signal: abortRef.current.signal,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
    } catch (e) {
      if (e instanceof AnalysisInputError) {
        setError(e.message);
      } else if ((e as Error).name !== 'AbortError') {
        setError('Analysis failed unexpectedly. Check console for details.');
      }
    } finally {
      setRunning(false);
    }
  }, [rawText, filename, session, tab, setCurrentAnalysis, addToHistory]);

  const reset = () => {
    abortRef.current?.abort();
    setRawText('');
    setFilename('pasted-email.eml');
    setCurrentAnalysis(null);
    setStages(initialStageStates());
    setError(null);
    setRunning(false);
  };

  return (
    <div style={{ padding: 24, maxWidth: 1300, margin: '0 auto' }}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>Email Analyzer</h1>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Upload or paste a suspicious email for AI-powered forensic analysis
          </div>
        </div>
        {currentAnalysis && (
          <button onClick={reset} className="btn-ghost flex items-center gap-2">
            <RotateCcw size={13} /> NEW ANALYSIS
          </button>
        )}
      </div>

      {/* Input section */}
      {!currentAnalysis && (
        <div className="grid gap-5" style={{ gridTemplateColumns: '1fr', maxWidth: 700, margin: '0 auto' }}>
          {/* Tabs */}
          <div className="flex gap-2">
            {(['paste', 'upload'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                style={{
                  padding: '8px 16px',
                  borderRadius: 6,
                  border: '1px solid',
                  borderColor: tab === t ? 'rgba(34,211,238,0.4)' : 'var(--color-border)',
                  background: tab === t ? 'rgba(34,211,238,0.1)' : 'transparent',
                  color: tab === t ? '#22d3ee' : 'var(--color-text-muted)',
                  fontWeight: 600,
                  fontSize: 12,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                }}
              >
                {t === 'paste' ? '📋 Paste Raw Email' : '📁 Upload File'}
              </button>
            ))}
            <button
              onClick={loadDemo}
              style={{
                marginLeft: 'auto',
                padding: '8px 14px',
                borderRadius: 6,
                border: '1px solid rgba(245,158,11,0.3)',
                background: 'rgba(245,158,11,0.08)',
                color: '#f59e0b',
                fontWeight: 600,
                fontSize: 12,
                cursor: 'pointer',
                letterSpacing: '0.04em',
              }}
            >
              ⚡ LOAD DEMO EMAIL
            </button>
          </div>

          {tab === 'paste' ? (
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
              <div
                className="flex items-center justify-between px-4 py-2"
                style={{ borderBottom: '1px solid var(--color-border)' }}
              >
                <span style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {filename}
                </span>
                <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                  {rawText.length} chars
                </span>
              </div>
              <textarea
                className="st-input st-textarea"
                style={{
                  borderRadius: 0,
                  border: 'none',
                  minHeight: 280,
                  padding: 16,
                  resize: 'vertical',
                }}
                placeholder={`Paste raw email content here...\n\nExample:\nReceived: from mail.example.com...\nFrom: sender@domain.com\nTo: recipient@domain.com\nSubject: Test\n...`}
                value={rawText}
                onChange={e => setRawText(e.target.value)}
              />
            </div>
          ) : (
            <div
              className="panel flex flex-col items-center justify-center gap-4 cursor-pointer transition-all-fast"
              style={{ padding: 48, minHeight: 200, textAlign: 'center', border: '2px dashed var(--color-border)' }}
              onClick={() => fileRef.current?.click()}
              onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = '#22d3ee'; }}
              onDragLeave={e => { e.currentTarget.style.borderColor = 'var(--color-border)'; }}
              onDrop={e => {
                e.preventDefault();
                e.currentTarget.style.borderColor = 'var(--color-border)';
                const file = e.dataTransfer.files[0];
                if (file) {
                  const reader = new FileReader();
                  reader.onload = ev => { setRawText(ev.target?.result as string ?? ''); setFilename(file.name); setTab('paste'); };
                  reader.readAsText(file);
                }
              }}
            >
              <Upload size={32} color="#22d3ee" />
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text)' }}>Drop email file here</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>Supports .eml · .msg · .txt</div>
              </div>
              <input ref={fileRef} type="file" accept=".eml,.msg,.txt" style={{ display: 'none' }} onChange={handleFile} />
            </div>
          )}

          {error && (
            <div
              className="flex items-center gap-2 rounded-lg p-3"
              style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444', fontSize: 13 }}
            >
              <AlertTriangle size={14} />
              {error}
            </div>
          )}

          <button
            onClick={runAnalysis}
            disabled={running || !rawText.trim()}
            className="btn-primary flex items-center justify-center gap-2"
            style={{ height: 46, fontSize: 14, letterSpacing: '0.06em', opacity: !rawText.trim() ? 0.5 : 1 }}
          >
            <Search size={16} />
            ANALYZE EMAIL
          </button>
        </div>
      )}

      {/* Pipeline progress */}
      {running && <PipelineProgress stages={stages} />}

      {/* Results */}
      {currentAnalysis && !running && (
        <div className="flex flex-col gap-5 animate-fade-in">
          {/* Verdict + score */}
          <VerdictCard analysis={currentAnalysis} />

          {/* IOC Table */}
          <IocTable analysis={currentAnalysis} />

          {/* AI Panel */}
          <AiPanel analysis={currentAnalysis} />

          {/* Evidence / chain of custody */}
          <div className="panel" style={{ padding: 20 }}>
            <div className="section-title">Chain of Custody</div>
            <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))' }}>
              {[
                { label: 'EVIDENCE ID', value: currentAnalysis.evidence.evidenceId },
                { label: 'SHA-256', value: currentAnalysis.evidence.sha256.slice(0, 32) + '…' },
                { label: 'ACQUIRED', value: new Date(currentAnalysis.evidence.acquiredAt).toLocaleString('en-IN') },
                { label: 'SOURCE', value: currentAnalysis.evidence.source },
                { label: 'ANALYST', value: currentAnalysis.evidence.analystId },
                { label: 'INTEGRITY', value: currentAnalysis.evidence.integrity },
              ].map(f => (
                <div key={f.label}>
                  <div className="label">{f.label}</div>
                  <div style={{ fontSize: 12, color: f.label === 'INTEGRITY' ? (f.value === 'VERIFIED' ? '#22c55e' : '#ef4444') : 'var(--color-text)', fontFamily: ['SHA-256', 'EVIDENCE ID'].includes(f.label) ? 'var(--font-mono)' : 'inherit', marginTop: 2, wordBreak: 'break-all' }}>
                    {f.value}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Warning note */}
          <div
            className="flex items-start gap-3 rounded-lg p-3"
            style={{ background: 'rgba(34,211,238,0.04)', border: '1px solid rgba(34,211,238,0.1)', fontSize: 11, color: 'var(--color-text-muted)' }}
          >
            <Info size={13} style={{ color: '#22d3ee', marginTop: 1, flexShrink: 0 }} />
            <div>
              <strong style={{ color: '#22d3ee' }}>Important:</strong> This analysis describes probable infrastructure, estimated locations, and associated indicators.
              It does not constitute definitive identification of any individual. All findings are investigative leads requiring further verification.
              {currentAnalysis.origin === 'SIMULATED' && (
                <span style={{ color: '#f59e0b', marginLeft: 8 }}>⚠ Analysis computed by local engine (backend not reached).</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
