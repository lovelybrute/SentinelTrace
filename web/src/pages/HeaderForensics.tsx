import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileSearch, Shield, AlertTriangle, CheckCircle, Copy,
  Info, ExternalLink, ArrowRight, Eye, RefreshCw, Layers
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';

export function HeaderForensics() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [analyzingDemo, setAnalyzingDemo] = useState(false);

  const copyToClipboard = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Demo Email Header Inspection',
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
          <FileSearch size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No Active Email Analysis</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            Please analyze an email first or load the pre-configured SIH demo threat to inspect forensic header anomalies, DKIM/SPF/DMARC alignment, and authentication headers.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load BEC Demo Email'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const { metadata, authentication, headers, rawHeaders } = analysis;

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSearch size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              RFC 5322 & Forensic Header Analysis
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Deep inspection of originator fields, authentication headers, delivery stamps, and header chain integrity
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/relay-chain')} className="btn-ghost text-xs flex items-center gap-1.5">
            <span>View SMTP Relay Chain</span>
            <ArrowRight size={13} />
          </button>
          <button onClick={() => navigate('/origin-trace')} className="btn-ghost text-xs flex items-center gap-1.5">
            <span>View Origin Map</span>
            <ArrowRight size={13} />
          </button>
        </div>
      </div>

      {/* Primary Header Fields Grid */}
      <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        {/* Originator Fields */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Envelope & Originator Fields</div>
          <div className="flex flex-col gap-3">
            <div>
              <div className="label">From (Display & Address)</div>
              <div className="flex items-center justify-between mt-1">
                <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: '#fca5a5', fontWeight: 600, wordBreak: 'break-all' }}>
                  {metadata.from || 'Not specified'}
                </div>
                <button
                  onClick={() => copyToClipboard('from', metadata.from)}
                  style={{ background: 'none', border: 'none', color: copiedKey === 'from' ? '#22c55e' : 'var(--color-text-muted)', cursor: 'pointer', padding: 4 }}
                >
                  {copiedKey === 'from' ? <CheckCircle size={13} /> : <Copy size={13} />}
                </button>
              </div>
            </div>

            <div>
              <div className="label">Reply-To (Return Path Route)</div>
              <div className="flex items-center justify-between mt-1">
                <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: metadata.replyTo ? '#f97316' : 'var(--color-text-muted)', fontWeight: 600, wordBreak: 'break-all' }}>
                  {metadata.replyTo || '(None specified)'}
                </div>
                {metadata.replyTo && (
                  <button
                    onClick={() => copyToClipboard('replyTo', metadata.replyTo!)}
                    style={{ background: 'none', border: 'none', color: copiedKey === 'replyTo' ? '#22c55e' : 'var(--color-text-muted)', cursor: 'pointer', padding: 4 }}
                  >
                    {copiedKey === 'replyTo' ? <CheckCircle size={13} /> : <Copy size={13} />}
                  </button>
                )}
              </div>
              {metadata.replyTo && metadata.from && !metadata.replyTo.includes(metadata.from.split('@')[1]?.replace('>', '') || '') && (
                <div className="mt-1.5 flex items-center gap-1.5" style={{ fontSize: 11, color: '#f97316' }}>
                  <AlertTriangle size={12} />
                  <span>Reply-To domain differs from From domain (BEC / Divert risk)</span>
                </div>
              )}
            </div>

            <div>
              <div className="label">Return-Path</div>
              <div className="flex items-center justify-between mt-1">
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', wordBreak: 'break-all' }}>
                  {metadata.returnPath || '(Not provided)'}
                </div>
                {metadata.returnPath && (
                  <button
                    onClick={() => copyToClipboard('returnPath', metadata.returnPath!)}
                    style={{ background: 'none', border: 'none', color: copiedKey === 'returnPath' ? '#22c55e' : 'var(--color-text-muted)', cursor: 'pointer', padding: 4 }}
                  >
                    {copiedKey === 'returnPath' ? <CheckCircle size={13} /> : <Copy size={13} />}
                  </button>
                )}
              </div>
            </div>

            <div>
              <div className="label">To (Intended Recipient)</div>
              <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', marginTop: 2, wordBreak: 'break-all' }}>
                {metadata.to || 'Not specified'}
              </div>
            </div>
          </div>
        </div>

        {/* Message Metadata */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Message Transport Metadata</div>
          <div className="flex flex-col gap-3">
            <div>
              <div className="label">Subject</div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)', marginTop: 2 }}>
                {metadata.subject || '(No subject)'}
              </div>
            </div>

            <div>
              <div className="label">Message-ID</div>
              <div className="flex items-center justify-between mt-1">
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', wordBreak: 'break-all' }}>
                  {metadata.messageId || '(Missing Message-ID)'}
                </div>
                {metadata.messageId && (
                  <button
                    onClick={() => copyToClipboard('messageId', metadata.messageId!)}
                    style={{ background: 'none', border: 'none', color: copiedKey === 'messageId' ? '#22c55e' : 'var(--color-text-muted)', cursor: 'pointer', padding: 4 }}
                  >
                    {copiedKey === 'messageId' ? <CheckCircle size={13} /> : <Copy size={13} />}
                  </button>
                )}
              </div>
            </div>

            <div>
              <div className="label">Date Header</div>
              <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', marginTop: 2 }}>
                {metadata.date || '(No Date header)'}
              </div>
            </div>

            <div>
              <div className="label">Total Received Relay Hops</div>
              <div className="flex items-center gap-2 mt-1">
                <span style={{ fontSize: 16, fontWeight: 800, color: '#22d3ee', fontFamily: 'var(--font-mono)' }}>
                  {analysis.relayChain.length}
                </span>
                <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                  hops reconstructed from Received headers
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Authentication Summary Score */}
        <div className="panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div className="section-title">Authentication & Trust Score</div>
            <div className="flex items-center gap-4 my-3">
              <div
                style={{
                  width: 60, height: 60, borderRadius: '50%',
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                  background: authentication.trustScore > 70 ? 'rgba(34,197,94,0.15)' : authentication.trustScore > 40 ? 'rgba(245,158,11,0.15)' : 'rgba(239,68,68,0.15)',
                  border: `2px solid ${authentication.trustScore > 70 ? '#22c55e' : authentication.trustScore > 40 ? '#f59e0b' : '#ef4444'}`,
                }}
              >
                <span style={{ fontSize: 18, fontWeight: 900, color: authentication.trustScore > 70 ? '#22c55e' : authentication.trustScore > 40 ? '#f59e0b' : '#ef4444' }}>
                  {authentication.trustScore}
                </span>
                <span style={{ fontSize: 8, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>TRUST</span>
              </div>

              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text)' }}>
                  Sender Domain: <span style={{ color: '#22d3ee', fontFamily: 'var(--font-mono)' }}>{authentication.senderDomain}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                  {authentication.alignmentNote || 'Authentication alignment evaluation'}
                </div>
              </div>
            </div>
          </div>

          <div style={{ fontSize: 11, color: 'var(--color-text-muted)', background: 'rgba(0,0,0,0.2)', padding: 10, borderRadius: 6, border: '1px solid var(--color-border)' }}>
            <strong>Forensic Note:</strong> A sender domain failing SPF or DMARC indicates that the sending MTA IP is not authorized by the legitimate domain DNS owner.
          </div>
        </div>
      </div>

      {/* Authentication Checks Breakdown */}
      <div className="panel mb-6" style={{ padding: 20 }}>
        <div className="section-title">Cryptographic & Policy Authentication (SPF / DKIM / DMARC)</div>
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          {authentication.checks.map(check => {
            const isPass = check.verdict === 'PASS';
            const isSoftFail = check.verdict === 'SOFTFAIL' || check.verdict === 'NEUTRAL';
            const color = isPass ? '#22c55e' : isSoftFail ? '#f59e0b' : '#ef4444';

            return (
              <div
                key={check.mechanism}
                className="panel-elevated"
                style={{
                  padding: 16,
                  borderLeft: `4px solid ${color}`,
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Shield size={16} color={color} />
                    <span style={{ fontSize: 14, fontWeight: 800, letterSpacing: '0.05em' }}>
                      {check.mechanism}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 11, fontWeight: 800,
                      color,
                      background: `${color}15`,
                      border: `1px solid ${color}30`,
                      borderRadius: 4,
                      padding: '2px 8px',
                    }}
                  >
                    {check.verdict}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 8, minHeight: 36 }}>
                  {check.detail}
                </div>

                {check.aligned !== null && (
                  <div className="flex items-center gap-1.5 mb-2" style={{ fontSize: 11 }}>
                    <span style={{ color: 'var(--color-text-muted)' }}>Identifier Alignment:</span>
                    <span style={{ fontWeight: 600, color: check.aligned ? '#22c55e' : '#ef4444' }}>
                      {check.aligned ? 'ALIGNED' : 'UNALIGNED / MISMATCH'}
                    </span>
                  </div>
                )}

                {check.raw && (
                  <div className="code-block" style={{ fontSize: 10, padding: 8, maxHeight: 80, overflowY: 'auto' }}>
                    {check.raw}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed Raw / Parsed Headers Table */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
          <div className="section-title mb-0">Parsed Header Fields ({headers.length})</div>
          <button
            onClick={() => copyToClipboard('rawHeaders', rawHeaders)}
            className="btn-ghost text-xs flex items-center gap-1.5"
            style={{ fontSize: 11 }}
          >
            {copiedKey === 'rawHeaders' ? <CheckCircle size={12} color="#22c55e" /> : <Copy size={12} />}
            <span>{copiedKey === 'rawHeaders' ? 'Copied Raw Headers' : 'Copy All Headers'}</span>
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table w-full">
            <thead>
              <tr>
                <th style={{ width: 220 }}>HEADER NAME</th>
                <th>VALUE & ANOMALIES</th>
                <th style={{ width: 100 }}>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {headers.map((h, i) => (
                <tr key={i}>
                  <td style={{ verticalAlign: 'top' }}>
                    <span style={{ fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-mono)', color: '#22d3ee' }}>
                      {h.name}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text)', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                      {h.value}
                    </div>
                    {h.anomaly && (
                      <div
                        className="flex items-center gap-1.5 mt-2 px-2.5 py-1 rounded"
                        style={{
                          background: 'rgba(239,68,68,0.1)',
                          border: '1px solid rgba(239,68,68,0.25)',
                          color: '#fca5a5',
                          fontSize: 11,
                          width: 'fit-content',
                        }}
                      >
                        <AlertTriangle size={12} color="#ef4444" />
                        <span><strong>Anomaly ({h.anomaly.severity}):</strong> {h.anomaly.reason}</span>
                      </div>
                    )}
                  </td>
                  <td style={{ verticalAlign: 'top' }}>
                    {h.anomaly ? (
                      <span style={{ fontSize: 10, fontWeight: 700, color: '#ef4444', background: 'rgba(239,68,68,0.15)', padding: '2px 6px', borderRadius: 4 }}>
                        SUSPICIOUS
                      </span>
                    ) : (
                      <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-muted)' }}>
                        VALID
                      </span>
                    )}
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
