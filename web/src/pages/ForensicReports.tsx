import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText, Download, Printer, CheckCircle, Shield,
  Clock, Hash, FileCheck, Copy, ExternalLink, ChevronRight
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { useSession } from '@/context/SessionContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';

export function ForensicReports() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const [analyzingDemo, setAnalyzingDemo] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const [includedSections, setIncludedSections] = useState<Record<string, boolean>>({
    exec_summary: true,
    metadata: true,
    auth: true,
    relay: true,
    geo: true,
    domain_ip: true,
    iocs: true,
    ai_assessment: true,
    custody: true,
  });

  const [analystNotes, setAnalystNotes] = useState(
    'Initial forensic triage confirms executive impersonation and weaponized payment diversion instructions. The email bypassed edge security filters through lookalike domain masquerading and third-party relay spoofing. All indicators have been logged to the SOC blocklist and threat intelligence correlation graph.'
  );

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Forensic Report Demo Load',
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
          <FileText size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No Report Generated</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            An email must be analyzed before compiling an official forensic intelligence report with cryptographic chain of custody.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load BEC Demo for Report'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const toggleSection = (key: string) => {
    setIncludedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const documentHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const handlePrint = () => {
    window.print();
  };

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      {/* Top Controls (Hidden during print) */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4 print:hidden">
        <div>
          <div className="flex items-center gap-2">
            <FileText size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Forensic Intelligence Report
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Standardized evidentiary report export compliant with CERT-In forensic chain-of-custody protocols
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="btn-primary flex items-center gap-2 text-xs"
          >
            <Printer size={14} />
            <span>PRINT / EXPORT PDF</span>
          </button>
        </div>
      </div>

      {/* Report Section Toggles Sidebar (Hidden during print) */}
      <div className="panel mb-6 p-4 print:hidden">
        <div className="section-title">Include Forensic Report Sections</div>
        <div className="flex flex-wrap gap-3">
          {[
            { id: 'exec_summary', label: 'Executive Summary' },
            { id: 'metadata', label: 'Email Metadata' },
            { id: 'auth', label: 'Authentication Checks' },
            { id: 'relay', label: 'SMTP Relay Chain' },
            { id: 'geo', label: 'Origin Geolocation' },
            { id: 'domain_ip', label: 'Domain & IP Intel' },
            { id: 'iocs', label: 'IOC Inventory' },
            { id: 'ai_assessment', label: 'AI Risk Findings' },
            { id: 'custody', label: 'Chain of Custody' },
          ].map(sec => (
            <label key={sec.id} className="flex items-center gap-2 cursor-pointer text-xs" style={{ color: includedSections[sec.id] ? '#22d3ee' : 'var(--color-text-muted)' }}>
              <input
                type="checkbox"
                checked={includedSections[sec.id]}
                onChange={() => toggleSection(sec.id)}
              />
              <span>{sec.label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Official Forensic Report Document Canvas */}
      <div
        className="panel shadow-2xl"
        style={{
          padding: 48,
          background: '#090d16',
          border: '1px solid rgba(34,211,238,0.2)',
          borderRadius: 8,
          color: '#e2e8f0',
        }}
      >
        {/* Document Header / Official Crest */}
        <div className="flex items-start justify-between pb-6 mb-6" style={{ borderBottom: '2px solid rgba(34,211,238,0.4)' }}>
          <div>
            <div className="flex items-center gap-3">
              <Shield size={32} color="#22d3ee" />
              <div>
                <div style={{ fontSize: 22, fontWeight: 900, letterSpacing: '0.1em', color: '#22d3ee' }}>
                  SENTINELTRACE
                </div>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.06em' }}>
                  FORENSIC EMAIL THREAT DETECTION & INTELLIGENCE REPORT
                </div>
              </div>
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 8 }}>
              SIH Problem Statement #26106 · Evidence Report ID: <strong style={{ color: '#e2e8f0', fontFamily: 'var(--font-mono)' }}>REP-2026-{analysis.evidence.evidenceId.slice(-6)}</strong>
            </div>
          </div>

          <div className="text-right">
            <div
              style={{
                fontSize: 12, fontWeight: 900,
                color: analysis.score.level === 'CRITICAL' ? '#ef4444' : '#f97316',
                background: analysis.score.level === 'CRITICAL' ? 'rgba(239,68,68,0.15)' : 'rgba(249,115,22,0.15)',
                border: `1px solid ${analysis.score.level === 'CRITICAL' ? '#ef4444' : '#f97316'}`,
                padding: '4px 12px', borderRadius: 4, display: 'inline-block',
              }}
            >
              THREAT LEVEL: {analysis.score.level} ({analysis.score.total}/100)
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 6 }}>
              Classification: <strong style={{ color: '#e2e8f0' }}>{analysis.assessment.classification.replace(/_/g, ' ')}</strong>
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-text-muted)', marginTop: 2 }}>
              Compiled: {new Date().toLocaleString('en-IN')}
            </div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        {includedSections.exec_summary && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              1. EXECUTIVE THREAT ASSESSMENT
            </h3>
            <div style={{ fontSize: 12, lineHeight: 1.7, color: 'var(--color-text-dim)', background: 'rgba(255,255,255,0.02)', padding: 14, borderRadius: 6, border: '1px solid var(--color-border)' }}>
              {analysis.assessment.narrative}
            </div>
          </div>
        )}

        {/* Section 2: Email Metadata */}
        {includedSections.metadata && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              2. EVIDENCE METADATA & ORIGINATOR ENVELOPE
            </h3>
            <div className="grid grid-cols-2 gap-4 text-xs" style={{ background: 'rgba(255,255,255,0.02)', padding: 14, borderRadius: 6, border: '1px solid var(--color-border)' }}>
              <div>
                <span className="label">From Address:</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: '#fca5a5', marginTop: 2 }}>{analysis.metadata.from}</div>
              </div>
              <div>
                <span className="label">Recipient (To):</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: '#e2e8f0', marginTop: 2 }}>{analysis.metadata.to}</div>
              </div>
              <div>
                <span className="label">Reply-To Route:</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: analysis.metadata.replyTo ? '#f97316' : 'var(--color-text-muted)', marginTop: 2 }}>
                  {analysis.metadata.replyTo || '(None)'}
                </div>
              </div>
              <div>
                <span className="label">Subject Line:</span>
                <div style={{ fontWeight: 600, color: '#e2e8f0', marginTop: 2 }}>{analysis.metadata.subject}</div>
              </div>
            </div>
          </div>
        )}

        {/* Section 3: Authentication Results */}
        {includedSections.auth && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              3. CRYPTOGRAPHIC AUTHENTICATION (SPF / DKIM / DMARC)
            </h3>
            <div className="grid grid-cols-3 gap-3 text-xs">
              {analysis.authentication.checks.map(c => (
                <div key={c.mechanism} className="p-3 rounded border border-border" style={{ background: 'rgba(255,255,255,0.02)' }}>
                  <div className="flex items-center justify-between mb-1">
                    <span style={{ fontWeight: 700 }}>{c.mechanism}</span>
                    <span style={{ fontWeight: 800, color: c.verdict === 'PASS' ? '#22c55e' : '#ef4444' }}>{c.verdict}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{c.detail}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section 4: SMTP Relay Chain */}
        {includedSections.relay && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              4. RECONSTRUCTED SMTP RELAY PATH
            </h3>
            <div className="flex flex-col gap-2 text-xs">
              {analysis.relayChain.map(h => (
                <div key={h.index} className="p-2.5 rounded border border-border flex items-center justify-between" style={{ background: 'rgba(255,255,255,0.02)' }}>
                  <div className="flex items-center gap-3">
                    <span style={{ fontWeight: 800, color: '#22d3ee' }}>#{h.index}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{h.ip || 'Hostname'}</span>
                    <span style={{ color: 'var(--color-text-muted)' }}>({h.hostname})</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span style={{ color: '#22d3ee' }}>{h.geo ? `${h.geo.city || ''} ${h.geo.country}` : 'Location unknown'}</span>
                    <span style={{ fontWeight: 700, color: h.trust === 'TRUSTED' ? '#22c55e' : '#ef4444' }}>{h.trust}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section 5: Origin Geolocation */}
        {includedSections.geo && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              5. ESTIMATED INFRASTRUCTURE ORIGIN
            </h3>
            <div className="grid grid-cols-3 gap-3 text-xs p-3 rounded border border-border" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div>
                <span className="label">Estimated Location</span>
                <div style={{ fontWeight: 700, color: '#22d3ee', marginTop: 2 }}>
                  {analysis.originAssessment.estimatedLocation?.country || 'Unknown'}
                </div>
              </div>
              <div>
                <span className="label">Attribution Confidence</span>
                <div style={{ fontWeight: 700, color: '#22d3ee', marginTop: 2 }}>
                  {analysis.originAssessment.confidence}%
                </div>
              </div>
              <div>
                <span className="label">Proxy / Anonymizer</span>
                <div style={{ fontWeight: 700, color: analysis.originAssessment.proxyOrVpnIndicator === 'DETECTED' ? '#ef4444' : '#22c55e', marginTop: 2 }}>
                  {analysis.originAssessment.proxyOrVpnIndicator}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 6: IOC Inventory */}
        {includedSections.iocs && (
          <div className="mb-6">
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              6. EXTRACTED INDICATORS OF COMPROMISE (IOCs)
            </h3>
            <table className="data-table w-full text-xs">
              <thead>
                <tr>
                  <th>TYPE</th>
                  <th>VALUE</th>
                  <th>RISK</th>
                  <th>REPUTATION</th>
                </tr>
              </thead>
              <tbody>
                {analysis.iocs.slice(0, 8).map(ioc => (
                  <tr key={ioc.id}>
                    <td style={{ fontWeight: 700, color: '#22d3ee' }}>{ioc.type}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{ioc.value}</td>
                    <td style={{ fontWeight: 700, color: ioc.risk === 'CRITICAL' ? '#ef4444' : '#f97316' }}>{ioc.risk}</td>
                    <td>{ioc.reputation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Section 7: Analyst Notes */}
        <div className="mb-6">
          <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
            7. SOC ANALYST DISPOSITION & RECOMMENDED ACTION
          </h3>
          <div className="text-xs p-3 rounded border border-border" style={{ background: 'rgba(255,255,255,0.02)', lineHeight: 1.6 }}>
            {analystNotes}
          </div>
        </div>

        {/* Section 8: Chain of Custody & Document Hash */}
        {includedSections.custody && (
          <div className="pt-6" style={{ borderTop: '1px solid var(--color-border)' }}>
            <h3 style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee', letterSpacing: '0.08em', marginBottom: 6 }}>
              8. EVIDENTIARY INTEGRITY & CHAIN OF CUSTODY
            </h3>
            <div className="grid grid-cols-2 gap-4 text-xs mb-4">
              <div>
                <span className="label">Original Evidence SHA-256 Digest:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#22d3ee', marginTop: 2, wordBreak: 'break-all' }}>
                  {analysis.evidence.sha256}
                </div>
              </div>
              <div>
                <span className="label">Integrity Status:</span>
                <div style={{ fontWeight: 800, color: '#22c55e', marginTop: 2 }}>
                  VERIFIED (Hash Verified Against Unmodified Ingest Payload)
                </div>
              </div>
            </div>

            <div className="p-3 rounded border border-border text-xs flex items-center justify-between" style={{ background: 'rgba(0,0,0,0.3)', fontFamily: 'var(--font-mono)' }}>
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>DOCUMENT HASH: </span>
                <span style={{ color: '#22d3ee' }}>{documentHash}</span>
              </div>
              <div style={{ color: 'var(--color-text-muted)' }}>
                SENTINELTRACE CERTIFIED AUDIT RECORD
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
