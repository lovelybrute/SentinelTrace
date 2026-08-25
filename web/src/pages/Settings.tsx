import React, { useState } from 'react';
import {
  Settings as SettingsIcon, Shield, Lock, Eye, Database,
  UserCheck, History, AlertTriangle, CheckCircle, Save
} from 'lucide-react';
import { MOCK_AUDIT } from '@/services/mockDataService';
import { useSession } from '@/context/SessionContext';
import type { PrivacySettings } from '@/types';

export function Settings() {
  const { session } = useSession();
  const [saved, setSaved] = useState(false);

  const [privacy, setPrivacy] = useState<PrivacySettings>({
    maskRecipients: true,
    maskBodyContent: false,
    retentionDays: 90,
    storeRawEmail: true,
    redactAttachments: false,
    auditLogging: true,
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <SettingsIcon size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Privacy, Compliance & System Settings
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Data minimization protocols, role-based access control, cryptographic evidence retention, and tamper-proof audit trails
          </div>
        </div>

        {saved && (
          <div className="flex items-center gap-2 text-xs" style={{ color: '#22c55e', background: 'rgba(34,197,94,0.15)', padding: '6px 14px', borderRadius: 6 }}>
            <CheckCircle size={14} />
            <span>Settings saved successfully!</span>
          </div>
        )}
      </div>

      <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(340px, 1fr) minmax(340px, 1fr)' }}>
        {/* Section 1: Privacy & Data Minimization */}
        <div className="panel" style={{ padding: 24 }}>
          <div className="section-title">Data Minimization & Redaction</div>
          <p style={{ fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 16 }}>
            Ensure compliance with DPDP Act & CERT-In guidelines by masking personally identifiable information (PII) during automated ingestion.
          </p>

          <form onSubmit={handleSave} className="flex flex-col gap-4">
            <label className="flex items-center justify-between p-3 rounded-lg border border-border cursor-pointer" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>Mask Recipient PII</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Redact internal usernames and personal mailboxes in analyst feeds</div>
              </div>
              <input
                type="checkbox"
                checked={privacy.maskRecipients}
                onChange={e => setPrivacy({ ...privacy, maskRecipients: e.target.checked })}
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-lg border border-border cursor-pointer" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>Store Raw RFC 5322 Bytes</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Preserve full original bytes for SHA-256 evidence verification</div>
              </div>
              <input
                type="checkbox"
                checked={privacy.storeRawEmail}
                onChange={e => setPrivacy({ ...privacy, storeRawEmail: e.target.checked })}
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-lg border border-border cursor-pointer" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>Immutable Audit Logging</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Record every analyst query, export, and triage action to forensic log</div>
              </div>
              <input
                type="checkbox"
                checked={privacy.auditLogging}
                onChange={e => setPrivacy({ ...privacy, auditLogging: e.target.checked })}
              />
            </label>

            <div>
              <label className="label mb-1 block">Evidence Retention Period (Days)</label>
              <select
                className="st-input"
                value={privacy.retentionDays}
                onChange={e => setPrivacy({ ...privacy, retentionDays: Number(e.target.value) })}
              >
                <option value={30}>30 Days (Standard SOC Triage)</option>
                <option value={90}>90 Days (CERT-In Mandated Default)</option>
                <option value={180}>180 Days (Extended Cybercrime Retention)</option>
                <option value={365}>365 Days (Critical Infrastructure)</option>
              </select>
            </div>

            <button type="submit" className="btn-primary flex items-center justify-center gap-2 mt-2">
              <Save size={14} />
              <span>SAVE PRIVACY CONFIGURATION</span>
            </button>
          </form>
        </div>

        {/* Section 2: Role-Based Access Control (RBAC) */}
        <div className="panel" style={{ padding: 24 }}>
          <div className="section-title">Active Role & Authorization Matrix</div>
          <div className="flex items-center gap-3 p-3 rounded-lg border border-border mb-4" style={{ background: 'rgba(34,211,238,0.05)' }}>
            <div
              style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'linear-gradient(135deg, #0e7490, #22d3ee)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 14, fontWeight: 800, color: '#030712',
              }}
            >
              {session?.displayName.charAt(0) || 'A'}
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text)' }}>
                {session?.displayName} ({session?.analystId})
              </div>
              <div style={{ fontSize: 11, color: '#22d3ee' }}>
                Role: <strong>{session?.role}</strong> · {session?.unit}
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2 text-xs">
            {[
              { role: 'ADMIN', perm: 'Full System Config, Retention Tuning, User Management', active: session?.role === 'ADMIN' },
              { role: 'SOC ANALYST', perm: 'Email Ingestion, Threat Triage, Blocklist Generation', active: session?.role === 'SOC_ANALYST' },
              { role: 'INVESTIGATOR', perm: 'Campaign Clustering, Evidence Attribution, Forensic Reports', active: session?.role === 'INVESTIGATOR' },
              { role: 'AUDITOR', perm: 'Read-Only Audit Trail, Chain of Custody Validation', active: session?.role === 'AUDITOR' },
            ].map(r => (
              <div
                key={r.role}
                className="p-3 rounded-lg border border-border flex items-center justify-between"
                style={{
                  background: r.active ? 'rgba(34,211,238,0.1)' : 'rgba(255,255,255,0.02)',
                  borderColor: r.active ? 'rgba(34,211,238,0.4)' : undefined,
                }}
              >
                <div>
                  <div style={{ fontWeight: 800, color: r.active ? '#22d3ee' : 'var(--color-text)' }}>
                    {r.role} {r.active && '(Current Session)'}
                  </div>
                  <div style={{ color: 'var(--color-text-muted)', marginTop: 2 }}>{r.perm}</div>
                </div>
                {r.active && <CheckCircle size={16} color="#22d3ee" />}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Section 3: Immutable Audit Trail Table */}
      <div className="panel mt-6" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div>
            <span className="section-title mb-0">Cryptographic System Audit Trail</span>
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 2 }}>
              Tamper-evident log of all evidentiary access, report generations, and blocklist actions
            </div>
          </div>
          <span className="status-dot online" />
        </div>

        <table className="data-table w-full text-xs">
          <thead>
            <tr>
              <th>LOG ID</th>
              <th>TIMESTAMP</th>
              <th>OPERATOR</th>
              <th>ACTION</th>
              <th>TARGET ENTITY</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_AUDIT.map(entry => (
              <tr key={entry.id}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>{entry.id}</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{new Date(entry.at).toLocaleTimeString('en-IN')}</td>
                <td style={{ fontWeight: 600, color: '#22d3ee' }}>{entry.actor} ({entry.role})</td>
                <td style={{ fontWeight: 700 }}>{entry.action}</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{entry.target}</td>
                <td>
                  <span
                    style={{
                      fontSize: 9, fontWeight: 800,
                      color: entry.outcome === 'SUCCESS' ? '#22c55e' : '#ef4444',
                      background: entry.outcome === 'SUCCESS' ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                      padding: '2px 6px', borderRadius: 3,
                    }}
                  >
                    {entry.outcome}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
