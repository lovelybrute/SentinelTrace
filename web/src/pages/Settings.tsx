import React, { useState } from 'react';
import {
  Settings as SettingsIcon, Shield, Lock, Eye, Database,
  UserCheck, History, AlertTriangle, CheckCircle, Save, Play, Sparkles, Zap
} from 'lucide-react';
import { MOCK_AUDIT } from '@/services/mockDataService';
import { useSession } from '@/context/SessionContext';
import { TeamBruteIntro } from '@/components/intro/TeamBruteIntro';
import type { PrivacySettings } from '@/types';

export function Settings() {
  const { session } = useSession();
  const [saved, setSaved] = useState(false);
  const [replayIntro, setReplayIntro] = useState(false);
  const [introEnabled, setIntroEnabled] = useState(() => {
    return localStorage.getItem('sentineltrace_intro_enabled') !== 'false';
  });

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
    localStorage.setItem('sentineltrace_intro_enabled', introEnabled ? 'true' : 'false');
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleTriggerReplay = () => {
    setReplayIntro(true);
  };

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }} className="space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <SettingsIcon size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Privacy, Compliance & Visual System Settings
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Data minimization protocols, role-based access control, cryptographic evidence retention, and cinematic motion preferences
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

        {/* Section 2: Visual Experience & Cinematic Intro */}
        <div className="panel" style={{ padding: 24 }}>
          <div className="section-title">Visual Experience & Motion Settings</div>
          <p style={{ fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 16 }}>
            Customize startup animations, 3D WebGL acceleration, and accessibility reduced-motion overrides.
          </p>

          <div className="flex flex-col gap-4">
            <label className="flex items-center justify-between p-3 rounded-lg border border-border cursor-pointer" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>Team Brute Cinematic Intro</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Play flowing crimson cyber fluid animation on first launch</div>
              </div>
              <input
                type="checkbox"
                checked={introEnabled}
                onChange={e => {
                  setIntroEnabled(e.target.checked);
                  localStorage.setItem('sentineltrace_intro_enabled', e.target.checked ? 'true' : 'false');
                }}
              />
            </label>

            <div className="p-3.5 rounded-lg bg-[#050a18] border border-cyan-500/20 flex items-center justify-between">
              <div>
                <div className="text-xs font-mono font-bold text-slate-200">Replay Cinematic Intro</div>
                <div className="text-[10px] text-slate-500 font-mono">Run the full cinematic Team Brute startup sequence manually</div>
              </div>
              <button
                onClick={handleTriggerReplay}
                className="btn-primary text-xs font-mono flex items-center gap-1.5"
              >
                <Play size={12} />
                <span>REPLAY INTRO</span>
              </button>
            </div>

            <div className="p-3 rounded-lg bg-[#050a18] border border-slate-800 text-xs font-mono space-y-1">
              <div className="text-[10px] text-slate-400 font-bold">ACCESSIBILITY (prefers-reduced-motion)</div>
              <div className="text-slate-300 text-[11px]">
                {window.matchMedia('(prefers-reduced-motion: reduce)').matches
                  ? 'Active in your browser: High-motion effects and continuous 3D rotations are disabled.'
                  : 'Hardware-accelerated 3D and fluid animations enabled.'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Replay Intro Modal */}
      {replayIntro && (
        <TeamBruteIntro
          forcePlay={true}
          onComplete={() => setReplayIntro(false)}
        />
      )}
    </div>
  );
}
