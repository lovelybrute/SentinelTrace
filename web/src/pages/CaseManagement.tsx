import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen, Plus, Shield, Clock, User, CheckCircle,
  FileText, MessageSquare, AlertTriangle, Paperclip, ChevronRight,
  Filter, Search
} from 'lucide-react';
import { MOCK_CASES } from '@/services/mockDataService';
import { useSession } from '@/context/SessionContext';
import type { CaseRecord, CaseStatus, Severity } from '@/types';

export function CaseManagement() {
  const { session } = useSession();
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>(MOCK_CASES);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(MOCK_CASES[0].id);
  const [newNoteBody, setNewNoteBody] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('HIGH');
  const [newSummary, setNewSummary] = useState('');

  const activeCase = cases.find(c => c.id === selectedCaseId) || cases[0];

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteBody.trim()) return;

    const newNote = {
      id: `note-${Date.now()}`,
      at: new Date().toISOString(),
      author: session?.analystId || 'SOC-07',
      body: newNoteBody.trim(),
    };

    setCases(prev => prev.map(c =>
      c.id === selectedCaseId
        ? { ...c, notes: [newNote, ...c.notes], updatedAt: new Date().toISOString() }
        : c
    ));

    setNewNoteBody('');
  };

  const handleCreateCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    const newCase: CaseRecord = {
      id: `ST-2026-${String(Math.floor(1000 + Math.random() * 9000))}`,
      title: newTitle.trim(),
      severity: newSeverity,
      status: 'INVESTIGATING',
      assignedTo: session?.analystId || 'SOC-07',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      summary: newSummary.trim() || 'New email threat incident investigation initiated.',
      linkedAnalysisIds: [],
      linkedCampaignIds: ['CT-2041'],
      indicators: [],
      notes: [{
        id: `note-init`,
        at: new Date().toISOString(),
        author: session?.analystId || 'SOC-07',
        body: 'Case created and assigned for forensic attribution and evidence correlation.',
      }],
      evidence: [],
      slaDueAt: new Date(Date.now() + 48 * 3600000).toISOString(),
    };

    setCases([newCase, ...cases]);
    setSelectedCaseId(newCase.id);
    setShowCreateModal(false);
    setNewTitle('');
    setNewSummary('');
  };

  const getStatusBadge = (status: CaseStatus) => {
    switch (status) {
      case 'INVESTIGATING': return { color: '#22d3ee', bg: 'rgba(34,211,238,0.15)', border: 'rgba(34,211,238,0.3)' };
      case 'PENDING_REVIEW': return { color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.3)' };
      case 'CLOSED': return { color: '#22c55e', bg: 'rgba(34,197,94,0.15)', border: 'rgba(34,197,94,0.3)' };
      case 'OPEN':
      default: return { color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.3)' };
    }
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      default: return '#22c55e';
    }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FolderOpen size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Case & Incident Management
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Investigation tracking, forensic chain-of-custody corroboration, analyst notes, and evidentiary records
          </div>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary flex items-center gap-2 text-xs"
        >
          <Plus size={14} />
          <span>NEW INVESTIGATION CASE</span>
        </button>
      </div>

      {/* Grid: Case List (Left) + Case Workspace (Right) */}
      <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(340px, 1.2fr) minmax(400px, 2fr)' }}>
        {/* Case List */}
        <div className="flex flex-col gap-3">
          <div className="section-title">Active Investigations ({cases.length})</div>

          {cases.map(c => {
            const isSelected = selectedCaseId === c.id;
            const statusBadge = getStatusBadge(c.status);
            const sevColor = getSeverityBadge(c.severity);

            return (
              <div
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`panel-elevated transition-all-fast cursor-pointer ${isSelected ? 'glow-cyan' : ''}`}
                style={{
                  padding: 16,
                  borderLeft: `4px solid ${sevColor}`,
                  background: isSelected ? 'rgba(34,211,238,0.06)' : 'var(--color-surface-2)',
                  borderColor: isSelected ? 'rgba(34,211,238,0.4)' : undefined,
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#22d3ee', fontWeight: 800 }}>
                    CASE #{c.id}
                  </span>
                  <div className="flex items-center gap-2">
                    <span
                      style={{
                        fontSize: 9, fontWeight: 800,
                        color: sevColor, background: `${sevColor}15`,
                        border: `1px solid ${sevColor}30`,
                        borderRadius: 3, padding: '2px 6px',
                      }}
                    >
                      {c.severity}
                    </span>
                    <span
                      style={{
                        fontSize: 9, fontWeight: 800,
                        color: statusBadge.color, background: statusBadge.bg,
                        border: `1px solid ${statusBadge.border}`,
                        borderRadius: 3, padding: '2px 6px',
                      }}
                    >
                      {c.status}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', marginTop: 4 }}>
                  {c.title}
                </div>

                <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4, lineClamp: 2 }}>
                  {c.summary}
                </div>

                <div className="flex items-center justify-between mt-3 pt-2 text-xs" style={{ borderTop: '1px solid var(--color-border)', color: 'var(--color-text-muted)' }}>
                  <div className="flex items-center gap-1">
                    <User size={11} />
                    <span>{c.assignedTo}</span>
                  </div>
                  <div>
                    {c.notes.length} Notes · {new Date(c.updatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Case Workspace Detail */}
        {activeCase && (
          <div className="panel" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Header */}
            <div className="flex items-start justify-between pb-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
              <div>
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: '#22d3ee', fontWeight: 800 }}>
                  CASE #{activeCase.id}
                </span>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--color-text)', marginTop: 2 }}>
                  {activeCase.title}
                </h2>
                <div className="flex items-center gap-4 mt-2" style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                  <span>Assigned: <strong style={{ color: '#22d3ee' }}>{activeCase.assignedTo}</strong></span>
                  <span>Created: {new Date(activeCase.createdAt).toLocaleDateString('en-IN')}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => navigate('/reports')}
                  className="btn-ghost flex items-center gap-1.5 text-xs"
                >
                  <FileText size={13} />
                  <span>Generate Report</span>
                </button>
              </div>
            </div>

            {/* Incident Summary */}
            <div>
              <div className="label mb-1">Executive Summary</div>
              <div style={{ fontSize: 13, color: 'var(--color-text-dim)', lineHeight: 1.6, background: 'rgba(0,0,0,0.2)', padding: 12, borderRadius: 6, border: '1px solid var(--color-border)' }}>
                {activeCase.summary}
              </div>
            </div>

            {/* Linked Entities */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="label mb-2">Linked Threat Campaign</div>
                <div className="p-3 rounded-lg flex items-center justify-between" style={{ background: 'rgba(34,211,238,0.06)', border: '1px solid var(--color-border)' }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#22d3ee' }}>
                      {activeCase.linkedCampaignIds[0] || 'Unlinked'}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Fake Invoice BEC Cluster</div>
                  </div>
                  <button onClick={() => navigate('/campaigns')} className="btn-ghost text-xs" style={{ padding: '4px 8px' }}>
                    View →
                  </button>
                </div>
              </div>

              <div>
                <div className="label mb-2">Evidence Status</div>
                <div className="p-3 rounded-lg flex items-center justify-between" style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid var(--color-border)' }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#22c55e' }}>
                      Chain of Custody Active
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>SHA-256 Hashes Verified</div>
                  </div>
                  <CheckCircle size={16} color="#22c55e" />
                </div>
              </div>
            </div>

            {/* Analyst Investigation Notes */}
            <div>
              <div className="label mb-3">Analyst Investigation Log ({activeCase.notes.length})</div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="mb-4">
                <textarea
                  className="st-input st-textarea text-xs"
                  style={{ minHeight: 80, padding: 10, borderRadius: 6 }}
                  placeholder="Add case observation, forensic artifact findings, or response notes..."
                  value={newNoteBody}
                  onChange={e => setNewNoteBody(e.target.value)}
                />
                <div className="flex justify-end mt-2">
                  <button
                    type="submit"
                    disabled={!newNoteBody.trim()}
                    className="btn-primary text-xs"
                    style={{ padding: '6px 14px' }}
                  >
                    POST ANALYST NOTE
                  </button>
                </div>
              </form>

              {/* Notes Feed */}
              <div className="flex flex-col gap-3">
                {activeCase.notes.map(n => (
                  <div key={n.id} className="panel-elevated" style={{ padding: 12 }}>
                    <div className="flex items-center justify-between mb-1" style={{ fontSize: 11 }}>
                      <span style={{ fontWeight: 700, color: '#22d3ee' }}>{n.author}</span>
                      <span style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {new Date(n.at).toLocaleString('en-IN')}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>
                      {n.body}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modal for Creating New Case */}
      {showCreateModal && (
        <div
          className="fixed inset-0 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(8px)', zIndex: 100 }}
        >
          <div className="panel animate-fade-in" style={{ padding: 28, width: '100%', maxWidth: 500 }}>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#22d3ee', marginBottom: 16 }}>
              Create New Security Investigation Case
            </h3>

            <form onSubmit={handleCreateCase} className="flex flex-col gap-4">
              <div>
                <label className="label mb-1.5 block">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Executive Impersonation — ACME Corp BEC"
                  className="st-input"
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                />
              </div>

              <div>
                <label className="label mb-1.5 block">Severity Rating</label>
                <select
                  className="st-input"
                  value={newSeverity}
                  onChange={e => setNewSeverity(e.target.value as Severity)}
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="label mb-1.5 block">Initial Case Summary</label>
                <textarea
                  className="st-input st-textarea"
                  style={{ minHeight: 100 }}
                  placeholder="Describe the detected threat, suspected perpetrator infrastructure, and immediate response required..."
                  value={newSummary}
                  onChange={e => setNewSummary(e.target.value)}
                />
              </div>

              <div className="flex justify-end gap-3 mt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="btn-ghost"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
