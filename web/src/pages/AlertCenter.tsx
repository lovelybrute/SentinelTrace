import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bell, AlertTriangle, Shield, CheckCircle, Clock,
  Filter, Search, ExternalLink, ChevronRight, Eye, Check
} from 'lucide-react';
import { useAlerts } from '@/context/AlertContext';
import type { Alert, AlertStatus, Severity } from '@/types';

export function AlertCenter() {
  const { alerts, unreadCount, acknowledge, resolve, clearAll } = useAlerts();
  const navigate = useNavigate();
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredAlerts = alerts.filter(a => {
    const matchesSev = selectedSeverity === 'ALL' || a.severity === selectedSeverity;
    const matchesStat = selectedStatus === 'ALL' || a.status === selectedStatus;
    const matchesSearch =
      a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.detail.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesStat && matchesSearch;
  });

  const getSevColor = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': return '#22c55e';
      default: return '#22d3ee';
    }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Bell size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Real-Time Security Alert Center
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Automated detection triggers, executive impersonation alerts, lookalike alerts, and anomaly triage
          </div>
        </div>

        {/* Clear / Actions */}
        <div className="flex items-center gap-3">
          {unreadCount > 0 && (
            <span
              style={{
                fontSize: 11, fontWeight: 700,
                background: 'rgba(239,68,68,0.2)', color: '#ef4444',
                border: '1px solid rgba(239,68,68,0.3)',
                padding: '4px 10px', borderRadius: 20,
              }}
            >
              {unreadCount} Unacknowledged Alerts
            </span>
          )}
          <button onClick={clearAll} className="btn-ghost text-xs">
            Clear All Alerts
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="panel mb-6 p-4 flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Severity Filters */}
          <div className="flex items-center gap-1 bg-surface-2 p-1 rounded-lg border border-border">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
              <button
                key={s}
                onClick={() => setSelectedSeverity(s)}
                style={{
                  fontSize: 11, fontWeight: 700,
                  padding: '4px 10px', borderRadius: 4,
                  background: selectedSeverity === s ? 'rgba(34,211,238,0.15)' : 'transparent',
                  color: selectedSeverity === s ? '#22d3ee' : 'var(--color-text-muted)',
                  border: 'none', cursor: 'pointer',
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Status Filters */}
          <div className="flex items-center gap-1 bg-surface-2 p-1 rounded-lg border border-border">
            {['ALL', 'NEW', 'ACKNOWLEDGED', 'RESOLVED'].map(st => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                style={{
                  fontSize: 11, fontWeight: 700,
                  padding: '4px 10px', borderRadius: 4,
                  background: selectedStatus === st ? 'rgba(34,211,238,0.15)' : 'transparent',
                  color: selectedStatus === st ? '#22d3ee' : 'var(--color-text-muted)',
                  border: 'none', cursor: 'pointer',
                }}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Search */}
        <div className="relative">
          <Search size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            placeholder="Search alerts by title or indicator..."
            className="st-input text-xs"
            style={{ paddingLeft: 34, width: 280 }}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Alert Feed Table */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="flex flex-col">
          {filteredAlerts.length === 0 ? (
            <div style={{ padding: 48, textAlign: 'center', color: 'var(--color-text-muted)' }}>
              No alerts match the active filter criteria.
            </div>
          ) : (
            filteredAlerts.map(alert => {
              const sevCol = getSevColor(alert.severity);

              return (
                <div
                  key={alert.id}
                  className="p-4 border-b border-border flex items-start justify-between gap-4 transition-all-fast"
                  style={{
                    background: alert.status === 'NEW' ? 'rgba(34,211,238,0.02)' : 'transparent',
                    borderLeft: `4px solid ${sevCol}`,
                  }}
                >
                  <div className="flex items-start gap-3">
                    <div
                      style={{
                        width: 32, height: 32, borderRadius: 8,
                        background: `${sevCol}15`, border: `1px solid ${sevCol}30`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}
                    >
                      <AlertTriangle size={16} color={sevCol} />
                    </div>

                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          style={{
                            fontSize: 9, fontWeight: 800,
                            color: sevCol, background: `${sevCol}15`,
                            border: `1px solid ${sevCol}30`,
                            borderRadius: 3, padding: '1px 6px',
                          }}
                        >
                          {alert.severity}
                        </span>
                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text)' }}>
                          {alert.title}
                        </span>
                        {alert.status === 'NEW' && (
                          <span style={{ fontSize: 9, fontWeight: 800, color: '#22d3ee', background: 'rgba(34,211,238,0.15)', padding: '1px 5px', borderRadius: 3 }}>
                            NEW
                          </span>
                        )}
                      </div>

                      <div style={{ fontSize: 12, color: 'var(--color-text-dim)', marginTop: 4, lineHeight: 1.5 }}>
                        {alert.detail}
                      </div>

                      <div className="flex items-center gap-4 mt-2" style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                        <span>Source: <strong style={{ color: 'var(--color-text)' }}>{alert.source}</strong></span>
                        <span>Triggered: {new Date(alert.at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</span>
                        {alert.relatedCampaignId && (
                          <span style={{ color: '#22d3ee' }}>Campaign: {alert.relatedCampaignId}</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {alert.status === 'NEW' && (
                      <button
                        onClick={() => acknowledge(alert.id)}
                        className="btn-ghost text-xs"
                        style={{ padding: '6px 12px' }}
                      >
                        Acknowledge
                      </button>
                    )}

                    {alert.status !== 'RESOLVED' && (
                      <button
                        onClick={() => resolve(alert.id)}
                        className="btn-ghost text-xs flex items-center gap-1"
                        style={{ borderColor: '#22c55e', color: '#22c55e', padding: '6px 12px' }}
                      >
                        <Check size={12} />
                        <span>Resolve</span>
                      </button>
                    )}

                    <button
                      onClick={() => navigate('/analyzer')}
                      className="btn-primary text-xs flex items-center gap-1"
                      style={{ padding: '6px 12px' }}
                    >
                      <span>Investigate</span>
                      <ChevronRight size={12} />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
