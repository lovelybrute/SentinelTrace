import React, { useState } from 'react';
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts';
import { BarChart3, TrendingUp, Shield, Globe, Lock, Activity, Calendar } from 'lucide-react';
import { mockAnalytics } from '@/services/mockDataService';
import type { TimeRange } from '@/types';

const CATEGORY_COLORS: Record<string, string> = {
  'Business Email Compromise': '#ef4444',
  'Phishing': '#f97316',
  'Malware Dropper': '#dc2626',
  'Credential Harvesting': '#f59e0b',
  'Spam / Bulk': '#3b82f6',
  'Impersonation': '#a855f7',
};

export function Analytics() {
  const [range, setRange] = useState<TimeRange>('30D');
  const data = mockAnalytics(range);

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BarChart3 size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Forensic Intelligence & Threat Analytics
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Aggregate statistical metrics, longitudinal attack vectors, geopolitical distribution, and authentication telemetry
          </div>
        </div>

        {/* Time-range filter pills */}
        <div className="flex items-center gap-1 bg-surface-2 p-1 rounded-lg border border-border">
          {(['24H', '7D', '30D', '90D'] as TimeRange[]).map(r => (
            <button
              key={r}
              onClick={() => setRange(r)}
              style={{
                fontSize: 11, fontWeight: 700,
                padding: '5px 12px', borderRadius: 4,
                background: range === r ? 'rgba(34,211,238,0.2)' : 'transparent',
                color: range === r ? '#22d3ee' : 'var(--color-text-muted)',
                border: 'none', cursor: 'pointer',
              }}
            >
              {r === '24H' ? 'Today' : r === '7D' ? '7 Days' : r === '30D' ? '30 Days' : '90 Days'}
            </button>
          ))}
        </div>
      </div>

      {/* Grid: Row 1 — Threats Over Time & Threat Categories */}
      <div className="grid gap-6 mb-6" style={{ gridTemplateColumns: 'minmax(350px, 1.8fr) minmax(300px, 1.2fr)' }}>
        {/* Threats Over Time Area Chart */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="flex items-center justify-between mb-4">
            <div className="section-title mb-0">Attack Vectors Over Time</div>
            <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Daily Threat Volume</span>
          </div>

          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.overTime}>
                <defs>
                  <linearGradient id="colorPhish" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorBec" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="date" stroke="#475569" fontSize={10} tickFormatter={v => v.slice(5)} />
                <YAxis stroke="#475569" fontSize={10} />
                <Tooltip
                  contentStyle={{ background: '#0a0f1a', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 6, fontSize: 11 }}
                />
                <Legend wrapperStyle={{ fontSize: 11, paddingTop: 10 }} />
                <Area type="monotone" dataKey="phishing" name="Phishing" stroke="#f97316" fillOpacity={1} fill="url(#colorPhish)" />
                <Area type="monotone" dataKey="bec" name="BEC / Fraud" stroke="#ef4444" fillOpacity={1} fill="url(#colorBec)" />
                <Area type="monotone" dataKey="malware" name="Malware" stroke="#a855f7" fill="none" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution by Category */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Threats by Classification</div>
          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.byCategory} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis type="number" stroke="#475569" fontSize={10} />
                <YAxis dataKey="category" type="category" stroke="#94a3b8" fontSize={10} width={130} />
                <Tooltip
                  contentStyle={{ background: '#0a0f1a', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 6, fontSize: 11 }}
                />
                <Bar dataKey="count" name="Incidents" radius={[0, 4, 4, 0]}>
                  {data.byCategory.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={CATEGORY_COLORS[entry.category] || '#22d3ee'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Grid: Row 2 — Geopolitical Country Distribution & Authentication Failures */}
      <div className="grid gap-6 mb-6" style={{ gridTemplateColumns: 'minmax(350px, 1.5fr) minmax(300px, 1.5fr)' }}>
        {/* Country Ingress Distribution */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Top Threat Ingress Jurisdictions</div>
          <div style={{ width: '100%', height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.countryDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="country" stroke="#94a3b8" fontSize={10} />
                <YAxis stroke="#475569" fontSize={10} />
                <Tooltip
                  contentStyle={{ background: '#0a0f1a', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 6, fontSize: 11 }}
                />
                <Bar dataKey="count" name="Observed Volume" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Authentication Failures (SPF/DKIM/DMARC) */}
        <div className="panel" style={{ padding: 20 }}>
          <div className="section-title">Email Protocol Authentication Failures</div>
          <div style={{ width: '100%', height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.authFailures}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="mechanism" stroke="#94a3b8" fontSize={11} fontWeight={700} />
                <YAxis stroke="#475569" fontSize={10} />
                <Tooltip
                  contentStyle={{ background: '#0a0f1a', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 6, fontSize: 11 }}
                />
                <Legend wrapperStyle={{ fontSize: 11, paddingTop: 6 }} />
                <Bar dataKey="pass" name="Valid / Aligned" fill="#22c55e" radius={[4, 4, 0, 0]} />
                <Bar dataKey="fail" name="Failed / Forged" fill="#ef4444" radius={[4, 4, 0, 0]} />
                <Bar dataKey="softfail" name="Softfail" fill="#f59e0b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Grid: Row 3 — Top Malicious Domains & High-Risk IPs */}
      <div className="grid gap-6" style={{ gridTemplateColumns: '1fr 1fr' }}>
        {/* Top Malicious Domains */}
        <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="px-4 py-3 border-b border-border">
            <span className="section-title mb-0">Top Flagged Lookalike Domains</span>
          </div>
          <table className="data-table w-full text-xs">
            <thead>
              <tr>
                <th>DOMAIN</th>
                <th>INCIDENT COUNT</th>
                <th>RISK LEVEL</th>
              </tr>
            </thead>
            <tbody>
              {data.topDomains.map(d => (
                <tr key={d.domain}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#fca5a5' }}>{d.domain}</td>
                  <td style={{ fontWeight: 700 }}>{d.count}</td>
                  <td>
                    <span style={{ fontSize: 9, fontWeight: 800, color: '#ef4444', background: 'rgba(239,68,68,0.15)', padding: '2px 6px', borderRadius: 3 }}>
                      {d.risk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Top Malicious IPs */}
        <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="px-4 py-3 border-b border-border">
            <span className="section-title mb-0">Top Origin & Relay Ingress IPs</span>
          </div>
          <table className="data-table w-full text-xs">
            <thead>
              <tr>
                <th>IP NODE</th>
                <th>COUNTRY</th>
                <th>VOLUME</th>
              </tr>
            </thead>
            <tbody>
              {data.topIps.map(ip => (
                <tr key={ip.ip}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#22d3ee' }}>{ip.ip}</td>
                  <td>{ip.country}</td>
                  <td style={{ fontWeight: 700 }}>{ip.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
