import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Mail, Shield, FileSearch, MapPin,
  Network, Layers, FolderOpen, FileText, Bell, BarChart3,
  Settings, ChevronLeft, ChevronRight, Target, AlertTriangle,
  Search, Database, GitBranch, BrainCircuit
} from 'lucide-react';
import { useAlerts } from '@/context/AlertContext';
import { useSession } from '@/context/SessionContext';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  badge?: number | string;
  group?: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', icon: <LayoutDashboard size={16} />, label: 'Dashboard', group: 'PLATFORM' },
  { to: '/analyzer', icon: <Mail size={16} />, label: 'Email Analyzer', group: 'PLATFORM' },
  { to: '/alerts', icon: <Bell size={16} />, label: 'Alert Center', group: 'PLATFORM' },

  { to: '/header-forensics', icon: <FileSearch size={16} />, label: 'Header Forensics', group: 'FORENSICS' },
  { to: '/relay-chain', icon: <GitBranch size={16} />, label: 'Relay Chain', group: 'FORENSICS' },
  { to: '/origin-trace', icon: <MapPin size={16} />, label: 'Origin Trace', group: 'FORENSICS' },

  { to: '/threat-intel', icon: <Shield size={16} />, label: 'Threat Intelligence', group: 'INTELLIGENCE' },
  { to: '/graph', icon: <Network size={16} />, label: 'Graph Investigation', group: 'INTELLIGENCE' },
  { to: '/campaigns', icon: <Layers size={16} />, label: 'Campaign Intel', group: 'INTELLIGENCE' },

  { to: '/cases', icon: <FolderOpen size={16} />, label: 'Case Management', group: 'OPERATIONS' },
  { to: '/reports', icon: <FileText size={16} />, label: 'Forensic Reports', group: 'OPERATIONS' },
  { to: '/analytics', icon: <BarChart3 size={16} />, label: 'Analytics', group: 'OPERATIONS' },
  { to: '/model-performance', icon: <BrainCircuit size={16} />, label: 'Model Performance', group: 'OPERATIONS' },

  { to: '/settings', icon: <Settings size={16} />, label: 'Settings', group: 'SYSTEM' },
];

const GROUPS = ['PLATFORM', 'FORENSICS', 'INTELLIGENCE', 'OPERATIONS', 'SYSTEM'];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { unreadCount } = useAlerts();
  const { session } = useSession();
  const location = useLocation();

  const items = NAV_ITEMS.map(item => ({
    ...item,
    badge: item.to === '/alerts' ? (unreadCount > 0 ? unreadCount : undefined) : item.badge,
  }));

  return (
    <aside
      className="glass-sidebar flex flex-col h-full transition-all duration-300 ease-in-out"
      style={{
        width: collapsed ? 56 : 240,
        flexShrink: 0,
        overflow: 'hidden',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 px-3 py-4"
        style={{
          borderBottom: '1px solid var(--color-border)',
          minHeight: 60,
        }}
      >
        <div
          className="flex-shrink-0 flex items-center justify-center rounded-lg"
          style={{ width: 32, height: 32, background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.25)' }}
        >
          <Shield size={16} color="#22d3ee" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: '0.08em', color: '#22d3ee', lineHeight: 1 }}>
              SENTINEL<span style={{ color: '#e2e8f0' }}>TRACE</span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--color-text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
              FORENSIC INTELLIGENCE
            </div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2" style={{ overflowX: 'hidden' }}>
        {GROUPS.map(group => {
          const groupItems = items.filter(i => i.group === group);
          if (groupItems.length === 0) return null;
          return (
            <div key={group} className="mb-4">
              {!collapsed && (
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: '0.12em',
                    color: 'var(--color-text-muted)',
                    padding: '4px 12px 6px',
                    textTransform: 'uppercase',
                  }}
                >
                  {group}
                </div>
              )}
              {collapsed && group !== 'PLATFORM' && (
                <div
                  style={{
                    height: 1,
                    background: 'var(--color-border)',
                    margin: '8px 4px',
                  }}
                />
              )}
              {groupItems.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `sidebar-item ${isActive ? 'active' : ''}`
                  }
                  title={collapsed ? item.label : undefined}
                >
                  <span className="sidebar-icon flex-shrink-0">{item.icon}</span>
                  {!collapsed && (
                    <>
                      <span className="flex-1">{item.label}</span>
                      {item.badge !== undefined && (
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            background: 'rgba(239,68,68,0.2)',
                            color: '#ef4444',
                            border: '1px solid rgba(239,68,68,0.3)',
                            borderRadius: 10,
                            padding: '1px 6px',
                            minWidth: 18,
                            textAlign: 'center',
                          }}
                        >
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                  {collapsed && item.badge !== undefined && (
                    <span
                      style={{
                        position: 'absolute',
                        top: 2,
                        right: 2,
                        width: 8,
                        height: 8,
                        background: '#ef4444',
                        borderRadius: '50%',
                        boxShadow: '0 0 6px #ef4444',
                      }}
                    />
                  )}
                </NavLink>
              ))}
            </div>
          );
        })}
      </nav>

      {/* Analyst Badge */}
      {session && !collapsed && (
        <div
          className="p-3"
          style={{ borderTop: '1px solid var(--color-border)' }}
        >
          <div
            className="sidebar-analyst-glass flex items-center gap-2 p-2 rounded-lg"
          >
            <div
              className="flex-shrink-0 flex items-center justify-center rounded-full"
              style={{
                width: 28, height: 28,
                background: 'linear-gradient(135deg, #0e7490, #22d3ee)',
                fontSize: 11, fontWeight: 700, color: '#030712',
              }}
            >
              {session.displayName.charAt(0)}
            </div>
            <div className="overflow-hidden">
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {session.displayName}
              </div>
              <div style={{ fontSize: 10, color: 'var(--color-text-muted)' }}>
                {session.role.replace('_', ' ')}
                {session.demo && <span style={{ color: '#f59e0b', marginLeft: 4 }}>[DEMO]</span>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Collapse Toggle */}
      <button
        onClick={onToggle}
        className="flex items-center justify-center py-3 w-full transition-all-fast"
        style={{
          background: 'transparent',
          border: 'none',
          color: 'var(--color-text-muted)',
          cursor: 'pointer',
          borderTop: '1px solid var(--color-border)',
        }}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </aside>
  );
}
