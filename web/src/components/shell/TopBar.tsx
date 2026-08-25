import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, LogOut, RefreshCw, Shield, Zap, Globe, Database, Cpu } from 'lucide-react';
import { useSession } from '@/context/SessionContext';
import { useAlerts } from '@/context/AlertContext';

interface ServiceIndicator {
  id: string;
  label: string;
  state: 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'CHECKING';
  icon: React.ReactNode;
}

export function TopBar() {
  const { session, signOut } = useSession();
  const { unreadCount } = useAlerts();
  const navigate = useNavigate();
  const [services, setServices] = useState<ServiceIndicator[]>([
    { id: 'ai', label: 'AI ENGINE', state: 'CHECKING', icon: <Cpu size={10} /> },
    { id: 'intel', label: 'THREAT INTEL', state: 'CHECKING', icon: <Shield size={10} /> },
    { id: 'geo', label: 'GEOLOCATION', state: 'CHECKING', icon: <Globe size={10} /> },
    { id: 'forensic', label: 'FORENSIC ENGINE', state: 'CHECKING', icon: <Database size={10} /> },
  ]);
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    // Check backend health
    const checkHealth = async () => {
      try {
        const resp = await fetch('/api/', { signal: AbortSignal.timeout(3000) });
        if (resp.ok) {
          setServices(s => s.map(svc => ({ ...svc, state: 'ONLINE' })));
        } else {
          setServices(s => s.map(svc => ({ ...svc, state: 'DEGRADED' })));
        }
      } catch {
        setServices(s => s.map((svc, i) =>
          i === 0
            ? { ...svc, state: 'ONLINE' }    // Local AI always online
            : { ...svc, state: 'DEGRADED' }  // Backend services degraded
        ));
      }
    };
    checkHealth();
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const stateColor = (state: ServiceIndicator['state']) => {
    switch (state) {
      case 'ONLINE': return '#22c55e';
      case 'DEGRADED': return '#f59e0b';
      case 'OFFLINE': return '#ef4444';
      default: return '#22d3ee';
    }
  };

  return (
    <header
      className="flex items-center justify-between px-5"
      style={{
        height: 60,
        background: 'var(--color-surface)',
        borderBottom: '1px solid var(--color-border)',
        flexShrink: 0,
        zIndex: 50,
      }}
    >
      {/* Left: brand + status */}
      <div className="flex items-center gap-6">
        <div>
          <div style={{ fontSize: 10, color: 'var(--color-text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            AI FORENSIC INTELLIGENCE PLATFORM
          </div>
          <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
            {now.toUTCString().replace('GMT', 'UTC')}
          </div>
        </div>

        {/* Service status indicators */}
        <div className="hidden lg:flex items-center gap-4">
          {services.map(svc => (
            <div key={svc.id} className="flex items-center gap-1.5">
              <span
                className="status-dot"
                style={{
                  background: stateColor(svc.state),
                  boxShadow: `0 0 6px ${stateColor(svc.state)}`,
                  animation: svc.state === 'CHECKING' ? 'blink 1s ease-in-out infinite' : undefined,
                }}
              />
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.06em', color: 'var(--color-text-muted)' }}>
                {svc.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Right: alert bell + user */}
      <div className="flex items-center gap-3">
        {/* Alert button */}
        <button
          onClick={() => navigate('/alerts')}
          className="relative flex items-center justify-center rounded-lg transition-all-fast"
          style={{
            width: 36, height: 36,
            background: 'rgba(34,211,238,0.05)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-dim)',
            cursor: 'pointer',
          }}
        >
          <Bell size={15} />
          {unreadCount > 0 && (
            <span
              className="absolute -top-1 -right-1 flex items-center justify-center rounded-full"
              style={{
                width: 16, height: 16,
                background: '#ef4444',
                fontSize: 9, fontWeight: 700, color: 'white',
                boxShadow: '0 0 6px rgba(239,68,68,0.6)',
              }}
            >
              {unreadCount}
            </span>
          )}
        </button>

        {/* Analyst info */}
        {session && (
          <div className="flex items-center gap-2">
            <div
              className="flex items-center justify-center rounded-full"
              style={{
                width: 30, height: 30,
                background: 'linear-gradient(135deg, #0e7490, #22d3ee)',
                fontSize: 12, fontWeight: 700, color: '#030712',
                flexShrink: 0,
              }}
            >
              {session.displayName.charAt(0)}
            </div>
            <div className="hidden sm:block">
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)', lineHeight: 1.2 }}>
                {session.analystId}
              </div>
              <div style={{ fontSize: 10, color: 'var(--color-text-muted)' }}>
                {session.role.replace('_', ' ')}
              </div>
            </div>
            <button
              onClick={signOut}
              className="flex items-center justify-center rounded-lg transition-all-fast"
              style={{
                width: 30, height: 30,
                background: 'transparent',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-muted)',
                cursor: 'pointer',
                marginLeft: 4,
              }}
              title="Sign out"
            >
              <LogOut size={13} />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
