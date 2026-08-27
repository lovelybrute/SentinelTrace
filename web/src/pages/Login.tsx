import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Eye,
  EyeOff,
  Lock,
  Mail,
  MapPin,
  Radio,
  Server,
  Shield,
} from 'lucide-react';
import { useSession } from '@/context/SessionContext';

const DEMO_ROLES = [
  { role: 'SOC_ANALYST' as const, label: 'SOC Analyst', sub: 'Tier-2 Email Threat Analysis', color: '#22d3ee' },
  { role: 'INVESTIGATOR' as const, label: 'Investigator', sub: 'Cybercrime Investigation Cell', color: '#a78bfa' },
  { role: 'ADMIN' as const, label: 'Administrator', sub: 'CERT-In National Response', color: '#f97316' },
  { role: 'AUDITOR' as const, label: 'Auditor', sub: 'Compliance & Evidence Review', color: '#22c55e' },
];

function LightweightThreatGlobe() {
  const globeRef = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const element = globeRef.current;
    if (!element) return;
    const observer = new IntersectionObserver(([entry]) => setPaused(!entry.isIntersecting), { threshold: 0.08 });
    const onVisibility = () => setPaused(document.hidden);
    observer.observe(element);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      observer.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  return (
    <div ref={globeRef} className={`login-lite-globe${paused ? ' paused' : ''}`} aria-label="Animated global threat relay map">
      <div className="login-lite-earth"><div className="login-lite-earth-surface" /></div>
      <svg className="login-lite-routes" viewBox="0 0 760 480" aria-hidden="true">
        <path className="trusted" d="M190 258 Q358 94 565 232" />
        <path className="threat" d="M235 358 Q390 148 603 192" />
        <path className="trusted delay-one" d="M548 360 Q520 188 330 185" />
        <path className="threat delay-two" d="M380 170 Q485 100 590 245" />
        <g className="relay-node trusted-node"><circle cx="190" cy="258" r="7" /><circle cx="565" cy="232" r="7" /><circle cx="548" cy="360" r="7" /></g>
        <g className="relay-node threat-node"><circle cx="235" cy="358" r="7" /><circle cx="603" cy="192" r="7" /><circle cx="380" cy="170" r="7" /></g>
      </svg>
      <div className="login-lite-atmosphere" aria-hidden="true" />
    </div>
  );
}

export function Login() {
  const { signIn, signInDemo } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [demoDropdown, setDemoDropdown] = useState(false);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!email || !password) {
      setError('Enter your credentials.');
      return;
    }
    setLoading(true);
    setError('');
    await new Promise((resolve) => setTimeout(resolve, 800));
    signIn(email, password);
    setLoading(false);
  };

  return (
    <main className="login-command-shell">
      <div className="login-cyber-grid" aria-hidden="true" />
      <div className="login-command-glow login-command-glow-cyan" aria-hidden="true" />
      <div className="login-command-glow login-command-glow-red" aria-hidden="true" />

      <div className="login-command-layout">
        <section className="login-intel-stage" aria-label="Live global threat intelligence">
          <div className="login-intel-brand-row">
            <div className="login-command-brand">
              <span><Shield size={20} /></span>
              <div><strong>SENTINELTRACE</strong><small>AI FORENSIC INTELLIGENCE</small></div>
            </div>
            <div className="login-command-health"><span><i /> SYSTEM ONLINE</span><b>SIH 26106</b></div>
          </div>
          <div className="login-intel-heading">
            <span>GLOBAL RELAY INTELLIGENCE</span>
            <h1>See the infrastructure<br />behind the message.</h1>
            <p>Live visualization of observed relay nodes, suspicious infrastructure and trusted mail gateways.</p>
          </div>

          <div className="login-globe-frame">
            <LightweightThreatGlobe />
            <div className="login-globe-scan" aria-hidden="true" />
            <div className="login-intel-tag login-intel-tag-threat">
              <Radio size={12} /> <span><b>THREAT DETECTED</b>AS60729 · HIGH RISK</span>
            </div>
            <div className="login-intel-tag login-intel-tag-relay">
              <Server size={12} /> <span><b>RELAY VERIFIED</b>RFC TRACE ACTIVE</span>
            </div>
            <div className="login-intel-tag login-intel-tag-origin">
              <MapPin size={12} /> <span><b>ORIGIN SIGNAL</b>INDIA · 95% CONF.</span>
            </div>
          </div>

          <div className="login-intel-status">
            <div><Activity size={14} /><span>ACTIVE NODES<strong>24</strong></span></div>
            <div><Radio size={14} /><span>RELAY CHAINS<strong>08</strong></span></div>
            <div><AlertTriangle size={14} /><span>HIGH-RISK SIGNALS<strong>03</strong></span></div>
          </div>
        </section>

        <aside className="login-access-card animate-fade-in" aria-labelledby="secure-access-title">
          <div className="login-access-brand">
            <span><Shield size={24} /></span>
            <p>AUTHORIZED PERSONNEL</p>
            <h2 id="secure-access-title">Secure SOC Access</h2>
            <small>Authenticate to enter the forensic operations workspace.</small>
          </div>

          <div className="login-team-signature">
            <span>BUILT FOR SIH 2026 BY</span>
            <strong>TEAM BRUTE</strong>
          </div>

          {error && (
            <div className="login-command-error"><AlertTriangle size={14} />{error}</div>
          )}

          <form onSubmit={handleSubmit} className="login-command-form">
            <label>
              <span>ANALYST EMAIL</span>
              <div><Mail size={14} /><input type="email" placeholder="analyst@cert-in.gov.in" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" /></div>
            </label>
            <label>
              <span>PASSWORD</span>
              <div>
                <Lock size={14} />
                <input type={showPass ? 'text' : 'password'} placeholder="••••••••••••" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />
                <button type="button" aria-label={showPass ? 'Hide password' : 'Show password'} onClick={() => setShowPass((shown) => !shown)}>{showPass ? <EyeOff size={14} /> : <Eye size={14} />}</button>
              </div>
            </label>
            <button type="submit" className="login-command-submit" disabled={loading}>
              {loading ? <><i /> AUTHENTICATING…</> : <>SIGN IN <ChevronRight size={14} /></>}
            </button>
          </form>

          <div className="login-command-divider"><span>OR</span></div>

          <div className="login-demo-control">
            <button type="button" className="login-demo-trigger" onClick={() => setDemoDropdown((open) => !open)} aria-expanded={demoDropdown}>
              <span>⚡ DEMO ANALYST MODE</span><ChevronRight size={13} className={demoDropdown ? 'open' : ''} />
            </button>
            {demoDropdown && (
              <div className="login-demo-menu animate-fade-in">
                {DEMO_ROLES.map((option) => (
                  <button type="button" key={option.role} onClick={() => signInDemo(option.role)}>
                    <i style={{ background: option.color, boxShadow: `0 0 7px ${option.color}` }} />
                    <span><strong>{option.label}</strong><small>{option.sub}</small></span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="login-access-footer">
            <span><i /> TLS SECURE</span><span>v2.0.0</span><span>CERT-In ALIGNED</span>
          </div>
        </aside>
      </div>
    </main>
  );
}
