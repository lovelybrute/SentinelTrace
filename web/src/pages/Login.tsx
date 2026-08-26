import React, { useState, useEffect, useRef } from 'react';
import { Shield, Eye, EyeOff, Lock, Mail, ChevronRight, AlertTriangle } from 'lucide-react';
import { useSession } from '@/context/SessionContext';

/* ------------------------------------------------------------------ */
/* Animated network canvas background                                  */
/* ------------------------------------------------------------------ */

function NetworkCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d')!;

    let animId = 0;
    let W = 0, H = 0;

    interface Particle {
      x: number; y: number;
      vx: number; vy: number;
    }

    const N = 60;
    const particles: Particle[] = [];

    const resize = () => {
      W = canvas.width = canvas.offsetWidth;
      H = canvas.height = canvas.offsetHeight;
      particles.length = 0;
      for (let i = 0; i < N; i++) {
        particles.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
        });
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      // Update
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }

      // Draw edges
      for (let i = 0; i < N; i++) {
        for (let j = i + 1; j < N; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 130) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(34,211,238,${0.08 * (1 - dist / 130)})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      for (const p of particles) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(34,211,238,0.35)';
        ctx.fill();
      }

      animId = requestAnimationFrame(draw);
    };

    resize();
    draw();
    window.addEventListener('resize', resize);
    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
      }}
    />
  );
}

/* ------------------------------------------------------------------ */
/* Login page                                                          */
/* ------------------------------------------------------------------ */

export function Login() {
  const { signIn, signInDemo } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [demoDropdown, setDemoDropdown] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) { setError('Enter your credentials.'); return; }
    setLoading(true);
    setError('');
    await new Promise(r => setTimeout(r, 800));
    signIn(email, password);
    setLoading(false);
  };

  return (
    <div
      className="login-shell relative flex items-center justify-center min-h-screen"
    >
      <NetworkCanvas />

      <div className="login-cyber-grid" aria-hidden="true" />
      <div className="login-aurora login-aurora-cyan" aria-hidden="true" />
      <div className="login-aurora login-aurora-red" aria-hidden="true" />

      {/* Login card */}
      <div
        className="login-glass-card relative animate-fade-in"
        style={{
          width: '100%',
          maxWidth: 480,
        }}
      >
        {/* Brand */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <div
              className="login-brand-shield flex items-center justify-center rounded-2xl"
              style={{
                width: 56, height: 56,
              }}
            >
              <Shield size={28} color="#22d3ee" />
            </div>
          </div>
          <div
            style={{
              fontSize: 22,
              fontWeight: 900,
              letterSpacing: '0.12em',
              color: '#22d3ee',
            }}
          >
            SENTINEL<span style={{ color: '#e2e8f0' }}>TRACE</span>
          </div>
          <div
            style={{
              fontSize: 11,
              color: 'var(--color-text-muted)',
              letterSpacing: '0.06em',
              marginTop: 4,
              textTransform: 'uppercase',
            }}
          >
            AI-Powered Email Threat Detection & Forensic Intelligence
          </div>

          {/* SIH badge */}
          <div
            className="inline-flex items-center gap-1.5 mt-3 px-3 py-1 rounded-full"
            style={{
              background: 'rgba(99,102,241,0.12)',
              border: '1px solid rgba(99,102,241,0.25)',
              fontSize: 10,
              fontWeight: 600,
              color: '#818cf8',
              letterSpacing: '0.04em',
            }}
          >
            <span>SIH 2026</span>
            <span style={{ color: 'rgba(99,102,241,0.5)' }}>•</span>
            <span>Problem #26106</span>
          </div>
        </div>

        {/* Permanent team signature — remains visible after the cinematic intro */}
        <section className="team-signature-glass" aria-label="Team Brute">
          <div className="team-signature-kicker">BUILT FOR SIH 2026 BY</div>
          <div className="brute-blood-lockup" aria-label="TEAM BRUTE">
            <span className="brute-blood-text" aria-hidden="true">TEAM BRUTE</span>
            <span className="blood-drip blood-drip-one" aria-hidden="true" />
            <span className="blood-drip blood-drip-two" aria-hidden="true" />
            <span className="blood-drip blood-drip-three" aria-hidden="true" />
            <span className="blood-drip blood-drip-four" aria-hidden="true" />
          </div>
        </section>

        {/* Error */}
        {error && (
          <div
            className="flex items-center gap-2 rounded-lg px-3 py-2 mb-4"
            style={{
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.25)',
              color: '#ef4444',
              fontSize: 13,
            }}
          >
            <AlertTriangle size={14} />
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="label mb-1.5 block">Analyst Email</label>
            <div className="relative">
              <Mail
                size={14}
                style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }}
              />
              <input
                className="st-input glass-input"
                style={{ paddingLeft: 36 }}
                type="email"
                placeholder="analyst@cert-in.gov.in"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="email"
              />
            </div>
          </div>

          <div>
            <label className="label mb-1.5 block">Password</label>
            <div className="relative">
              <Lock
                size={14}
                style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }}
              />
              <input
                className="st-input glass-input"
                style={{ paddingLeft: 36, paddingRight: 40 }}
                type={showPass ? 'text' : 'password'}
                placeholder="••••••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPass(s => !s)}
                style={{
                  position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--color-text-muted)',
                }}
              >
                {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="btn-primary login-primary-action flex items-center justify-center gap-2"
            style={{ marginTop: 4, height: 44 }}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="animate-spin" style={{ display: 'inline-block', width: 14, height: 14, border: '2px solid rgba(3,7,18,0.3)', borderTop: '2px solid #030712', borderRadius: '50%' }} />
                Authenticating...
              </>
            ) : (
              <>
                SIGN IN
                <ChevronRight size={14} />
              </>
            )}
          </button>
        </form>

        {/* Divider */}
        <div className="flex items-center gap-3 my-5">
          <div style={{ flex: 1, height: 1, background: 'var(--color-border)' }} />
          <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>OR</span>
          <div style={{ flex: 1, height: 1, background: 'var(--color-border)' }} />
        </div>

        {/* Demo Mode */}
        <div className="relative">
          <button
            onClick={() => setDemoDropdown(d => !d)}
            className="demo-glass-action w-full flex items-center justify-center gap-2"
            style={{
              padding: '11px 20px',
              borderRadius: 8,
              color: '#f59e0b',
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              letterSpacing: '0.03em',
              transition: 'all 0.2s',
            }}
          >
            ⚡ DEMO ANALYST MODE
            <ChevronRight size={13} style={{ transform: demoDropdown ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }} />
          </button>

          {demoDropdown && (
            <div
              className="demo-glass-menu absolute w-full mt-2 rounded-lg overflow-hidden animate-fade-in"
              style={{
                zIndex: 10,
              }}
            >
              {[
                { role: 'SOC_ANALYST' as const, label: 'SOC Analyst', sub: 'Tier-2 Email Threat Analysis', color: '#22d3ee' },
                { role: 'INVESTIGATOR' as const, label: 'Investigator', sub: 'Cybercrime Investigation Cell', color: '#a78bfa' },
                { role: 'ADMIN' as const, label: 'Administrator', sub: 'CERT-In National Response', color: '#f97316' },
                { role: 'AUDITOR' as const, label: 'Auditor', sub: 'Compliance & Evidence Review', color: '#22c55e' },
              ].map(opt => (
                <button
                  key={opt.role}
                  onClick={() => signInDemo(opt.role)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left transition-all-fast"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    borderBottom: '1px solid var(--color-border)',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(34,211,238,0.05)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <div
                    style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: opt.color, boxShadow: `0 0 6px ${opt.color}`,
                      flexShrink: 0,
                    }}
                  />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>{opt.label}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{opt.sub}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>


        <div className="login-version-line text-center mt-5">
          SentinelTrace v1.0 · SIH 26106 · CERT-In Aligned
        </div>
      </div>
    </div>
  );
}
