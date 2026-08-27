import React, { Suspense, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  FileSearch,
  Menu,
  Network,
  Shield,
  X,
  Zap,
} from 'lucide-react';
import { DEMO_EMAIL_FILENAME, DEMO_EMAIL_RAW } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useAnalysis } from '@/context/AnalysisContext';

const HeroNetwork3D = React.lazy(() =>
  import('@/components/3d/HeroNetwork3D').then((module) => ({ default: module.HeroNetwork3D })),
);

const NAV_ITEMS = [
  { label: 'Overview', target: 'top' },
  { label: 'Capabilities', target: 'capabilities' },
  { label: 'Validation', target: 'validation' },
];

const STATS = [
  { figure: '106K+', label: 'Evidence records', foot: 'Validated training corpus' },
  { figure: '98.74%', label: 'Held-out accuracy', foot: 'Transparent ML evaluation' },
  { figure: '15+', label: 'Forensic modules', foot: 'One investigation workspace' },
];

export function Landing() {
  const navigate = useNavigate();
  const { setCurrentAnalysis, addToHistory } = useAnalysis();
  const [active, setActive] = useState('Overview');
  const [menuOpen, setMenuOpen] = useState(false);
  const [isIngestingDemo, setIsIngestingDemo] = useState(false);

  useEffect(() => {
    document.body.style.overflow = menuOpen ? 'hidden' : '';
    return () => {
      document.body.style.overflow = '';
    };
  }, [menuOpen]);

  const navigateTo = (label: string, target: string) => {
    setActive(label);
    setMenuOpen(false);
    document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleLaunchDemo = async () => {
    setIsIngestingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: 'HERO_DEMO',
        acquisitionSource: 'Cyber Landing Page Ingest',
        useBackend: true,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
      navigate('/analyzer');
    } catch (error) {
      console.error(error);
      navigate('/login');
    } finally {
      setIsIngestingDemo(false);
    }
  };

  return (
    <main id="top" className="cyber-landing">
      <div className="cyber-hero-media" aria-hidden="true">
        <Suspense fallback={<div className="cyber-hero-fallback" />}>
          <HeroNetwork3D />
        </Suspense>
        <div className="cyber-hero-scrim" />
        <div className="cyber-data-rain" />
      </div>

      <header className="cyber-pill-nav" aria-label="SentinelTrace navigation">
        <button className="cyber-brand" type="button" onClick={() => navigateTo('Overview', 'top')}>
          <span className="cyber-brand-mark"><Shield size={17} /></span>
          <span>SENTINELTRACE</span>
        </button>

        <nav className="cyber-nav-rail" aria-label="Primary">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.label}
              type="button"
              className={active === item.label ? 'active' : ''}
              onClick={() => navigateTo(item.label, item.target)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="cyber-nav-actions">
          <button type="button" className="cyber-login-link" onClick={() => navigate('/login')}>
            Analyst Login
          </button>
          <button type="button" className="cyber-pill-action" onClick={() => navigate('/login')}>
            Enter SOC <ArrowRight size={14} />
          </button>
        </div>

        <button
          type="button"
          className="cyber-menu-toggle"
          aria-expanded={menuOpen}
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          onClick={() => setMenuOpen((value) => !value)}
        >
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>

        {menuOpen && (
          <div className="cyber-mobile-sheet">
            {NAV_ITEMS.map((item) => (
              <button key={item.label} type="button" onClick={() => navigateTo(item.label, item.target)}>
                {item.label}
              </button>
            ))}
            <button type="button" onClick={() => navigate('/login')}>Analyst Login</button>
            <button type="button" className="cyber-pill-action" onClick={() => navigate('/login')}>
              Enter SOC <ArrowRight size={14} />
            </button>
          </div>
        )}
      </header>

      <section className="cyber-hero-body">
        <div className="cyber-live-badge">
          <span /> AI FORENSIC INTELLIGENCE · SYSTEM ONLINE
        </div>
        <h1>
          <span>Trace the Signal.</span>
          Expose the Threat.
        </h1>
        <p>
          Turn raw email evidence into explainable threat intelligence—authenticate identity,
          reconstruct relay infrastructure, identify attack patterns, and preserve investigation evidence.
        </p>
        <div className="cyber-hero-actions">
          <button type="button" className="cyber-primary-cta" onClick={() => navigate('/login')}>
            <FileSearch size={17} /> Start Investigation <ArrowRight size={16} />
          </button>
          <button
            type="button"
            className="cyber-demo-cta"
            onClick={handleLaunchDemo}
            disabled={isIngestingDemo}
          >
            <Zap size={16} /> {isIngestingDemo ? 'INITIALIZING…' : 'Run Attack Demo'}
          </button>
        </div>
      </section>

      <section id="capabilities" className="cyber-hero-foot" aria-label="Platform evidence">
        <article className="cyber-note-card">
          <div className="cyber-note-icon"><Network size={18} /></div>
          <div>
            <h2>Forensics beyond detection</h2>
            <p>Explain the verdict, trace the infrastructure, and give analysts the next defensible action.</p>
          </div>
        </article>

        <div id="validation" className="cyber-stat-row">
          {STATS.map((stat, index) => (
            <article key={stat.label} className="cyber-stat-card">
              <div className="cyber-stat-topline">
                {index === 0 ? <Activity size={14} /> : index === 1 ? <Shield size={14} /> : <Network size={14} />}
                {stat.label}
              </div>
              <strong>{stat.figure}</strong>
              <small>{stat.foot}</small>
            </article>
          ))}
        </div>
      </section>

      <div className="cyber-hero-status">
        <span>TEAM BRUTE</span>
        <span>SIH 26106</span>
        <span>RFC FORENSICS · VALIDATED ML</span>
      </div>
    </main>
  );
}
