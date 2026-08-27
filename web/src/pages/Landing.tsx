import React, { Suspense, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Database,
  FileSearch,
  FileArchive,
  Link2,
  MailCheck,
  MapPin,
  Menu,
  Network,
  Route,
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

const CAPABILITIES = [
  {
    icon: MailCheck,
    code: 'AUTH-01',
    title: 'Sender Authentication',
    copy: 'Evaluate SPF and DMARC alignment, and verify DKIM when the required raw evidence and DNS records are available.',
  },
  {
    icon: Route,
    code: 'RELAY-02',
    title: 'Relay Reconstruction',
    copy: 'Convert Received headers into an ordered MTA timeline and isolate the earliest reliable external infrastructure.',
  },
  {
    icon: MapPin,
    code: 'GEO-03',
    title: 'Origin Intelligence',
    copy: 'Enrich observed relay IPs with ASN, provider and geolocation clues while clearly communicating attribution limits.',
  },
  {
    icon: BrainCircuit,
    code: 'ML-04',
    title: 'Explainable ML Triage',
    copy: 'Combine validated phishing probability with transparent forensic signals instead of presenting a black-box verdict.',
  },
  {
    icon: Link2,
    code: 'GRAPH-05',
    title: 'Campaign Correlation',
    copy: 'Connect messages through shared domains, IP ranges, URLs and infrastructure to reveal coordinated activity.',
  },
  {
    icon: FileArchive,
    code: 'CASE-06',
    title: 'Evidence Operations',
    copy: 'Create cases, preserve analysis context, generate reports and export investigation-ready IOC and STIX evidence.',
  },
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

      <section className="cyber-hero-foot" aria-label="Platform evidence">
        <article className="cyber-note-card">
          <div className="cyber-note-icon"><Network size={18} /></div>
          <div>
            <h2>Forensics beyond detection</h2>
            <p>Explain the verdict, trace the infrastructure, and give analysts the next defensible action.</p>
          </div>
        </article>

        <div className="cyber-stat-row">
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

      <section id="capabilities" className="cyber-detail-section" aria-labelledby="capabilities-title">
        <div className="cyber-section-heading">
          <span>CAPABILITY MATRIX · 06 MODULES</span>
          <h2 id="capabilities-title">One investigation workspace.<br />Every signal connected.</h2>
          <p>
            SentinelTrace moves beyond a simple phishing label by connecting protocol evidence,
            infrastructure intelligence, machine learning and analyst operations.
          </p>
        </div>

        <div className="cyber-capability-grid">
          {CAPABILITIES.map(({ icon: Icon, code, title, copy }) => (
            <article key={code} className="cyber-capability-card">
              <div className="cyber-capability-icon"><Icon size={20} /></div>
              <span>{code}</span>
              <h3>{title}</h3>
              <p>{copy}</p>
              <div className="cyber-card-line" />
            </article>
          ))}
        </div>
      </section>

      <section id="validation" className="cyber-detail-section cyber-validation-section" aria-labelledby="validation-title">
        <div className="cyber-section-heading">
          <span>VALIDATION EVIDENCE · HELD-OUT TEST SET</span>
          <h2 id="validation-title">Measured performance.<br />Clearly stated limitations.</h2>
          <p>
            Model claims are tied to a reproducible artifact and published evaluation evidence—never presented as universal accuracy.
          </p>
        </div>

        <div className="cyber-validation-layout">
          <article className="cyber-validation-main">
            <div className="cyber-validation-title">
              <Database size={20} />
              <div>
                <span>DATASET EVIDENCE</span>
                <h3>MeAJOR v2.0 cleaned/preprocessed corpus</h3>
              </div>
              <strong><CheckCircle2 size={15} /> VALIDATED HOLDOUT</strong>
            </div>
            <div className="cyber-metric-grid">
              <div><span>Accuracy</span><strong>98.74%</strong></div>
              <div><span>Precision</span><strong>98.71%</strong></div>
              <div><span>Recall</span><strong>98.74%</strong></div>
              <div><span>Macro F1</span><strong>98.73%</strong></div>
            </div>
            <div className="cyber-validation-meta">
              <span><b>106,159</b> total records</span>
              <span><b>84,927 / 21,232</b> train / test</span>
              <span><b>Logistic regression</b> selected model</span>
            </div>
          </article>

          <aside className="cyber-limits-card">
            <Shield size={22} />
            <span>HONEST AI SCOPE</span>
            <h3>Evidence, not certainty.</h3>
            <p>
              Holdout results apply to the supplied corpus. Independent cross-dataset and recent real-world validation remain required.
              Final containment and attribution decisions stay with the human analyst.
            </p>
            <button type="button" onClick={() => navigate('/model-performance')}>
              Inspect model evidence <ArrowRight size={14} />
            </button>
          </aside>
        </div>
      </section>

      <footer className="cyber-landing-footer">
        <span>SENTINELTRACE · TEAM BRUTE</span>
        <button type="button" onClick={() => navigate('/login')}>Enter SOC <ArrowRight size={13} /></button>
        <span>SIH 26106 · FORENSIC INTELLIGENCE</span>
      </footer>
    </main>
  );
}
