import React, { Suspense, useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useSession } from '@/context/SessionContext';
import { Layout } from '@/components/shell/Layout';
import { Shield } from 'lucide-react';

// Route-Level Lazy Loading
const Landing = React.lazy(() => import('@/pages/Landing').then(m => ({ default: m.Landing })));
const Login = React.lazy(() => import('@/pages/Login').then(m => ({ default: m.Login })));
const Dashboard = React.lazy(() => import('@/pages/Dashboard').then(m => ({ default: m.Dashboard })));
const EmailAnalyzer = React.lazy(() => import('@/pages/EmailAnalyzer').then(m => ({ default: m.EmailAnalyzer })));
const HeaderForensics = React.lazy(() => import('@/pages/HeaderForensics').then(m => ({ default: m.HeaderForensics })));
const RelayChain = React.lazy(() => import('@/pages/RelayChain').then(m => ({ default: m.RelayChain })));
const OriginTrace = React.lazy(() => import('@/pages/OriginTrace').then(m => ({ default: m.OriginTrace })));
const ThreatIntelligence = React.lazy(() => import('@/pages/ThreatIntelligence').then(m => ({ default: m.ThreatIntelligence })));
const GraphInvestigation = React.lazy(() => import('@/pages/GraphInvestigation').then(m => ({ default: m.GraphInvestigation })));
const CampaignIntelligence = React.lazy(() => import('@/pages/CampaignIntelligence').then(m => ({ default: m.CampaignIntelligence })));
const CaseManagement = React.lazy(() => import('@/pages/CaseManagement').then(m => ({ default: m.CaseManagement })));
const ForensicReports = React.lazy(() => import('@/pages/ForensicReports').then(m => ({ default: m.ForensicReports })));
const AlertCenter = React.lazy(() => import('@/pages/AlertCenter').then(m => ({ default: m.AlertCenter })));
const Analytics = React.lazy(() => import('@/pages/Analytics').then(m => ({ default: m.Analytics })));
const Settings = React.lazy(() => import('@/pages/Settings').then(m => ({ default: m.Settings })));
const TeamBruteIntro = React.lazy(() =>
  import('@/components/intro/TeamBruteIntro').then(m => ({ default: m.TeamBruteIntro })),
);

function LoadingFallback() {
  return (
    <div className="min-h-screen bg-[#020617] flex flex-col items-center justify-center text-center p-6 space-y-4">
      <div className="relative">
        <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.3)]">
          <Shield size={24} className="animate-pulse" />
        </div>
        <div className="absolute inset-0 rounded-xl border-2 border-cyan-400 border-t-transparent animate-spin" />
      </div>
      <div className="font-mono text-xs font-bold text-cyan-300 tracking-widest uppercase">
        LOADING FORENSIC MODULE...
      </div>
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { session } = useSession();
  if (!session) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  const { session } = useSession();
  const [showIntro, setShowIntro] = useState(() => {
    // Play once per browser session (sessionStorage), not once ever
    const introDisabled = localStorage.getItem('sentineltrace_intro_enabled') === 'false';
    const introSeen = sessionStorage.getItem('sentineltrace_intro_seen') === 'true';
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    return !introDisabled && !introSeen && !prefersReducedMotion;
  });

  return (
    <>
      {/* Cinematic Startup Sequence (First visit or manual trigger) */}
      {showIntro && (
        <Suspense fallback={<div className="fixed inset-0 z-[9999] bg-[#02070D]" aria-label="Loading cinematic intro" />}>
          <TeamBruteIntro onComplete={() => setShowIntro(false)} />
        </Suspense>
      )}

      {/* Main Application with Lazy Route Suspense */}
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          {/* Public Hero / Storytelling Landing Page */}
          <Route path="/" element={<Landing />} />
          <Route path="/landing" element={<Landing />} />

          {/* Auth */}
          <Route
            path="/login"
            element={session ? <Navigate to="/dashboard" replace /> : <Login />}
          />

          {/* Protected SOC Forensic Modules */}
          <Route
            path="/dashboard"
            element={<ProtectedRoute><Dashboard /></ProtectedRoute>}
          />
          <Route
            path="/analyzer"
            element={<ProtectedRoute><EmailAnalyzer /></ProtectedRoute>}
          />
          <Route
            path="/header-forensics"
            element={<ProtectedRoute><HeaderForensics /></ProtectedRoute>}
          />
          <Route
            path="/relay-chain"
            element={<ProtectedRoute><RelayChain /></ProtectedRoute>}
          />
          <Route
            path="/origin-trace"
            element={<ProtectedRoute><OriginTrace /></ProtectedRoute>}
          />
          <Route
            path="/threat-intel"
            element={<ProtectedRoute><ThreatIntelligence /></ProtectedRoute>}
          />
          <Route
            path="/graph"
            element={<ProtectedRoute><GraphInvestigation /></ProtectedRoute>}
          />
          <Route
            path="/campaigns"
            element={<ProtectedRoute><CampaignIntelligence /></ProtectedRoute>}
          />
          <Route
            path="/cases"
            element={<ProtectedRoute><CaseManagement /></ProtectedRoute>}
          />
          <Route
            path="/reports"
            element={<ProtectedRoute><ForensicReports /></ProtectedRoute>}
          />
          <Route
            path="/alerts"
            element={<ProtectedRoute><AlertCenter /></ProtectedRoute>}
          />
          <Route
            path="/analytics"
            element={<ProtectedRoute><Analytics /></ProtectedRoute>}
          />
          <Route
            path="/settings"
            element={<ProtectedRoute><Settings /></ProtectedRoute>}
          />

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </>
  );
}
