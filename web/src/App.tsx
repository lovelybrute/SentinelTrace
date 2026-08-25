import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useSession } from '@/context/SessionContext';
import { Layout } from '@/components/shell/Layout';
import { Landing } from '@/pages/Landing';
import { Login } from '@/pages/Login';
import { Dashboard } from '@/pages/Dashboard';
import { EmailAnalyzer } from '@/pages/EmailAnalyzer';
import { HeaderForensics } from '@/pages/HeaderForensics';
import { RelayChain } from '@/pages/RelayChain';
import { OriginTrace } from '@/pages/OriginTrace';
import { ThreatIntelligence } from '@/pages/ThreatIntelligence';
import { GraphInvestigation } from '@/pages/GraphInvestigation';
import { CampaignIntelligence } from '@/pages/CampaignIntelligence';
import { CaseManagement } from '@/pages/CaseManagement';
import { ForensicReports } from '@/pages/ForensicReports';
import { AlertCenter } from '@/pages/AlertCenter';
import { Analytics } from '@/pages/Analytics';
import { Settings } from '@/pages/Settings';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { session } = useSession();
  if (!session) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  const { session } = useSession();

  return (
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
  );
}
