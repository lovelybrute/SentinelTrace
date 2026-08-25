import React, { createContext, useContext, useState, useCallback } from 'react';
import type { EmailAnalysis, AnalysisSummary, DashboardMetrics } from '@/types';

interface AnalysisContextValue {
  currentAnalysis: EmailAnalysis | null;
  history: AnalysisSummary[];
  metrics: DashboardMetrics;
  setCurrentAnalysis: (analysis: EmailAnalysis | null) => void;
  addToHistory: (analysis: EmailAnalysis) => void;
  clearHistory: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);

const DEFAULT_METRICS: DashboardMetrics = {
  emailsAnalyzed: 2847,
  threatsDetected: 634,
  criticalThreats: 127,
  suspiciousDomains: 89,
  maliciousIps: 214,
  activeInvestigations: 18,
  deltas: {
    emailsAnalyzed: 12.4,
    threatsDetected: 8.7,
    criticalThreats: -3.2,
    activeInvestigations: 5.1,
  },
  trend: Array.from({ length: 14 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (13 - i));
    return {
      date: date.toISOString().slice(0, 10),
      analyzed: Math.floor(150 + Math.random() * 80),
      threats: Math.floor(30 + Math.random() * 40),
    };
  }),
  origin: 'SIMULATED',
};

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [currentAnalysis, setCurrentAnalysis] = useState<EmailAnalysis | null>(null);
  const [history, setHistory] = useState<AnalysisSummary[]>([]);
  const [metrics, setMetrics] = useState<DashboardMetrics>(DEFAULT_METRICS);

  const addToHistory = useCallback((analysis: EmailAnalysis) => {
    const summary: AnalysisSummary = {
      id: analysis.id,
      backendId: analysis.backendId,
      origin: analysis.origin,
      sender: analysis.metadata.from,
      subject: analysis.metadata.subject,
      score: analysis.score.total,
      level: analysis.score.level,
      classification: analysis.assessment.classification,
      country: analysis.originAssessment.estimatedLocation?.country ?? null,
      analyzedAt: analysis.analyzedAt,
    };
    setHistory(prev => [summary, ...prev.slice(0, 49)]);
    setMetrics(prev => ({
      ...prev,
      emailsAnalyzed: prev.emailsAnalyzed + 1,
      threatsDetected: analysis.score.total >= 50 ? prev.threatsDetected + 1 : prev.threatsDetected,
      criticalThreats: analysis.score.total >= 75 ? prev.criticalThreats + 1 : prev.criticalThreats,
    }));
  }, []);

  const clearHistory = useCallback(() => setHistory([]), []);

  return (
    <AnalysisContext.Provider value={{
      currentAnalysis,
      history,
      metrics,
      setCurrentAnalysis,
      addToHistory,
      clearHistory,
    }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider');
  return ctx;
}
