import React, { createContext, useContext, useState, useCallback } from 'react';
import type { Alert, AlertStatus } from '@/types';

interface AlertContextValue {
  alerts: Alert[];
  unreadCount: number;
  addAlert: (alert: Omit<Alert, 'id' | 'at'>) => void;
  acknowledge: (id: string) => void;
  resolve: (id: string) => void;
  clearAll: () => void;
}

const AlertContext = createContext<AlertContextValue | null>(null);

const SEED_ALERTS: Alert[] = [
  {
    id: 'ALT-001',
    at: new Date(Date.now() - 2 * 60000).toISOString(),
    severity: 'CRITICAL',
    title: 'Executive impersonation detected',
    detail: 'Email from finance@paypa1-security.com impersonates CFO requesting urgent wire transfer.',
    source: 'AI Engine',
    status: 'NEW',
    relatedAnalysisId: null,
    relatedCampaignId: 'CT-2041',
  },
  {
    id: 'ALT-002',
    at: new Date(Date.now() - 15 * 60000).toISOString(),
    severity: 'HIGH',
    title: 'Lookalike domain detected',
    detail: 'paypa1-security.com shows 96.2% similarity to paypal.com — registered 12 days ago.',
    source: 'Domain Intelligence',
    status: 'NEW',
    relatedAnalysisId: null,
    relatedCampaignId: null,
  },
  {
    id: 'ALT-003',
    at: new Date(Date.now() - 45 * 60000).toISOString(),
    severity: 'HIGH',
    title: 'Suspicious SMTP relay chain',
    detail: 'Email relayed through 3 jurisdictions including anonymizing infrastructure in Singapore.',
    source: 'Relay Analysis',
    status: 'ACKNOWLEDGED',
    relatedAnalysisId: null,
    relatedCampaignId: null,
  },
  {
    id: 'ALT-004',
    at: new Date(Date.now() - 2 * 3600000).toISOString(),
    severity: 'MEDIUM',
    title: 'Reply-To mismatch detected',
    detail: 'From: cfo@acmecorp.com but Reply-To: reply-acme@protonmail.com — possible interception attempt.',
    source: 'Header Analysis',
    status: 'ACKNOWLEDGED',
    relatedAnalysisId: null,
    relatedCampaignId: null,
  },
  {
    id: 'ALT-005',
    at: new Date(Date.now() - 6 * 3600000).toISOString(),
    severity: 'CRITICAL',
    title: 'Campaign CT-2041 spike detected',
    detail: '47 related emails detected in the last 6 hours. Fake Invoice Campaign escalating.',
    source: 'Campaign Intelligence',
    status: 'NEW',
    relatedAnalysisId: null,
    relatedCampaignId: 'CT-2041',
  },
];

let alertIdCounter = 100;

export function AlertProvider({ children }: { children: React.ReactNode }) {
  const [alerts, setAlerts] = useState<Alert[]>(SEED_ALERTS);

  const unreadCount = alerts.filter(a => a.status === 'NEW').length;

  const addAlert = useCallback((alert: Omit<Alert, 'id' | 'at'>) => {
    const newAlert: Alert = {
      ...alert,
      id: `ALT-${++alertIdCounter}`,
      at: new Date().toISOString(),
    };
    setAlerts(prev => [newAlert, ...prev]);
  }, []);

  const acknowledge = useCallback((id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'ACKNOWLEDGED' as AlertStatus } : a));
  }, []);

  const resolve = useCallback((id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'RESOLVED' as AlertStatus } : a));
  }, []);

  const clearAll = useCallback(() => setAlerts([]), []);

  return (
    <AlertContext.Provider value={{ alerts, unreadCount, addAlert, acknowledge, resolve, clearAll }}>
      {children}
    </AlertContext.Provider>
  );
}

export function useAlerts() {
  const ctx = useContext(AlertContext);
  if (!ctx) throw new Error('useAlerts must be used within AlertProvider');
  return ctx;
}
