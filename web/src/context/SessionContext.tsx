import React, { createContext, useContext, useState, useCallback } from 'react';
import type { Session, Role } from '@/types';

interface SessionContextValue {
  session: Session | null;
  signIn: (email: string, password: string) => void;
  signInDemo: (role?: Role) => void;
  signOut: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

const DEMO_SESSIONS: Record<Role, Session> = {
  ADMIN: {
    analystId: 'ADMIN-01',
    displayName: 'Dr. Arjun Sharma',
    email: 'arjun.sharma@cert-in.gov.in',
    role: 'ADMIN',
    unit: 'CERT-In National Cyber Response Team',
    signedInAt: new Date().toISOString(),
    demo: true,
  },
  SOC_ANALYST: {
    analystId: 'SOC-07',
    displayName: 'Priya Nair',
    email: 'priya.nair@soc.sentineltrace.in',
    role: 'SOC_ANALYST',
    unit: 'Tier-2 Email Threat Analysis',
    signedInAt: new Date().toISOString(),
    demo: true,
  },
  INVESTIGATOR: {
    analystId: 'INV-03',
    displayName: 'Rahul Mehta',
    email: 'rahul.mehta@cybercellindia.gov.in',
    role: 'INVESTIGATOR',
    unit: 'Cybercrime Investigation Cell',
    signedInAt: new Date().toISOString(),
    demo: true,
  },
  AUDITOR: {
    analystId: 'AUD-02',
    displayName: 'Kavya Reddy',
    email: 'kavya.reddy@audit.sentineltrace.in',
    role: 'AUDITOR',
    unit: 'Compliance & Evidence Review',
    signedInAt: new Date().toISOString(),
    demo: true,
  },
};

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);

  const signIn = useCallback((email: string, _password: string) => {
    setSession({
      analystId: 'USR-01',
      displayName: email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      email,
      role: 'SOC_ANALYST',
      unit: 'Email Security Operations',
      signedInAt: new Date().toISOString(),
      demo: false,
    });
  }, []);

  const signInDemo = useCallback((role: Role = 'SOC_ANALYST') => {
    setSession(DEMO_SESSIONS[role]);
  }, []);

  const signOut = useCallback(() => setSession(null), []);

  return (
    <SessionContext.Provider value={{ session, signIn, signInDemo, signOut }}>
      {children}
    </SessionContext.Provider>
  );
}

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used within SessionProvider');
  return ctx;
}
