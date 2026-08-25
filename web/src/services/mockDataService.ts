/**
 * Mock data service.
 *
 * Provides simulated campaigns, cases, alerts, and analytics data
 * for the SIH demo. Clearly separated from real backend calls.
 * All functions are prefixed with `mock` to make the origin obvious.
 */

import type {
  Campaign,
  CaseRecord,
  AnalyticsBundle,
  TimeRange,
  AuditEntry,
  Ioc,
} from '@/types';

/* ------------------------------------------------------------------ */
/* Campaigns                                                           */
/* ------------------------------------------------------------------ */

export const MOCK_CAMPAIGNS: Campaign[] = [
  {
    id: 'CT-2041',
    name: 'Fake Invoice Campaign',
    clusterBasis: ['Shared sender domain', 'Identical URL pattern', 'Same relay infrastructure', 'Common MX record'],
    emailCount: 127,
    domainCount: 8,
    ipCount: 14,
    victimCount: 43,
    firstObserved: '2026-08-12T09:14:00Z',
    lastObserved: '2026-08-25T07:33:00Z',
    risk: 'CRITICAL',
    classification: 'BUSINESS_EMAIL_COMPROMISE',
    status: 'ACTIVE',
    activity: Array.from({ length: 14 }, (_, i) => {
      const d = new Date('2026-08-12');
      d.setDate(d.getDate() + i);
      return { date: d.toISOString().slice(0, 10), count: Math.floor(4 + Math.random() * 18) };
    }),
    topDomains: ['paypa1-security.com', 'payme-secure.net', 'invoicesecure.io', 'acme-billing.net'],
    topIps: ['203.0.113.24', '185.220.101.45', '45.33.32.156', '198.41.0.4'],
    summary: 'Coordinated BEC campaign targeting finance departments across 43 Indian organizations. Uses lookalike PayPal domains and executive impersonation to redirect vendor payments.',
  },
  {
    id: 'CT-1987',
    name: 'Credential Phishing Wave',
    clusterBasis: ['Identical HTML template', 'Shared malicious URL', 'Same hosting ASN'],
    emailCount: 342,
    domainCount: 19,
    ipCount: 31,
    victimCount: 118,
    firstObserved: '2026-07-28T14:00:00Z',
    lastObserved: '2026-08-20T22:10:00Z',
    risk: 'HIGH',
    classification: 'PHISHING',
    status: 'CONTAINED',
    activity: Array.from({ length: 14 }, (_, i) => {
      const d = new Date('2026-07-28');
      d.setDate(d.getDate() + i);
      return { date: d.toISOString().slice(0, 10), count: Math.floor(10 + Math.random() * 40) };
    }),
    topDomains: ['secure-mail-verify.com', 'login-verify-now.net', 'account-check-in.org'],
    topIps: ['91.108.4.10', '77.88.5.204', '198.199.100.10'],
    summary: 'Mass credential harvesting campaign using spoofed Microsoft 365 login pages. Infrastructure traced to bulletproof hosting in Eastern Europe.',
  },
  {
    id: 'CT-1834',
    name: 'Malware Dropper Campaign',
    clusterBasis: ['Same attachment hash', 'Identical macro signature', 'Shared C2 domain'],
    emailCount: 58,
    domainCount: 4,
    ipCount: 7,
    victimCount: 22,
    firstObserved: '2026-08-01T00:00:00Z',
    lastObserved: '2026-08-18T16:00:00Z',
    risk: 'CRITICAL',
    classification: 'MALWARE',
    status: 'DORMANT',
    activity: Array.from({ length: 14 }, (_, i) => {
      const d = new Date('2026-08-01');
      d.setDate(d.getDate() + i);
      return { date: d.toISOString().slice(0, 10), count: Math.floor(Math.random() * 8) };
    }),
    topDomains: ['update-check.io', 'cdn-assets-load.com'],
    topIps: ['172.67.68.228', '104.21.90.111'],
    summary: 'Targeted dropper campaign delivering Cobalt Strike beacons via malicious Excel macros. Appears to be early-stage reconnaissance against financial sector targets.',
  },
];

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

export const MOCK_CASES: CaseRecord[] = [
  {
    id: 'ST-2026-00842',
    title: 'Executive Impersonation — Finance Department BEC',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    assignedTo: 'SOC-07',
    createdAt: '2026-08-24T10:30:00Z',
    updatedAt: '2026-08-25T08:55:00Z',
    summary: 'Suspected BEC attack targeting the finance department. Attacker impersonated CFO requesting urgent wire transfer of ₹47 lakh to a newly registered vendor account.',
    linkedAnalysisIds: ['local-001', 'local-002'],
    linkedCampaignIds: ['CT-2041'],
    indicators: [],
    notes: [
      {
        id: 'note-001',
        at: '2026-08-24T10:35:00Z',
        author: 'SOC-07',
        body: 'Initial triage complete. Email header shows mismatched Reply-To (protonmail) vs claimed sender domain (acmecorp.com). SPF and DMARC both failing. Escalating to Tier-2.',
      },
      {
        id: 'note-002',
        at: '2026-08-24T14:20:00Z',
        author: 'INV-03',
        body: 'Domain paypa1-security.com registered 12 days ago via Namecheap. Registrant details are privacy-protected. Hosting on Cloudflare with MX pointed to SendGrid. Classic infrastructure for BEC.',
      },
      {
        id: 'note-003',
        at: '2026-08-25T08:55:00Z',
        author: 'SOC-07',
        body: 'Finance team confirmed no wire transfer was initiated. Email was quarantined before reaching the CFO\'s secondary mailbox. Recommend blocking domain and associated IP range.',
      },
    ],
    evidence: [],
    slaDueAt: '2026-08-27T10:30:00Z',
  },
  {
    id: 'ST-2026-00837',
    title: 'Phishing — Credential Harvesting via Fake Microsoft Login',
    severity: 'HIGH',
    status: 'PENDING_REVIEW',
    assignedTo: 'SOC-04',
    createdAt: '2026-08-22T15:00:00Z',
    updatedAt: '2026-08-23T11:30:00Z',
    summary: 'Multiple users received phishing emails with a fake Microsoft 365 login link. 3 users clicked through. Credential reset initiated for affected accounts.',
    linkedAnalysisIds: [],
    linkedCampaignIds: ['CT-1987'],
    indicators: [],
    notes: [
      {
        id: 'note-010',
        at: '2026-08-22T15:30:00Z',
        author: 'SOC-04',
        body: 'URL analysis: secure-mail-verify.com resolves to Cloudflare front. Page mirrors Microsoft login exactly. Reported to Google Safe Browsing.',
      },
    ],
    evidence: [],
    slaDueAt: '2026-08-25T15:00:00Z',
  },
  {
    id: 'ST-2026-00821',
    title: 'Malware — Excel Dropper in Procurement Department',
    severity: 'CRITICAL',
    status: 'CLOSED',
    assignedTo: 'INV-03',
    createdAt: '2026-08-18T09:00:00Z',
    updatedAt: '2026-08-20T17:00:00Z',
    summary: 'Malicious Excel file with VBA macro delivered to procurement department. Macro attempted to download Cobalt Strike beacon. Endpoint protection blocked execution.',
    linkedAnalysisIds: [],
    linkedCampaignIds: ['CT-1834'],
    indicators: [],
    notes: [],
    evidence: [],
    slaDueAt: null,
  },
];

/* ------------------------------------------------------------------ */
/* Analytics                                                           */
/* ------------------------------------------------------------------ */

function genOverTime(days: number) {
  return Array.from({ length: days }, (_, i) => {
    const d = new Date();
    d.setDate(d.getDate() - (days - 1 - i));
    return {
      date: d.toISOString().slice(0, 10),
      phishing: Math.floor(8 + Math.random() * 20),
      bec: Math.floor(2 + Math.random() * 8),
      malware: Math.floor(1 + Math.random() * 6),
      spam: Math.floor(30 + Math.random() * 50),
    };
  });
}

export function mockAnalytics(range: TimeRange): AnalyticsBundle {
  const days = range === '24H' ? 1 : range === '7D' ? 7 : range === '30D' ? 30 : 90;
  return {
    range,
    origin: 'SIMULATED',
    byCategory: [
      { category: 'Business Email Compromise', count: 127, severity: 'CRITICAL' },
      { category: 'Phishing', count: 342, severity: 'HIGH' },
      { category: 'Malware Dropper', count: 58, severity: 'CRITICAL' },
      { category: 'Credential Harvesting', count: 214, severity: 'HIGH' },
      { category: 'Spam / Bulk', count: 891, severity: 'LOW' },
      { category: 'Impersonation', count: 67, severity: 'HIGH' },
    ],
    overTime: genOverTime(Math.min(days, 30)),
    topDomains: [
      { domain: 'paypa1-security.com', count: 47, risk: 'CRITICAL' },
      { domain: 'secure-mail-verify.com', count: 31, risk: 'CRITICAL' },
      { domain: 'invoicesecure.io', count: 22, risk: 'HIGH' },
      { domain: 'login-verify-now.net', count: 18, risk: 'CRITICAL' },
      { domain: 'update-check.io', count: 14, risk: 'HIGH' },
      { domain: 'payme-secure.net', count: 11, risk: 'HIGH' },
    ],
    topIps: [
      { ip: '203.0.113.24', count: 54, country: 'Singapore', risk: 'CRITICAL' },
      { ip: '185.220.101.45', count: 38, country: 'Germany', risk: 'CRITICAL' },
      { ip: '91.108.4.10', count: 27, country: 'Russia', risk: 'HIGH' },
      { ip: '45.33.32.156', count: 21, country: 'United States', risk: 'HIGH' },
      { ip: '77.88.5.204', count: 16, country: 'Netherlands', risk: 'MEDIUM' },
    ],
    countryDistribution: [
      { country: 'Singapore', countryCode: 'SG', count: 89, avgScore: 74 },
      { country: 'Russia', countryCode: 'RU', count: 67, avgScore: 81 },
      { country: 'United States', countryCode: 'US', count: 54, avgScore: 48 },
      { country: 'Germany', countryCode: 'DE', count: 48, avgScore: 63 },
      { country: 'China', countryCode: 'CN', count: 41, avgScore: 77 },
      { country: 'Netherlands', countryCode: 'NL', count: 33, avgScore: 55 },
      { country: 'India', countryCode: 'IN', count: 29, avgScore: 42 },
      { country: 'Ukraine', countryCode: 'UA', count: 24, avgScore: 79 },
    ],
    confidenceDistribution: [
      { bucket: '90–100%', count: 89 },
      { bucket: '80–90%', count: 134 },
      { bucket: '70–80%', count: 98 },
      { bucket: '60–70%', count: 67 },
      { bucket: '50–60%', count: 45 },
      { bucket: '<50%', count: 23 },
    ],
    authFailures: [
      { mechanism: 'SPF', pass: 312, fail: 198, softfail: 47 },
      { mechanism: 'DKIM', pass: 278, fail: 234, softfail: 0 },
      { mechanism: 'DMARC', pass: 241, fail: 271, softfail: 0 },
    ],
    campaignActivity: Array.from({ length: 14 }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (13 - i));
      return {
        date: d.toISOString().slice(0, 10),
        campaigns: Math.floor(1 + Math.random() * 3),
        emails: Math.floor(20 + Math.random() * 60),
      };
    }),
  };
}

/* ------------------------------------------------------------------ */
/* Audit log                                                           */
/* ------------------------------------------------------------------ */

export const MOCK_AUDIT: AuditEntry[] = [
  { id: 'AUD-001', at: new Date(Date.now() - 5 * 60000).toISOString(), actor: 'SOC-07', role: 'SOC_ANALYST', action: 'ANALYZE_EMAIL', target: 'paypa1-security-invoice.eml', outcome: 'SUCCESS', ipAddress: '10.0.1.45' },
  { id: 'AUD-002', at: new Date(Date.now() - 18 * 60000).toISOString(), actor: 'INV-03', role: 'INVESTIGATOR', action: 'EXPORT_REPORT', target: 'ST-2026-00842', outcome: 'SUCCESS', ipAddress: '10.0.1.67' },
  { id: 'AUD-003', at: new Date(Date.now() - 45 * 60000).toISOString(), actor: 'SOC-04', role: 'SOC_ANALYST', action: 'BLOCK_DOMAIN', target: 'paypa1-security.com', outcome: 'SUCCESS', ipAddress: '10.0.1.34' },
  { id: 'AUD-004', at: new Date(Date.now() - 2 * 3600000).toISOString(), actor: 'ADMIN-01', role: 'ADMIN', action: 'MANAGE_SETTINGS', target: 'RetentionPolicy', outcome: 'SUCCESS', ipAddress: '10.0.0.10' },
  { id: 'AUD-005', at: new Date(Date.now() - 3 * 3600000).toISOString(), actor: 'AUD-02', role: 'AUDITOR', action: 'VIEW_AUDIT', target: 'AuditLog-2026-08', outcome: 'SUCCESS', ipAddress: '10.0.1.89' },
  { id: 'AUD-006', at: new Date(Date.now() - 6 * 3600000).toISOString(), actor: 'SOC-07', role: 'SOC_ANALYST', action: 'CREATE_CASE', target: 'ST-2026-00842', outcome: 'SUCCESS', ipAddress: '10.0.1.45' },
  { id: 'AUD-007', at: new Date(Date.now() - 8 * 3600000).toISOString(), actor: 'UNKNOWN-IP', role: 'AUDITOR', action: 'EXPORT_REPORT', target: 'ST-2026-00837', outcome: 'DENIED', ipAddress: '203.0.113.99' },
];
