/**
 * Offline domain registration intelligence.
 *
 * Stands in for WHOIS/RDAP and DNS, which the backend can only provide when it
 * has egress. Domains absent from the table resolve to a record whose fields are
 * explicitly `null` with a note explaining that registration data was not
 * available — never invented values.
 */

import type { Reputation } from '@/types';

export interface DomainRecord {
  registrar: string | null;
  createdAt: string | null;
  nameservers: string[];
  mxRecords: { host: string; priority: number; suspicious: boolean }[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  reputation: Reputation;
  /** Registrant country from RDAP, where disclosed. */
  registrantCountry: string | null;
  blacklists: { source: string; listed: boolean }[];
  notes: string[];
}

const DEFAULT_BLACKLISTS = ['Spamhaus DBL', 'SURBL', 'PhishTank', 'URLhaus', 'OpenPhish'];

function blacklists(listed: string[]): { source: string; listed: boolean }[] {
  return DEFAULT_BLACKLISTS.map((source) => ({ source, listed: listed.includes(source) }));
}

/**
 * Curated records. Legitimate brands carry real-world registrars and
 * nameservers; the adversary infrastructure belongs to the bundled demo corpus
 * and uses reserved documentation-style naming.
 */
const DOMAINS: Record<string, DomainRecord> = {
  /* ---------------- Adversary infrastructure (demo corpus) ---------------- */
  'paypa1-security.com': {
    registrar: 'PDR Ltd. d/b/a PublicDomainRegistry.com',
    createdAt: '2026-08-12T04:18:11Z',
    nameservers: ['ns1.cheapnamehost.net', 'ns2.cheapnamehost.net'],
    mxRecords: [{ host: 'mail.paypa1-security.com', priority: 10, suspicious: true }],
    spfRecord: 'v=spf1 ip4:203.0.113.0/24 -all',
    dmarcRecord: 'v=DMARC1; p=none; rua=mailto:dmarc@paypa1-security.com; pct=100',
    reputation: 'MALICIOUS',
    registrantCountry: null,
    blacklists: blacklists(['Spamhaus DBL', 'PhishTank', 'OpenPhish']),
    notes: [
      'Registered 12 days before the message was sent — newly created domains are disproportionately represented in credential-theft and payment-fraud campaigns.',
      'Registrant details are withheld behind a privacy service, so no organisation can be tied to the registration.',
      'The single MX host resolves into the same /24 as the sending relay, indicating purpose-built rather than shared infrastructure.',
      'SPF authorises only 203.0.113.0/24 and terminates in `-all`, yet the message was relayed into the recipient from 198.51.100.77 — an address the policy explicitly excludes, which is why SPF fails despite the attacker controlling the domain.',
      'DMARC is published at p=none, so the domain requests no enforcement. This is why a failing message was still delivered rather than quarantined or rejected.',
    ],
  },
  'nexora-finance.com': {
    registrar: 'NameSilo, LLC',
    createdAt: '2026-07-29T11:02:44Z',
    nameservers: ['ns1.dnsowl.com', 'ns2.dnsowl.com'],
    mxRecords: [{ host: 'mx.nexora-finance.com', priority: 10, suspicious: true }],
    spfRecord: 'v=spf1 ip4:198.51.100.0/24 ~all',
    dmarcRecord: 'v=DMARC1; p=none',
    reputation: 'MALICIOUS',
    registrantCountry: null,
    blacklists: blacklists(['Spamhaus DBL', 'SURBL']),
    notes: [
      'Registered 26 days before use, with privacy-protected registrant data.',
      'A DMARC record exists but is set to p=none, which publishes no enforcement and is common on domains stood up purely to survive basic filters.',
    ],
  },
  'secure-doc-review.net': {
    registrar: 'Hostinger Operations, UAB',
    createdAt: '2026-08-05T08:44:02Z',
    nameservers: ['ns1.dns-parking.com', 'ns2.dns-parking.com'],
    mxRecords: [],
    spfRecord: null,
    dmarcRecord: null,
    reputation: 'MALICIOUS',
    registrantCountry: null,
    blacklists: blacklists(['PhishTank', 'URLhaus', 'OpenPhish']),
    notes: [
      'No MX records published — the domain cannot receive mail and exists only to host web content.',
      'Nameservers belong to a parking service, consistent with a short-lived landing page.',
    ],
  },
  'hdfc-bank-verify.in': {
    registrar: 'Endurance Digital Domain Technology',
    createdAt: '2026-08-18T06:12:39Z',
    nameservers: ['ns1.parkingcrew.net', 'ns2.parkingcrew.net'],
    mxRecords: [{ host: 'mail.hdfc-bank-verify.in', priority: 10, suspicious: true }],
    spfRecord: 'v=spf1 +all',
    dmarcRecord: null,
    reputation: 'MALICIOUS',
    registrantCountry: 'IN',
    blacklists: blacklists(['Spamhaus DBL', 'PhishTank']),
    notes: [
      'Registered 6 days before observed use.',
      'The SPF record uses `+all`, which authorises every host on the internet to send as this domain — the opposite of a protective policy and a strong indicator of abuse tooling defaults.',
    ],
  },
  'invoice-settlement.cc': {
    registrar: 'Gname.com Pte. Ltd.',
    createdAt: '2026-06-14T15:31:20Z',
    nameservers: ['ns1.gname.net', 'ns2.gname.net'],
    mxRecords: [{ host: 'mail.invoice-settlement.cc', priority: 10, suspicious: true }],
    spfRecord: 'v=spf1 ip4:45.145.0.0/16 -all',
    dmarcRecord: null,
    reputation: 'MALICIOUS',
    registrantCountry: null,
    blacklists: blacklists(['Spamhaus DBL', 'SURBL', 'URLhaus']),
    notes: [
      'Long-lived relative to the other campaign domains, suggesting a reused staging asset.',
      'SPF authorises a bulk-hosting range associated with repeated abuse reports.',
    ],
  },

  /* ---------------- Legitimate reference domains ---------------- */
  'paypal.com': {
    registrar: 'MarkMonitor Inc.',
    createdAt: '1999-07-15T00:00:00Z',
    nameservers: ['ns1.p57.dynect.net', 'ns2.p57.dynect.net', 'pdns100.ultradns.com'],
    mxRecords: [
      { host: 'mx1.paypal.com', priority: 10, suspicious: false },
      { host: 'mx2.paypal.com', priority: 20, suspicious: false },
    ],
    spfRecord: 'v=spf1 include:_spf.paypal.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:d@rua.agari.com',
    reputation: 'CLEAN',
    registrantCountry: 'US',
    blacklists: blacklists([]),
    notes: ['Brand-protection registrar, registry-locked, DMARC enforced at p=reject.'],
  },
  'nexoragroup.in': {
    registrar: 'GoDaddy.com, LLC',
    createdAt: '2014-03-04T09:15:00Z',
    nameservers: ['ns17.domaincontrol.com', 'ns18.domaincontrol.com'],
    mxRecords: [
      { host: 'nexoragroup-in.mail.protection.outlook.com', priority: 0, suspicious: false },
    ],
    spfRecord: 'v=spf1 include:spf.protection.outlook.com -all',
    dmarcRecord: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@nexoragroup.in; adkim=s; aspf=s',
    reputation: 'CLEAN',
    registrantCountry: 'IN',
    blacklists: blacklists([]),
    notes: [
      'The organisation genuinely impersonated in this campaign. Mail is served by Exchange Online with strict alignment and a quarantine policy.',
    ],
  },
  'hdfcbank.com': {
    registrar: 'Network Solutions, LLC',
    createdAt: '1997-11-06T00:00:00Z',
    nameservers: ['ns1.hdfcbank.com', 'ns2.hdfcbank.com'],
    mxRecords: [{ host: 'mx.hdfcbank.com', priority: 10, suspicious: false }],
    spfRecord: 'v=spf1 include:spf.hdfcbank.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:dmarc@hdfcbank.com',
    reputation: 'CLEAN',
    registrantCountry: 'IN',
    blacklists: blacklists([]),
    notes: ['Established registration with enforced DMARC.'],
  },
  'gmail.com': {
    registrar: 'MarkMonitor Inc.',
    createdAt: '1995-08-13T00:00:00Z',
    nameservers: ['ns1.google.com', 'ns2.google.com'],
    mxRecords: [
      { host: 'gmail-smtp-in.l.google.com', priority: 5, suspicious: false },
      { host: 'alt1.gmail-smtp-in.l.google.com', priority: 10, suspicious: false },
    ],
    spfRecord: 'v=spf1 redirect=_spf.google.com',
    dmarcRecord: 'v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com',
    reputation: 'CLEAN',
    registrantCountry: 'US',
    blacklists: blacklists([]),
    notes: ['Consumer mail provider. Sender identity within the provider is not verifiable from headers alone.'],
  },
};

/** Look up curated registration intelligence for a domain. */
export function lookupDomain(domain: string): DomainRecord | null {
  return DOMAINS[domain.trim().toLowerCase().replace(/^www\./, '')] ?? null;
}

/** A record for domains with no curated intelligence — all unknowns, stated. */
export function unresolvedDomainRecord(reason: string): DomainRecord {
  return {
    registrar: null,
    createdAt: null,
    nameservers: [],
    mxRecords: [],
    spfRecord: null,
    dmarcRecord: null,
    reputation: 'UNKNOWN',
    registrantCountry: null,
    blacklists: DEFAULT_BLACKLISTS.map((source) => ({ source, listed: false })),
    notes: [reason],
  };
}

/** Days between a registration date and the analysis time. */
export function ageInDays(createdAt: string | null, at: string): number | null {
  if (!createdAt) return null;
  const created = new Date(createdAt).getTime();
  const now = new Date(at).getTime();
  if (Number.isNaN(created) || Number.isNaN(now)) return null;
  return Math.max(0, Math.floor((now - created) / 86_400_000));
}
