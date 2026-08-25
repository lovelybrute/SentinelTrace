/**
 * Recognised mail transfer agents.
 *
 * Relay-path analysis is only useful if the analyst can tell "this hop is
 * Exchange Online" from "this hop is a VPS nobody has heard of". This table
 * carries the well-known providers; anything not listed is treated as unknown
 * rather than assumed hostile, because plenty of legitimate organisations run
 * their own mail.
 *
 * ASNs are recorded only where they are known with confidence. An unknown ASN is
 * `null`, never a guess.
 */

export interface MtaRecord {
  /** Suffix that identified this provider. */
  suffix: string;
  provider: string;
  asn: string | null;
  isp: string;
  /**
   * True for infrastructure operated by a provider that authenticates its
   * senders. A trusted hop is not proof of a benign message — bulk senders are
   * routinely abused — but it does mean the hop itself is accounted for.
   */
  trusted: boolean;
  /** Shown in the hop inspector when present. */
  note?: string;
}

const MTAS: MtaRecord[] = [
  { suffix: 'protection.outlook.com', provider: 'Microsoft Exchange Online Protection', asn: 'AS8075', isp: 'Microsoft Corporation', trusted: true },
  { suffix: 'outbound.protection.outlook.com', provider: 'Microsoft Exchange Online Protection', asn: 'AS8075', isp: 'Microsoft Corporation', trusted: true },
  { suffix: 'outlook.com', provider: 'Microsoft Outlook', asn: 'AS8075', isp: 'Microsoft Corporation', trusted: true },
  { suffix: 'hotmail.com', provider: 'Microsoft Outlook', asn: 'AS8075', isp: 'Microsoft Corporation', trusted: true },
  { suffix: 'l.google.com', provider: 'Google Mail', asn: 'AS15169', isp: 'Google LLC', trusted: true },
  { suffix: 'google.com', provider: 'Google LLC', asn: 'AS15169', isp: 'Google LLC', trusted: true },
  { suffix: 'googlemail.com', provider: 'Google Mail', asn: 'AS15169', isp: 'Google LLC', trusted: true },
  { suffix: 'amazonses.com', provider: 'Amazon SES', asn: 'AS16509', isp: 'Amazon.com, Inc.', trusted: true, note: 'Transactional sending platform. Legitimate transport, but frequently abused by actors who sign up with stolen cards — treat the platform as accounted for and judge the message on its content.' },
  { suffix: 'amazonaws.com', provider: 'Amazon Web Services', asn: 'AS16509', isp: 'Amazon.com, Inc.', trusted: false, note: 'General-purpose compute. A mail server here may be legitimate or attacker-controlled; the hostname alone does not distinguish them.' },
  { suffix: 'sendgrid.net', provider: 'Twilio SendGrid', asn: 'AS11377', isp: 'Twilio Inc.', trusted: true, note: 'Bulk sending platform with sender authentication.' },
  { suffix: 'mailgun.org', provider: 'Mailgun', asn: null, isp: 'Mailgun Technologies', trusted: true },
  { suffix: 'mailgun.net', provider: 'Mailgun', asn: null, isp: 'Mailgun Technologies', trusted: true },
  { suffix: 'mandrillapp.com', provider: 'Mailchimp Transactional', asn: null, isp: 'Intuit Mailchimp', trusted: true },
  { suffix: 'sparkpostmail.com', provider: 'SparkPost', asn: null, isp: 'MessageBird', trusted: true },
  { suffix: 'postmarkapp.com', provider: 'Postmark', asn: null, isp: 'ActiveCampaign', trusted: true },
  { suffix: 'mimecast.com', provider: 'Mimecast', asn: null, isp: 'Mimecast Services Ltd', trusted: true, note: 'Inbound security gateway.' },
  { suffix: 'pphosted.com', provider: 'Proofpoint', asn: 'AS22843', isp: 'Proofpoint, Inc.', trusted: true, note: 'Inbound security gateway.' },
  { suffix: 'ppops.net', provider: 'Proofpoint', asn: 'AS22843', isp: 'Proofpoint, Inc.', trusted: true },
  { suffix: 'messagelabs.com', provider: 'Broadcom Email Security.cloud', asn: null, isp: 'Broadcom Inc.', trusted: true },
  { suffix: 'barracudanetworks.com', provider: 'Barracuda Email Gateway', asn: null, isp: 'Barracuda Networks', trusted: true },
  { suffix: 'iphmx.com', provider: 'Cisco Secure Email', asn: null, isp: 'Cisco Systems', trusted: true },
  { suffix: 'icloud.com', provider: 'Apple iCloud Mail', asn: 'AS714', isp: 'Apple Inc.', trusted: true },
  { suffix: 'me.com', provider: 'Apple iCloud Mail', asn: 'AS714', isp: 'Apple Inc.', trusted: true },
  { suffix: 'yahoodns.net', provider: 'Yahoo Mail', asn: 'AS36647', isp: 'Yahoo Inc.', trusted: true },
  { suffix: 'zoho.com', provider: 'Zoho Mail', asn: null, isp: 'Zoho Corporation', trusted: true },
  { suffix: 'zohomail.com', provider: 'Zoho Mail', asn: null, isp: 'Zoho Corporation', trusted: true },
  { suffix: 'rediffmail.com', provider: 'Rediffmail', asn: null, isp: 'Rediff.com India Ltd', trusted: true },
  { suffix: 'nic.in', provider: 'National Informatics Centre', asn: null, isp: 'National Informatics Centre', trusted: true, note: 'Government of India mail infrastructure.' },
  { suffix: 'gov.in', provider: 'Government of India', asn: null, isp: 'National Informatics Centre', trusted: true },
];

/** Longest suffix wins, so `l.google.com` beats `google.com`. */
const SORTED = [...MTAS].sort((a, b) => b.suffix.length - a.suffix.length);

export function lookupMta(hostname: string | null): MtaRecord | null {
  if (!hostname) return null;
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  for (const record of SORTED) {
    if (host === record.suffix || host.endsWith(`.${record.suffix}`)) return record;
  }
  return null;
}

/** True when the hop belongs to a provider that authenticates its senders. */
export function isKnownGoodMta(hostname: string | null): boolean {
  return lookupMta(hostname)?.trusted === true;
}
