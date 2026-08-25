/**
 * Offline network intelligence tables.
 *
 * The backend enriches IPs through ip-api.com, which needs egress. The SIH
 * demonstration must run with no external services at all, so this module holds
 * a static table of well-known netblocks — the kind of curated intelligence a
 * real platform ships and refreshes on a feed.
 *
 * Crucially, an address that is *not* in the table returns `null` rather than a
 * plausible-looking guess. An unresolved hop is honest; a fabricated one would
 * corrupt an investigation.
 */

import type { GeoPoint, Reputation } from '@/types';

export interface NetworkRecord {
  geo: GeoPoint;
  isp: string;
  organization: string;
  asn: string;
  asnOwner: string;
  hostingType: 'DATACENTER' | 'RESIDENTIAL' | 'MOBILE' | 'UNKNOWN';
  /** Baseline reputation for the netblock, before per-IP signals. */
  reputation: Reputation;
}

interface NetblockEntry extends NetworkRecord {
  cidr: string;
}

/** City coordinates used for map projection. */
const CITY: Record<string, { country: string; countryCode: string; city: string; region: string; lat: number; lon: number }> = {
  singapore: { country: 'Singapore', countryCode: 'SG', city: 'Singapore', region: 'Central Singapore', lat: 1.3521, lon: 103.8198 },
  frankfurt: { country: 'Germany', countryCode: 'DE', city: 'Frankfurt am Main', region: 'Hesse', lat: 50.1109, lon: 8.6821 },
  amsterdam: { country: 'Netherlands', countryCode: 'NL', city: 'Amsterdam', region: 'North Holland', lat: 52.3676, lon: 4.9041 },
  london: { country: 'United Kingdom', countryCode: 'GB', city: 'London', region: 'England', lat: 51.5074, lon: -0.1278 },
  ashburn: { country: 'United States', countryCode: 'US', city: 'Ashburn', region: 'Virginia', lat: 39.0438, lon: -77.4874 },
  mountainview: { country: 'United States', countryCode: 'US', city: 'Mountain View', region: 'California', lat: 37.3861, lon: -122.0839 },
  redmond: { country: 'United States', countryCode: 'US', city: 'Redmond', region: 'Washington', lat: 47.674, lon: -122.1215 },
  mumbai: { country: 'India', countryCode: 'IN', city: 'Mumbai', region: 'Maharashtra', lat: 19.076, lon: 72.8777 },
  newdelhi: { country: 'India', countryCode: 'IN', city: 'New Delhi', region: 'Delhi', lat: 28.6139, lon: 77.209 },
  bengaluru: { country: 'India', countryCode: 'IN', city: 'Bengaluru', region: 'Karnataka', lat: 12.9716, lon: 77.5946 },
  hyderabad: { country: 'India', countryCode: 'IN', city: 'Hyderabad', region: 'Telangana', lat: 17.385, lon: 78.4867 },
  moscow: { country: 'Russia', countryCode: 'RU', city: 'Moscow', region: 'Moscow', lat: 55.7558, lon: 37.6173 },
  lagos: { country: 'Nigeria', countryCode: 'NG', city: 'Lagos', region: 'Lagos', lat: 6.5244, lon: 3.3792 },
  hongkong: { country: 'Hong Kong', countryCode: 'HK', city: 'Hong Kong', region: 'Hong Kong', lat: 22.3193, lon: 114.1694 },
  tokyo: { country: 'Japan', countryCode: 'JP', city: 'Tokyo', region: 'Tokyo', lat: 35.6762, lon: 139.6503 },
  sydney: { country: 'Australia', countryCode: 'AU', city: 'Sydney', region: 'New South Wales', lat: -33.8688, lon: 151.2093 },
  saopaulo: { country: 'Brazil', countryCode: 'BR', city: 'São Paulo', region: 'São Paulo', lat: -23.5505, lon: -46.6333 },
  bucharest: { country: 'Romania', countryCode: 'RO', city: 'Bucharest', region: 'Bucharest', lat: 44.4268, lon: 26.1025 },
  kyiv: { country: 'Ukraine', countryCode: 'UA', city: 'Kyiv', region: 'Kyiv', lat: 50.4501, lon: 30.5234 },
  panama: { country: 'Panama', countryCode: 'PA', city: 'Panama City', region: 'Panamá', lat: 8.9824, lon: -79.5199 },
  seychelles: { country: 'Seychelles', countryCode: 'SC', city: 'Victoria', region: 'Mahé', lat: -4.6191, lon: 55.4513 },
};

function geo(key: keyof typeof CITY): GeoPoint {
  const c = CITY[key];
  return {
    country: c.country,
    countryCode: c.countryCode,
    city: c.city,
    region: c.region,
    latitude: c.lat,
    longitude: c.lon,
  };
}

/**
 * Netblocks are matched longest-prefix-first. ASNs and owners are real; the
 * ranges are representative slices of each operator's announced space.
 */
const NETBLOCKS: NetblockEntry[] = [
  // --- Documentation ranges (RFC 5737). Used by the bundled demo corpus. ---
  { cidr: '203.0.113.0/24', ...record('singapore', 'Pacific Rim Colocation', 'PRC Hosting Pte Ltd', 'AS64512', 'Pacific Rim Colocation', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '198.51.100.0/24', ...record('frankfurt', 'Continental Bulk Hosting', 'CBH Networks GmbH', 'AS64513', 'Continental Bulk Hosting', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '192.0.2.0/24', ...record('amsterdam', 'Meridian Transit BV', 'Meridian Transit', 'AS64514', 'Meridian Transit BV', 'DATACENTER', 'UNKNOWN') },

  // --- Hyperscalers ---
  { cidr: '52.0.0.0/8', ...record('ashburn', 'Amazon Web Services', 'Amazon.com, Inc.', 'AS16509', 'AMAZON-02', 'DATACENTER', 'CLEAN') },
  { cidr: '54.0.0.0/8', ...record('ashburn', 'Amazon Web Services', 'Amazon.com, Inc.', 'AS16509', 'AMAZON-02', 'DATACENTER', 'CLEAN') },
  { cidr: '13.104.0.0/14', ...record('redmond', 'Microsoft Corporation', 'Microsoft Corporation', 'AS8075', 'MICROSOFT-CORP-MSN-AS-BLOCK', 'DATACENTER', 'CLEAN') },
  { cidr: '40.92.0.0/15', ...record('redmond', 'Microsoft Corporation', 'Microsoft Outlook', 'AS8075', 'MICROSOFT-CORP-MSN-AS-BLOCK', 'DATACENTER', 'CLEAN') },
  { cidr: '40.107.0.0/16', ...record('redmond', 'Microsoft Corporation', 'Exchange Online Protection', 'AS8075', 'MICROSOFT-CORP-MSN-AS-BLOCK', 'DATACENTER', 'CLEAN') },
  { cidr: '104.47.0.0/16', ...record('redmond', 'Microsoft Corporation', 'Exchange Online Protection', 'AS8075', 'MICROSOFT-CORP-MSN-AS-BLOCK', 'DATACENTER', 'CLEAN') },
  { cidr: '209.85.128.0/17', ...record('mountainview', 'Google LLC', 'Google Mail', 'AS15169', 'GOOGLE', 'DATACENTER', 'CLEAN') },
  { cidr: '142.250.0.0/15', ...record('mountainview', 'Google LLC', 'Google LLC', 'AS15169', 'GOOGLE', 'DATACENTER', 'CLEAN') },
  { cidr: '172.217.0.0/16', ...record('mountainview', 'Google LLC', 'Google LLC', 'AS15169', 'GOOGLE', 'DATACENTER', 'CLEAN') },
  { cidr: '35.190.0.0/16', ...record('ashburn', 'Google Cloud', 'Google LLC', 'AS15169', 'GOOGLE', 'DATACENTER', 'CLEAN') },
  { cidr: '104.16.0.0/13', ...record('london', 'Cloudflare, Inc.', 'Cloudflare, Inc.', 'AS13335', 'CLOUDFLARENET', 'DATACENTER', 'CLEAN') },

  // --- Budget / bulletproof-adjacent hosting, frequently seen in abuse data ---
  { cidr: '45.145.0.0/16', ...record('bucharest', 'Alexhost SRL', 'AlexHost', 'AS200019', 'ALEXHOST-AS', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '185.220.100.0/22', ...record('frankfurt', 'Zwiebelfreunde e.V.', 'Tor Exit Relay Infrastructure', 'AS205100', 'F3NETZE', 'DATACENTER', 'MALICIOUS') },
  { cidr: '194.180.48.0/20', ...record('kyiv', 'Green Floid LLC', 'Green Floid', 'AS215540', 'GREENFLOID', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '5.188.0.0/16', ...record('moscow', 'Petersburg Internet Network', 'PIN Ltd', 'AS44050', 'PIN-AS', 'DATACENTER', 'MALICIOUS') },
  { cidr: '91.219.236.0/22', ...record('seychelles', 'Flyservers S.A.', 'FlyServers', 'AS209588', 'FLYSERVERS', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '167.99.0.0/16', ...record('amsterdam', 'DigitalOcean, LLC', 'DigitalOcean', 'AS14061', 'DIGITALOCEAN-ASN', 'DATACENTER', 'UNKNOWN') },
  { cidr: '134.209.0.0/16', ...record('london', 'DigitalOcean, LLC', 'DigitalOcean', 'AS14061', 'DIGITALOCEAN-ASN', 'DATACENTER', 'UNKNOWN') },
  { cidr: '51.75.0.0/16', ...record('frankfurt', 'OVH SAS', 'OVHcloud', 'AS16276', 'OVH', 'DATACENTER', 'UNKNOWN') },
  { cidr: '178.63.0.0/16', ...record('frankfurt', 'Hetzner Online GmbH', 'Hetzner', 'AS24940', 'HETZNER-AS', 'DATACENTER', 'UNKNOWN') },
  { cidr: '161.97.0.0/16', ...record('frankfurt', 'Contabo GmbH', 'Contabo', 'AS51167', 'CONTABO', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '139.180.128.0/17', ...record('singapore', 'The Constant Company', 'Vultr Holdings', 'AS20473', 'AS-VULTR', 'DATACENTER', 'UNKNOWN') },
  { cidr: '45.32.0.0/16', ...record('singapore', 'The Constant Company', 'Vultr Holdings', 'AS20473', 'AS-VULTR', 'DATACENTER', 'UNKNOWN') },
  { cidr: '47.74.0.0/16', ...record('hongkong', 'Alibaba Cloud', 'Alibaba (US) Technology', 'AS45102', 'ALIBABA-CN-NET', 'DATACENTER', 'UNKNOWN') },
  { cidr: '103.109.52.0/22', ...record('singapore', 'Ecatel Sarl', 'Quasi Networks', 'AS29073', 'QUASINETWORKS', 'DATACENTER', 'MALICIOUS') },

  // --- Indian consumer and enterprise networks ---
  { cidr: '49.36.0.0/14', ...record('mumbai', 'Reliance Jio Infocomm', 'Reliance Jio Infocomm Limited', 'AS55836', 'RELIANCEJIO-IN', 'MOBILE', 'CLEAN') },
  { cidr: '117.196.0.0/14', ...record('newdelhi', 'Bharat Sanchar Nigam Ltd', 'BSNL Internet', 'AS9829', 'BSNL-NIB', 'RESIDENTIAL', 'CLEAN') },
  { cidr: '122.176.0.0/14', ...record('newdelhi', 'Bharti Airtel Ltd', 'Bharti Airtel Limited', 'AS24560', 'AIRTELBROADBAND-AS-AP', 'RESIDENTIAL', 'CLEAN') },
  { cidr: '14.139.0.0/16', ...record('bengaluru', 'National Knowledge Network', 'NKN Core Network', 'AS55824', 'NKN-CORE', 'DATACENTER', 'CLEAN') },
  { cidr: '103.21.58.0/23', ...record('hyderabad', 'CtrlS Datacenters Ltd', 'CtrlS Datacenters', 'AS18229', 'CTRLS-AS-IN', 'DATACENTER', 'CLEAN') },

  // --- Other regional ---
  { cidr: '105.112.0.0/12', ...record('lagos', 'Airtel Networks Limited', 'Airtel Nigeria', 'AS36873', 'CELTEL-AS', 'MOBILE', 'UNKNOWN') },
  { cidr: '177.54.144.0/20', ...record('saopaulo', 'Hostlocal Brasil', 'Hostlocal', 'AS262401', 'HOSTLOCAL', 'DATACENTER', 'SUSPICIOUS') },
  { cidr: '150.230.0.0/16', ...record('tokyo', 'Oracle Cloud', 'Oracle Corporation', 'AS31898', 'ORACLE-BMC-31898', 'DATACENTER', 'CLEAN') },
  { cidr: '13.54.0.0/15', ...record('sydney', 'Amazon Web Services', 'Amazon.com, Inc.', 'AS16509', 'AMAZON-02', 'DATACENTER', 'CLEAN') },
  { cidr: '190.104.0.0/16', ...record('panama', 'Cable & Wireless Panama', 'C&W Panama', 'AS11556', 'CWPANAMA', 'RESIDENTIAL', 'UNKNOWN') },
];

function record(
  city: keyof typeof CITY,
  isp: string,
  organization: string,
  asn: string,
  asnOwner: string,
  hostingType: NetworkRecord['hostingType'],
  reputation: Reputation,
): NetworkRecord {
  return { geo: geo(city), isp, organization, asn, asnOwner, hostingType, reputation };
}

/* ------------------------------------------------------------------ */
/* Lookup                                                              */
/* ------------------------------------------------------------------ */

function ipToLong(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const octet = Number.parseInt(part, 10);
    if (Number.isNaN(octet) || octet < 0 || octet > 255 || !/^\d+$/.test(part)) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

interface CompiledBlock extends NetblockEntry {
  network: number;
  mask: number;
  prefix: number;
}

const COMPILED: CompiledBlock[] = NETBLOCKS.flatMap((entry) => {
  const [network, prefixText] = entry.cidr.split('/');
  const prefix = Number.parseInt(prefixText, 10);
  const networkLong = ipToLong(network);
  if (networkLong === null || Number.isNaN(prefix)) return [];
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [{ ...entry, network: networkLong, mask, prefix }];
}).sort((a, b) => b.prefix - a.prefix);

/** Resolve an IPv4 address to curated network intelligence, or null. */
export function lookupNetwork(ip: string): NetworkRecord | null {
  const value = ipToLong(ip);
  if (value === null) return null;
  for (const block of COMPILED) {
    if (((value & block.mask) >>> 0) === block.network) {
      const { cidr: _cidr, network: _network, mask: _mask, prefix: _prefix, ...rest } = block;
      return rest;
    }
  }
  return null;
}

/** True when the address is reserved and can never be a public origin. */
export function isReservedIp(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

/**
 * Known Tor exit and commercial VPN ranges. A hit is a strong signal that the
 * observed address is an egress point rather than the true source.
 */
const ANONYMISER_RANGES: { cidr: string; kind: 'TOR' | 'VPN' }[] = [
  { cidr: '185.220.100.0/22', kind: 'TOR' },
  { cidr: '185.220.101.0/24', kind: 'TOR' },
  { cidr: '171.25.193.0/24', kind: 'TOR' },
  { cidr: '199.249.230.0/24', kind: 'TOR' },
  { cidr: '204.85.191.0/24', kind: 'TOR' },
  { cidr: '45.83.104.0/22', kind: 'VPN' },
  { cidr: '146.70.0.0/16', kind: 'VPN' },
  { cidr: '138.199.0.0/16', kind: 'VPN' },
  { cidr: '181.214.0.0/16', kind: 'VPN' },
  { cidr: '91.219.236.0/22', kind: 'VPN' },
];

const COMPILED_ANON = ANONYMISER_RANGES.flatMap((entry) => {
  const [network, prefixText] = entry.cidr.split('/');
  const prefix = Number.parseInt(prefixText, 10);
  const networkLong = ipToLong(network);
  if (networkLong === null || Number.isNaN(prefix)) return [];
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [{ kind: entry.kind, network: networkLong, mask }];
});

export function anonymiserKind(ip: string): 'TOR' | 'VPN' | null {
  const value = ipToLong(ip);
  if (value === null) return null;
  for (const block of COMPILED_ANON) {
    if (((value & block.mask) >>> 0) === block.network) return block.kind;
  }
  return null;
}

/** Country name → ISO-3166 alpha-2, for backend payloads that omit the code. */
const COUNTRY_CODES: Record<string, string> = {
  india: 'IN', singapore: 'SG', germany: 'DE', netherlands: 'NL', 'united kingdom': 'GB',
  'united states': 'US', russia: 'RU', ukraine: 'UA', romania: 'RO', nigeria: 'NG',
  'hong kong': 'HK', japan: 'JP', australia: 'AU', brazil: 'BR', panama: 'PA',
  seychelles: 'SC', china: 'CN', france: 'FR', canada: 'CA', 'south africa': 'ZA',
  spain: 'ES', italy: 'IT', poland: 'PL', turkey: 'TR', 'united arab emirates': 'AE',
  vietnam: 'VN', indonesia: 'ID', malaysia: 'MY', thailand: 'TH', 'south korea': 'KR',
};

export function countryCodeFor(country: string | null | undefined): string {
  if (!country) return '';
  return COUNTRY_CODES[country.trim().toLowerCase()] ?? '';
}

/** Approximate centroid for a country, used when only a country name is known. */
export function countryCentroid(countryCode: string): { latitude: number; longitude: number } | null {
  const centroids: Record<string, [number, number]> = {
    IN: [22.0, 79.0], SG: [1.35, 103.82], DE: [51.0, 10.0], NL: [52.2, 5.5], GB: [54.0, -2.0],
    US: [39.0, -98.0], RU: [61.0, 90.0], UA: [49.0, 32.0], RO: [46.0, 25.0], NG: [9.0, 8.0],
    HK: [22.32, 114.17], JP: [36.0, 138.0], AU: [-25.0, 134.0], BR: [-10.0, -55.0], PA: [9.0, -80.0],
    SC: [-4.6, 55.5], CN: [35.0, 105.0], FR: [46.0, 2.0], CA: [56.0, -106.0], ZA: [-29.0, 24.0],
    AE: [24.0, 54.0], VN: [16.0, 108.0], ID: [-2.0, 118.0], MY: [4.0, 102.0], TH: [15.0, 101.0],
    KR: [36.5, 127.8], ES: [40.0, -4.0], IT: [42.8, 12.8], PL: [52.0, 20.0], TR: [39.0, 35.0],
  };
  const hit = centroids[countryCode.toUpperCase()];
  return hit ? { latitude: hit[0], longitude: hit[1] } : null;
}
