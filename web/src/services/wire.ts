/**
 * Wire types mirroring the existing FastAPI backend exactly as implemented in
 * `backend/main.py`, `email_parser.py`, `advanced_forensics.py` and
 * `geolocation.py`. Nothing here is aspirational — if a field is optional, it is
 * because the Python code can genuinely omit it.
 */

export interface WireReceivedHeader {
  raw: string;
}

export interface WireSenderLocation {
  ip: string;
  /** Present only for private/loopback addresses. */
  type?: string;
  warning?: string;
  error?: string;
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  isp?: string | null;
  organization?: string | null;
  threat_level?: string;
}

export interface WireEvidence {
  from: string;
  to: string;
  subject: string;
  date: string;
  message_id: string;
  content_hash: string;
  authentication_results: string;
  dkim_signature: string;
  received_headers: WireReceivedHeader[];
  body_preview: string;
  filename?: string;
}

export interface WireThreatAssessment {
  threat_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_factors: string[];
  score_breakdown?: {
    validated_phishing_probability?: number | null;
    prototype_primary_classification?: string | null;
    prototype_confidence?: number | null;
    ml_probability_source?: string;
  };
}

export interface WireDkim {
  valid: boolean;
  status: string;
  message: string;
  severity?: string;
}

export interface WireSpf {
  found: boolean;
  status: string;
  message: string;
  records?: string[];
  severity?: string;
}

export interface WireDmarc {
  found: boolean;
  status: string;
  message: string;
  policy?: string;
  records?: string[];
  severity?: string;
}

export interface WireAuthentication {
  sender: string;
  sender_domain: string | null;
  dkim: WireDkim | null;
  spf: WireSpf | null;
  dmarc: WireDmarc | null;
  overall_trust_score: number;
}

export interface WireSpoofing {
  detected: boolean;
  confidence: number;
  factors: string[];
}

export interface WireHeaderChain {
  chain_length: number;
  anomalies: string[];
  hop_analysis?: { hop: number; server: string; raw: string }[];
  analysis?: string;
}

export interface WireForensics {
  authentication: WireAuthentication;
  spoofing_analysis: WireSpoofing;
  header_chain: WireHeaderChain;
}

export interface WireAttachment {
  filename: string;
  size: number;
  hash: string;
}

/** Full `POST /analyze` response. */
export interface WireAnalysis {
  evidence: WireEvidence;
  geolocation: {
    sender_locations: WireSenderLocation[];
    location_count: number;
  };
  threat_indicators: {
    urls: string[];
    ip_addresses: string[];
    emails: string[];
  };
  attachments: WireAttachment[];
  threat_assessment: WireThreatAssessment;
  forensics?: WireForensics;
  analysis_id?: number | null;
  storage_status?: string;
  storage_warning?: string;
}

/** `GET /stats` */
export interface WireStats {
  total_emails: number;
  flagged_emails: number;
  critical_threats: number;
  high_threats: number;
  average_threat_score: number;
  flagged_percentage: number;
}

/** `GET /recent-threats` */
export interface WireRecentThreat {
  id: number;
  sender: string;
  subject: string;
  threat_score: number;
  threat_level: string;
  country: string | null;
  analyzed_at: string;
}

/** `GET /threat-by-country` */
export interface WireCountryThreat {
  country: string;
  email_count: number;
  average_threat_score: number;
}

/** `GET /analysis/{id}` */
export interface WireStoredAnalysis {
  id: number;
  filename: string;
  sender: string;
  recipient: string;
  subject: string;
  threat_score: number;
  threat_level: string;
  geolocation: { country: string | null; city: string | null; ip: string | null };
  artifacts: { urls: number; ips: number; attachments: number };
  analyzed_at: string;
  full_analysis: WireAnalysis | Record<string, never>;
}
