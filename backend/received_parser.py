import ipaddress
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Dict, Any, List, Optional, Tuple

# RFC 1918 + loopback + link-local + APIPA ranges that are never legitimate
# external SMTP sources. Excludes RFC 5737 / 5737 documentation ranges
# (e.g. 198.51.100.x, 203.0.113.x) which Python 3.11+ marks is_private=True
# but are correctly treated as "external" for forensic analysis.
_NON_ROUTABLE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("100.64.0.0/10"),    # Shared Address Space (RFC 6598)
]


class ReceivedHeaderParser:
    """
    Forensic SMTP/Received-chain reconstruction and anomaly detection engine.
    RFC 5322 headers are parsed and reordered into chronological transmission order.
    Identifies the Earliest Plausible External Source with confidence ratings.
    """

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    )

    def __init__(self):
        pass

    def parse_header_text(self, raw_header: str, hop_index_from_top: int) -> Dict[str, Any]:
        """
        Parse a single Received header into structured forensic components.
        """
        cleaned = re.sub(r"\r?\n[ \t]+", " ", raw_header.strip())

        hop_data: Dict[str, Any] = {
            "hop_index_raw": hop_index_from_top,
            "raw": raw_header,
            "from_host": None,
            "from_ip": None,
            "from_ip_type": "NONE",
            "by_host": None,
            "by_ip": None,
            "protocol": None,
            "timestamp_raw": None,
            "timestamp_iso": None,
            "timestamp_epoch": None,
            "tls_used": False,
            "anomalies": []
        }

        # 1. Date/Time parsing (separated by semicolon in RFC 5322)
        if ";" in cleaned:
            parts = cleaned.rsplit(";", 1)
            route_part = parts[0].strip()
            date_part = parts[1].strip()
            hop_data["timestamp_raw"] = date_part
            try:
                dt = parsedate_to_datetime(date_part)
                hop_data["timestamp_iso"] = dt.isoformat()
                hop_data["timestamp_epoch"] = dt.timestamp()
            except Exception:
                hop_data["anomalies"].append(f"Unparseable date in Received header: '{date_part}'")
        else:
            route_part = cleaned

        # 2. Extract 'from' host and IP
        from_match = re.search(r"\bfrom\s+([^\s\[\(]+)", route_part, re.IGNORECASE)
        if from_match:
            hop_data["from_host"] = from_match.group(1).rstrip(",;")

        # Find all IP addresses in the 'from' segment
        from_segment_match = re.search(r"\bfrom\s+(.*?)\bby\b", route_part, re.IGNORECASE)
        search_area = from_segment_match.group(1) if from_segment_match else route_part

        ips_found = self.IP_PATTERN.findall(search_area)
        for ip_str in ips_found:
            validated = self._classify_ip(ip_str)
            if validated:
                hop_data["from_ip"] = validated["ip"]
                hop_data["from_ip_type"] = validated["type"]
                break

        # 3. Extract 'by' host and IP
        by_match = re.search(r"\bby\s+([^\s\[\(]+)", route_part, re.IGNORECASE)
        if by_match:
            hop_data["by_host"] = by_match.group(1).rstrip(",;")

        by_segment_match = re.search(r"\bby\s+(.*?)(?:\bwith\b|\bfor\b|\bid\b|$)", route_part, re.IGNORECASE)
        if by_segment_match:
            by_ips = self.IP_PATTERN.findall(by_segment_match.group(1))
            for ip_str in by_ips:
                validated = self._classify_ip(ip_str)
                if validated:
                    hop_data["by_ip"] = validated["ip"]
                    break

        # 4. Extract protocol / TLS
        with_match = re.search(r"\bwith\s+([^\s;]+)", route_part, re.IGNORECASE)
        if with_match:
            hop_data["protocol"] = with_match.group(1)

        if "tls" in route_part.lower() or "esmtps" in (hop_data.get("protocol") or "").lower():
            hop_data["tls_used"] = True

        return hop_data

    def _classify_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """
        Validate and classify an IP address for forensic SMTP chain analysis.

        Uses explicit RFC 1918 / loopback / link-local network checks rather
        than ip_obj.is_private, because Python 3.11+ broadened is_private to
        cover ALL IANA special-purpose blocks (including RFC 5737 documentation
        ranges such as 198.51.100.x / 203.0.113.x / 192.0.2.x) which should
        still be treated as "external" hops in a relay chain.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())

            # Check against known non-routable/internal network blocks
            is_non_routable = any(
                ip_obj in net for net in _NON_ROUTABLE_NETWORKS
            )

            if ip_obj.is_loopback:
                ip_type = "LOOPBACK"
            elif ip_obj.is_multicast:
                ip_type = "MULTICAST"
            elif ip_obj.is_link_local:
                ip_type = "LINK_LOCAL"
            elif is_non_routable:
                ip_type = "PRIVATE"
            else:
                ip_type = "PUBLIC"

            return {
                "ip": str(ip_obj),
                "type": ip_type,
                "version": ip_obj.version,
                "is_public": (ip_type == "PUBLIC")
            }
        except ValueError:
            return None

    def analyze_chain(self, raw_received_headers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Reconstruct and analyze the complete SMTP Received header chain.
        """
        if not raw_received_headers:
            return {
                "chain_length": 0,
                "chronological_hops": [],
                "anomalies": ["No Received headers found in email message."],
                "earliest_external_source": None,
                "transit_time_seconds": 0,
                "summary": "No relay chain available."
            }

        # 1. Parse individual headers in order as they appear in the raw email (top = latest receiving MTA)
        top_down_hops: List[Dict[str, Any]] = []
        for i, header_entry in enumerate(raw_received_headers):
            raw_text = header_entry.get("raw", "") if isinstance(header_entry, dict) else str(header_entry)
            parsed_hop = self.parse_header_text(raw_text, i)
            top_down_hops.append(parsed_hop)

        # 2. Reverse to chronological order (Hop 1 = origin / earliest sender)
        chronological_hops: List[Dict[str, Any]] = list(reversed(top_down_hops))
        for idx, hop in enumerate(chronological_hops):
            hop["hop_number"] = idx + 1

        anomalies: List[str] = []

        # 3. Analyze timestamps and detect anomalies along chronological path
        prev_epoch = None
        transit_time = 0.0

        for i, hop in enumerate(chronological_hops):
            current_epoch = hop.get("timestamp_epoch")
            if current_epoch and prev_epoch:
                diff = current_epoch - prev_epoch
                hop["delay_from_previous_seconds"] = diff
                if diff < -120:  # Time went backwards by more than 2 minutes
                    msg = f"Impossible chronology: Hop {i+1} timestamp is {abs(int(diff))}s earlier than Hop {i}."
                    anomalies.append(msg)
                    hop["anomalies"].append(msg)
                elif diff > 86400:  # Took more than 24 hours between relays
                    msg = f"Suspicious delay: {int(diff/3600)}h elapsed between Hop {i} and Hop {i+1}."
                    anomalies.append(msg)
            elif current_epoch:
                hop["delay_from_previous_seconds"] = 0

            if current_epoch:
                prev_epoch = current_epoch

            # Check for suspicious hostnames
            from_host = (hop.get("from_host") or "").lower()
            if from_host in ("localhost", "127.0.0.1", "friendly-client"):
                anomalies.append(f"Hop {hop['hop_number']} claims localhost origin: '{from_host}'.")

        # Total transit calculation
        epochs = [h["timestamp_epoch"] for h in chronological_hops if h.get("timestamp_epoch") is not None]
        if len(epochs) >= 2:
            transit_time = max(0.0, max(epochs) - min(epochs))

        # 4. Identify Earliest Plausible External Source (First public/routable IP in chronological transmission)
        earliest_source = None
        for hop in chronological_hops:
            if hop.get("from_ip") and hop.get("from_ip_type") in ("PUBLIC", "RESERVED"):
                confidence = 85
                # Reduce confidence if anomalies detected before or at this hop
                if hop.get("anomalies"):
                    confidence -= 20
                if hop["hop_number"] > 1:
                    # Traversed internal relays first
                    confidence -= 5

                earliest_source = {
                    "ip": hop["from_ip"],
                    "host": hop.get("from_host"),
                    "hop_number": hop["hop_number"],
                    "confidence_percentage": max(10, min(95, confidence)),
                    "tls_used": hop.get("tls_used", False),
                    "timestamp": hop.get("timestamp_iso"),
                    "evidence": [
                        f"Earliest observed public IP in chronological Received chain at Hop {hop['hop_number']}",
                        f"Reported sending host: {hop.get('from_host') or 'Unknown'}",
                        f"Protocol: {hop.get('protocol') or 'SMTP'}"
                    ],
                    "limitations": [
                        "Represents observed transmission relay or proxy infrastructure.",
                        "Does not determine the human actor or originating client behind a VPN, proxy, or cloud relay."
                    ]
                }
                break

        # Fallback if only private/loopback IPs found
        if not earliest_source and chronological_hops:
            first_hop = chronological_hops[0]
            earliest_source = {
                "ip": first_hop.get("from_ip") or "Unknown",
                "host": first_hop.get("from_host"),
                "hop_number": 1,
                "confidence_percentage": 30,
                "tls_used": first_hop.get("tls_used", False),
                "timestamp": first_hop.get("timestamp_iso"),
                "evidence": ["All hops recorded internal or private IP ranges."],
                "limitations": ["No public gateway IP recorded in received headers."]
            }

        return {
            "chain_length": len(chronological_hops),
            "chronological_hops": chronological_hops,
            "anomalies": anomalies,
            "earliest_external_source": earliest_source,
            "transit_time_seconds": round(transit_time, 2),
            "summary": (
                f"Parsed {len(chronological_hops)} transmission hops. "
                f"{'Identified external gateway IP: ' + earliest_source['ip'] if earliest_source and earliest_source.get('ip') != 'Unknown' else 'No external public IP discovered.'} "
                f"({len(anomalies)} anomalies detected)."
            )
        }
