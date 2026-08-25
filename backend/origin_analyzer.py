from typing import Dict, Any, List, Optional


class OriginAnalyzer:
    """
    Forensic origin infrastructure assessment engine.
    Synthesizes Received hop chronology, ASN classification, reverse DNS, and geolocation
    to assess the probable origin infrastructure without making false claims about human identity.
    """

    KNOWN_CLOUD_ISPS = [
        "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
        "linode", "akamai", "hetzner", "ovh", "vultr", "oracle", "alibaba",
        "rackspace", "choopa", "fastly", "cloudflare"
    ]

    KNOWN_MAIL_SERVICES = [
        "google llc", "microsoft corporation", "proofpoint", "mimecast",
        "zoho", "sendgrid", "mailgun", "mandrill", "postmark", "fastmail"
    ]

    def __init__(self):
        pass

    def assess_origin(
        self,
        chain_analysis: Dict[str, Any],
        geo_data: Optional[Dict[str, Any]] = None,
        auth_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Produce a confidence-weighted origin assessment with clear evidence and limitations.
        """
        earliest_source = chain_analysis.get("earliest_external_source") or {}
        ip_str = earliest_source.get("ip")
        hostname = (earliest_source.get("host") or "").lower()

        isp = ((geo_data or {}).get("isp") or "").lower()
        org = ((geo_data or {}).get("organization") or "").lower()
        country = (geo_data or {}).get("country") or "Unknown"
        city = (geo_data or {}).get("city") or "Unknown"

        classification = "UNKNOWN"
        confidence = 50
        evidence: List[str] = []

        if not ip_str or ip_str == "Unknown":
            return {
                "classification": "UNKNOWN",
                "probable_source_infrastructure": "Undetermined Infrastructure",
                "geographic_estimate": {
                    "country": "Unknown",
                    "city": "Unknown",
                    "coordinates": None
                },
                "confidence_score": 20,
                "evidence": ["No public IP address identifiable in Received headers."],
                "limitations": [
                    "Email routing headers are either missing or composed entirely of internal private networks.",
                    "Cannot establish origin without external gateway headers."
                ]
            }

        evidence.append(f"Identified earliest external gateway hop: IP {ip_str} ({hostname or 'no hostname'})")

        # 1. Check for Enterprise/Corporate Mail Providers
        is_corporate_mail = any(m in isp or m in org or m in hostname for m in self.KNOWN_MAIL_SERVICES)
        if is_corporate_mail:
            classification = "CORPORATE_MAIL_SERVER"
            confidence = 88
            evidence.append(f"Infrastructure belongs to known enterprise email service provider: {isp or org}")

        # 2. Check for Cloud/Hosting/VPS Providers
        elif any(c in isp or c in org or c in hostname for c in self.KNOWN_CLOUD_ISPS):
            if "vps" in isp or "vps" in org or "hetzner" in isp or "vultr" in isp or "digitalocean" in isp:
                classification = "VPS"
                confidence = 82
                evidence.append(f"IP is registered to commercial VPS/cloud hosting network: {isp or org}")
            else:
                classification = "CLOUD_HOSTING"
                confidence = 85
                evidence.append(f"IP is registered to public cloud hosting provider: {isp or org}")

        # 3. Check for Anomalous / Direct Origin
        elif chain_analysis.get("chain_length", 0) == 1:
            classification = "DIRECT_ORIGIN"
            confidence = 70
            evidence.append("Single hop transmission observed directly from sending IP to receiving MX.")

        else:
            classification = "PUBLIC_RELAY"
            confidence = 65
            evidence.append(f"Observed relay infrastructure on ISP network: {isp or org or 'Standard ISP'}")

        # Factor in SPF and DKIM authentication state
        if auth_data:
            spf_pass = auth_data.get("spf", {}).get("is_pass", False)
            dkim_pass = (auth_data.get("dkim", {}).get("status") == "PASS")
            if spf_pass and dkim_pass:
                confidence = min(95, confidence + 10)
                evidence.append("Cryptographic authentication (SPF + DKIM) aligned with origin infrastructure.")
            elif not spf_pass and not dkim_pass:
                evidence.append("Origin infrastructure lacks SPF and DKIM authentication alignment.")

        # Structure final assessment
        readable_label_map = {
            "DIRECT_ORIGIN": "Direct Origin Mail Server",
            "CORPORATE_MAIL_SERVER": "Enterprise Cloud Mail Infrastructure",
            "CLOUD_HOSTING": "Cloud Hosting Infrastructure",
            "VPS": "Cloud-Hosted Virtual Private Server (VPS)",
            "VPN": "Commercial VPN Service",
            "TOR_EXIT": "Tor Anonymization Exit Node",
            "OPEN_RELAY": "Suspected Open Mail Relay",
            "COMPROMISED_INFRASTRUCTURE": "Suspected Compromised Server",
            "CDN": "Content Delivery Network / Proxy",
            "PUBLIC_RELAY": "Observed Public Mail Relay",
            "UNKNOWN": "Unverified Relay Infrastructure"
        }

        lat = (geo_data or {}).get("latitude")
        lon = (geo_data or {}).get("longitude")

        return {
            "classification": classification,
            "probable_source_infrastructure": readable_label_map.get(classification, classification),
            "observed_ip": ip_str,
            "organization": org or isp or "Unknown",
            "geographic_estimate": {
                "country": country,
                "city": city,
                "latitude": lat,
                "longitude": lon,
                "coordinates": f"{lat}, {lon}" if lat is not None and lon is not None else "Unavailable"
            },
            "confidence_score": confidence,
            "evidence": evidence,
            "limitations": [
                "Geographic coordinates represent estimated ISP/datacenter registration location, not the threat actor's physical location.",
                "Observed infrastructure may represent intermediary proxies, relays, or compromised cloud instances.",
                "Attribution of human actors requires law enforcement subpoenas and ISP connection log corroboration."
            ]
        }
