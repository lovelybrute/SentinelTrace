import ipaddress
import re
from typing import Dict, Any, List, Optional
import requests
from config import settings


class GeoLocationIntelligence:
    """
    IP Geolocation and Network Infrastructure Intelligence Engine.
    Uses strict Python ipaddress validation and graceful degradation when external APIs are unavailable.
    """

    def __init__(self):
        self.api_url = settings.GEO_API_URL
        self.timeout = settings.GEO_TIMEOUT_SECONDS
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_valid_ip(self, ip_string: str) -> bool:
        """Validate IP address using ipaddress module."""
        if not ip_string or not isinstance(ip_string, str):
            return False
        try:
            ipaddress.ip_address(ip_string.strip())
            return True
        except ValueError:
            return False

    def is_private_ip(self, ip_string: str) -> bool:
        """Check if IP is private, loopback, or reserved."""
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_reserved or
                ip_obj.is_link_local or
                ip_obj.is_multicast
            )
        except ValueError:
            return False

    def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation and ISP/ASN data for a public IP address.
        """
        if not ip_address:
            return None

        clean_ip = ip_address.strip()
        if not self.is_valid_ip(clean_ip):
            return None

        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Handle private / internal addresses without remote DNS/HTTP query
        if self.is_private_ip(clean_ip):
            result = {
                "ip": clean_ip,
                "type": "private",
                "warning": "Internal/Private network address (RFC 1918 / Loopback)",
                "country": "Internal Network",
                "country_code": "INT",
                "region": "Internal",
                "city": "Internal",
                "latitude": None,
                "longitude": None,
                "isp": "Local Network",
                "organization": "Internal Infrastructure",
                "threat_level": "none"
            }
            self._cache[clean_ip] = result
            return result

        try:
            # Query ip-api for public IP
            # Standard free fields: status, message, country, countryCode, regionName, city, lat, lon, isp, org, as, query
            url = f"{self.api_url}/{clean_ip}"
            params = {
                "fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
            }
            response = requests.get(url, params=params, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    geo_info = {
                        "ip": clean_ip,
                        "type": "public",
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "organization": data.get("org") or data.get("isp"),
                        "asn": data.get("as"),
                        "threat_level": "Unavailable"  # Free tier does not include threat intel; avoid fake data
                    }
                    self._cache[clean_ip] = geo_info
                    return geo_info

            # Fallback if API returned error
            fallback = {
                "ip": clean_ip,
                "type": "public",
                "country": "Unknown",
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "isp": "Unavailable",
                "organization": "Unavailable",
                "threat_level": "Unavailable",
                "note": "Geolocation query returned non-success status."
            }
            self._cache[clean_ip] = fallback
            return fallback

        except Exception as e:
            fallback = {
                "ip": clean_ip,
                "type": "public",
                "country": "Unknown",
                "city": "Unknown",
                "latitude": None,
                "longitude": None,
                "isp": "Unavailable",
                "organization": "Unavailable",
                "threat_level": "Unavailable",
                "error": f"Lookup timeout or error: {str(e)}"
            }
            return fallback

    def analyze_sender_location(self, received_headers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract unique public IPs and geolocate them in chronological order.
        """
        sender_locations: List[Dict[str, Any]] = []
        seen_ips = set()

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

        for header in received_headers:
            raw = header.get("raw", "") if isinstance(header, dict) else str(header)
            found = re.findall(ip_pattern, raw)
            for ip in found:
                if ip not in seen_ips and self.is_valid_ip(ip):
                    seen_ips.add(ip)
                    geo = self.get_geolocation(ip)
                    if geo:
                        sender_locations.append(geo)

        return sender_locations
