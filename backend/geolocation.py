import requests
import re


# ============================================================
# GEOLOCATION & IP INTELLIGENCE
# ============================================================

class GeoLocationIntelligence:

    def __init__(self):
        # Using free IP geolocation API
        self.api_url = "http://ip-api.com/json"
        self.timeout = 5

    # --------------------------------------------------------
    # GET GEOLOCATION FROM IP
    # --------------------------------------------------------

    def get_geolocation(self, ip_address):
        """
        Get geolocation data for an IP address
        """

        try:

            # Validate IP address format
            if not self._is_valid_ip(ip_address):
                return None

            # Private/local IPs shouldn't be geolocated
            if self._is_private_ip(ip_address):
                return {
                    "ip": ip_address,
                    "type": "private",
                    "warning": "Private IP address"
                }

            params = {
                "query": ip_address,
                "fields": "status,country,countryCode,region,regionName,city,lat,lon,isp,org,threat"
            }

            response = requests.get(
                self.api_url,
                params=params,
                timeout=self.timeout
            )

            if response.status_code == 200:

                data = response.json()

                if data.get("status") == "success":

                    return {
                        "ip": ip_address,
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "threat_level": data.get("threat", "low")
                    }

            return None

        except Exception as e:

            return {
                "ip": ip_address,
                "error": str(e)
            }

    # --------------------------------------------------------
    # VALIDATE IP FORMAT
    # --------------------------------------------------------

    def _is_valid_ip(self, ip_string):

        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'

        return bool(re.match(ip_pattern, ip_string))

    # --------------------------------------------------------
    # CHECK IF IP IS PRIVATE
    # --------------------------------------------------------

    def _is_private_ip(self, ip_string):

        parts = ip_string.split('.')

        if len(parts) != 4:
            return False

        try:

            octets = [int(p) for p in parts]

            # 10.0.0.0/8
            if octets[0] == 10:
                return True

            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True

            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True

            # 127.0.0.0/8 (localhost)
            if octets[0] == 127:
                return True

            return False

        except:

            return False

    # --------------------------------------------------------
    # EXTRACT IPS FROM RECEIVED HEADERS
    # --------------------------------------------------------

    def extract_ips_from_headers(self, received_headers):
        """
        Extract sender IPs from Received headers
        """

        ips = []

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        for header in received_headers:

            raw_header = header.get("raw", "")

            found_ips = re.findall(
                ip_pattern,
                raw_header
            )

            for ip in found_ips:

                if ip not in ips:
                    ips.append(ip)

        return ips

    # --------------------------------------------------------
    # ANALYZE SENDER LOCATION
    # --------------------------------------------------------

    def analyze_sender_location(self, received_headers):
        """
        Analyze sender's geolocation from email headers
        """

        ips = self.extract_ips_from_headers(
            received_headers
        )

        sender_locations = []

        for ip in ips:

            geo_data = self.get_geolocation(ip)

            if geo_data:
                sender_locations.append(geo_data)

        return sender_locations
