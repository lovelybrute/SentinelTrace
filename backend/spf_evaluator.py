import ipaddress
import re
from typing import Dict, Any, List, Optional, Tuple

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class SPFEvaluator:
    """
    RFC 7208 compliant SPF (Sender Policy Framework) evaluator.
    Evaluates sending IP against published SPF records without conflating
    the mere existence of an SPF DNS record with an SPF PASS verdict.
    """

    def __init__(self, timeout: float = 4.0, max_lookups: int = 10):
        self.timeout = timeout
        self.max_lookups = max_lookups
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
        else:
            self.resolver = None

    def query_spf_record(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Query DNS TXT records for SPF policy (v=spf1).
        Returns (spf_record, error_message).
        """
        if not DNS_AVAILABLE or not self.resolver:
            return None, "DNS resolver unavailable"

        domain = domain.strip().lower()
        if not domain:
            return None, "Empty domain provided"

        try:
            answers = self.resolver.resolve(domain, "TXT")
            spf_records = []
            for rdata in answers:
                # Handle multi-chunk TXT strings
                txt_bytes = b"".join(rdata.strings) if hasattr(rdata, "strings") else str(rdata).encode("utf-8")
                txt_str = txt_bytes.decode("utf-8", errors="ignore").strip("\"'")
                if txt_str.startswith("v=spf1"):
                    spf_records.append(txt_str)

            if len(spf_records) == 1:
                return spf_records[0], None
            elif len(spf_records) > 1:
                # RFC 7208 Section 3.2: multiple SPF records results in PermError
                return spf_records[0], "Multiple SPF records published (PermError under RFC 7208)"
            else:
                return None, f"No SPF record found for domain '{domain}'"

        except dns.resolver.NXDOMAIN:
            return None, f"Domain '{domain}' does not exist (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            return None, f"No TXT records found for domain '{domain}'"
        except dns.exception.Timeout:
            return None, f"DNS query timed out for '{domain}'"
        except Exception as e:
            return None, f"DNS lookup failed for '{domain}': {str(e)}"

    def evaluate(self, sender_domain: str, sending_ip: Optional[str]) -> Dict[str, Any]:
        """
        Evaluate SPF for a sender domain and sending IP.
        
        Results:
        - PASS: IP is authorized by SPF
        - FAIL: IP is explicitly forbidden (-all or failed hard mechanism)
        - SOFTFAIL: IP is not authorized (~all)
        - NEUTRAL: IP is neutral (?all)
        - NONE: No SPF record exists
        - TEMPERROR: DNS lookup failed temporarily
        - PERMERROR: SPF record is syntactically invalid or multiple records exist
        """
        result: Dict[str, Any] = {
            "domain": sender_domain,
            "sending_ip": sending_ip,
            "record_present": False,
            "raw_record": None,
            "result": "NONE",
            "matched_mechanism": None,
            "is_pass": False,
            "evidence": [],
            "reasoning": ""
        }

        if not sender_domain:
            result["result"] = "PERMERROR"
            result["reasoning"] = "Sender domain is missing or invalid"
            return result

        spf_record, error_msg = self.query_spf_record(sender_domain)

        if error_msg and "Multiple SPF" in error_msg:
            result["record_present"] = True
            result["raw_record"] = spf_record
            result["result"] = "PERMERROR"
            result["reasoning"] = error_msg
            result["evidence"].append(error_msg)
            return result

        if not spf_record:
            if error_msg and "timed out" in error_msg:
                result["result"] = "TEMPERROR"
                result["reasoning"] = error_msg
            else:
                result["result"] = "NONE"
                result["reasoning"] = error_msg or f"No SPF record published for {sender_domain}"
            result["evidence"].append(result["reasoning"])
            return result

        result["record_present"] = True
        result["raw_record"] = spf_record
        result["evidence"].append(f"SPF record discovered: {spf_record}")

        if not sending_ip:
            result["result"] = "NEUTRAL"
            result["reasoning"] = "SPF record exists, but sending IP was not determined from message headers."
            result["evidence"].append(result["reasoning"])
            return result

        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(sending_ip.strip())
        except ValueError:
            result["result"] = "PERMERROR"
            result["reasoning"] = f"Invalid sending IP address format: '{sending_ip}'"
            result["evidence"].append(result["reasoning"])
            return result

        # If sending IP is private or loopback, SPF evaluation against public domain is unroutable
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            result["result"] = "NEUTRAL"
            result["reasoning"] = f"Sending IP {sending_ip} is a private/internal address; SPF evaluation is not applicable."
            result["evidence"].append(result["reasoning"])
            return result

        # Evaluate terms in SPF record
        lookup_counter = [0]
        eval_result, matched_mech, reason = self._evaluate_record(spf_record, sender_domain, ip_obj, lookup_counter)
        result["result"] = eval_result
        result["matched_mechanism"] = matched_mech
        result["is_pass"] = (eval_result == "PASS")
        result["reasoning"] = reason
        result["evidence"].append(f"Evaluation verdict: {eval_result} (matched: {matched_mech or 'default'}) - {reason}")

        return result

    def _evaluate_record(
        self,
        record: str,
        current_domain: str,
        target_ip: ipaddress._BaseAddress,
        lookup_counter: List[int]
    ) -> Tuple[str, Optional[str], str]:
        """
        Evaluate terms in a single SPF record string.
        """
        terms = record.split()
        if not terms or terms[0].lower() != "v=spf1":
            return "PERMERROR", None, "Record does not start with 'v=spf1'"

        qualifier_map = {
            "+": "PASS",
            "-": "FAIL",
            "~": "SOFTFAIL",
            "?": "NEUTRAL"
        }

        for term in terms[1:]:
            # Check lookup limit (RFC 7208 Section 4.6.4: max 10 lookups)
            if lookup_counter[0] > self.max_lookups:
                return "PERMERROR", term, "Exceeded maximum SPF DNS lookup limit (10)"

            # Parse qualifier
            qualifier = "+"
            mechanism_str = term
            if term and term[0] in "+-~?":
                qualifier = term[0]
                mechanism_str = term[1:]

            mech_lower = mechanism_str.lower()
            verdict = qualifier_map.get(qualifier, "PASS")

            # 1. 'all' mechanism
            if mech_lower == "all":
                return verdict, term, f"Matched '{term}' mechanism"

            # 2. 'ip4:' mechanism
            if mech_lower.startswith("ip4:"):
                cidr = mechanism_str[4:].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if target_ip.version == 4 and target_ip in net:
                        return verdict, term, f"IP {target_ip} matches ip4 subnet {cidr}"
                except ValueError:
                    return "PERMERROR", term, f"Invalid ip4 syntax in term '{term}'"

            # 3. 'ip6:' mechanism
            elif mech_lower.startswith("ip6:"):
                cidr = mechanism_str[4:].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if target_ip.version == 6 and target_ip in net:
                        return verdict, term, f"IP {target_ip} matches ip6 subnet {cidr}"
                except ValueError:
                    return "PERMERROR", term, f"Invalid ip6 syntax in term '{term}'"

            # 4. 'a' or 'a:domain' mechanism
            elif mech_lower == "a" or mech_lower.startswith("a:"):
                lookup_counter[0] += 1
                target_a_domain = current_domain if mech_lower == "a" else mechanism_str[2:].strip()
                match = self._check_a_match(target_a_domain, target_ip)
                if match:
                    return verdict, term, f"IP {target_ip} matches 'A' record for {target_a_domain}"

            # 5. 'mx' or 'mx:domain' mechanism
            elif mech_lower == "mx" or mech_lower.startswith("mx:"):
                lookup_counter[0] += 1
                target_mx_domain = current_domain if mech_lower == "mx" else mechanism_str[3:].strip()
                match = self._check_mx_match(target_mx_domain, target_ip)
                if match:
                    return verdict, term, f"IP {target_ip} matches MX exchange for {target_mx_domain}"

            # 6. 'include:domain' mechanism
            elif mech_lower.startswith("include:"):
                lookup_counter[0] += 1
                inc_domain = mechanism_str[8:].strip()
                inc_record, err = self.query_spf_record(inc_domain)
                if inc_record:
                    inc_res, inc_mech, inc_reason = self._evaluate_record(
                        inc_record, inc_domain, target_ip, lookup_counter
                    )
                    if inc_res == "PASS":
                        return verdict, term, f"Matched via include:{inc_domain} ({inc_reason})"
                    elif inc_res in ("PERMERROR", "TEMPERROR"):
                        return inc_res, term, f"Included domain {inc_domain} returned {inc_res}"

            # 7. 'redirect=domain' modifier
            elif mech_lower.startswith("redirect="):
                lookup_counter[0] += 1
                red_domain = mechanism_str[9:].strip()
                red_record, err = self.query_spf_record(red_domain)
                if red_record:
                    return self._evaluate_record(red_record, red_domain, target_ip, lookup_counter)
                else:
                    return "PERMERROR", term, f"Redirect domain {red_domain} has no SPF record"

        # Default RFC result if no mechanism matched
        return "NEUTRAL", "default", "No SPF mechanism explicitly matched; default NEUTRAL applied"

    def _check_a_match(self, domain: str, target_ip: ipaddress._BaseAddress) -> bool:
        if not DNS_AVAILABLE or not self.resolver:
            return False
        try:
            qtype = "A" if target_ip.version == 4 else "AAAA"
            answers = self.resolver.resolve(domain, qtype)
            for rdata in answers:
                if str(rdata).strip() == str(target_ip):
                    return True
        except Exception:
            pass
        return False

    def _check_mx_match(self, domain: str, target_ip: ipaddress._BaseAddress) -> bool:
        if not DNS_AVAILABLE or not self.resolver:
            return False
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip(".")
                if self._check_a_match(mx_host, target_ip):
                    return True
        except Exception:
            pass
        return False
