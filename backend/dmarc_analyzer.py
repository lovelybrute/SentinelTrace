import re
from typing import Dict, Any, Optional, Tuple, List

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DMARCAnalyzer:
    """
    RFC 7489 compliant DMARC (Domain-based Message Authentication, Reporting,
    and Conformance) policy parser and evaluation engine.
    Correlates SPF and DKIM evaluation with From domain alignment.
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
        else:
            self.resolver = None

    def parse_dmarc_tags(self, record_txt: str) -> Dict[str, str]:
        """Parse semicolon-separated tag=value pairs from DMARC record."""
        tags: Dict[str, str] = {}
        if not record_txt:
            return tags

        cleaned = re.sub(r"\r?\n[ \t]+", " ", record_txt.strip())
        parts = cleaned.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    def query_dmarc_record(self, from_domain: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Query DNS for DMARC TXT record at _dmarc.<domain>.
        Falls back to organizational domain if subdomain has no record (RFC 7489 Section 6.6.3).
        Returns (record_txt, queried_domain, error_message).
        """
        if not DNS_AVAILABLE or not self.resolver:
            return None, None, "DNS resolver unavailable"

        if not from_domain:
            return None, None, "From domain is missing"

        norm_domain = from_domain.strip().lower().strip(".")
        candidates = [norm_domain]

        # Check organizational domain fallback (e.g. sub.example.com -> example.com)
        parts = norm_domain.split(".")
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            if org_domain not in candidates:
                candidates.append(org_domain)

        last_error = None
        for cand in candidates:
            dmarc_host = f"_dmarc.{cand}"
            try:
                answers = self.resolver.resolve(dmarc_host, "TXT")
                for rdata in answers:
                    txt_bytes = b"".join(rdata.strings) if hasattr(rdata, "strings") else str(rdata).encode("utf-8")
                    txt_str = txt_bytes.decode("utf-8", errors="ignore").strip("\"'")
                    if txt_str.startswith("v=DMARC1"):
                        return txt_str, cand, None
            except dns.resolver.NXDOMAIN:
                last_error = f"DMARC record '{dmarc_host}' does not exist (NXDOMAIN)"
            except dns.resolver.NoAnswer:
                last_error = f"No TXT records found at '{dmarc_host}'"
            except dns.exception.Timeout:
                return None, cand, f"DNS query timed out for '{dmarc_host}'"
            except Exception as e:
                last_error = f"DNS lookup failed for '{dmarc_host}': {str(e)}"

        return None, candidates[0], last_error or f"No DMARC record found for '{from_domain}'"

    def evaluate(
        self,
        from_domain: Optional[str],
        spf_result: Dict[str, Any],
        dkim_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate DMARC compliance according to RFC 7489.
        """
        result: Dict[str, Any] = {
            "record_present": False,
            "raw_record": None,
            "policy_domain": None,
            "policy": "none",
            "subdomain_policy": None,
            "spf_alignment_mode": "r",  # r=relaxed, s=strict
            "dkim_alignment_mode": "r",
            "percentage": 100,
            "rua": None,
            "ruf": None,
            "result": "NONE",
            "spf_aligned_pass": False,
            "dkim_aligned_pass": False,
            "disposition": "none",  # none, quarantine, reject
            "reasoning": "",
            "evidence": []
        }

        if not from_domain or not from_domain.strip():
            result["result"] = "NONE"
            result["reasoning"] = "Sender domain is missing; DMARC evaluation skipped."
            result["evidence"].append("Sender domain missing.")
            return result

        from_domain_norm = from_domain.strip().lower()

        # Query DMARC record
        dmarc_txt, policy_domain, err = self.query_dmarc_record(from_domain_norm)

        if not dmarc_txt:
            result["result"] = "NONE"
            result["reasoning"] = err or f"No published DMARC policy for domain '{from_domain}'."
            result["evidence"].append(result["reasoning"])
            return result

        result["record_present"] = True
        result["raw_record"] = dmarc_txt
        result["policy_domain"] = policy_domain
        result["evidence"].append(f"DMARC record found at _dmarc.{policy_domain}: {dmarc_txt}")

        tags = self.parse_dmarc_tags(dmarc_txt)

        # Policy parsing
        p_val = tags.get("p", "none").lower()
        if p_val not in ("none", "quarantine", "reject"):
            p_val = "none"
        result["policy"] = p_val

        sp_val = tags.get("sp", p_val).lower()
        result["subdomain_policy"] = sp_val

        aspf = tags.get("aspf", "r").lower()
        result["spf_alignment_mode"] = aspf

        adkim = tags.get("adkim", "r").lower()
        result["dkim_alignment_mode"] = adkim

        try:
            result["percentage"] = int(tags.get("pct", "100"))
        except ValueError:
            result["percentage"] = 100

        result["rua"] = tags.get("rua")
        result["ruf"] = tags.get("ruf")

        # Evaluate SPF Identifier Alignment
        spf_pass = (spf_result.get("result") == "PASS")
        spf_domain = (spf_result.get("domain") or "").strip().lower()
        spf_aligned = False

        if spf_pass and spf_domain:
            if aspf == "s":
                spf_aligned = (spf_domain == from_domain_norm)
            else:
                spf_aligned = (
                    spf_domain == from_domain_norm or
                    spf_domain.endswith("." + from_domain_norm) or
                    from_domain_norm.endswith("." + spf_domain)
                )

        result["spf_aligned_pass"] = (spf_pass and spf_aligned)

        # Evaluate DKIM Identifier Alignment
        dkim_pass = (dkim_result.get("status") == "PASS")
        dkim_domain = (dkim_result.get("signing_domain") or "").strip().lower()
        dkim_aligned = False

        if dkim_pass and dkim_domain:
            if adkim == "s":
                dkim_aligned = (dkim_domain == from_domain_norm)
            else:
                dkim_aligned = (
                    dkim_domain == from_domain_norm or
                    dkim_domain.endswith("." + from_domain_norm) or
                    from_domain_norm.endswith("." + dkim_domain)
                )

        result["dkim_aligned_pass"] = (dkim_pass and dkim_aligned)

        # Final DMARC Verdict (RFC 7489: Pass if SPF aligned OR DKIM aligned)
        if result["spf_aligned_pass"] or result["dkim_aligned_pass"]:
            result["result"] = "PASS"
            reasons = []
            if result["spf_aligned_pass"]:
                reasons.append("SPF authenticated and aligned")
            if result["dkim_aligned_pass"]:
                reasons.append("DKIM signed and aligned")
            result["reasoning"] = f"DMARC PASS: {', '.join(reasons)}."
            result["disposition"] = "none"
            result["evidence"].append(result["reasoning"])
        else:
            result["result"] = "FAIL"
            effective_policy = sp_val if (from_domain_norm != policy_domain) else p_val
            result["disposition"] = effective_policy
            result["reasoning"] = (
                f"DMARC FAIL: Neither SPF nor DKIM passed with aligned identifiers. "
                f"Published policy is p={p_val} (disposition: {effective_policy})."
            )
            result["evidence"].append(result["reasoning"])

        return result
