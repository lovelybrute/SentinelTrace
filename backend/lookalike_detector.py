import re
import unicodedata
from typing import Dict, Any, List, Optional, Tuple

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False


class LookalikeDetector:
    """
    Brand impersonation and lookalike/typosquatting domain detection engine.
    Detects Levenshtein distance variants, visual homoglyphs, Punycode IDNs,
    character substitutions, and subdomain deception.
    """

    TARGET_BRANDS = [
        "paypal", "microsoft", "google", "apple", "amazon", "netflix",
        "chase", "wellsfargo", "bankofamerica", "citibank", "barclays", "hsbc",
        "hdfcbank", "icicibank", "sbi", "axisbank", "paytm",
        "docusign", "dropbox", "adobe", "github", "zoom", "office365",
        "linkedin", "facebook", "instagram", "whatsapp", "telegram",
        "stripe", "coinbase", "binance", "metamask", "okta", "cisco"
    ]

    SUBSTITUTION_MAP = {
        "0": "o", "1": "l", "!": "i", "@": "a", "3": "e", "4": "a",
        "5": "s", "7": "t", "8": "b", "9": "g", "v": "u", "vv": "w",
        "rn": "m", "cl": "d", "nn": "m"
    }

    def __init__(self):
        pass

    def extract_domain_parts(self, domain_or_url: str) -> Tuple[str, str, str]:
        """
        Extract (subdomain, registered_domain, tld/suffix).
        """
        raw = domain_or_url.strip().lower()
        # Strip scheme and path if URL is passed
        raw = re.sub(r"^https?://", "", raw)
        raw = raw.split("/")[0].split(":")[0]

        if TLD_AVAILABLE:
            ext = tldextract.extract(raw)
            return ext.subdomain, ext.domain, ext.suffix
        else:
            parts = raw.split(".")
            if len(parts) >= 2:
                return ".".join(parts[:-2]), parts[-2], parts[-1]
            return "", raw, ""

    def damerau_levenshtein(self, s1: str, s2: str) -> int:
        """Compute Damerau-Levenshtein distance with transposition support."""
        d: Dict[Tuple[int, int], int] = {}
        len1 = len(s1)
        len2 = len(s2)

        for i in range(-1, len1 + 1):
            d[(i, -1)] = i + 1
        for j in range(-1, len2 + 1):
            d[(-1, j)] = j + 1

        for i in range(len1):
            for j in range(len2):
                cost = 0 if s1[i] == s2[j] else 1
                d[(i, j)] = min(
                    d[(i - 1, j)] + 1,        # deletion
                    d[(i, j - 1)] + 1,        # insertion
                    d[(i - 1, j - 1)] + cost  # substitution
                )
                if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost)  # transposition

        return d[(len1 - 1, len2 - 1)]

    def normalize_substitutions(self, name: str) -> str:
        """Normalize common leetspeak substitutions to standard characters."""
        res = name.lower()
        for k, v in self.SUBSTITUTION_MAP.items():
            res = res.replace(k, v)
        return res

    def check_domain(self, domain_or_email: str) -> Dict[str, Any]:
        """
        Analyze a domain or email address for lookalike and impersonation indicators.
        """
        if "@" in domain_or_email:
            domain_or_email = domain_or_email.split("@")[-1]

        subdomain, reg_domain, tld = self.extract_domain_parts(domain_or_email)
        full_domain = f"{reg_domain}.{tld}" if tld else reg_domain

        result: Dict[str, Any] = {
            "domain": domain_or_email,
            "registered_domain": reg_domain,
            "is_lookalike": False,
            "impersonated_brand": None,
            "similarity_score": 0.0,
            "homoglyph_risk": False,
            "punycode_risk": False,
            "subdomain_deception": False,
            "risk_level": "NONE",
            "evidence": []
        }

        if not reg_domain:
            return result

        # 1. Punycode check (IDN)
        if "xn--" in domain_or_email.lower():
            result["punycode_risk"] = True
            try:
                decoded = domain_or_email.encode("ascii").decode("idna")
                result["evidence"].append(f"Internationalized Domain Name (Punycode): '{domain_or_email}' decodes to '{decoded}'")
            except Exception:
                result["evidence"].append(f"Punycode encoded domain detected: '{domain_or_email}'")

        # 2. Subdomain deception check (e.g., paypal.com.attacker.com)
        if subdomain:
            for brand in self.TARGET_BRANDS:
                if brand in subdomain.lower().split("."):
                    result["subdomain_deception"] = True
                    result["is_lookalike"] = True
                    result["impersonated_brand"] = brand
                    result["similarity_score"] = 0.95
                    result["risk_level"] = "CRITICAL"
                    result["evidence"].append(
                        f"Subdomain deception detected: Target brand '{brand}' appears inside subdomain '{subdomain}' of unrelated domain '{full_domain}'."
                    )
                    return result

        # 3. Normalized substitutions and edit distance
        norm_name = self.normalize_substitutions(reg_domain)
        cleaned_name = re.sub(r"[-_]", "", reg_domain)

        for brand in self.TARGET_BRANDS:
            # Exact match means it's the legitimate brand domain itself (or legitimate brand name)
            if reg_domain.lower() == brand:
                continue

            # Check if brand is embedded with hyphenation/keywords (e.g. paypal-security, paypa1-security, login-microsoft)
            if (brand in reg_domain) or (brand in norm_name):
                result["is_lookalike"] = True
                result["impersonated_brand"] = brand
                result["similarity_score"] = 0.90
                result["risk_level"] = "HIGH"
                result["evidence"].append(
                    f"Brand embedding: Target brand '{brand}' is embedded within domain '{reg_domain}.{tld}'."
                )
                break

            # Edit distance check against brand name
            dist = self.damerau_levenshtein(reg_domain, brand)
            max_len = max(len(reg_domain), len(brand))
            similarity = 1.0 - (dist / max_len)

            # Check normalized substitution distance (e.g. paypa1 -> paypal)
            norm_dist = self.damerau_levenshtein(norm_name, brand)
            norm_sim = 1.0 - (norm_dist / max(len(norm_name), len(brand)))

            effective_sim = max(similarity, norm_sim)

            if effective_sim >= 0.75 and dist <= 2:
                result["is_lookalike"] = True
                result["impersonated_brand"] = brand
                result["similarity_score"] = round(effective_sim, 2)
                result["risk_level"] = "CRITICAL" if dist == 1 else "HIGH"
                result["evidence"].append(
                    f"Typosquatting/Lookalike match: Domain '{reg_domain}' is {round(effective_sim * 100)}% similar to brand '{brand}' (edit distance: {min(dist, norm_dist)})."
                )
                break

        return result
