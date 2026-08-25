import hashlib
import os
import re
from typing import Dict, Any, List


class AttachmentAnalyzer:
    """
    Safe static attachment analysis pipeline.
    Calculates cryptographic hashes (SHA-256, SHA-512) and inspects file extensions,
    MIME types, double-extension obfuscation, and macro indicators WITHOUT executing payloads.
    """

    CRITICAL_EXTENSIONS = {
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".msc", ".jar",
        ".iso", ".img", ".vhd", ".lnk", ".gadget"
    }

    HIGH_RISK_MACRO_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".docb"
    }

    ARCHIVE_EXTENSIONS = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace"
    }

    def __init__(self):
        pass

    def analyze_attachment(
        self,
        filename: str,
        content_bytes: bytes,
        declared_mime_type: str = "application/octet-stream"
    ) -> Dict[str, Any]:
        """
        Perform static forensic analysis of an email attachment.
        """
        clean_filename = os.path.basename(filename or "unnamed_attachment")
        file_size = len(content_bytes)

        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        sha512_hash = hashlib.sha512(content_bytes).hexdigest()
        md5_hash = hashlib.md5(content_bytes).hexdigest()

        # Parse extensions
        ext = os.path.splitext(clean_filename)[1].lower()
        parts = clean_filename.split(".")
        has_double_ext = len(parts) > 2

        risk_level = "LOW"
        risk_score = 0
        indicators: List[str] = []

        # 1. Critical Executable/Script Check
        if ext in self.CRITICAL_EXTENSIONS:
            risk_level = "CRITICAL"
            risk_score += 85
            indicators.append(f"Dangerous executable/script file type: '{ext}'")

        # 2. Macro-enabled Office Document Check
        elif ext in self.HIGH_RISK_MACRO_EXTENSIONS:
            risk_level = "HIGH"
            risk_score += 65
            indicators.append(f"Macro-enabled document format: '{ext}' (potential VBA macro delivery)")

        # 3. Archive Delivery Check
        elif ext in self.ARCHIVE_EXTENSIONS:
            risk_level = "MEDIUM"
            risk_score += 35
            indicators.append(f"Compressed archive container: '{ext}' (common evasion container)")

            # Check if zip is encrypted/password protected (Flag bit 0 set in local header)
            if content_bytes.startswith(b"PK\x03\x04") and len(content_bytes) > 8:
                flags = int.from_bytes(content_bytes[6:8], byteorder="little")
                if flags & 0x0001:
                    risk_score += 25
                    risk_level = "HIGH"
                    indicators.append("Password-protected/encrypted ZIP archive detected (payload inspection blocked).")

        # 4. Double Extension Detection (e.g. Invoice.pdf.exe)
        if has_double_ext:
            second_last = "." + parts[-2].lower()
            if second_last in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
                risk_score += 40
                risk_level = "CRITICAL" if ext in self.CRITICAL_EXTENSIONS else "HIGH"
                indicators.append(f"Double extension evasion detected: '{clean_filename}' hides as a '{second_last}' file.")

        # 5. Static Magic Byte Verification
        magic_mismatch = False
        if content_bytes.startswith(b"MZ"):
            # Windows Executable / PE binary
            if ext not in self.CRITICAL_EXTENSIONS:
                magic_mismatch = True
                risk_level = "CRITICAL"
                risk_score += 90
                indicators.append(f"MIME/Magic byte mismatch: File '{clean_filename}' contains Windows PE (MZ) binary header despite '{ext}' extension.")
        elif content_bytes.startswith(b"%PDF") and ext not in (".pdf", ".pdfm"):
            indicators.append("Contains PDF header with non-PDF extension.")

        # 6. Check for Right-to-Left Override (RTLO) unicode attack in filename
        if "\u202e" in clean_filename:
            risk_level = "CRITICAL"
            risk_score += 95
            indicators.append("Right-to-Left Override (RTLO) Unicode character detected in filename (severe spoofing tactic).")

        risk_score = min(100, max(0, risk_score))

        return {
            "filename": clean_filename,
            "extension": ext,
            "size_bytes": file_size,
            "declared_mime": declared_mime_type,
            "sha256": sha256_hash,
            "sha512": sha512_hash,
            "md5": md5_hash,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "has_double_extension": has_double_ext,
            "is_dangerous": (risk_level in ("CRITICAL", "HIGH")),
            "indicators": indicators,
            "evidence": indicators if indicators else ["Static attachment profile matches expected benign file format."]
        }
