import json
from datetime import datetime, timezone
from typing import Dict, Any


class ReportGenerator:
    """
    Forensic report generation engine.
    Produces comprehensive technical and executive incident reports in HTML and JSON formats.
    Includes SHA-256/SHA-512 evidence digests, chain of custody logs, and assessment limitations.
    """

    def __init__(self):
        pass

    def generate_json_report(self, analysis_result: Dict[str, Any]) -> str:
        """Serialize full forensic record to pretty-printed JSON."""
        return json.dumps(analysis_result, indent=2)

    def generate_html_report(self, analysis_result: Dict[str, Any]) -> str:
        """
        Generate a professional SOC/Forensic incident investigation report in HTML format.
        """
        evidence = analysis_result.get("evidence", {})
        threat = analysis_result.get("threat_assessment", {})
        forensics = analysis_result.get("forensics", {})
        auth = forensics.get("authentication", {})
        origin = forensics.get("origin_assessment", {})
        geo = analysis_result.get("geolocation", {}).get("sender_locations", [{}])
        geo_item = geo[0] if geo else {}
        iocs = analysis_result.get("iocs", [])
        mitre = analysis_result.get("mitre_mappings", [])
        recommendations = threat.get("investigation_recommendations", [])
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        threat_score = threat.get("threat_score", 0)
        threat_level = threat.get("threat_level", "LOW")
        score_color = "#ff4757" if threat_score >= 80 else ("#ffa502" if threat_score >= 50 else "#2ed573")

        hops_html = ""
        for h in forensics.get("header_chain", {}).get("chronological_hops", []):
            hops_html += f"""
            <tr>
                <td style="padding:8px; border:1px solid #334155;">Hop {h.get('hop_number', 1)}</td>
                <td style="padding:8px; border:1px solid #334155;"><code>{h.get('from_ip') or 'N/A'}</code> ({h.get('from_host') or 'Unknown'})</td>
                <td style="padding:8px; border:1px solid #334155;">{h.get('by_host') or 'N/A'}</td>
                <td style="padding:8px; border:1px solid #334155;">{h.get('protocol') or 'SMTP'} {'🔒 TLS' if h.get('tls_used') else '⚠️ Clear'}</td>
                <td style="padding:8px; border:1px solid #334155;">{h.get('timestamp_raw') or 'N/A'}</td>
            </tr>
            """

        iocs_html = ""
        for ioc in iocs[:20]:
            iocs_html += f"""
            <tr>
                <td style="padding:6px; border:1px solid #334155;"><b>{ioc.get('type')}</b></td>
                <td style="padding:6px; border:1px solid #334155;"><code>{ioc.get('value')}</code></td>
                <td style="padding:6px; border:1px solid #334155;">{ioc.get('source')}</td>
                <td style="padding:6px; border:1px solid #334155;">{ioc.get('confidence')}%</td>
            </tr>
            """

        mitre_html = ""
        for m in mitre:
            mitre_html += f"""
            <div style="background:#1e293b; padding:10px; margin-bottom:8px; border-radius:6px; border-left:4px solid #38bdf8;">
                <b style="color:#38bdf8;">{m.get('technique_id')} — {m.get('technique_name')}</b> ({m.get('tactic')})<br>
                <span style="font-size:13px; color:#cbd5e1;">Evidence: {', '.join(m.get('evidence', []))}</span>
            </div>
            """

        recs_html = ""
        for r in recommendations:
            badge_color = "#ef4444" if r.get('priority') == "HIGH" else ("#f59e0b" if r.get('priority') == "MEDIUM" else "#10b981")
            recs_html += f"""
            <li style="margin-bottom:8px;">
                <span style="background:{badge_color}; color:#fff; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold;">{r.get('priority')}</span>
                <span style="color:#f1f5f9; margin-left:6px;">{r.get('action')}</span>
            </li>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelTrace Forensic Investigation Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ background: {score_color}; color: #fff; padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
        .section {{ margin-bottom: 28px; }}
        .section h3 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 14px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; text-align: left; padding: 8px; border: 1px solid #334155; }}
        .alert-box {{ background: rgba(239,68,68,0.15); border-left: 4px solid #ef4444; padding: 12px; border-radius: 4px; margin-bottom: 16px; }}
        .disclaimer {{ font-size: 12px; color: #94a3b8; background: #0f172a; padding: 12px; border-radius: 6px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; color:#f8fafc; font-size:24px;">SENTINELTRACE FORENSIC REPORT</h1>
                <p style="margin:4px 0 0 0; color:#94a3b8; font-size:13px;">AI-Powered Email Threat Detection & Forensic Intelligence Platform (SIH 26106)</p>
            </div>
            <div>
                <span class="badge">{threat_level} — {threat_score}/100</span>
            </div>
        </div>

        <div class="section">
            <h3>1. Case & Evidence Custody Information</h3>
            <table>
                <tr><th style="width:25%;">Evidence File</th><td>{evidence.get('filename', 'email.eml')}</td><th style="width:25%;">Report Generated</th><td>{now_str}</td></tr>
                <tr><th>SHA-256 Digest</th><td colspan="3"><code>{evidence.get('content_hash', 'N/A')}</code></td></tr>
                <tr><th>Message-ID</th><td colspan="3"><code>{evidence.get('message_id', 'N/A')}</code></td></tr>
                <tr><th>From Header</th><td>{evidence.get('from', 'N/A')}</td><th>Date Header</th><td>{evidence.get('date', 'N/A')}</td></tr>
                <tr><th>Subject</th><td colspan="3">{evidence.get('subject', 'N/A')}</td></tr>
            </table>
        </div>

        <div class="section">
            <h3>2. Executive Assessment & Threat Classification</h3>
            <p><b>Primary Classification:</b> {threat.get('classification', 'SUSPICIOUS')} (Confidence: {threat.get('confidence_score', 85)}%)</p>
            <div style="background:#0f172a; padding:12px; border-radius:6px;">
                <b>Observed Infrastructure:</b> {origin.get('probable_source_infrastructure', 'Unknown')}<br>
                <b>Estimated Geographic Origin:</b> {geo_item.get('city') or 'Unknown'}, {geo_item.get('country') or 'Unknown'} (ISP: {geo_item.get('isp') or 'Unknown'})<br>
                <b>Authentication Verdict:</b> SPF: {auth.get('spf', {}).get('result', 'NONE')} | DKIM: {auth.get('dkim', {}).get('status', 'NONE')} | DMARC: {auth.get('dmarc', {}).get('result', 'NONE')}
            </div>
        </div>

        <div class="section">
            <h3>3. Authentication Forensics</h3>
            <table>
                <tr><th>Protocol</th><th>Status</th><th>Reasoning / Parameters</th></tr>
                <tr><td><b>SPF (RFC 7208)</b></td><td><b>{auth.get('spf', {}).get('result', 'NONE')}</b></td><td>{auth.get('spf', {}).get('reasoning', 'N/A')}</td></tr>
                <tr><td><b>DKIM (RFC 6376)</b></td><td><b>{auth.get('dkim', {}).get('status', 'NONE')}</b></td><td>{auth.get('dkim', {}).get('reasoning', 'N/A')}</td></tr>
                <tr><td><b>DMARC (RFC 7489)</b></td><td><b>{auth.get('dmarc', {}).get('result', 'NONE')}</b></td><td>{auth.get('dmarc', {}).get('reasoning', 'N/A')}</td></tr>
            </table>
        </div>

        <div class="section">
            <h3>4. Transmission Relay Chain (Chronological)</h3>
            <table>
                <tr><th>Hop</th><th>From Host / IP</th><th>By Host</th><th>Protocol / TLS</th><th>Timestamp</th></tr>
                {hops_html if hops_html else '<tr><td colspan="5" style="text-align:center;">No relay hops recorded.</td></tr>'}
            </table>
        </div>

        <div class="section">
            <h3>5. MITRE ATT&CK Technique Mapping</h3>
            {mitre_html if mitre_html else '<p style="color:#94a3b8;">No direct ATT&CK mappings identified for benign profile.</p>'}
        </div>

        <div class="section">
            <h3>6. Indicators of Compromise (IOCs)</h3>
            <table>
                <tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr>
                {iocs_html if iocs_html else '<tr><td colspan="4" style="text-align:center;">No extracted IOCs.</td></tr>'}
            </table>
        </div>

        <div class="section">
            <h3>7. Recommended Incident Response Actions</h3>
            <ul style="padding-left:20px;">
                {recs_html if recs_html else '<li>No immediate containment required.</li>'}
            </ul>
        </div>

        <div class="disclaimer">
            <b>Forensic Assessment Limitations:</b><br>
            SentinelTrace produces technical evidence derived strictly from message telemetry, cryptographic headers, and network observables.
            Observed IP addresses and geolocation coordinates represent observed network gateways, proxies, or cloud relays and do NOT independently establish the physical identity of human perpetrators.
        </div>
    </div>
</body>
</html>
"""
        return html
