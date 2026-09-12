"""
modules/testssl_scanner.py — testssl Integration
Audits SSL/TLS configuration: protocols, ciphers, certificate, vulnerabilities.
"""
import json
import logging
import os
from typing import Dict, Any, List
from urllib.parse import urlparse

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.testssl")

# Severity mapping for testssl finding ids
TESTSSL_SEVERITY_MAP = {
    "OK":       "INFO",
    "INFO":     "INFO",
    "LOW":      "LOW",
    "MEDIUM":   "MEDIUM",
    "HIGH":     "HIGH",
    "CRITICAL": "CRITICAL",
    "WARN":     "LOW",
    "FATAL":    "CRITICAL",
}


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run testssl against the target URL.
    """
    parsed   = urlparse(url)
    host     = parsed.hostname or url
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    out_json = os.path.join(output_dir, "testssl_results.json")

    target = f"{host}:{port}"

    cmd = [
        config.TOOL_PATHS["testssl"],
        "--jsonfile", out_json,
        "--color", "0",
        "--quiet",
        "--warnings", "off",
        "--fast",          # Skip slow checks for speed
        target,
    ]

    rc, stdout, stderr = run_tool(cmd, "testssl", timeout=config.TIMEOUTS["testssl"])

    result = {
        "tool":     "testssl",
        "status":   "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url":      url,
        "target":   target,
        "findings": [],
        "ssl_info": {},
        "raw_output": stdout + stderr,
    }

    if os.path.exists(out_json):
        try:
            result.update(_parse_testssl_json(out_json))
        except Exception as e:
            logger.warning(f"[testssl] Failed to parse JSON: {e}")

    logger.info(f"[testssl] {len(result['findings'])} findings")
    return result


def _parse_testssl_json(json_file: str) -> Dict:
    """Parse testssl JSON output into findings."""
    with open(json_file, "r", errors="replace") as f:
        content = f.read().strip()

    if not content:
        return {"findings": [], "ssl_info": {}}

    # Strip any non-JSON header lines (e.g. warning messages)
    idx = min(
        [i for i in [content.find("["), content.find("{")] if i != -1],
        default=-1
    )
    if idx != -1:
        content = content[idx:]

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning(f"[testssl] Failed to parse JSON: {e}")
        return {"findings": [], "ssl_info": {}}

    findings = []
    ssl_info = {}

    # testssl JSON structure: {"scanResult": [{...findings...}]}
    scan_results = []
    if isinstance(data, dict):
        scan_results = data.get("scanResult", [data])
    elif isinstance(data, list):
        scan_results = data

    items_to_process = []
    for scan in scan_results:
        if not isinstance(scan, dict):
            continue
        if "id" in scan or "finding" in scan or "severity" in scan:
            items_to_process.append(scan)
        else:
            for cat_key, cat_val in scan.items():
                if isinstance(cat_val, list):
                    for item in cat_val:
                        if isinstance(item, dict):
                            items_to_process.append(item)
                elif isinstance(cat_val, dict):
                    items_to_process.append(cat_val)

    for item in items_to_process:
        finding_id  = item.get("id", "")
        severity    = str(item.get("severity", "INFO")).upper()
        finding     = str(item.get("finding", ""))
        cve_str     = item.get("cve", "")

        # Map testssl severity
        mapped_sev = TESTSSL_SEVERITY_MAP.get(severity, "INFO")

        # Collect SSL info
        if finding_id in ("cert_commonName", "cert_notAfter", "cert_issuer",
                           "cert_keySize", "cert_signatureAlgorithm"):
            ssl_info[finding_id] = finding

        # Only record actual problems (not INFO/OK)
        if mapped_sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") or (
            mapped_sev == "INFO" and _is_notable_info(finding_id, finding)
        ):
            title, desc, cvss = _get_finding_details(finding_id, finding)
            if not title:
                title = f"SSL/TLS Issue: {finding_id}"
                desc  = finding

            finding_entry = {
                "tool":        "testssl",
                "title":       title,
                "severity":    mapped_sev if mapped_sev != "INFO" else "LOW",
                "description": desc,
                "evidence":    f"[{finding_id}] {finding}",
                "category":   "SSL/TLS",
                "cvss_vector": cvss,
            }
            if cve_str:
                finding_entry["cve"] = cve_str

            findings.append(finding_entry)

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f["title"]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {"findings": unique, "ssl_info": ssl_info}


def _is_notable_info(finding_id: str, finding: str) -> bool:
    """Flag notable INFO items worth reporting."""
    notable_ids = {
        "SSLv2", "SSLv3", "TLS1", "TLS1_1",
        "BEAST", "CRIME_TLS", "BREACH", "POODLE_SSL",
        "heartbleed", "CCS", "ticketbleed", "ROBOT",
        "LUCKY13", "SWEET32", "DROWN",
    }
    return finding_id in notable_ids and "not vulnerable" not in finding.lower()


def _get_finding_details(finding_id: str, finding: str):
    """Map testssl finding IDs to human-readable titles and CVSS vectors."""
    # (title, description, cvss_vector)
    known = {
        "SSLv2":      ("SSLv2 Protocol Supported",
                       "SSLv2 is obsolete and cryptographically broken.",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "SSLv3":      ("SSLv3 Protocol Supported (POODLE)",
                       "SSLv3 is vulnerable to the POODLE attack allowing CBC decryption.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "TLS1":       ("TLS 1.0 Protocol Supported",
                       "TLS 1.0 has known weaknesses (BEAST, POODLE). Should be disabled.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "TLS1_1":     ("TLS 1.1 Protocol Supported",
                       "TLS 1.1 is deprecated by RFC 8996. Disable in favour of TLS 1.2+.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "BEAST":      ("BEAST Attack Vulnerability",
                       "Server is vulnerable to BEAST (Browser Exploit Against SSL/TLS).",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"),
        "POODLE_SSL": ("POODLE Attack Vulnerability",
                       "SSLv3/CBC is vulnerable to POODLE padding oracle attack.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "heartbleed": ("Heartbleed Vulnerability (CVE-2014-0160)",
                       "OpenSSL Heartbleed allows remote memory disclosure.",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "CCS":        ("CCS Injection (CVE-2014-0224)",
                       "OpenSSL CCS Injection allows MITM key material theft.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "ROBOT":      ("ROBOT Attack (Return Of Bleichenbacher's Oracle Threat)",
                       "RSA PKCS#1 v1.5 padding oracle allows private key exposure.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "SWEET32":    ("SWEET32 Birthday Attack",
                       "64-bit block ciphers (3DES) vulnerable to birthday attacks in long sessions.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "DROWN":      ("DROWN Attack (CVE-2016-0800)",
                       "SSLv2 support allows DROWN decryption of modern TLS sessions.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "LUCKY13":    ("LUCKY13 Attack",
                       "CBC-mode TLS vulnerable to timing-based padding oracle.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "CRIME_TLS":  ("CRIME Attack (Compression Ratio Info-leak Made Easy)",
                       "TLS compression enabled; vulnerable to CRIME attack.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "cert_expired":("SSL Certificate Expired",
                        "The SSL certificate has expired, causing browser warnings and MITM risk.",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
        "cert_selfSigned":("Self-Signed SSL Certificate",
                           "Self-signed certificate not trusted by browsers; enables MITM.",
                           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"),
        "HSTS":       ("HSTS Not Configured",
                       "HTTP Strict Transport Security not set. Downgrade attacks possible.",
                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    }
    if finding_id in known:
        return known[finding_id]
    return None, None, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
