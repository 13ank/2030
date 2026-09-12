"""
modules/nikto_scanner.py — Nikto Integration
Web server scanner for misconfigurations, dangerous files, and outdated software.
"""
import json
import logging
import os
import re
from typing import Dict, Any, List

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.nikto")




def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Nikto web scanner against the target URL.
    """
    out_json = os.path.join(output_dir, "nikto_results.json")

    cmd = [
        config.TOOL_PATHS["nikto"],
        "-h", url,
        "-Format", "json",
        "-output", out_json,
        "-nointeractive",
        "-Tuning", "2",          # Tuning 2 = Misconfiguration / Default Files
        "-timeout", "5",
    ]

    rc, stdout, stderr = run_tool(cmd, "nikto", timeout=config.TIMEOUTS["nikto"])

    result = {
        "tool":     "nikto",
        "status":   "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url":      url,
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # Parse JSON output
    json_file_to_parse = None
    if os.path.exists(out_json):
        json_file_to_parse = out_json
    elif os.path.exists(out_json + ".json"):
        json_file_to_parse = out_json + ".json"

    if json_file_to_parse:
        try:
            result["findings"] = _parse_nikto_json(json_file_to_parse)
        except Exception as e:
            logger.warning(f"[nikto] Failed to parse JSON, trying text parse: {e}")
            result["findings"] = _parse_nikto_text(stdout)

    # Fallback if no findings from JSON parsing
    if not result["findings"] and stdout:
        result["findings"] = _parse_nikto_text(stdout)

    logger.info(f"[nikto] {len(result['findings'])} findings")
    return result


def _parse_nikto_json(json_file: str) -> List[Dict]:
    """Parse Nikto JSON output format."""
    with open(json_file, "r", errors="replace") as f:
        content = f.read().strip()

    if not content:
        return []

    # Strip any non-JSON prefix (e.g. warning banners)
    idx = min(
        [i for i in [content.find("["), content.find("{")] if i != -1],
        default=-1
    )
    if idx != -1:
        content = content[idx:]

    data = json.loads(content)

    findings = []
    vulns = []
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
        if not vulns and "host" in data:
            host_obj = data["host"]
            if isinstance(host_obj, dict):
                vulns = host_obj.get("vulnerabilities", [])
        if not vulns and "hosts" in data:
            hosts_obj = data["hosts"]
            if isinstance(hosts_obj, list):
                for h in hosts_obj:
                    if isinstance(h, dict):
                        vulns.extend(h.get("vulnerabilities", []))
    elif isinstance(data, list):
        for host_obj in data:
            if isinstance(host_obj, dict):
                vulns.extend(host_obj.get("vulnerabilities", []))

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue

        osvdb    = str(vuln.get("OSVDBID", vuln.get("OSVDB", vuln.get("osvdb", vuln.get("id", "0")))))
        msg      = vuln.get("msg", vuln.get("message", vuln.get("description", "")))
        uri      = vuln.get("uri", vuln.get("url", vuln.get("path", "")))
        method   = vuln.get("method", "GET")

        if not msg:
            continue

        severity = _classify_nikto_severity(msg)

        findings.append({
            "tool":        "nikto",
            "title":       _clean_nikto_title(msg),
            "severity":    severity,
            "description": msg,
            "evidence":    f"{method} {uri}" if uri else msg[:100],
            "category":   _classify_nikto_category(msg),
            "osvdb":       osvdb,
            "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(severity, config.DEFAULT_CVSS_VECTORS["MEDIUM"]),
        })

    return findings


def _parse_nikto_text(stdout: str) -> List[Dict]:
    """Fallback: parse Nikto plain text output."""
    findings = []
    # Look for lines starting with + that contain findings
    finding_pattern = re.compile(r"^\+ (.+)$", re.MULTILINE)
    for match in finding_pattern.finditer(stdout):
        line = match.group(1).strip()
        # Skip summary lines
        if any(skip in line.lower() for skip in [
            "target ip", "target hostname", "target port", "start time",
            "end time", "host(s) tested", "requests made",
        ]):
            continue

        severity = _classify_nikto_severity(line)
        findings.append({
            "tool":        "nikto",
            "title":       _clean_nikto_title(line),
            "severity":    severity,
            "description": line,
            "evidence":    line[:200],
            "category":   _classify_nikto_category(line),
            "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(severity, config.DEFAULT_CVSS_VECTORS["MEDIUM"]),
        })

    return findings


def _classify_nikto_severity(msg: str) -> str:
    """Classify severity based on message keywords."""
    msg_lower = msg.lower()

    if any(re.search(r'\b' + re.escape(k) + r'\b', msg_lower) for k in [
        "sql injection", "remote code", "command injection", "rce",
        "authentication bypass", "admin password", "default credentials",
        "webshell", "backdoor", "critical",
    ]):
        return "CRITICAL"

    if any(k in msg_lower for k in [
        "xss", "cross-site", "directory traversal", "path traversal",
        "arbitrary file", "file inclusion", "lfi", "rfi",
        "upload", "unrestricted", "admin panel", "management interface",
        "default password", "exposed credentials",
    ]):
        return "HIGH"

    if any(k in msg_lower for k in [
        "directory listing", "directory index", "information disclosure",
        "server banner", "version disclosed", "debug", "stack trace",
        "phpinfo", "server-status", "server-info",
        "backup file", "config file", "sensitive",
    ]):
        return "MEDIUM"

    if any(k in msg_lower for k in [
        "header", "cookie", "missing", "outdated", "deprecated",
        "insecure", "redirect", "clickjacking",
    ]):
        return "LOW"

    return "INFO"


def _classify_nikto_category(msg: str) -> str:
    msg_lower = msg.lower()
    if "sql" in msg_lower:        return "Injection"
    if "xss" in msg_lower or "cross-site" in msg_lower: return "XSS"
    if "directory" in msg_lower:  return "Directory Exposure"
    if "header" in msg_lower:     return "Security Headers"
    if "ssl" in msg_lower or "tls" in msg_lower: return "SSL/TLS"
    if "default" in msg_lower:    return "Default Configuration"
    if "backup" in msg_lower or "config" in msg_lower: return "Sensitive Files"
    if "admin" in msg_lower:      return "Admin Exposure"
    return "Web Misconfiguration"


def _clean_nikto_title(msg: str) -> str:
    """Trim Nikto message to a clean title (max 80 chars)."""
    # Remove OSVDB references
    msg = re.sub(r"OSVDB-\d+:\s*", "", msg)
    msg = msg.strip()
    if len(msg) > 80:
        msg = msg[:77] + "..."
    return msg


