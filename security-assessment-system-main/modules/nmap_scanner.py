"""
modules/nmap_scanner.py — Nmap Integration
Port scanning + service detection + HTTP/SSL scripts via XML output parsing.
"""
import xml.etree.ElementTree as ET
import logging
import os
import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.nmap")


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Nmap service detection and HTTP/SSL scripts against the target.

    Returns:
        {
            "tool": "nmap",
            "status": ...,
            "url": url,
            "host": host,
            "open_ports": [...],
            "services": [...],
            "findings": [...],
            "raw_output": "..."
        }
    """
    parsed = urlparse(url)
    host = parsed.hostname or url
    out_xml = os.path.join(output_dir, "nmap_results.xml")

    target_ports = config.NMAP_PORTS
    if parsed.port and str(parsed.port) not in target_ports.split(","):
        target_ports = f"{parsed.port},{target_ports}"

    cmd = [
        config.TOOL_PATHS["nmap"],
        "-sV", "-sC",
        "-p", target_ports,
        f"--script={config.NMAP_SCRIPTS}",
        "--script-timeout", "30s",
        "-oX", out_xml,
        "--open",
        host,
    ]

    rc, stdout, stderr = run_tool(cmd, "nmap", timeout=config.TIMEOUTS["nmap"])

    result = {
        "tool":       "nmap",
        "status":     "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url":        url,
        "host":       host,
        "open_ports": [],
        "services":   [],
        "http_info":  {},
        "findings":   [],
        "raw_output": stdout + stderr,
    }

    # Parse XML
    if os.path.exists(out_xml):
        try:
            result.update(_parse_nmap_xml(out_xml))
        except Exception as e:
            logger.warning(f"[nmap] Failed to parse XML: {e}")

    result["findings"] = _generate_findings(result)
    logger.info(f"[nmap] {len(result['open_ports'])} open ports, "
                f"{len(result['findings'])} findings")
    return result


def _parse_nmap_xml(xml_file: str) -> Dict:
    """Parse nmap XML output and extract port/service/script data."""
    tree = ET.parse(xml_file)
    root = tree.getroot()

    open_ports = []
    services = []
    http_info = {}
    script_outputs = []

    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = int(port.get("portid", 0))
            proto  = port.get("protocol", "tcp")
            open_ports.append(portid)

            svc = port.find("service")
            svc_info = {
                "port":    portid,
                "proto":   proto,
                "name":    svc.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "tunnel":  svc.get("tunnel", "") if svc is not None else "",
                "scripts": {},
            }

            # Parse script outputs
            for script in port.findall("script"):
                sid    = script.get("id", "")
                sout   = script.get("output", "")
                svc_info["scripts"][sid] = sout
                script_outputs.append({"script": sid, "output": sout, "port": portid})

                # Extract HTTP headers
                if sid == "http-headers":
                    http_info["headers"] = _parse_headers(sout)
                elif sid == "http-methods":
                    http_info["methods"] = [m.strip() for m in sout.split(",") if m.strip()]
                elif sid == "http-title":
                    http_info["title"] = sout.strip()
                elif sid == "http-server-header":
                    http_info["server"] = sout.strip()
                elif sid == "ssl-cert":
                    http_info["ssl_cert"] = _parse_ssl_cert(sout)
                elif sid == "http-enum":
                    http_info["enum_paths"] = _parse_http_enum(sout)
                elif sid == "http-config-backup":
                    http_info["config_backups"] = _parse_http_config_backup(sout)
                elif sid == "http-apache-server-status":
                    http_info["apache_status"] = sout.strip()

            services.append(svc_info)

    return {
        "open_ports":     open_ports,
        "services":       services,
        "http_info":      http_info,
        "script_outputs": script_outputs,
    }


def _parse_headers(raw: str) -> Dict[str, str]:
    """Parse HTTP headers from nmap script output."""
    headers = {}
    for line in raw.splitlines():
        cleaned = re.sub(r"^\s*\d+:\s*", "", line).strip()
        if ":" in cleaned and not cleaned.startswith("(") and not cleaned.lower().startswith("http/"):
            k, _, v = cleaned.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _parse_ssl_cert(raw: str) -> Dict:
    """Extract basic SSL cert info."""
    info = {}
    for line in raw.splitlines():
        if "Subject:" in line:
            info["subject"] = line.split("Subject:", 1)[1].strip()
        elif "Not valid after:" in line:
            info["expires"] = line.split("Not valid after:", 1)[1].strip()
        elif "Issuer:" in line:
            info["issuer"] = line.split("Issuer:", 1)[1].strip()
    return info


def _parse_http_enum(raw: str) -> List[Dict]:
    """Parse http-enum script output to extract discovered paths.

    Typical output format:
      /admin/: Possible admin folder
      /config/: Configuration directory
      /icons/: Apache default icons
    """
    paths = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("|"):
            line = line.lstrip("|").strip()
            if not line or line.startswith("_"):
                continue
        # Match lines like: /path/: Description text
        match = re.match(r"^(/\S+?):\s*(.*)$", line)
        if match:
            paths.append({
                "path":        match.group(1),
                "description": match.group(2).strip(),
            })
    return paths


def _parse_http_config_backup(raw: str) -> List[str]:
    """Parse http-config-backup script output.

    Typical output format:
      http://target/web.config.bak
      http://target/.htaccess.bak
    Or just file paths like:
      /web.config.bak
      /.htaccess.bak
    """
    backups = []
    for line in raw.splitlines():
        line = line.strip().lstrip("|").strip()
        if not line or line.startswith("_"):
            continue
        # Extract path from URL or bare path
        if line.startswith("http"):
            # Extract path portion from full URL
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(line)
            backups.append(parsed.path or line)
        elif line.startswith("/"):
            backups.append(line)
        elif re.match(r"^[\w./\\-]+\.(bak|old|orig|save|swp|copy|backup|conf|config)$", line, re.IGNORECASE):
            backups.append(line)
    return backups


def _generate_findings(result: Dict) -> List[Dict]:
    """Generate security findings from nmap scan results."""
    findings = []
    open_ports = result.get("open_ports", [])
    services   = result.get("services", [])
    http_info  = result.get("http_info", {})
    headers    = http_info.get("headers", {})

    # ── Dangerous open ports ─────────────────────────────────────────────
    dangerous_ports = {
        21:   ("FTP Port Open",        "MEDIUM",
               "FTP (port 21) is open. FTP transmits data in cleartext."),
        23:   ("Telnet Port Open",     "HIGH",
               "Telnet (port 23) is open. Telnet is unencrypted and insecure."),
        3389: ("RDP Port Exposed",     "HIGH",
               "RDP (port 3389) exposed. Brute-force and exploitation risk."),
        445:  ("SMB Port Exposed",     "HIGH",
               "SMB (port 445) exposed. High risk for lateral movement exploits."),
        3306: ("MySQL Port Exposed",   "MEDIUM",
               "MySQL (port 3306) exposed to network. Restrict to localhost."),
        5432: ("PostgreSQL Exposed",   "MEDIUM",
               "PostgreSQL (port 5432) exposed to network."),
        6379: ("Redis Port Exposed",   "HIGH",
               "Redis (port 6379) exposed. Often unauthenticated by default."),
        27017:("MongoDB Port Exposed", "HIGH",
               "MongoDB (port 27017) exposed. Frequently found unauthenticated."),
        2375: ("Docker API Exposed",   "CRITICAL",
               "Docker daemon API (port 2375) exposed without TLS. Full container control possible."),
    }
    for port in open_ports:
        if port in dangerous_ports:
            title, sev, desc = dangerous_ports[port]
            findings.append({
                "tool":        "nmap",
                "title":       title,
                "severity":    sev,
                "description": desc,
                "evidence":    f"Port {port}/tcp open",
                "category":   "Network Exposure",
                "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(sev, config.DEFAULT_CVSS_VECTORS["MEDIUM"]),
            })

    # ── HTTP Methods ──────────────────────────────────────────────────────
    dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
    allowed_methods = set(http_info.get("methods", []))
    risky = allowed_methods & dangerous_methods
    if risky:
        findings.append({
            "tool":        "nmap",
            "title":       f"Dangerous HTTP Methods Enabled: {', '.join(sorted(risky))}",
            "severity":    "MEDIUM",
            "description": "Server allows potentially dangerous HTTP methods that could enable "
                           "unauthorized file upload, deletion, or request smuggling.",
            "evidence":    f"Allowed: {', '.join(sorted(allowed_methods))}",
            "category":    "HTTP Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        })

    # ── Missing Security Headers ──────────────────────────────────────────
    security_headers = {
        "x-frame-options":          ("Missing X-Frame-Options Header", "MEDIUM",
                                     "Absence allows clickjacking attacks.",
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
        "x-content-type-options":   ("Missing X-Content-Type-Options Header", "LOW",
                                     "Allows MIME-type sniffing attacks.",
                                     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "strict-transport-security":("Missing HSTS Header", "MEDIUM",
                                     "No HSTS forces browsers to use HTTPS, enabling MITM.",
                                     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "content-security-policy":  ("Missing Content-Security-Policy Header", "MEDIUM",
                                     "No CSP allows XSS and data injection attacks.",
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        "x-xss-protection":         ("Missing X-XSS-Protection Header", "LOW",
                                     "Legacy header absence may allow reflected XSS on older browsers.",
                                     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "referrer-policy":          ("Missing Referrer-Policy Header", "LOW",
                                     "Referrer info may leak to third parties.",
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "permissions-policy":       ("Missing Permissions-Policy Header", "LOW",
                                     "Browser features (camera, mic, geolocation) not restricted.",
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    }
    # Fire missing-header findings only when http-headers script actually ran and returned header data
    if "headers" in http_info:

        for header_key, (title, sev, desc, cvss) in security_headers.items():
            if header_key not in headers:
                findings.append({
                    "tool":        "nmap",
                    "title":       title,
                    "severity":    sev,
                    "description": desc,
                    "evidence":    f"Header '{header_key}' not present in HTTP response",
                    "category":    "Security Headers",
                    "cvss_vector": cvss,
                })

    # ── Server Header Disclosure ──────────────────────────────────────────
    server = http_info.get("server", "") or headers.get("server", "")
    if server:
        findings.append({
            "tool":        "nmap",
            "title":       f"Server Version Disclosed: {server}",
            "severity":    "LOW",
            "description": "Server banner reveals software version, aiding attacker fingerprinting.",
            "evidence":    f"Server: {server}",
            "category":    "Information Disclosure",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        })

    # ── http-enum: Discovered directories and files ───────────────────────
    enum_paths = http_info.get("enum_paths", [])
    for ep in enum_paths:
        path = ep.get("path", "")
        desc = ep.get("description", "")
        if not path:
            continue
        # Classify severity based on the path content
        sev = "MEDIUM"
        category = "Directory/File Exposure"
        if re.search(r"(admin|manager|phpmyadmin|cpanel)", path, re.IGNORECASE):
            sev = "CRITICAL"
            category = "Admin Panel Exposure"
        elif re.search(r"(\.env|\.git|\.svn|\.htpasswd|config|backup|dump)", path, re.IGNORECASE):
            sev = "HIGH"
            category = "Sensitive File Exposure"
        elif re.search(r"(phpinfo|info\.php|test|debug|status)", path, re.IGNORECASE):
            sev = "HIGH"
            category = "Information Disclosure"
        findings.append({
            "tool":        "nmap",
            "title":       f"Enumerated Path: {path}",
            "severity":    sev,
            "description": desc or f"http-enum script discovered accessible path: {path}",
            "evidence":    f"Path: {path}",
            "category":    category,
            "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(sev, config.DEFAULT_CVSS_VECTORS["MEDIUM"]),
        })

    # ── http-config-backup: Configuration backup files found ──────────────
    config_backups = http_info.get("config_backups", [])
    for cb in config_backups:
        findings.append({
            "tool":        "nmap",
            "title":       f"Configuration Backup File Found: {cb}",
            "severity":    "HIGH",
            "description": ("A configuration backup file was discovered on the server. "
                           "These files often contain database credentials, API keys, "
                           "and other sensitive information."),
            "evidence":    f"Backup file: {cb}",
            "category":    "Sensitive File Exposure",
            "cvss_vector": config.DEFAULT_CVSS_VECTORS["HIGH"],
        })

    # ── http-apache-server-status: Apache status page exposed ─────────────
    apache_status = http_info.get("apache_status", "")
    if apache_status:
        findings.append({
            "tool":        "nmap",
            "title":       "Apache Server Status Page Exposed",
            "severity":    "MEDIUM",
            "description": ("Apache mod_status (server-status) page is publicly accessible. "
                           "This reveals active connections, request details, server uptime, "
                           "and internal IP addresses — valuable for attackers."),
            "evidence":    f"server-status output: {apache_status[:300]}",
            "category":    "Information Disclosure",
            "cvss_vector": config.DEFAULT_CVSS_VECTORS["MEDIUM"],
        })

    return findings


