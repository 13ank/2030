"""
modules/nmap_scanner.py — Nmap Integration
Port scanning + service detection + HTTP misconfiguration checks.
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
    Run Nmap against the target URL.

    Nmap checks:
        - Service/version detection
        - HTTP headers
        - HTTP methods
        - HTTP enumeration
        - Configuration backups
        - Apache server-status
    """

    parsed = urlparse(url)

    host = parsed.hostname or url

    # Use port from target URL.
    # If no port is specified, use standard HTTP/HTTPS port.
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80

    out_xml = os.path.join(output_dir, "nmap_results.xml")

    # Only scan the target port.
    target_ports = str(port)

    cmd = [
        config.TOOL_PATHS["nmap"],
        "-sV",
        "-p", target_ports,
        f"--script={config.NMAP_SCRIPTS}",
        "--script-timeout", "30s",
        "-oX", out_xml,
        "--open",
        host,
    ]

    rc, stdout, stderr = run_tool(
        cmd,
        "nmap",
        timeout=config.TIMEOUTS["nmap"]
    )

    result = {
        "tool": "nmap",
        "status": (
            "success"
            if rc == 0
            else ("timeout" if rc == -1 else "error")
        ),
        "url": url,
        "host": host,
        "port": port,
        "open_ports": [],
        "services": [],
        "http_info": {},
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # ---------------------------------------------------------
    # Parse XML
    # ---------------------------------------------------------
    if os.path.exists(out_xml):
        try:
            result.update(_parse_nmap_xml(out_xml))
        except Exception as e:
            logger.warning(
                "[nmap] Failed to parse XML: %s",
                e
            )

    # ---------------------------------------------------------
    # Generate findings
    # ---------------------------------------------------------
    result["findings"] = _generate_findings(result)

    logger.info(
        "[nmap] %d open ports, %d findings",
        len(result["open_ports"]),
        len(result["findings"])
    )

    return result


def _parse_nmap_xml(xml_file: str) -> Dict[str, Any]:
    """Parse Nmap XML output."""

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

            if state is None:
                continue

            if state.get("state") != "open":
                continue

            try:
                portid = int(port.get("portid", 0))
            except (ValueError, TypeError):
                portid = 0

            proto = port.get("protocol", "tcp")

            open_ports.append(portid)

            svc = port.find("service")

            svc_info = {
                "port": portid,
                "proto": proto,
                "name": (
                    svc.get("name", "unknown")
                    if svc is not None
                    else "unknown"
                ),
                "product": (
                    svc.get("product", "")
                    if svc is not None
                    else ""
                ),
                "version": (
                    svc.get("version", "")
                    if svc is not None
                    else ""
                ),
                "tunnel": (
                    svc.get("tunnel", "")
                    if svc is not None
                    else ""
                ),
                "scripts": {},
            }

            # -------------------------------------------------
            # Parse Nmap scripts
            # -------------------------------------------------
            for script in port.findall("script"):

                sid = script.get("id", "")
                sout = script.get("output", "")

                svc_info["scripts"][sid] = sout

                script_outputs.append({
                    "script": sid,
                    "output": sout,
                    "port": portid,
                })

                if sid == "http-headers":
                    http_info["headers"] = _parse_headers(sout)

                elif sid == "http-methods":
                    http_info["methods"] = _parse_http_methods(sout)

                elif sid == "http-title":
                    http_info["title"] = sout.strip()

                elif sid == "http-server-header":
                    http_info["server"] = sout.strip()

                elif sid == "http-enum":
                    http_info["enum_paths"] = _parse_http_enum(sout)

                elif sid == "http-config-backup":
                    http_info["config_backups"] = (
                        _parse_http_config_backup(sout)
                    )

                elif sid == "http-apache-server-status":
                    http_info["apache_status"] = sout.strip()

                elif sid == "ssl-cert":
                    http_info["ssl_cert"] = _parse_ssl_cert(sout)

            services.append(svc_info)

    return {
        "open_ports": open_ports,
        "services": services,
        "http_info": http_info,
        "script_outputs": script_outputs,
    }


def _parse_headers(raw: str) -> Dict[str, str]:
    """Parse HTTP headers."""

    headers = {}

    for line in raw.splitlines():

        cleaned = re.sub(
            r"^\s*\d+:\s*",
            "",
            line
        ).strip()

        if (
            ":" in cleaned
            and not cleaned.startswith("(")
            and not cleaned.lower().startswith("http/")
        ):
            key, _, value = cleaned.partition(":")

            headers[key.strip().lower()] = value.strip()

    return headers


def _parse_http_methods(raw: str) -> List[str]:
    """Extract HTTP methods from Nmap http-methods output."""

    methods = []

    # Look for common method names.
    possible_methods = {
        "GET",
        "HEAD",
        "POST",
        "OPTIONS",
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
        "PATCH",
    }

    for method in possible_methods:

        if re.search(
            rf"\b{method}\b",
            raw,
            re.IGNORECASE
        ):
            methods.append(method)

    return sorted(set(methods))


def _parse_ssl_cert(raw: str) -> Dict[str, str]:
    """Extract basic SSL certificate information."""

    info = {}

    for line in raw.splitlines():

        if "Subject:" in line:
            info["subject"] = line.split(
                "Subject:",
                1
            )[1].strip()

        elif "Not valid after:" in line:
            info["expires"] = line.split(
                "Not valid after:",
                1
            )[1].strip()

        elif "Issuer:" in line:
            info["issuer"] = line.split(
                "Issuer:",
                1
            )[1].strip()

    return info


def _parse_http_enum(raw: str) -> List[Dict[str, str]]:
    """Parse http-enum discovered paths."""

    paths = []

    for line in raw.splitlines():

        line = line.strip()

        if line.startswith("|"):
            line = line.lstrip("|").strip()

        if not line or line.startswith("_"):
            continue

        match = re.match(
            r"^(/\S+?):\s*(.*)$",
            line
        )

        if match:

            paths.append({
                "path": match.group(1),
                "description": match.group(2).strip(),
            })

    return paths


def _parse_http_config_backup(raw: str) -> List[str]:
    """Parse discovered configuration backup files."""

    backups = []

    for line in raw.splitlines():

        line = line.strip().lstrip("|").strip()

        if not line or line.startswith("_"):
            continue

        if line.startswith("http"):

            parsed = urlparse(line)

            if parsed.path:
                backups.append(parsed.path)

        elif line.startswith("/"):

            backups.append(line)

        elif re.match(
            r"^[\w./\\-]+\.(bak|old|orig|save|swp|copy|backup|conf|config)$",
            line,
            re.IGNORECASE
        ):
            backups.append(line)

    return list(dict.fromkeys(backups))


def _generate_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:

    findings = []

    open_ports = result.get("open_ports", [])
    services = result.get("services", [])
    http_info = result.get("http_info", {})

    headers = http_info.get("headers", {})

    # ---------------------------------------------------------
    # HTTP Methods
    # ---------------------------------------------------------
    dangerous_methods = {
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
        "PATCH",
    }

    allowed_methods = set(
        http_info.get("methods", [])
    )

    risky_methods = allowed_methods & dangerous_methods

    if risky_methods:

        methods = ", ".join(
            sorted(risky_methods)
        )

        findings.append({
            "tool": "nmap",
            "title": f"Dangerous HTTP Methods Enabled: {methods}",
            "severity": "MEDIUM",
            "description": (
                "Potentially dangerous HTTP methods "
                "are enabled by the server."
            ),
            "evidence": (
                "Allowed methods: "
                + ", ".join(sorted(allowed_methods))
            ),
            "category": "HTTP Misconfiguration",
            "cvss_vector": (
                config.DEFAULT_CVSS_VECTORS["MEDIUM"]
            ),
        })

    # ---------------------------------------------------------
    # Security Headers
    # ---------------------------------------------------------
    # Only check these headers when HTTP headers were actually
    # returned by Nmap.
    if "headers" in http_info:

        security_headers = {
            "x-frame-options": (
                "Missing X-Frame-Options Header",
                "MEDIUM",
                "The response does not define X-Frame-Options."
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options Header",
                "LOW",
                "The response does not define X-Content-Type-Options."
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy Header",
                "LOW",
                "The response does not define Content-Security-Policy."
            ),
            "referrer-policy": (
                "Missing Referrer-Policy Header",
                "LOW",
                "The response does not define Referrer-Policy."
            ),
            "permissions-policy": (
                "Missing Permissions-Policy Header",
                "LOW",
                "The response does not define Permissions-Policy."
            ),
        }

        # HSTS is meaningful for HTTPS.
        parsed_url = urlparse(
            result.get("url", "")
        )

        if parsed_url.scheme == "https":

            security_headers["strict-transport-security"] = (
                "Missing HSTS Header",
                "MEDIUM",
                "HTTPS response does not define HSTS."
            )

        for header_key, (
            title,
            severity,
            description
        ) in security_headers.items():

            if header_key not in headers:

                findings.append({
                    "tool": "nmap",
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "evidence": (
                        f"Header '{header_key}' "
                        "not present in HTTP response"
                    ),
                    "category": "Security Headers",
                    "cvss_vector": (
                        config.DEFAULT_CVSS_VECTORS.get(
                            severity,
                            config.DEFAULT_CVSS_VECTORS["LOW"]
                        )
                    ),
                })

    # ---------------------------------------------------------
    # Server Version Disclosure
    # ---------------------------------------------------------
    server = (
        http_info.get("server", "")
        or headers.get("server", "")
    )

    if server:

        findings.append({
            "tool": "nmap",
            "title": f"Server Version Disclosed: {server}",
            "severity": "LOW",
            "description": (
                "Server banner reveals software information."
            ),
            "evidence": f"Server: {server}",
            "category": "Information Disclosure",
            "cvss_vector": (
                config.DEFAULT_CVSS_VECTORS["LOW"]
            ),
        })

    # ---------------------------------------------------------
    # HTTP Enumeration
    # ---------------------------------------------------------
    enum_paths = http_info.get(
        "enum_paths",
        []
    )

    for entry in enum_paths:

        path = entry.get("path", "")
        description = entry.get(
            "description",
            ""
        )

        if not path:
            continue

        # Enumeration alone does NOT mean Critical.
        # Use MEDIUM as a conservative baseline.
        severity = "MEDIUM"
        category = "Directory/File Exposure"

        if re.search(
            r"(\.env|\.git|\.svn|\.htpasswd)",
            path,
            re.IGNORECASE
        ):
            severity = "MEDIUM"
            category = "Potential Sensitive File Exposure"

        elif re.search(
            r"(config|backup|dump)",
            path,
            re.IGNORECASE
        ):
            severity = "MEDIUM"
            category = "Configuration Exposure"

        elif re.search(
            r"(phpinfo|info\.php|debug)",
            path,
            re.IGNORECASE
        ):
            severity = "MEDIUM"
            category = "Information Disclosure"

        elif re.search(
            r"(admin|manager|phpmyadmin|cpanel)",
            path,
            re.IGNORECASE
        ):
            severity = "MEDIUM"
            category = "Administrative Path Exposure"

        findings.append({
            "tool": "nmap",
            "title": f"Enumerated Path: {path}",
            "severity": severity,
            "description": (
                description
                or f"Nmap discovered path: {path}"
            ),
            "evidence": (
                f"Path: {path}"
            ),
            "category": category,
            "cvss_vector": (
                config.DEFAULT_CVSS_VECTORS["MEDIUM"]
            ),
        })

    # ---------------------------------------------------------
    # Configuration Backup Files
    # ---------------------------------------------------------
    config_backups = http_info.get(
        "config_backups",
        []
    )

    for backup in config_backups:

        findings.append({
            "tool": "nmap",
            "title": (
                f"Configuration Backup File Found: {backup}"
            ),
            "severity": "HIGH",
            "description": (
                "A configuration backup file was discovered."
            ),
            "evidence": (
                f"Backup file: {backup}"
            ),
            "category": "Sensitive File Exposure",
            "cvss_vector": (
                config.DEFAULT_CVSS_VECTORS["HIGH"]
            ),
        })

    # ---------------------------------------------------------
    # Apache Server Status
    # ---------------------------------------------------------
    apache_status = http_info.get(
        "apache_status",
        ""
    )

    if apache_status:

        findings.append({
            "tool": "nmap",
            "title": "Apache Server Status Page Exposed",
            "severity": "MEDIUM",
            "description": (
                "Apache server-status information "
                "is publicly accessible."
            ),
            "evidence": (
                apache_status[:300]
            ),
            "category": "Information Disclosure",
            "cvss_vector": (
                config.DEFAULT_CVSS_VECTORS["MEDIUM"]
            ),
        })

    return findings
