"""
modules/nmap_scanner.py — Nmap Integration
Port scanning + service detection + HTTP misconfiguration checks.

Project scope covered by this module:
- Missing HTTP Security Headers
- Unnecessary Open Ports and Dangerous Services
- Information Disclosure via Server Banners
- Unsafe HTTP Methods

Note: SSL/TLS certificate/protocol findings are intentionally NOT
generated here. testssl_scanner.py is the single source of truth
for the "Weak SSL/TLS and Cipher Configurations" risk to avoid
duplicate findings between tools.
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

# Ports relevant to "Unnecessary Open Ports and Dangerous Services"
# in the project scope: unencrypted comms, database services, and
# remote management interfaces.
DANGEROUS_PORTS = {
    21:    ("FTP", "HIGH", "Unencrypted file transfer service (FTP) is exposed."),
    23:    ("Telnet", "CRITICAL", "Unencrypted remote administration service (Telnet) is exposed."),
    1433:  ("MSSQL", "HIGH", "Microsoft SQL Server is directly reachable from the network."),
    3306:  ("MySQL", "HIGH", "MySQL database service is directly reachable from the network."),
    5432:  ("PostgreSQL", "HIGH", "PostgreSQL database service is directly reachable from the network."),
    6379:  ("Redis", "HIGH", "Redis is directly reachable and may lack authentication by default."),
    27017: ("MongoDB", "HIGH", "MongoDB is directly reachable and may lack authentication by default."),
    3389:  ("RDP", "HIGH", "Remote Desktop Protocol (RDP) is exposed to the network."),
    2375:  ("Docker API (unencrypted)", "CRITICAL", "Unencrypted Docker API exposes full host control."),
    2376:  ("Docker API (TLS)", "MEDIUM", "Docker API exposed; verify TLS/client-cert enforcement."),
    5900:  ("VNC", "HIGH", "VNC remote desktop service is exposed to the network."),
}

# Target ports to actively scan for (in addition to the web port itself).
SCAN_PORT_LIST = "21,22,23,80,443,1433,2375,2376,3306,3389,5432,5900,6379,27017"


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Nmap against the target URL.

    Nmap checks:
        - Service/version detection
        - Open ports / dangerous services
        - HTTP headers
        - HTTP methods
        - HTTP enumeration
        - Configuration backups
        - Apache server-status
    """

    parsed = urlparse(url)

    host = parsed.hostname or url

    if parsed.port:
        web_port = parsed.port
    elif parsed.scheme == "https":
        web_port = 443
    else:
        web_port = 80

    out_xml = os.path.join(output_dir, "nmap_results.xml")

    # Scan the web port plus the fixed list of commonly dangerous ports
    # so open-port/dangerous-service findings can actually be generated.
    port_set = set(int(p) for p in SCAN_PORT_LIST.split(","))
    port_set.add(web_port)
    target_ports = ",".join(str(p) for p in sorted(port_set))

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
        "port": web_port,
        "open_ports": [],
        "services": [],
        "http_info": {},
        "findings": [],
        "raw_output": stdout + stderr,
    }

    if os.path.exists(out_xml):
        try:
            result.update(_parse_nmap_xml(out_xml))
        except Exception as e:
            logger.warning(
                "[nmap] Failed to parse XML: %s",
                e
            )

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

                # NOTE: ssl-cert output is intentionally not parsed into
                # a finding-generating field here. Certificate/TLS
                # findings are owned by testssl_scanner.py.

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
    # Unnecessary Open Ports and Dangerous Services
    # ---------------------------------------------------------
    web_port = result.get("port")

    for svc in services:
        port = svc.get("port")

        if port == web_port:
            # Skip the web application's own port — that's the target
            # being assessed, not an "unnecessary" exposed service.
            continue

        if port in DANGEROUS_PORTS:
            service_label, severity, description = DANGEROUS_PORTS[port]

            product = svc.get("product", "")
            version = svc.get("version", "")
            version_text = f" {product} {version}".strip()

            findings.append({
                "tool": "nmap",
                "title": f"Unnecessary Open Port: {port}/{svc.get('proto', 'tcp')} ({service_label})",
                "severity": severity,
                "description": description,
                "evidence": f"Port {port} open — service: {svc.get('name', 'unknown')}{(' - ' + version_text) if version_text.strip() else ''}",
                "category": "Open Ports/Dangerous Services",
                "cvss_vector": (
                    config.DEFAULT_CVSS_VECTORS.get(
                        severity,
                        config.DEFAULT_CVSS_VECTORS["HIGH"]
                    )
                ),
            })

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
        }

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
    # Server Version / Technology Disclosure
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

    x_powered_by = headers.get("x-powered-by", "")

    if x_powered_by:

        findings.append({
            "tool": "nmap",
            "title": f"X-Powered-By Header Disclosed: {x_powered_by}",
            "severity": "LOW",
            "description": (
                "X-Powered-By header reveals backend technology/version information."
            ),
            "evidence": f"X-Powered-By: {x_powered_by}",
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
