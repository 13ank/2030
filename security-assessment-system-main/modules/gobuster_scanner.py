"""
modules/gobuster_scanner.py — Gobuster Integration
Directory and file brute-forcing to discover hidden content.
"""
import logging
import os
import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.gobuster")

# Sensitive paths that indicate a finding if discovered
SENSITIVE_PATH_PATTERNS = [
    (r"/(admin|administrator|management|manager|wp-admin|cp|controlpanel)", "CRITICAL",
     "Admin panel discovered", "Administrative interface exposed without restriction."),
    (r"/(phpinfo|info\.php|test\.php|debug\.php)", "HIGH",
     "PHP Info/Debug File Exposed", "PHP info or debug file exposes server configuration."),
    (r"/\.env|/\.git|/\.svn|/\.hg|/\.htpasswd|/\.htaccess", "HIGH",
     "Sensitive File Exposed", "Sensitive configuration/source control file accessible."),
    (r"/(backup|bak|old|archive|dump|db)\.", "HIGH",
     "Backup/Archive File Found", "Backup file may contain sensitive data or source code."),
    (r"/(config|configuration|settings|conf)\.(php|yml|yaml|json|xml|ini|env)", "HIGH",
     "Configuration File Exposed", "Configuration file with potential secrets is publicly accessible."),
    (r"/(server-status|server-info|status|health|ping|actuator)", "MEDIUM",
     "Server Status Page Exposed", "Server diagnostics page reveals internal information."),
    (r"/(upload|uploads)(/|$)", "LOW",
     "Upload Directory Accessible", "Upload directory exposed. Check for directory listing or upload abuse."),
    (r"/robots\.txt", "INFO",
     "robots.txt Discovered", "robots.txt may reveal hidden paths disallowed for crawlers."),
    (r"/(crossdomain\.xml|clientaccesspolicy\.xml)", "MEDIUM",
     "Flash/Silverlight Policy File", "Policy file may allow cross-domain access."),
    (r"/(wp-content|wp-includes|wp-login)", "MEDIUM",
     "WordPress Files Discovered", "WordPress installation paths exposed."),
    (r"/(phpmyadmin|pma|myadmin|sqladmin)", "CRITICAL",
     "phpMyAdmin Panel Exposed", "Database management interface accessible without restriction."),
    (r"/(swagger|api-docs|openapi|graphql)", "MEDIUM",
     "API Documentation Exposed", "API documentation may reveal endpoints and data structures."),
    (r"\.(log|bak|sql|dump|tar|zip|gz|rar)$", "HIGH",
     "Sensitive File Extension", "File with sensitive extension is publicly accessible."),
]


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Gobuster directory brute-force against the target URL.
    """
    out_file  = os.path.join(output_dir, "gobuster_results.txt")
    wordlist  = config.get_wordlist()

    if not os.path.exists(wordlist):
        logger.warning(f"[gobuster] Wordlist not found: {wordlist}")
        return {
            "tool":     "gobuster",
            "status":   "error",
            "url":      url,
            "findings": [],
            "paths":    [],
            "raw_output": f"Wordlist not found: {wordlist}",
        }

    cmd = [
        config.TOOL_PATHS["gobuster"],
        "dir",
        "-u", url,
        "-w", wordlist,
        "-o", out_file,
        "-x", config.GOBUSTER_EXTENSIONS,
        "-t", "20",               # 20 threads
        "--no-progress",
        "--no-error",
        "-q",                     # quiet mode
        "-r",                     # follow redirects
        "--timeout", "10s",
    ]

    rc, stdout, stderr = run_tool(cmd, "gobuster", timeout=config.TIMEOUTS["gobuster"])

    result = {
        "tool":     "gobuster",
        "status":   "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url":      url,
        "paths":    [],
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # Parse output file
    raw = ""
    if os.path.exists(out_file):
        with open(out_file, "r", errors="replace") as f:
            raw = f.read()
    elif stdout:
        raw = stdout

    result["paths"]    = _parse_gobuster_output(raw)
    result["findings"] = _generate_findings(url, result["paths"])

    logger.info(f"[gobuster] Found {len(result['paths'])} paths, "
                f"{len(result['findings'])} sensitive findings")
    return result


def _parse_gobuster_output(raw: str) -> List[Dict]:
    """
    Parse gobuster output lines.
    Format: /path   (Status: 200) [Size: 1234]
       or:  http://target/path (Status: 200) [Size: 1234]
    """
    paths = []
    # Match lines like: /admin  (Status: 200) [Size: 4096] or http://target/admin (Status: 200)
    pattern = re.compile(
        r"(?:^|\s)(?:https?://[^/\s]+)?(/[^?\s#]*)\s+\(Status:\s*(\d+)\)(?:.*\[Size:\s*(\d+)\])?",
        re.IGNORECASE | re.MULTILINE
    )
    for m in pattern.finditer(raw):
        path, code, size = m.group(1), int(m.group(2)), m.group(3)
        # Only keep successful/interesting responses
        if code in (200, 204, 301, 302, 307, 308, 401, 403):
            paths.append({
                "path":        path,
                "status_code": code,
                "size":        int(size) if size else 0,
            })
    return paths


def _generate_findings(base_url: str, paths: List[Dict]) -> List[Dict]:
    """Match discovered paths against sensitive patterns."""
    findings = []
    seen_titles = set()

    for path_info in paths:
        path = path_info["path"]
        code = path_info["status_code"]
        full_url = base_url.rstrip("/") + path

        for pattern, severity, title, description in SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                # Use local vars to avoid mutating loop variables
                effective_severity = "INFO" if code in (401, 403) else severity
                display_title      = f"{title} (Auth Required)" if code in (401, 403) else title

                key = f"{display_title}:{path}"
                if key not in seen_titles:
                    seen_titles.add(key)
                    findings.append({
                        "tool":        "gobuster",
                        "title":       display_title,
                        "severity":    effective_severity,
                        "description": description,
                        "evidence":    f"HTTP {code}: {full_url}",
                        "category":   "Directory/File Exposure",
                        "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(effective_severity, config.DEFAULT_CVSS_VECTORS["MEDIUM"]),
                    })
                break

    return findings


