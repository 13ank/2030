"""
config.py — Central Configuration
Automated Security Misconfiguration Assessment and Auditing System
"""
import logging
import os
import shutil

# ─────────────────────────────────────────
#  Tool Paths (auto-detect from PATH)
# ─────────────────────────────────────────
TOOL_PATHS = {
    "nikto":    shutil.which("nikto")    or "/usr/bin/nikto",
    "nuclei":   shutil.which("nuclei")   or "/usr/bin/nuclei",
    "nmap":     shutil.which("nmap")     or "/usr/bin/nmap",
    "gobuster": shutil.which("gobuster") or "/usr/bin/gobuster",
    "testssl":  shutil.which("testssl")  or shutil.which("testssl.sh") or "/usr/bin/testssl",
    "whatweb":  shutil.which("whatweb")  or "/usr/bin/whatweb",
}

# ─────────────────────────────────────────────────────────────────
#  Timeouts (seconds) — Default: 600s (10 mins per tool)
# ─────────────────────────────────────────────────────────────────
TIMEOUTS = {
    "nikto":    600,
    "nuclei":   600,
    "nmap":     600,
    "gobuster": 600,
    "testssl":  600,
    "whatweb":  300,
}

# ─────────────────────────────────────────
#  Wordlists
# ─────────────────────────────────────────
WORDLISTS = [
    os.path.join(os.path.dirname(__file__), "wordlists", "common.txt"),
    os.path.join(os.path.dirname(__file__), "wordlists", "directory-list-2.3-small.txt"),
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

def get_wordlist() -> str:
    """Return first available wordlist."""
    for wl in WORDLISTS:
        if os.path.exists(wl):
            return wl
    logging.getLogger("assessor.config").warning("No valid wordlist found on system from default paths.")
    return WORDLISTS[0]  # will fail gracefully in gobuster

# ─────────────────────────────────────────
#  Nmap Ports & Scripts
# ─────────────────────────────────────────
# Web ports + all dangerous service ports checked by _generate_findings()
NMAP_PORTS = (
    "21,23,80,443,445,"
    "2375,3000,3306,3389,"
    "5000,5432,6379,"
    "8000,8080,8443,8888,"
    "27017"
)
NMAP_SCRIPTS = (
    "http-headers,http-methods,http-title,http-server-header,"
    "http-enum,http-config-backup,http-apache-server-status,"
    "ssl-cert,ssl-enum-ciphers"
)

# ─────────────────────────────────────────
#  Nuclei Templates
# ─────────────────────────────────────────
NUCLEI_TAGS = "misconfig,exposure,config,panel,takeover,cve,ssl,headers"
NUCLEI_SEVERITY = "critical,high,medium,low"

# ─────────────────────────────────────────
#  Gobuster Extensions
# ─────────────────────────────────────────
GOBUSTER_EXTENSIONS = "php,html,js,txt,json,xml,bak,old,zip,env,conf,config"

# ─────────────────────────────────────────
#  Report Settings
# ─────────────────────────────────────────
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
REPORT_AUTHOR = "Automated Security Assessment System"
REPORT_VERSION = "1.0"

# ─────────────────────────────────────────────────────────────────
#  Default CVSS 3.1 Vectors — shared by all scanner modules
#  Centralised here to ensure consistency across tools.
# ─────────────────────────────────────────────────────────────────
DEFAULT_CVSS_VECTORS = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "LOW":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "INFO":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

# ─────────────────────────────────────────
#  Severity Colors (for PDF)
# ─────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": (220, 20,  20),
    "HIGH":     (220, 100, 20),
    "MEDIUM":   (220, 165, 0),
    "LOW":      (50,  130, 200),
    "INFO":     (100, 100, 100),
}

# ─────────────────────────────────────────
#  All available scan modules (in order)
# ─────────────────────────────────────────
DEFAULT_TOOLS = ["whatweb", "nmap", "testssl", "nikto", "gobuster", "nuclei"]
