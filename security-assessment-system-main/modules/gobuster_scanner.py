"""
modules/gobuster_scanner.py — Gobuster Integration
Directory and file brute-forcing to discover hidden content.
"""

import logging
import os
import re
from typing import Dict, Any, List

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.gobuster")


# Paths/files that should be investigated when discovered.
# Severity is intentionally conservative because Gobuster only
# discovers paths; it does not prove that the resource is vulnerable.
SENSITIVE_PATH_PATTERNS = [
    (
        r"/(phpinfo|info\.php|test\.php|debug\.php)(/|$)",
        "MEDIUM",
        "PHP Info/Debug File Discovered",
        "A PHP information or debug file was discovered and may expose server configuration."
    ),
    (
        r"/\.env($|/)|/\.git($|/)|/\.svn($|/)|/\.hg($|/)|/\.htpasswd($|/)|/\.htaccess($|/)",
        "MEDIUM",
        "Sensitive File Discovered",
        "A sensitive configuration or source-control path was discovered."
    ),
    (
        r"/(config|configuration|settings|conf)\.(php|yml|yaml|json|xml|ini|env)$",
        "MEDIUM",
        "Configuration File Discovered",
        "A configuration file was discovered and should be checked for sensitive information."
    ),
    (
        r"/(backup|bak|old|archive|dump|db)\.",
        "MEDIUM",
        "Backup File Discovered",
        "A possible backup or archive file was discovered."
    ),
    (
        r"/(server-status|server-info)(/|$)",
        "MEDIUM",
        "Server Status Page Discovered",
        "A server diagnostic page was discovered."
    ),
    (
        r"/(upload|uploads)(/|$)",
        "LOW",
        "Upload Directory Discovered",
        "An upload directory was discovered and should be checked for directory listing or unsafe file upload."
    ),
    (
        r"/robots\.txt$",
        "INFO",
        "robots.txt Discovered",
        "robots.txt was discovered and may reveal paths intended to be excluded from crawlers."
    ),
    (
        r"/(crossdomain\.xml|clientaccesspolicy\.xml)$",
        "LOW",
        "Policy File Discovered",
        "A cross-domain policy file was discovered and should be reviewed."
    ),
    (
        r"/(wp-content|wp-includes|wp-login)(/|$)",
        "LOW",
        "WordPress Path Discovered",
        "A WordPress installation path was discovered."
    ),
    (
        r"/(phpmyadmin|pma|myadmin|sqladmin)(/|$)",
        "MEDIUM",
        "Database Management Path Discovered",
        "A database management interface path was discovered."
    ),
    (
        r"/(swagger|api-docs|openapi|graphql)(/|$)",
        "LOW",
        "API Documentation Discovered",
        "An API documentation path was discovered and may reveal endpoints and data structures."
    ),
    (
        r"\.(log|bak|sql|dump|tar|zip|gz|rar)$",
        "MEDIUM",
        "Potentially Sensitive File Discovered",
        "A file with a potentially sensitive extension was discovered."
    ),
]


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Gobuster directory/file brute-force against the target URL.
    """

    out_file = os.path.join(output_dir, "gobuster_results.txt")
    wordlist = config.get_wordlist()

    # Check wordlist
    if not os.path.exists(wordlist):
        logger.warning(
            f"[gobuster] Wordlist not found: {wordlist}"
        )

        return {
            "tool": "gobuster",
            "status": "error",
            "url": url,
            "paths": [],
            "findings": [],
            "raw_output": f"Wordlist not found: {wordlist}",
        }

    # Remove previous output file so old results
    # cannot be accidentally parsed.
    if os.path.exists(out_file):
        try:
            os.remove(out_file)
        except OSError:
            logger.warning(
                f"[gobuster] Could not remove old output file: {out_file}"
            )

    # Gobuster command
    cmd = [
        config.TOOL_PATHS["gobuster"],
        "dir",
        "-u", url,
        "-w", wordlist,
        "-o", out_file,
        "-x", config.GOBUSTER_EXTENSIONS,
        "-t", "20",
        "--no-progress",
        "--no-error",
        "-q",
        "-r",
        "--timeout", "10s",
    ]

    logger.info(
        f"[gobuster] Scanning {url}"
    )

    rc, stdout, stderr = run_tool(
        cmd,
        "gobuster",
        timeout=config.TIMEOUTS["gobuster"]
    )

    # Determine status
    if rc == 0:
        status = "success"
    elif rc == -1:
        status = "timeout"
    else:
        status = "error"

    result = {
        "tool": "gobuster",
        "status": status,
        "url": url,
        "paths": [],
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # Read Gobuster output
    raw = ""

    if os.path.exists(out_file):
        try:
            with open(
                out_file,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:
                raw = f.read()
        except OSError as exc:
            logger.warning(
                f"[gobuster] Failed to read output: {exc}"
            )

    # Fall back to stdout
    if not raw and stdout:
        raw = stdout

    # Parse discovered paths
    result["paths"] = _parse_gobuster_output(raw)

    # Generate findings
    result["findings"] = _generate_findings(
        url,
        result["paths"]
    )

    logger.info(
        f"[gobuster] Found {len(result['paths'])} paths, "
        f"{len(result['findings'])} findings"
    )

    return result


def _parse_gobuster_output(raw: str) -> List[Dict]:
    """
    Parse Gobuster output.

    Supported examples:

        /admin              (Status: 200) [Size: 4096]
        /config             (Status: 301) [Size: 312]
        http://target/test  (Status: 200) [Size: 1234]

    Returns:
        [
            {
                "path": "/admin",
                "status_code": 200,
                "size": 4096
            }
        ]
    """

    paths = []

    if not raw:
        return paths

    pattern = re.compile(
        r"""
        (?:^|\s)
        (?:
            https?://[^/\s]+
        )?
        (?P<path>/[^?\s#]*)
        \s+
        \(Status:\s*(?P<status>\d+)\)
        (?:.*?\[Size:\s*(?P<size>\d+)\])?
        """,
        re.IGNORECASE | re.MULTILINE | re.VERBOSE,
    )

    seen = set()

    for match in pattern.finditer(raw):
        path = match.group("path")
        status_code = int(match.group("status"))
        size_text = match.group("size")

        size = int(size_text) if size_text else 0

        # Keep interesting HTTP responses.
        if status_code not in (
            200,
            204,
            301,
            302,
            307,
            308,
            401,
            403,
        ):
            continue

        # Normalize path
        if not path.startswith("/"):
            path = "/" + path

        # Remove duplicate trailing slashes
        if path != "/" and path.endswith("//"):
            path = path.rstrip("/")

        key = (
            path.lower(),
            status_code,
            size,
        )

        if key in seen:
            continue

        seen.add(key)

        paths.append(
            {
                "path": path,
                "status_code": status_code,
                "size": size,
            }
        )

    return paths


def _generate_findings(
    base_url: str,
    paths: List[Dict]
) -> List[Dict]:
    """
    Generate findings from discovered Gobuster paths.

    Important:
    Gobuster discovers paths but does not prove that a resource
    is vulnerable. Therefore:

        200/204 -> resource appears accessible
        301/302/307/308 -> resource discovered but redirected
        401/403 -> resource discovered but access restricted

    401/403 findings are therefore reported as INFO.
    """

    findings = []
    seen = set()

    for path_info in paths:

        path = path_info.get("path", "")
        code = path_info.get("status_code", 0)

        if not path:
            continue

        # Construct target URL
        full_url = base_url.rstrip("/") + path

        for (
            pattern,
            severity,
            title,
            description,
        ) in SENSITIVE_PATH_PATTERNS:

            if not re.search(
                pattern,
                path,
                re.IGNORECASE
            ):
                continue

            # -------------------------------------------------
            # Access restricted
            # -------------------------------------------------
            if code in (401, 403):

                effective_severity = "INFO"

                display_title = (
                    f"{title} (Access Restricted)"
                )

                effective_description = (
                    f"{description} "
                    f"The server returned HTTP {code}, "
                    f"so direct access was restricted."
                )

            # -------------------------------------------------
            # Directly accessible
            # -------------------------------------------------
            elif code in (200, 204):

                effective_severity = severity
                display_title = title
                effective_description = description

            # -------------------------------------------------
            # Redirect
            # -------------------------------------------------
            elif code in (301, 302, 307, 308):

                effective_severity = "INFO"

                display_title = (
                    f"{title} (Redirect)"
                )

                effective_description = (
                    f"{description} "
                    f"The discovered path returned HTTP {code}; "
                    f"direct exposure was not confirmed."
                )

            # -------------------------------------------------
            # Other response
            # -------------------------------------------------
            else:

                effective_severity = "INFO"
                display_title = title
                effective_description = description

            # Avoid duplicate findings
            key = (
                display_title,
                path.lower(),
            )

            if key in seen:
                break

            seen.add(key)

            # CVSS vector
            cvss_vectors = getattr(
                config,
                "DEFAULT_CVSS_VECTORS",
                {}
            )

            default_vector = cvss_vectors.get(
                "INFO",
                ""
            )

            cvss_vector = cvss_vectors.get(
                effective_severity,
                default_vector
            )

            findings.append(
                {
                    "tool": "gobuster",
                    "title": display_title,
                    "severity": effective_severity,
                    "description": effective_description,
                    "evidence": (
                        f"HTTP {code}: {full_url}"
                    ),
                    "category": "Directory/File Exposure",
                    "cvss_vector": cvss_vector,
                }
            )

            # One matching pattern per path
            break

    return findings
