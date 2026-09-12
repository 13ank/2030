"""
modules/nuclei_scanner.py — Nuclei Integration
Template-based scanner for misconfigurations and exposures.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.nuclei")


# Nuclei severity -> standard severity
NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Nuclei against the target URL.

    Nuclei is mainly used here for:
    - Misconfiguration
    - Sensitive exposure
    - Configuration exposure
    - Security-related findings
    """

    out_jsonl = os.path.join(
        output_dir,
        "nuclei_results.jsonl"
    )

    # Remove old output to prevent stale findings.
    if os.path.exists(out_jsonl):
        try:
            os.remove(out_jsonl)
        except OSError:
            logger.warning(
                f"[nuclei] Could not remove old output file: {out_jsonl}"
            )

    # Build command from config.
    cmd = [
        config.TOOL_PATHS["nuclei"],
        "-u",
        url,
        "-jsonl-export",
        out_jsonl,
        "-severity",
        config.NUCLEI_SEVERITY,
        "-tags",
        config.NUCLEI_TAGS,
        "-silent",
        "-no-interactsh",
        "-timeout",
        "10",
        "-retries",
        "1",
        "-rate-limit",
        "50",
    ]

    logger.info(
        f"[nuclei] Scanning {url}"
    )

    rc, stdout, stderr = run_tool(
        cmd,
        "nuclei",
        timeout=config.TIMEOUTS["nuclei"]
    )

    # Determine status.
    if rc == 0:
        status = "success"
    elif rc == -1:
        status = "timeout"
    else:
        status = "error"

    result = {
        "tool": "nuclei",
        "status": status,
        "url": url,
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # Parse JSONL results.
    if os.path.exists(out_jsonl):
        try:
            result["findings"] = _parse_nuclei_jsonl(
                out_jsonl
            )
        except Exception as exc:
            logger.warning(
                f"[nuclei] Failed to parse JSONL: {exc}"
            )

    logger.info(
        f"[nuclei] Found {len(result['findings'])} findings"
    )

    return result


def _parse_nuclei_jsonl(
    jsonl_file: str
) -> List[Dict]:
    """
    Parse Nuclei JSONL output.

    Each line normally contains one JSON object.
    """

    findings = []

    try:
        with open(
            jsonl_file,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:

            for line_num, line in enumerate(f, 1):

                line = line.strip()

                if not line:
                    continue

                try:
                    entry = json.loads(line)

                except json.JSONDecodeError as exc:
                    logger.debug(
                        f"[nuclei] JSON parse error "
                        f"line {line_num}: {exc}"
                    )
                    continue

                finding = _convert_nuclei_entry(entry)

                if finding:
                    findings.append(finding)

    except OSError as exc:
        logger.warning(
            f"[nuclei] Cannot read JSONL file: {exc}"
        )

    return findings


def _convert_nuclei_entry(
    entry: Dict
) -> Optional[Dict]:
    """
    Convert one Nuclei result into the project's
    unified finding format.
    """

    if not isinstance(entry, dict):
        return None

    # ---------------------------------------------------------
    # Basic information
    # ---------------------------------------------------------

    info = entry.get("info")

    if not isinstance(info, dict):
        info = {}

    template_id = entry.get(
        "template-id",
        entry.get(
            "templateID",
            "unknown"
        )
    )

    template_name = info.get(
        "name",
        template_id
    )

    severity_raw = str(
        info.get(
            "severity",
            "info"
        )
    ).lower()

    severity = NUCLEI_SEVERITY_MAP.get(
        severity_raw,
        "INFO"
    )

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    classification = info.get(
        "classification"
    )

    if not isinstance(classification, dict):
        classification = {}

    cve_ids = classification.get(
        "cve-id",
        []
    )

    cvss_score = classification.get(
        "cvss-score",
        None
    )

    cvss_vector = classification.get(
        "cvss-metrics",
        None
    )

    # ---------------------------------------------------------
    # Description
    # ---------------------------------------------------------

    description = info.get(
        "description",
        ""
    )

    if not description:
        description = (
            f"Nuclei template [{template_id}] matched."
        )

    # ---------------------------------------------------------
    # Matched target
    # ---------------------------------------------------------

    matched_at = entry.get(
        "matched-at",
        entry.get(
            "matched",
            ""
        )
    )

    if not matched_at:
        matched_at = entry.get(
            "host",
            ""
        )

    # ---------------------------------------------------------
    # CURL command
    # ---------------------------------------------------------

    curl_command = entry.get(
        "curl-command",
        ""
    )

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    evidence = str(
        matched_at
        or curl_command
        or ""
    )

    if len(evidence) > 500:
        evidence = evidence[:500] + "..."

    # ---------------------------------------------------------
    # Tags
    # ---------------------------------------------------------

    tags = info.get(
        "tags",
        []
    )

    if isinstance(tags, str):
        tags = [
            tag.strip()
            for tag in tags.split(",")
            if tag.strip()
        ]

    if not isinstance(tags, list):
        tags = []

    tags = [
        str(tag)
        for tag in tags
    ]

    # ---------------------------------------------------------
    # Category
    # ---------------------------------------------------------

    category = _categorize_from_tags(
        tags
    )

    # ---------------------------------------------------------
    # References
    # ---------------------------------------------------------

    references = info.get(
        "reference",
        []
    )

    if isinstance(references, str):
        references = [references]

    if not isinstance(references, list):
        references = []

    references = [
        str(ref)
        for ref in references[:5]
        if ref
    ]

    # ---------------------------------------------------------
    # CVE IDs
    # ---------------------------------------------------------

    if isinstance(cve_ids, list):

        cve_string = ", ".join(
            str(cve)
            for cve in cve_ids
            if cve
        )

    elif cve_ids:

        cve_string = str(
            cve_ids
        )

    else:

        cve_string = ""

    # ---------------------------------------------------------
    # CVSS fallback
    # ---------------------------------------------------------

    default_vectors = getattr(
        config,
        "DEFAULT_CVSS_VECTORS",
        {}
    )

    default_vector = default_vectors.get(
        severity,
        default_vectors.get(
            "INFO",
            ""
        )
    )

    if not cvss_vector:
        cvss_vector = default_vector

    # ---------------------------------------------------------
    # Return unified finding
    # ---------------------------------------------------------

    return {
        "tool": "nuclei",

        "title": str(
            template_name
        ),

        "severity": severity,

        "description": str(
            description
        ),

        "evidence": evidence,

        "category": category,

        "template_id": str(
            template_id
        ),

        "cvss_vector": str(
            cvss_vector
        ),

        "cvss_score": cvss_score,

        "cve": cve_string,

        "references": references,

        "tags": tags,
    }


def _categorize_from_tags(
    tags: List[str]
) -> str:
    """
    Determine finding category from Nuclei tags.
    """

    tag_set = {
        str(tag).lower()
        for tag in tags
    }

    # Misconfiguration
    if "misconfig" in tag_set:
        return "Misconfiguration"

    # Exposure
    if "exposure" in tag_set:
        return "Sensitive Exposure"

    # Configuration
    if "config" in tag_set:
        return "Configuration"

    # Information disclosure
    if "info-leak" in tag_set:
        return "Information Disclosure"

    # Security headers
    if "headers" in tag_set:
        return "Security Headers"

    # CVE
    if "cve" in tag_set:
        return "CVE"

    # Admin panels
    if "panel" in tag_set:
        return "Admin Panel"

    # SSL/TLS
    if "ssl" in tag_set:
        return "SSL/TLS"

    # Takeover
    if "takeover" in tag_set:
        return "Subdomain Takeover"

    # Injection
    if "injection" in tag_set:
        return "Injection"

    # XSS
    if "xss" in tag_set:
        return "XSS"

    # SQL Injection
    if "sqli" in tag_set:
        return "SQL Injection"

    # RCE
    if "rce" in tag_set:
        return "Remote Code Execution"

    # Authentication bypass
    if "auth-bypass" in tag_set:
        return "Authentication Bypass"

    return "Vulnerability"
