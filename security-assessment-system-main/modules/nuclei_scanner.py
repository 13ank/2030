"""
modules/nuclei_scanner.py — Nuclei Integration
Template-based vulnerability scanner for misconfigurations, CVEs, and exposures.
"""
import json
import logging
import os
from typing import Dict, Any, List

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.nuclei")

# Nuclei severity → standard severity mapping
NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}




def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Nuclei template-based scanner against the target URL.
    """
    out_jsonl = os.path.join(output_dir, "nuclei_results.jsonl")

    cmd = [
        config.TOOL_PATHS["nuclei"],
        "-u", url,
        "-jsonl-export", out_jsonl,
        "-severity", config.NUCLEI_SEVERITY,
        "-tags", config.NUCLEI_TAGS,
        "-silent",
        "-no-interactsh",   # Disable OAST to avoid DNS callback in passive mode
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", "50",
    ]

    rc, stdout, stderr = run_tool(cmd, "nuclei", timeout=config.TIMEOUTS["nuclei"])

    result = {
        "tool":     "nuclei",
        "status":   "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url":      url,
        "findings": [],
        "raw_output": stdout + stderr,
    }

    # Parse JSONL output
    if os.path.exists(out_jsonl):
        try:
            result["findings"] = _parse_nuclei_jsonl(out_jsonl)
        except Exception as e:
            logger.warning(f"[nuclei] Failed to parse JSONL: {e}")

    logger.info(f"[nuclei] {len(result['findings'])} findings")
    return result


def _parse_nuclei_jsonl(jsonl_file: str) -> List[Dict]:
    """Parse Nuclei JSONL output (one JSON object per line)."""
    findings = []

    with open(jsonl_file, "r", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                finding = _convert_nuclei_entry(entry)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError as e:
                logger.debug(f"[nuclei] JSON parse error on line {line_num}: {e}")

    return findings


def _convert_nuclei_entry(entry: Dict) -> Dict:
    """Convert a single Nuclei JSON result to unified finding format."""
    if not isinstance(entry, dict):
        return None

    info = entry.get("info")
    if not isinstance(info, dict):
        info = {}

    classification = info.get("classification")
    if not isinstance(classification, dict):
        classification = {}

    template_id   = entry.get("template-id", entry.get("templateID", "unknown"))
    template_name = info.get("name", template_id)
    severity_raw  = str(info.get("severity", "info")).lower()
    severity      = NUCLEI_SEVERITY_MAP.get(severity_raw, "INFO")

    description  = info.get("description", "")
    matched_at   = entry.get("matched-at", entry.get("matched", ""))
    curl_command = entry.get("curl-command", "")
    reference    = info.get("reference", [])
    cve_ids      = classification.get("cve-id", [])
    cvss_score   = classification.get("cvss-score", None)
    cvss_vector  = classification.get("cvss-metrics", config.DEFAULT_CVSS_VECTORS.get(severity, ""))

    # Use nuclei-provided CVSS if available, else our default
    if not cvss_vector:
        cvss_vector = config.DEFAULT_CVSS_VECTORS.get(severity, config.DEFAULT_CVSS_VECTORS["INFO"])

    # Category from tags
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    category = _categorize_from_tags(tags)

    # Evidence: matched URL or request snippet
    evidence = matched_at
    if not evidence and curl_command:
        evidence = str(curl_command)[:200]

    # References
    refs = []
    if isinstance(reference, list):
        refs = [str(r) for r in reference[:3] if r]
    elif isinstance(reference, str):
        refs = [reference]

    # Format CVE string safely
    cve_str = ""
    if isinstance(cve_ids, list):
        cve_str = ", ".join(str(c) for c in cve_ids if c)
    elif cve_ids:
        cve_str = str(cve_ids)

    return {
        "tool":         "nuclei",
        "title":        str(template_name),
        "severity":     severity,
        "description":  str(description) or f"Nuclei template [{template_id}] matched.",
        "evidence":     str(evidence),
        "category":     category,
        "template_id":  str(template_id),
        "cvss_vector":  cvss_vector,
        "cvss_score":   cvss_score,
        "cve":          cve_str,
        "references":   refs,
        "tags":         tags if isinstance(tags, list) else [],
    }


def _categorize_from_tags(tags: List[str]) -> str:
    """Determine finding category from Nuclei tags."""
    tag_set = {t.lower() for t in tags}
    if "cve" in tag_set:          return "CVE"
    if "misconfig" in tag_set:    return "Misconfiguration"
    if "exposure" in tag_set:     return "Sensitive Exposure"
    if "panel" in tag_set:        return "Admin Panel"
    if "takeover" in tag_set:     return "Subdomain Takeover"
    if "ssl" in tag_set:          return "SSL/TLS"
    if "headers" in tag_set:      return "Security Headers"
    if "config" in tag_set:       return "Configuration"
    if "injection" in tag_set:    return "Injection"
    if "xss" in tag_set:          return "XSS"
    if "sqli" in tag_set:         return "SQL Injection"
    if "rce" in tag_set:          return "Remote Code Execution"
    if "auth-bypass" in tag_set:  return "Authentication Bypass"
    if "info-leak" in tag_set:    return "Information Disclosure"
    return "Vulnerability"
