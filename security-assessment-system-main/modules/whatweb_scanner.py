"""
modules/whatweb_scanner.py — WhatWeb Integration
Identifies technologies, CMS, frameworks, and server info of a web target.
"""
import json
import logging
import os
from typing import Dict, Any, List

from modules.runner import run_tool
import config

logger = logging.getLogger("assessor.whatweb")


def scan(url: str, output_dir: str) -> Dict[str, Any]:
    """
    Run WhatWeb against the target URL.

    Returns a dict with:
        {
            "tool": "whatweb",
            "status": "success"|"error"|"timeout",
            "url": url,
            "technologies": [...],
            "findings": [...],
            "raw_output": "..."
        }
    """
    out_file = os.path.join(output_dir, "whatweb_results.json")
    cmd = [
        config.TOOL_PATHS["whatweb"],
        "--log-json", out_file,
        "--color", "never",
        "-a", "1",       # aggression level 1 = stealthy (passive, no extra requests)
        url,
    ]

    rc, stdout, stderr = run_tool(cmd, "whatweb", timeout=config.TIMEOUTS["whatweb"])

    result = {
        "tool": "whatweb",
        "status": "success" if rc == 0 else ("timeout" if rc == -1 else "error"),
        "url": url,
        "technologies": [],
        "findings": [],
        "http_status": 0,
        "raw_output": stdout + stderr,
    }

    # Parse JSON output file
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", errors="replace") as f:
                content = f.read().strip()
            
            entries = []
            if content:
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        entries.extend(data)
                    elif isinstance(data, dict):
                        entries.append(data)
                except json.JSONDecodeError:
                    # WhatWeb outputs multi-line JSON array or JSONL
                    for line in content.splitlines():
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        try:
                            item = json.loads(line)
                            if isinstance(item, list):
                                entries.extend(item)
                            elif isinstance(item, dict):
                                entries.append(item)
                        except json.JSONDecodeError:
                            pass

            for entry in entries:
                plugins = entry.get("plugins", {})
                for tech_name, tech_info in plugins.items():
                    if not isinstance(tech_info, dict):
                        continue
                    versions = tech_info.get("version", [])
                    strings = tech_info.get("string", [])
                    ver_val = versions[0] if isinstance(versions, list) and versions else (versions if isinstance(versions, str) else None)
                    str_val = strings[0] if isinstance(strings, list) and strings else (strings if isinstance(strings, str) else None)
                    tech_entry = {
                        "name": tech_name,
                        "version": ver_val,
                        "detail": str_val,
                    }
                    result["technologies"].append(tech_entry)

                # HTTP status
                http_status = entry.get("http_status", 0)
                if http_status:
                    result["http_status"] = http_status
        except Exception as e:
            logger.warning(f"[whatweb] Failed to parse output: {e}")

    # Generate findings from technologies
    result["findings"] = _generate_findings(result["technologies"])

    logger.info(f"[whatweb] Found {len(result['technologies'])} technologies, "
                f"{len(result['findings'])} findings")
    return result


def _generate_findings(technologies: List[Dict]) -> List[Dict]:
    """Convert technology detections into security findings."""
    findings = []
    tech_names = {t["name"].lower() for t in technologies}

    # Check for outdated or risky components
    risky_techs = {
        "php":         ("Exposed PHP Version", "MEDIUM",
                        "PHP version disclosed. Older versions may have known CVEs."),
        "apache":      ("Exposed Apache Version", "LOW",
                        "Apache server version disclosed in headers."),
        "nginx":       ("Exposed Nginx Version", "LOW",
                        "Nginx server version disclosed in headers."),
        "wordpress":   ("WordPress CMS Detected", "MEDIUM",
                        "WordPress installation found. Ensure plugins and core are updated."),
        "drupal":      ("Drupal CMS Detected", "MEDIUM",
                        "Drupal installation found. Verify security patches are applied."),
        "joomla":      ("Joomla CMS Detected", "MEDIUM",
                        "Joomla installation found. Ensure core and extensions are patched."),
        "iis":         ("Microsoft IIS Detected", "LOW",
                        "IIS version may be disclosed. Verify security hardening."),
        "jquery":      ("jQuery Detected", "INFO",
                        "jQuery version exposed. Ensure no vulnerable version is used."),
        "x-powered-by":("X-Powered-By Header Present", "LOW",
                        "Technology stack disclosed via X-Powered-By header."),
        "python":      ("Exposed Python Framework", "LOW",
                        "Python/framework version exposed in headers."),
        "ruby":        ("Exposed Ruby Framework", "LOW",
                        "Ruby/Rails version may be exposed."),
    }

    for tech in technologies:
        tech_lower = tech["name"].lower()
        for key, (title, severity, desc) in risky_techs.items():
            if key in tech_lower:
                ver_str = f" v{tech['version']}" if tech.get("version") else ""
                findings.append({
                    "tool":        "whatweb",
                    "title":       f"{title}{ver_str}",
                    "severity":    severity,
                    "description": desc,
                    "evidence":    f"Detected: {tech['name']}{ver_str}",
                    "category":    "Information Disclosure",
                    "cvss_vector": config.DEFAULT_CVSS_VECTORS.get(severity, config.DEFAULT_CVSS_VECTORS["LOW"]),
                })
                break

    # Deduplicate by title
    seen = set()
    deduped = []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            deduped.append(f)
    return deduped


