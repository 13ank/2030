"""
modules/whatweb_scanner.py — WhatWeb Integration
Identifies technologies, CMS, frameworks, and server information.
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

    Returns:
        {
            "tool": "whatweb",
            "status": "success"|"error"|"timeout",
            "url": url,
            "technologies": [...],
            "findings": [...],
            "http_status": 0,
            "raw_output": "..."
        }
    """

    out_file = os.path.join(output_dir, "whatweb_results.json")

    cmd = [
        config.TOOL_PATHS["whatweb"],
        "--log-json", out_file,
        "--color", "never",
        "-a", "1",
        url,
    ]

    rc, stdout, stderr = run_tool(
        cmd,
        "whatweb",
        timeout=config.TIMEOUTS["whatweb"]
    )

    result = {
        "tool": "whatweb",
        "status": (
            "success"
            if rc == 0
            else ("timeout" if rc == -1 else "error")
        ),
        "url": url,
        "technologies": [],
        "findings": [],
        "http_status": 0,
        "raw_output": stdout + stderr,
    }

    # ---------------------------------------------------------
    # Parse WhatWeb JSON output
    # ---------------------------------------------------------
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            entries = _parse_json_output(content)

            logger.debug(
                "[whatweb] Parsed %d JSON entries",
                len(entries)
            )

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                # HTTP status
                http_status = entry.get("http_status")
                if http_status:
                    try:
                        result["http_status"] = int(http_status)
                    except (ValueError, TypeError):
                        pass

                # WhatWeb plugins
                plugins = entry.get("plugins", {})

                if not isinstance(plugins, dict):
                    continue

                for tech_name, tech_info in plugins.items():

                    if not isinstance(tech_info, dict):
                        continue

                    version = tech_info.get("version")
                    string = tech_info.get("string")

                    version_value = _first_value(version)
                    string_value = _first_value(string)

                    technology = {
                        "name": tech_name,
                        "version": version_value,
                        "detail": string_value,
                    }

                    # Avoid duplicate technologies
                    if not any(
                        t["name"].lower() == tech_name.lower()
                        for t in result["technologies"]
                    ):
                        result["technologies"].append(technology)

        except Exception as e:
            logger.warning(
                "[whatweb] Failed to parse JSON output: %s",
                e
            )

    # ---------------------------------------------------------
    # Generate security findings
    # ---------------------------------------------------------
    result["findings"] = _generate_findings(
        result["technologies"]
    )

    logger.info(
        "[whatweb] Found %d technologies, %d findings",
        len(result["technologies"]),
        len(result["findings"])
    )

    return result


def _parse_json_output(content: str) -> List[Dict[str, Any]]:
    """
    Parse different JSON formats that WhatWeb may produce.

    Supports:
        1. JSON array
        2. Single JSON object
        3. JSON Lines
        4. Multiple concatenated JSON objects
    """

    if not content:
        return []

    entries = []

    # ---------------------------------------------------------
    # Try normal JSON first
    # ---------------------------------------------------------
    try:
        data = json.loads(content)

        if isinstance(data, list):
            return [
                item for item in data
                if isinstance(item, dict)
            ]

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    # ---------------------------------------------------------
    # Try JSON Lines
    # ---------------------------------------------------------
    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            data = json.loads(line)

            if isinstance(data, list):
                entries.extend(
                    item for item in data
                    if isinstance(item, dict)
                )

            elif isinstance(data, dict):
                entries.append(data)

        except json.JSONDecodeError:
            continue

    if entries:
        return entries

    # ---------------------------------------------------------
    # Try concatenated JSON objects
    # ---------------------------------------------------------
    decoder = json.JSONDecoder()
    position = 0

    while position < len(content):

        while position < len(content) and content[position].isspace():
            position += 1

        if position >= len(content):
            break

        try:
            data, end = decoder.raw_decode(
                content,
                position
            )

            if isinstance(data, list):
                entries.extend(
                    item for item in data
                    if isinstance(item, dict)
                )

            elif isinstance(data, dict):
                entries.append(data)

            position = end

        except json.JSONDecodeError:
            break

    return entries


def _first_value(value):
    """
    Return the first useful value from WhatWeb plugin data.
    """

    if isinstance(value, list):
        return value[0] if value else None

    if isinstance(value, str):
        return value

    return None


def _generate_findings(
    technologies: List[Dict]
) -> List[Dict]:

    findings = []

    risky_techs = {
        "php": (
            "Exposed PHP Version",
            "MEDIUM",
            "PHP technology/version is disclosed by the web server."
        ),

        "apache": (
            "Exposed Apache Version",
            "LOW",
            "Apache server version is disclosed."
        ),

        "nginx": (
            "Exposed Nginx Version",
            "LOW",
            "Nginx server version is disclosed."
        ),

        "iis": (
            "Exposed Microsoft IIS Version",
            "LOW",
            "IIS server information may be disclosed."
        ),

        "x-powered-by": (
            "X-Powered-By Header Present",
            "LOW",
            "Technology stack information is disclosed through X-Powered-By."
        ),

        "jquery": (
            "jQuery Version Detected",
            "INFO",
            "jQuery version is exposed. Verify that the version is supported."
        ),

        "python": (
            "Exposed Python Framework",
            "LOW",
            "Python/framework information is disclosed."
        ),

        "ruby": (
            "Exposed Ruby Framework",
            "LOW",
            "Ruby/Rails framework information is disclosed."
        ),
    }

    for tech in technologies:

        tech_name = str(
            tech.get("name", "")
        )

        tech_lower = tech_name.lower()

        for key, (title, severity, description) in risky_techs.items():

            if key in tech_lower:

                version = tech.get("version")

                version_text = (
                    f" v{version}"
                    if version
                    else ""
                )

                finding = {
                    "tool": "whatweb",
                    "title": f"{title}{version_text}",
                    "severity": severity,
                    "description": description,
                    "evidence": (
                        f"Detected: {tech_name}"
                        f"{version_text}"
                    ),
                    "category": "Information Disclosure",
                    "cvss_vector": (
                        config.DEFAULT_CVSS_VECTORS.get(
                            severity,
                            config.DEFAULT_CVSS_VECTORS["LOW"]
                        )
                    ),
                }

                findings.append(finding)
                break

    # ---------------------------------------------------------
    # Deduplicate findings
    # ---------------------------------------------------------
    seen = set()
    deduped = []

    for finding in findings:

        title = finding["title"]

        if title not in seen:
            seen.add(title)
            deduped.append(finding)

    return deduped
