#!/usr/bin/env python3

import argparse
import logging
import os
import re
import shutil
import sys
from datetime import datetime
from urllib.parse import urlparse

import config

from modules import (
    whatweb_scanner,
    nmap_scanner,
    testssl_scanner,
    nikto_scanner,
    gobuster_scanner,
    nuclei_scanner,
)

from modules.risk_scorer import (
    score_all_findings,
    calculate_overall_score,
    get_risk_label,
)

from modules.report_generator import generate_report


# =============================================================================
# ASCII Banner
# =============================================================================

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           ███████╗ ██████╗  █████╗  ███╗   ██╗██╗             ║
║           ██╔════╝██╔════╝ ██╔══██╗ ████╗  ██║██║             ║
║           ███████╗██║      ███████║ ██╔██╗ ██║██║             ║
║           ╚════██║██║      ██╔══██║ ██║╚██╗██║╚═╝             ║
║           ███████║╚██████╗ ██║  ██║ ██║ ╚████║██╗             ║
║           ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝╚═╝             ║
║                                                               ║
║   Automated Security Misconfiguration Assessment System       ║
║   Tools: Nikto | Nuclei | Nmap | Gobuster | testssl | WhatWeb ║
╚═══════════════════════════════════════════════════════════════╝
"""


# =============================================================================
# Tool Map
# =============================================================================

TOOL_MAP = {
    "whatweb": whatweb_scanner,
    "nmap": nmap_scanner,
    "testssl": testssl_scanner,
    "nikto": nikto_scanner,
    "gobuster": gobuster_scanner,
    "nuclei": nuclei_scanner,
}


# =============================================================================
# Setup & Helper Functions
# =============================================================================

def setup_logging(verbose: bool, log_file: str = None):
    level = logging.DEBUG if verbose else logging.INFO

    handlers = [
        logging.StreamHandler(sys.stdout)
    ]

    if log_file:
        handlers.append(
            logging.FileHandler(log_file)
        )

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def validate_url(url: str) -> str:
    """
    Ensure URL has a valid HTTP/HTTPS scheme.
    """

    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError(
            f"Invalid URL: {url}"
        )

    return url


def is_tool_available(path: str) -> bool:
    """
    Check if a tool exists and is executable or available in PATH.
    """

    return bool(
        path
        and (
            shutil.which(path)
            or (
                os.path.isfile(path)
                and os.access(path, os.X_OK)
            )
        )
    )


def check_tools(tool_names: list) -> bool:
    """
    Verify required tools are available.
    """

    ok = True

    for name in tool_names:

        path = config.TOOL_PATHS.get(name)

        if not is_tool_available(path):

            print(
                f"  [MISSING] {name} ({path})"
            )

            ok = False

        else:

            print(
                f"  [FOUND]   {name}: {path}"
            )

    return ok


def get_next_scan_number(report_dir: str) -> int:
    """
    Find next sequential scan number.
    """

    if not os.path.exists(report_dir):
        return 1

    max_num = 0
    dirs_count = 0

    for name in os.listdir(report_dir):

        full_path = os.path.join(
            report_dir,
            name
        )

        if not os.path.isdir(full_path):
            continue

        if name.startswith("."):
            continue

        dirs_count += 1

        match = re.match(
            r"^\((\d+)\)",
            name
        )

        if match:
            max_num = max(
                max_num,
                int(match.group(1))
            )

    if max_num > 0:
        return max_num + 1

    return dirs_count + 1


def create_output_dir(
    url: str,
    timestamp: str
) -> str:

    """
    Create output directory for current scan.
    """

    scan_num = get_next_scan_number(
        config.REPORT_DIR
    )

    parsed = urlparse(url)

    host = parsed.hostname or "target"

    host_clean = re.sub(
        r"[^\w\.-]",
        "_",
        host
    )

    port_str = (
        f"_port{parsed.port}"
        if parsed.port
        else ""
    )

    dir_name = (
        f"({scan_num})"
        f"report_{host_clean}"
        f"{port_str}_"
        f"{timestamp}"
    )

    output_dir = os.path.join(
        config.REPORT_DIR,
        dir_name
    )

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    return output_dir


# =============================================================================
# Progress Printer
# =============================================================================

class Progress:

    def __init__(self, total: int):

        self.total = total
        self.current = 0

    def start(self, tool_name: str):

        self.current += 1

        filled = "#" * self.current

        empty = "-" * (
            self.total - self.current
        )

        print(
            f"\n  [{self.current}/{self.total}] "
            f">> Running {tool_name.upper()}"
        )

        print(
            f"  [{filled}{empty}]"
        )

        sys.stdout.flush()

    def done(
        self,
        tool_name: str,
        finding_count: int,
        status: str,
        error_reason: str = ""
    ):

        if status == "success":

            icon = "[OK] "

            detail = (
                f"{finding_count} finding(s)"
            )

        else:

            icon = "[ERROR]"

            detail = (
                error_reason
                or status
            )

        print(
            f"  {icon} "
            f"{tool_name.upper()} -- "
            f"{detail}"
        )

        if (
            status != "success"
            and error_reason
        ):

            for line in error_reason.splitlines()[:3]:

                print(
                    f"           "
                    f"{line.strip()}"
                )

        sys.stdout.flush()


# =============================================================================
# Normalize Finding
# =============================================================================

def normalize_finding(finding: dict) -> dict:
    """
    Normalize fields from different scanners.
    """

    result = dict(finding)

    severity = str(
        result.get(
            "severity",
            "INFO"
        )
    ).upper()

    allowed = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }

    if severity not in allowed:
        severity = "INFO"

    result["severity"] = severity

    if not result.get("tool"):
        result["tool"] = "unknown"

    if not result.get("title"):
        result["title"] = "Unknown Finding"

    return result


# =============================================================================
# Main Assessment
# =============================================================================

def run_assessment(args) -> int:

    print(BANNER)

    # -------------------------------------------------------------------------
    # Validate URL
    # -------------------------------------------------------------------------

    try:

        url = validate_url(
            args.url
        )

    except ValueError as e:

        print(
            f"\n[ERROR] {e}"
        )

        return 1

    # -------------------------------------------------------------------------
    # Determine Tools
    # -------------------------------------------------------------------------

    if args.tools:

        tools = [
            t.strip().lower()
            for t in args.tools.split(",")
            if t.strip()
        ]

        invalid = [
            t
            for t in tools
            if t not in TOOL_MAP
        ]

        if invalid:

            print(
                f"[ERROR] Unknown tools: "
                f"{', '.join(invalid)}"
            )

            print(
                "  Valid: "
                f"{', '.join(TOOL_MAP.keys())}"
            )

            return 1

    else:

        tools = list(
            config.DEFAULT_TOOLS
        )

    # -------------------------------------------------------------------------
    # Skip testssl for HTTP
    # -------------------------------------------------------------------------

    if (
        url.lower().startswith("http://")
        and "testssl" in tools
    ):

        print(
            "\n  [!] Skipping testssl "
            "(target uses HTTP, not HTTPS)"
        )

        tools = [
            t
            for t in tools
            if t != "testssl"
        ]

    # -------------------------------------------------------------------------
    # Setup Output Directory
    # -------------------------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    output_dir = create_output_dir(
        url,
        timestamp
    )

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    setup_logging(
        args.verbose
    )

    logger = logging.getLogger(
        "assessor"
    )

    print(
        f"  Target  : {url}"
    )

    print(
        f"  Tools   : {', '.join(tools)}"
    )

    print(
        f"  Output  : {output_dir}"
    )

    print()

    # -------------------------------------------------------------------------
    # Tool Availability
    # -------------------------------------------------------------------------

    print(
        "  Checking tool availability..."
    )

    if not check_tools(tools):

        if not args.ignore_missing:

            print(
                "\n  [!] Some tools are missing."
            )

            print(
                "  Use --ignore-missing "
                "to proceed anyway."
            )

            return 1

    # -------------------------------------------------------------------------
    # Start Scan
    # -------------------------------------------------------------------------

    print(
        f"\n{'═' * 65}"
    )

    print(
        "  Starting scan at "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"{'═' * 65}"
    )

    scan_results = {}

    all_findings = []

    progress = Progress(
        len(tools)
    )

    # -------------------------------------------------------------------------
    # Run Each Scanner
    # -------------------------------------------------------------------------

    for tool_name in tools:

        module = TOOL_MAP[
            tool_name
        ]

        progress.start(
            tool_name
        )

        try:

            result = module.scan(
                url,
                output_dir
            )

            if not isinstance(
                result,
                dict
            ):
                result = {
                    "tool": tool_name,
                    "status": "error",
                    "error_reason":
                        "Scanner returned invalid result",
                    "findings": [],
                    "raw_output": "",
                }

            scan_results[
                tool_name
            ] = result

            findings = result.get(
                "findings",
                []
            )

            if not isinstance(
                findings,
                list
            ):
                findings = []

            findings = [
                normalize_finding(f)
                for f in findings
                if isinstance(f, dict)
            ]

            result["findings"] = findings

            status = result.get(
                "status",
                "unknown"
            )

            error_reason = result.get(
                "error_reason",
                ""
            )

            # -------------------------------------------------------------
            # Extract error reason from raw output
            # -------------------------------------------------------------

            if (
                status != "success"
                and not error_reason
            ):

                raw = result.get(
                    "raw_output",
                    ""
                )

                if raw.strip():

                    error_reason = (
                        raw.strip()
                        .splitlines()[-1][:120]
                    )

                else:

                    error_reason = status

            # -------------------------------------------------------------
            # Save Tool Log
            # -------------------------------------------------------------

            raw_output = result.get(
                "raw_output",
                ""
            )

            tool_log_path = os.path.join(
                output_dir,
                f"{tool_name}.log"
            )

            try:

                with open(
                    tool_log_path,
                    "w",
                    encoding="utf-8",
                    errors="replace"
                ) as f_log:

                    f_log.write(
                        str(raw_output)
                    )

            except Exception as log_err:

                logger.warning(
                    f"Failed to save log "
                    f"for {tool_name}: "
                    f"{log_err}"
                )

            # -------------------------------------------------------------
            # Add Findings
            # -------------------------------------------------------------

            all_findings.extend(
                findings
            )

            progress.done(
                tool_name,
                len(findings),
                status,
                error_reason
            )

            if status != "success":

                logger.error(
                    f"[{tool_name}] "
                    f"Scan failed: "
                    f"{error_reason}"
                )

        except Exception as e:

            error_reason = str(e)

            logger.error(
                f"[{tool_name}] "
                f"Unexpected error: "
                f"{error_reason}",
                exc_info=args.verbose
            )

            tool_log_path = os.path.join(
                output_dir,
                f"{tool_name}.log"
            )

            try:

                with open(
                    tool_log_path,
                    "w",
                    encoding="utf-8",
                    errors="replace"
                ) as f_log:

                    f_log.write(
                        "Unexpected error: "
                        f"{error_reason}"
                    )

            except Exception:
                pass

            scan_results[
                tool_name
            ] = {
                "tool": tool_name,
                "status": "error",
                "error_reason": error_reason,
                "findings": [],
                "raw_output": error_reason,
            }

            progress.done(
                tool_name,
                0,
                "error",
                error_reason
            )

    # =========================================================================
    # CVSS Scoring
    # =========================================================================

    print(
        f"\n{'═' * 65}"
    )

    print(
        "  Computing CVSS risk scores..."
    )

    scored_findings = score_all_findings(
        all_findings
    )

    risk_summary = calculate_overall_score(
        scored_findings
    )

    # -------------------------------------------------------------------------
    # Update Tool Results With Scored Findings
    # -------------------------------------------------------------------------

    for tool_name in tools:

        if tool_name not in scan_results:
            continue

        tool_findings = [
            finding
            for finding in scored_findings
            if finding.get("tool") == tool_name
        ]

        scan_results[
            tool_name
        ]["findings"] = tool_findings

    # =========================================================================
    # Print Summary
    # =========================================================================

    _print_scan_summary(
        url,
        risk_summary,
        scored_findings,
        tools
    )

    # =========================================================================
    # Generate Report
    # =========================================================================

    if not args.no_report:

        print(
            f"\n{'═' * 65}"
        )

        print(
            "  Generating reports..."
        )

        try:

            report_paths = generate_report(
                url=url,
                scan_results=scan_results,
                risk_summary=risk_summary,
                findings=scored_findings,
                output_dir=output_dir,
                timestamp=timestamp,
            )

            print(
                f"\n  [OK] PDF  Report : "
                f"{report_paths['pdf']}"
            )

            print(
                f"  [OK] TXT  Report : "
                f"{report_paths['txt']}"
            )

        except Exception as e:

            logger.error(
                f"Report generation failed: {e}",
                exc_info=args.verbose
            )

            print(
                f"  [ERROR] "
                f"Report generation failed: {e}"
            )

    # =========================================================================
    # Cleanup
    # =========================================================================

    print(
        f"\n{'═' * 65}"
    )

    print(
        "  Cleaning up temporary scan files..."
    )

    for handler in logging.root.handlers[:]:

        if isinstance(
            handler,
            logging.FileHandler
        ):

            handler.close()

            logging.root.removeHandler(
                handler
            )

    for item in os.listdir(
        output_dir
    ):

        item_path = os.path.join(
            output_dir,
            item
        )

        if not os.path.isfile(
            item_path
        ):
            continue

        ext = os.path.splitext(
            item
        )[1].lower()

        if ext not in (
            ".pdf",
            ".txt",
            ".log"
        ):

            try:

                os.remove(
                    item_path
                )

            except OSError:
                pass

    print(
        "  [OK] Scan completed and "
        "individual tool logs retained "
        "in output directory."
    )

    print(
        f"\n{'═' * 65}"
    )

    print(
        "  Scan complete! Output directory: "
        f"{output_dir}"
    )

    print(
        f"{'═' * 65}\n"
    )

    return 0


# =============================================================================
# Scan Summary
# =============================================================================

def _print_scan_summary(
    url,
    risk_summary,
    findings,
    tools
):
    """
    Print scan summary.

    IMPORTANT:
    risk_scorer.py returns severity information
    inside risk_summary["breakdown"], not ["counts"].
    """

    max_score = risk_summary.get(
        "max_score",
        0.0
    )

    max_sev = str(
        risk_summary.get(
            "max_severity",
            "INFO"
        )
    ).upper()

    total_risks = risk_summary.get(
        "total_risks",
        0
    )

    total = risk_summary.get(
        "total_findings",
        len(findings)
    )

    breakdown = risk_summary.get(
        "breakdown",
        {}
    )

    # -------------------------------------------------------------------------
    # Colors
    # -------------------------------------------------------------------------

    COLORS = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[31m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[34m",
        "INFO": "\033[37m",
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "CYAN": "\033[36m",
    }

    C = COLORS

    sev_color = C.get(
        max_sev,
        C["RESET"]
    )

    # -------------------------------------------------------------------------
    # Severity Counts
    # -------------------------------------------------------------------------

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]

    counts = {}

    for severity in severity_order:

        severity_data = breakdown.get(
            severity,
            {}
        )

        if isinstance(
            severity_data,
            dict
        ):

            counts[severity] = int(
                severity_data.get(
                    "count",
                    0
                )
            )

        else:

            counts[severity] = 0

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------

    print(
        f"\n{'═' * 65}"
    )

    print(
        f"  {C['BOLD']}"
        f"SCAN RESULTS SUMMARY"
        f"{C['RESET']}"
    )

    print(
        f"{'═' * 65}"
    )

    print(
        f"  Target        : "
        f"{C['CYAN']}"
        f"{url}"
        f"{C['RESET']}"
    )

    print(
        f"  Total Findings: "
        f"{C['BOLD']}"
        f"{total}"
        f"{C['RESET']} "
        f"(Including INFO)"
    )

    print(
        f"  Total Risks   : "
        f"{sev_color}"
        f"{C['BOLD']}"
        f"{total_risks}"
        f"{C['RESET']} "
        f"(Excluding INFO)"
    )

    print(
        f"  Max CVSS Score: "
        f"{sev_color}"
        f"{C['BOLD']}"
        f"{max_score:.1f} / 10"
        f"{C['RESET']} "
        f"[{get_risk_label(max_score)}]"
    )

    print()

    print(
        f"  {'Severity':<12}"
        f"{'Count':>6}  Bar"
    )

    print(
        f"  {'-' * 40}"
    )

    max_count = max(
        counts.values(),
        default=0
    )

    if max_count <= 0:
        max_count = 1

    for severity in severity_order:

        count = counts.get(
            severity,
            0
        )

        color = C.get(
            severity,
            C["RESET"]
        )

        if count > 0:

            bar_len = max(
                1,
                int(
                    (count / max_count) * 20
                )
            )

        else:

            bar_len = 0

        bar = "|" * bar_len

        print(
            f"  {color}"
            f"{severity:<12}"
            f"{C['RESET']} "
            f"{count:>6}  "
            f"{color}"
            f"{bar}"
            f"{C['RESET']}"
        )

    # -------------------------------------------------------------------------
    # Top Critical / High Findings
    # -------------------------------------------------------------------------

    high_findings = [
        finding
        for finding in findings
        if str(
            finding.get(
                "severity",
                "INFO"
            )
        ).upper()
        in (
            "CRITICAL",
            "HIGH"
        )
    ]

    if high_findings:

        print(
            f"\n  {C['BOLD']}"
            f"Top 5 Critical/High Findings:"
            f"{C['RESET']}"
        )

        for finding in high_findings[:5]:

            severity = str(
                finding.get(
                    "severity",
                    "INFO"
                )
            ).upper()

            try:

                score = float(
                    finding.get(
                        "cvss_base_score",
                        0.0
                    )
                )

            except (
                TypeError,
                ValueError
            ):

                score = 0.0

            title = str(
                finding.get(
                    "title",
                    "Unknown Finding"
                )
            )[:60]

            source = str(
                finding.get(
                    "cvss_source",
                    "N/A"
                )
            )

            version = str(
                finding.get(
                    "cvss_version",
                    "N/A"
                )
            )

            color = C.get(
                severity,
                C["RESET"]
            )

            print(
                f"  {color}"
                f"[{severity}]"
                f"{C['RESET']} "
                f"CVSS {score:.1f} - "
                f"{title}"
            )

            print(
                f"             "
                f"CVSS Source: {source} | "
                f"Version: {version}"
            )

    print()


# =============================================================================
# CLI Argument Parser
# =============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="assessor",
        description=(
            "Automated Security Misconfiguration "
            "Assessment and Auditing System\n"
            "Integrates: Nikto | Nuclei | Nmap | "
            "Gobuster | testssl | WhatWeb"
        ),
        formatter_class=(
            argparse.RawDescriptionHelpFormatter
        ),
        epilog="""
Examples:

  python3 main.py -u https://example.com

  python3 main.py -u http://testphp.vulnweb.com

  python3 main.py -u https://example.com --tools nmap,nikto,nuclei

  python3 main.py -u https://example.com -v --no-report

  python3 main.py -u https://example.com --list-tools
        """,
    )

    parser.add_argument(
        "-u",
        "--url",
        required=False,
        metavar="URL",
        help=(
            "Target URL to scan "
            "(e.g. https://example.com)"
        ),
    )

    parser.add_argument(
        "--tools",
        metavar="TOOLS",
        help=(
            "Comma-separated list of tools to run. "
            f"Default: all "
            f"({', '.join(config.DEFAULT_TOOLS)}). "
            "Options: whatweb, nmap, testssl, "
            "nikto, gobuster, nuclei"
        ),
    )

    parser.add_argument(
        "--no-report",
        action="store_true",
        help=(
            "Run scans but skip report generation"
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=(
            "Enable verbose/debug logging"
        ),
    )

    parser.add_argument(
        "--ignore-missing",
        action="store_true",
        help=(
            "Continue even if some tools "
            "are not found"
        ),
    )

    parser.add_argument(
        "--list-tools",
        action="store_true",
        help=(
            "List available tools and "
            "their paths, then exit"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"%(prog)s "
            f"{config.REPORT_VERSION}"
        ),
    )

    return parser


# =============================================================================
# Entry Point
# =============================================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    # -------------------------------------------------------------------------
    # List Tools
    # -------------------------------------------------------------------------

    if args.list_tools:

        print(BANNER)

        print(
            "  Available Tools:"
        )

        print(
            f"  {'Tool':<12}"
            f" {'Path':<40}"
            f" {'Available'}"
        )

        print(
            f"  {'-' * 60}"
        )

        for name, path in (
            config.TOOL_PATHS.items()
        ):

            available = (
                "✓"
                if is_tool_available(path)
                else "✗"
            )

            print(
                f"  {name:<12}"
                f" {path:<40}"
                f" {available}"
            )

        sys.exit(0)

    # -------------------------------------------------------------------------
    # URL Required
    # -------------------------------------------------------------------------

    if not args.url:

        parser.print_help()

        sys.exit(1)

    # -------------------------------------------------------------------------
    # Run Assessment
    # -------------------------------------------------------------------------

    sys.exit(
        run_assessment(args)
    )


if __name__ == "__main__":
    main()
