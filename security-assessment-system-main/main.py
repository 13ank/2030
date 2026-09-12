#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sys
import shutil

# Fix Windows console encoding for Unicode output (banner, symbols, etc.)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
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
from modules.risk_scorer import score_all_findings, calculate_overall_score, get_risk_label
from modules.report_generator import generate_report


# ─────────────────────────────────────────────────────────────────────────────
#  ASCII Banner
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
#  Tool map
# ─────────────────────────────────────────────────────────────────────────────
TOOL_MAP = {
    "whatweb":  whatweb_scanner,
    "nmap":     nmap_scanner,
    "testssl":  testssl_scanner,
    "nikto":    nikto_scanner,
    "gobuster": gobuster_scanner,
    "nuclei":   nuclei_scanner,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Setup & Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
def setup_logging(verbose: bool, log_file: str = None):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def validate_url(url: str) -> str:
    """Ensure URL has a valid scheme. Default to https if missing."""
    if not re.match(r"^https?://", url):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Invalid URL: {url}")
    return url


def is_tool_available(path: str) -> bool:
    """Check if a tool path exists and is executable or available in PATH."""
    return bool(path and (shutil.which(path) or (os.path.isfile(path) and os.access(path, os.X_OK))))


def check_tools(tool_names: list) -> bool:
    """Verify required tools are available."""
    ok = True
    for name in tool_names:
        path = config.TOOL_PATHS.get(name)
        if not is_tool_available(path):
            print(f"  [MISSING] {name} ({path})")
            ok = False
        else:
            print(f"  [FOUND]   {name}: {path}")
    return ok


def get_next_scan_number(report_dir: str) -> int:
    """Find the next scan run number based on existing scan directories."""
    if not os.path.exists(report_dir):
        return 1
    
    max_num = 0
    dirs_count = 0
    for name in os.listdir(report_dir):
        full_path = os.path.join(report_dir, name)
        if os.path.isdir(full_path) and not name.startswith("."):
            dirs_count += 1
            match = re.match(r"^\((\d+)\)", name)
            if match:
                max_num = max(max_num, int(match.group(1)))
    
    if max_num > 0:
        return max_num + 1
    return dirs_count + 1


def create_output_dir(url: str, timestamp: str) -> str:
    """Create a clear, human-readable unique output directory for this scan with sequential number prefix."""
    scan_num   = get_next_scan_number(config.REPORT_DIR)
    parsed     = urlparse(url)
    host       = parsed.hostname or "target"
    host_clean = re.sub(r"[^\w.-]", "_", host)
    port_str   = f"_port{parsed.port}" if parsed.port else ""
    dir_name   = f"({scan_num})report_{host_clean}{port_str}_{timestamp}"
    out_dir    = os.path.join(config.REPORT_DIR, dir_name)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


# ─────────────────────────────────────────────────────────────────────────────
#  Progress Printer
# ─────────────────────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int):
        self.total   = total
        self.current = 0

    def start(self, tool_name: str):
        self.current += 1
        filled = "#" * self.current
        empty  = "-" * (self.total - self.current)
        print(f"\n  [{self.current}/{self.total}] >> Running {tool_name.upper()}")
        print(f"  [{filled}{empty}]")
        sys.stdout.flush()

    def done(self, tool_name: str, finding_count: int, status: str,
             error_reason: str = ""):
        if status == "success":
            icon = "[OK] "
            detail = f"{finding_count} finding(s)"
        else:
            icon = "[ERROR]"
            detail = error_reason or status
        print(f"  {icon} {tool_name.upper()} -- {detail}")
        if status != "success" and error_reason:
            # Indent error reason for readability
            for line in error_reason.splitlines()[:3]:
                print(f"           {line.strip()}")
        sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
#  Main Scan Orchestrator
# ─────────────────────────────────────────────────────────────────────────────
def run_assessment(args) -> int:
    """Main scan workflow. Returns exit code."""
    print(BANNER)

    # ── Validate URL ─────────────────────────────────────────────────────────
    try:
        url = validate_url(args.url)
    except ValueError as e:
        print(f"\n[ERROR] {e}")
        return 1

    # ── Determine tools ───────────────────────────────────────────────────────
    if args.tools:
        tools = [t.strip().lower() for t in args.tools.split(",") if t.strip()]
        invalid = [t for t in tools if t not in TOOL_MAP]
        if invalid:
            print(f"[ERROR] Unknown tools: {', '.join(invalid)}")
            print(f"  Valid: {', '.join(TOOL_MAP.keys())}")
            return 1
    else:
        tools = config.DEFAULT_TOOLS

    # ── Skip SSL checks for http:// targets ──────────────────────────────────
    if url.startswith("http://") and "testssl" in tools:
        print("\n  [!] Skipping testssl (target uses HTTP, not HTTPS)")
        tools = [t for t in tools if t != "testssl"]

    # ── Setup logging ────────────────────────────────────────────────────────
    timestamp  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = create_output_dir(url, timestamp)
    setup_logging(args.verbose)
    logger = logging.getLogger("assessor")

    print(f"  Target  : {url}")
    print(f"  Tools   : {', '.join(tools)}")
    print(f"  Output  : {output_dir}")
    print()

    # ── Tool availability check ───────────────────────────────────────────────
    print("  Checking tool availability...")
    if not check_tools(tools):
        if not args.ignore_missing:
            print("\n  [!] Some tools are missing. Use --ignore-missing to proceed anyway.")
            return 1

    # ── Run scans ─────────────────────────────────────────────────────────────
    print(f"\n{'═'*65}")
    print(f"  Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*65}")

    scan_results = {}
    all_findings = []
    progress = Progress(len(tools))

    for tool_name in tools:
        module = TOOL_MAP[tool_name]
        progress.start(tool_name)

        try:
            result = module.scan(url, output_dir)
            scan_results[tool_name] = result
            findings     = result.get("findings", [])
            status       = result.get("status", "unknown")
            error_reason = result.get("error_reason", "")

            # Extract error reason from raw_output if not explicitly set
            if status != "success" and not error_reason:
                raw = result.get("raw_output", "")
                error_reason = raw.strip().splitlines()[-1][:120] if raw.strip() else status

            # Save individual tool log file directly in report output directory
            raw_output = result.get("raw_output", "")
            tool_log_path = os.path.join(output_dir, f"{tool_name}.log")
            try:
                with open(tool_log_path, "w", encoding="utf-8", errors="replace") as f_log:
                    f_log.write(raw_output)
            except Exception as log_err:
                logger.warning(f"Failed to save log for {tool_name}: {log_err}")

            all_findings.extend(findings)
            progress.done(tool_name, len(findings), status, error_reason)

            if status != "success":
                logger.error(
                    f"[{tool_name}] Scan failed: {error_reason}"
                )

        except Exception as e:
            error_reason = str(e)
            logger.error(
                f"[{tool_name}] Unexpected error: {error_reason}",
                exc_info=args.verbose
            )
            tool_log_path = os.path.join(output_dir, f"{tool_name}.log")
            try:
                with open(tool_log_path, "w", encoding="utf-8", errors="replace") as f_log:
                    f_log.write(f"Unexpected error: {error_reason}")
            except Exception:
                pass
            scan_results[tool_name] = {
                "tool":         tool_name,
                "status":       "error",
                "error_reason": error_reason,
                "findings":     [],
                "raw_output":   error_reason,
            }
            progress.done(tool_name, 0, "error", error_reason)

    # ── CVSS Scoring ──────────────────────────────────────────────────────────
    print(f"\n{'═'*65}")
    print("  Computing CVSS risk scores...")
    scored_findings = score_all_findings(all_findings)
    risk_summary    = calculate_overall_score(scored_findings)

    # Update scan_results findings with scored findings
    for tool_name in tools:
        if tool_name in scan_results:
            tool_data = scan_results[tool_name]
            tool_findings = [f for f in scored_findings if f.get("tool") == tool_name]
            tool_data["findings"] = tool_findings

    # ── Print interim summary ─────────────────────────────────────────────────
    _print_scan_summary(url, risk_summary, scored_findings, tools)

    # ── Generate reports ──────────────────────────────────────────────────────
    if not args.no_report:
        print(f"\n{'═'*65}")
        print("  Generating reports...")
        try:
            report_paths = generate_report(
                url=url,
                scan_results=scan_results,
                risk_summary=risk_summary,
                findings=scored_findings,
                output_dir=output_dir,
                timestamp=timestamp,
            )
            print(f"\n  [OK] PDF  Report : {report_paths['pdf']}")
            print(f"  [OK] TXT  Report : {report_paths['txt']}")
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=args.verbose)
            print(f"  [ERROR] Report generation failed: {e}")

    # ── Cleanup temporary files ───────────────────────────────────────────────
    print(f"\n{'═'*65}")
    print("  Cleaning up temporary scan files...")
    for handler in logging.root.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.close()
            logging.root.removeHandler(handler)
        
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isfile(item_path):
            ext = os.path.splitext(item)[1].lower()
            if ext not in (".pdf", ".txt", ".log"):
                try:
                    os.remove(item_path)
                except OSError:
                    pass

    print("  [OK] Scan completed and individual tool logs retained in output directory.")

                
    print(f"\n{'═'*65}")
    print(f"  Scan complete! Output directory: {output_dir}")
    print(f"{'═'*65}\n")
    return 0


def _print_scan_summary(url, risk_summary, findings, tools):
    """Print a coloured terminal summary."""
    max_score    = risk_summary.get("max_score", 0.0)
    max_sev      = risk_summary.get("max_severity", "INFO")
    total_risks  = risk_summary.get("total_risks", 0)
    counts       = risk_summary.get("counts", {})
    total        = sum(counts.values())

    # ANSI colour codes
    COLORS = {
        "CRITICAL": "\033[91m",  # bright red
        "HIGH":     "\033[31m",  # red
        "MEDIUM":   "\033[33m",  # yellow
        "LOW":      "\033[34m",  # blue
        "INFO":     "\033[37m",  # grey
        "RESET":    "\033[0m",
        "BOLD":     "\033[1m",
        "GREEN":    "\033[32m",
        "CYAN":     "\033[36m",
    }

    C = COLORS
    sev_color = C.get(max_sev, C["RESET"])

    print(f"\n{'═'*65}")
    print(f"  {C['BOLD']}SCAN RESULTS SUMMARY{C['RESET']}")
    print(f"{'═'*65}")
    print(f"  Target        : {C['CYAN']}{url}{C['RESET']}")
    print(f"  Total Findings: {C['BOLD']}{total}{C['RESET']} (Including INFO)")
    print(f"  Total Risks   : {sev_color}{C['BOLD']}{total_risks}{C['RESET']} (Excluding INFO)")
    print(f"  Max CVSS Score: {sev_color}{C['BOLD']}{max_score:.1f} / 10  "
          f"[{get_risk_label(max_score)}]{C['RESET']}")
    print()
    print(f"  {'Severity':<12} {'Count':>6}  {'Bar'}")
    print(f"  {'-'*40}")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    max_count = max((counts.get(s, 0) for s in severity_order), default=1) or 1

    for sev in severity_order:
        count   = counts.get(sev, 0)
        color   = C.get(sev, C["RESET"])
        bar_len = int((count / max_count) * 20) if count > 0 else 0
        bar     = "|" * bar_len
        print(f"  {color}{sev:<12}{C['RESET']} {count:>6}  {color}{bar}{C['RESET']}")

    if findings:
        high_findings = [f for f in findings
                         if f.get("severity", "INFO") in ("CRITICAL", "HIGH")]
        if high_findings:
            print(f"\n  {C['BOLD']}Top 5 Critical/High Findings:{C['RESET']}")
            for f in high_findings[:5]:
                sev   = f.get("severity", "INFO")
                score = f.get("cvss_base_score", 0.0)
                color = C.get(sev, C["RESET"])
                title = f.get("title", "")[:60]
                print(f"  {color}[{sev}]{C['RESET']} CVSS {score:.1f} - {title}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI Argument Parser
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assessor",
        description=(
            "Automated Security Misconfiguration Assessment and Auditing System\n"
            "Integrates: Nikto | Nuclei | Nmap | Gobuster | testssl | WhatWeb"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        "-u", "--url",
        required=False,
        metavar="URL",
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--tools",
        metavar="TOOLS",
        help=(
            "Comma-separated list of tools to run. "
            f"Default: all ({', '.join(config.DEFAULT_TOOLS)}). "
            "Options: whatweb, nmap, testssl, nikto, gobuster, nuclei"
        ),
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Run scans but skip report generation",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--ignore-missing",
        action="store_true",
        help="Continue even if some tools are not found",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools and their paths, then exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {config.REPORT_VERSION}",
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_tools:
        print(BANNER)
        print("  Available Tools:")
        print(f"  {'Tool':<12} {'Path':<40} {'Available'}")
        print(f"  {'-'*60}")
        for name, path in config.TOOL_PATHS.items():
            avail = "✓" if is_tool_available(path) else "✗"
            print(f"  {name:<12} {path:<40} {avail}")
        sys.exit(0)

    if not args.url:
        parser.print_help()
        sys.exit(1)

    sys.exit(run_assessment(args))


if __name__ == "__main__":
    main()
