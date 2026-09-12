"""
modules/risk_scorer.py — CVSS-based Risk Scoring Engine

Calculates CVSS base scores for findings and produces
an overall risk summary.

Important:
- Uses CVSS score supplied by a scanner when available.
- Uses CVSS v3 vector when available.
- Does NOT assign an artificially high CVSS score to findings
  just because their severity label is high.
- Scanner severity is preserved when no real CVSS score exists.
"""

import logging
from typing import Dict, Any, List, Optional

try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False


logger = logging.getLogger("assessor.risk_scorer")


# ---------------------------------------------------------
# Fallback scores
# ---------------------------------------------------------
#
# These are conservative representative scores used only
# when a finding has no actual CVSS score/vector.
#
# They should NOT be interpreted as official CVSS scores.
#

FALLBACK_SCORES = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
    "INFO": 0.0,
}


# ---------------------------------------------------------
# Severity order
# ---------------------------------------------------------

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ---------------------------------------------------------
# Score a single finding
# ---------------------------------------------------------

def score_finding(finding: Dict) -> Dict:
    """
    Calculate a CVSS base score for one finding.

    Priority:

    1. Explicit CVSS score supplied by the scanner.
    2. CVSS v3 vector supplied by the scanner.
    3. Conservative fallback based on scanner severity.

    The original scanner severity is preserved in:
        original_severity

    The calculated severity is stored in:
        cvss_severity

    If a real CVSS score/vector exists, severity is synchronized
    with the calculated CVSS severity.

    If no real CVSS information exists, the original scanner
    severity is preserved.
    """

    finding = dict(finding)

    # -----------------------------------------------------
    # Original severity
    # -----------------------------------------------------

    original_severity = str(
        finding.get("severity", "INFO")
    ).upper()

    if original_severity not in SEVERITY_ORDER:
        original_severity = "INFO"

    finding["original_severity"] = original_severity

    # -----------------------------------------------------
    # Get CVSS information
    # -----------------------------------------------------

    vector = finding.get(
        "cvss_vector",
        ""
    )

    if vector is None:
        vector = ""

    vector = str(vector).strip()

    explicit_score = finding.get(
        "cvss_score",
        None
    )

    base_score: Optional[float] = None

    score_source = "fallback"

    # -----------------------------------------------------
    # Priority 1:
    # Explicit CVSS score from scanner
    # -----------------------------------------------------

    if explicit_score is not None:

        try:

            parsed_score = float(
                explicit_score
            )

            if 0.0 <= parsed_score <= 10.0:

                base_score = parsed_score
                score_source = "scanner"

        except (
            ValueError,
            TypeError
        ):

            logger.debug(
                f"Invalid CVSS score: {explicit_score}"
            )

    # -----------------------------------------------------
    # Priority 2:
    # Calculate from CVSS v3 vector
    # -----------------------------------------------------

    if (
        base_score is None
        and CVSS_AVAILABLE
        and vector
        and vector.upper().startswith("CVSS:3")
    ):

        try:

            cvss = CVSS3(vector)

            base_score = float(
                cvss.base_score
            )

            score_source = "vector"

        except Exception as exc:

            logger.debug(
                f"CVSS vector parse error "
                f"'{vector}': {exc}"
            )

    # -----------------------------------------------------
    # Priority 3:
    # Conservative fallback
    # -----------------------------------------------------

    if base_score is None:

        base_score = FALLBACK_SCORES.get(
            original_severity,
            0.0
        )

        score_source = "fallback"

    # -----------------------------------------------------
    # Calculate CVSS severity
    # -----------------------------------------------------

    cvss_severity = _score_to_severity(
        base_score
    )

    # -----------------------------------------------------
    # IMPORTANT:
    #
    # If there is no real CVSS information,
    # preserve the scanner severity instead of changing it
    # based on our fallback score.
    # -----------------------------------------------------

    if score_source == "fallback":

        final_severity = original_severity

    else:

        final_severity = cvss_severity

    # -----------------------------------------------------
    # Store results
    # -----------------------------------------------------

    finding["cvss_base_score"] = round(
        base_score,
        1
    )

    finding["cvss_severity"] = cvss_severity

    finding["severity"] = final_severity

    finding["cvss_source"] = score_source

    return finding


# ---------------------------------------------------------
# Score all findings
# ---------------------------------------------------------

def score_all_findings(
    findings: List[Dict]
) -> List[Dict]:
    """
    Score all findings and sort them from highest
    severity/risk to lowest.
    """

    if not findings:
        return []

    scored = [
        score_finding(finding)
        for finding in findings
    ]

    scored.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(
                str(
                    finding.get(
                        "severity",
                        "INFO"
                    )
                ).upper(),
                4
            ),

            -float(
                finding.get(
                    "cvss_base_score",
                    0.0
                )
            ),
        )
    )

    return scored


# ---------------------------------------------------------
# Calculate overall score
# ---------------------------------------------------------

def calculate_overall_score(
    findings: List[Dict]
) -> Dict[str, Any]:
    """
    Calculate an overall summary of findings.

    Returns:

        max_score
            Highest CVSS score.

        max_severity
            Severity corresponding to max_score.

        total_risks
            Number of non-INFO findings.

        counts
            Number of findings for each severity.

        breakdown
            Count, maximum and average score for each severity.
    """

    severity_keys = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]

    # -----------------------------------------------------
    # Empty result
    # -----------------------------------------------------

    if not findings:

        return {
            "max_score": 0.0,
            "max_severity": "INFO",
            "total_risks": 0,
            "counts": {
                severity: 0
                for severity in severity_keys
            },
            "breakdown": {},
        }

    # -----------------------------------------------------
    # Initialize counters
    # -----------------------------------------------------

    counts = {
        severity: 0
        for severity in severity_keys
    }

    scores_by_severity = {
        severity: []
        for severity in severity_keys
    }

    # -----------------------------------------------------
    # Process findings
    # -----------------------------------------------------

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                "INFO"
            )
        ).upper()

        if severity not in counts:
            severity = "INFO"

        # Get calculated score.
        raw_score = finding.get(
            "cvss_base_score",
            None
        )

        try:

            if raw_score is None:

                score = FALLBACK_SCORES.get(
                    severity,
                    0.0
                )

            else:

                score = float(
                    raw_score
                )

        except (
            ValueError,
            TypeError
        ):

            score = FALLBACK_SCORES.get(
                severity,
                0.0
            )

        # Keep score inside CVSS range.
        score = max(
            0.0,
            min(
                10.0,
                score
            )
        )

        counts[severity] += 1
        scores_by_severity[severity].append(
            score
        )

    # -----------------------------------------------------
    # Highest score
    # -----------------------------------------------------

    all_scores = [
        score
        for scores in scores_by_severity.values()
        for score in scores
        if score > 0.0
    ]

    if all_scores:

        max_score = max(
            all_scores
        )

    else:

        max_score = 0.0

    # -----------------------------------------------------
    # Overall severity
    # -----------------------------------------------------

    max_severity = _score_to_severity(
        max_score
    )

    # -----------------------------------------------------
    # Number of actual risks
    # -----------------------------------------------------

    total_risks = sum(
        counts[severity]
        for severity in severity_keys
        if severity != "INFO"
    )

    # -----------------------------------------------------
    # Breakdown
    # -----------------------------------------------------

    breakdown = {}

    for severity in severity_keys:

        scores = scores_by_severity[
            severity
        ]

        if not scores:
            continue

        breakdown[severity] = {
            "count": len(scores),

            "max": round(
                max(scores),
                1
            ),

            "avg": round(
                sum(scores) / len(scores),
                1
            ),
        }

    # -----------------------------------------------------
    # Return summary
    # -----------------------------------------------------

    return {
        "max_score": round(
            max_score,
            1
        ),

        "max_severity": max_severity,

        "total_risks": total_risks,

        "counts": counts,

        "breakdown": breakdown,
    }


# ---------------------------------------------------------
# Convert CVSS score to severity
# ---------------------------------------------------------

def _score_to_severity(
    score: float
) -> str:
    """
    Convert CVSS v3 base score to severity.

    CVSS v3 ranges:

        9.0 - 10.0  CRITICAL
        7.0 - 8.9   HIGH
        4.0 - 6.9   MEDIUM
        0.1 - 3.9   LOW
        0.0         INFO
    """

    try:
        score = float(score)

    except (
        ValueError,
        TypeError
    ):
        return "INFO"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0.0:
        return "LOW"

    return "INFO"


# ---------------------------------------------------------
# Human-readable risk label
# ---------------------------------------------------------

def get_risk_label(
    score: float
) -> str:
    """
    Convert an overall score into a human-readable
    risk label.
    """

    try:
        score = float(score)

    except (
        ValueError,
        TypeError
    ):
        return "INFORMATIONAL"

    if score >= 9.0:
        return "CRITICAL RISK"

    if score >= 7.0:
        return "HIGH RISK"

    if score >= 4.0:
        return "MEDIUM RISK"

    if score > 0.0:
        return "LOW RISK"

    return "INFORMATIONAL"
