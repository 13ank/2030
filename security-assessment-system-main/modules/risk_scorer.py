"""
modules/risk_scorer.py — CVSS-based Risk Scoring Engine

ใช้ CVSS สำหรับประเมินระดับความเสี่ยงของ Finding
รองรับ:
1. CVSS Score ที่ Scanner ส่งมาโดยตรง
2. CVSS Vector ที่ Scanner ส่งมาแล้วนำมาคำนวณ
3. Fallback Score กรณีไม่มีข้อมูล CVSS

หมายเหตุ:
Fallback Score ไม่ใช่คะแนน CVSS จริง
"""

import logging
from typing import Dict, Any, List

try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False


logger = logging.getLogger("assessor.risk_scorer")


# ============================================================
# Fallback Score
# ============================================================
# ใช้เฉพาะกรณีที่ไม่มี CVSS Score และไม่มี CVSS Vector
# ค่าเหล่านี้ไม่ใช่คะแนน CVSS ที่คำนวณจริง
FALLBACK_SCORES = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
    "INFO": 0.0,
}


# ============================================================
# CVSS Severity Range
# ============================================================

def _score_to_severity(score: float) -> str:
    """
    แปลง CVSS Base Score เป็นระดับความรุนแรง
    """

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0.0:
        return "LOW"

    return "INFO"


# ============================================================
# Validate Score
# ============================================================

def _valid_score(value: Any) -> bool:
    """
    ตรวจสอบว่าเป็น CVSS Score ที่อยู่ในช่วง 0-10 หรือไม่
    """

    try:
        score = float(value)
        return 0.0 <= score <= 10.0
    except (TypeError, ValueError):
        return False


# ============================================================
# Score Single Finding
# ============================================================

def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    คำนวณ CVSS สำหรับ Finding หนึ่งรายการ

    ลำดับการเลือกคะแนน:

    1. ใช้ cvss_score จาก Scanner ถ้ามี
    2. ใช้ cvss_vector แล้วคำนวณ CVSS3 ถ้ามี
    3. ใช้ Fallback Score ตาม severity ถ้าไม่มีข้อมูล CVSS

    คืนค่า Finding พร้อมข้อมูล:
    - cvss_base_score
    - cvss_severity
    - severity
    - cvss_source
    - cvss_version
    """

    result = dict(finding)

    original_severity = str(
        finding.get("severity", "INFO")
    ).upper()

    result["original_severity"] = original_severity

    score = None
    source = "fallback"
    version = "N/A"

    # --------------------------------------------------------
    # 1. Scanner-provided CVSS Score
    # --------------------------------------------------------

    scanner_score = finding.get("cvss_score")

    if _valid_score(scanner_score):
        score = float(scanner_score)
        source = "scanner"
        version = _detect_cvss_version(
            finding.get("cvss_vector", "")
        )

    # --------------------------------------------------------
    # 2. CVSS Vector
    # --------------------------------------------------------

    if score is None:
        vector = str(
            finding.get("cvss_vector", "")
        ).strip()

        if vector.startswith("CVSS:3") and CVSS_AVAILABLE:

            try:
                cvss = CVSS3(vector)

                score = float(cvss.base_score)

                source = "vector"
                version = _detect_cvss_version(vector)

            except Exception as exc:
                logger.warning(
                    "[risk] Invalid CVSS vector '%s': %s",
                    vector,
                    exc
                )

    # --------------------------------------------------------
    # 3. Fallback
    # --------------------------------------------------------

    if score is None:

        score = FALLBACK_SCORES.get(
            original_severity,
            FALLBACK_SCORES["INFO"]
        )

        source = "fallback"
        version = "N/A"

    # --------------------------------------------------------
    # Final Severity
    # --------------------------------------------------------

    cvss_severity = _score_to_severity(score)

    if source == "fallback":
        # ถ้าเป็น fallback ให้รักษา severity เดิมจาก scanner
        final_severity = original_severity
    else:
        # ถ้ามี CVSS จริง ให้ severity อิงจาก CVSS
        final_severity = cvss_severity

    # --------------------------------------------------------
    # Store Results
    # --------------------------------------------------------

    result["cvss_base_score"] = round(score, 1)
    result["cvss_severity"] = cvss_severity
    result["severity"] = final_severity
    result["cvss_source"] = source
    result["cvss_version"] = version

    return result


# ============================================================
# Detect CVSS Version
# ============================================================

def _detect_cvss_version(vector: Any) -> str:
    """
    ตรวจสอบ Version จาก CVSS Vector
    """

    vector = str(vector or "").strip()

    if vector.startswith("CVSS:3.1"):
        return "3.1"

    if vector.startswith("CVSS:3.0"):
        return "3.0"

    if vector.startswith("CVSS:4.0"):
        return "4.0"

    return "Unknown"


# ============================================================
# Score All Findings
# ============================================================

def score_all_findings(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    คำนวณคะแนน CVSS ให้ Finding ทั้งหมด
    """

    scored = []

    for finding in findings:

        try:
            scored.append(
                score_finding(finding)
            )

        except Exception as exc:

            logger.exception(
                "[risk] Failed to score finding: %s",
                exc
            )

            fallback = dict(finding)

            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            fallback["original_severity"] = severity
            fallback["cvss_base_score"] = FALLBACK_SCORES.get(
                severity,
                0.0
            )
            fallback["cvss_severity"] = severity
            fallback["severity"] = severity
            fallback["cvss_source"] = "fallback"
            fallback["cvss_version"] = "N/A"

            scored.append(fallback)

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    scored.sort(
        key=lambda x: (
            severity_order.get(
                str(x.get("severity", "INFO")).upper(),
                0
            ),
            float(
                x.get("cvss_base_score", 0.0)
            ),
        ),
        reverse=True,
    )

    return scored


# ============================================================
# Overall Risk
# ============================================================

def calculate_overall_score(
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    คำนวณภาพรวมความเสี่ยงจาก CVSS

    Overall Risk ใช้คะแนน CVSS สูงสุด
    ไม่ใช่การนำคะแนนทั้งหมดมาบวกกัน
    """

    if not findings:

        return {
            "max_score": 0.0,
            "max_severity": "INFO",
            "total_findings": 0,
            "total_risks": 0,
            "breakdown": {
                "CRITICAL": {
                    "count": 0,
                    "max_score": 0.0,
                    "average_score": 0.0,
                },
                "HIGH": {
                    "count": 0,
                    "max_score": 0.0,
                    "average_score": 0.0,
                },
                "MEDIUM": {
                    "count": 0,
                    "max_score": 0.0,
                    "average_score": 0.0,
                },
                "LOW": {
                    "count": 0,
                    "max_score": 0.0,
                    "average_score": 0.0,
                },
                "INFO": {
                    "count": 0,
                    "max_score": 0.0,
                    "average_score": 0.0,
                },
            },
        }

    scores = []

    breakdown = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }

    # --------------------------------------------------------
    # Collect Scores
    # --------------------------------------------------------

    for finding in findings:

        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        score = finding.get(
            "cvss_base_score",
            0.0
        )

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0

        if severity not in breakdown:
            severity = "INFO"

        breakdown[severity].append(score)

        if score > 0:
            scores.append(score)

    # --------------------------------------------------------
    # Maximum Score
    # --------------------------------------------------------

    max_score = max(scores) if scores else 0.0

    max_severity = _score_to_severity(max_score)

    # --------------------------------------------------------
    # Breakdown
    # --------------------------------------------------------

    breakdown_result = {}

    for severity, values in breakdown.items():

        if values:

            breakdown_result[severity] = {
                "count": len(values),
                "max_score": round(
                    max(values),
                    1
                ),
                "average_score": round(
                    sum(values) / len(values),
                    1
                ),
            }

        else:

            breakdown_result[severity] = {
                "count": 0,
                "max_score": 0.0,
                "average_score": 0.0,
            }

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "max_score": round(max_score, 1),
        "max_severity": max_severity,
        "total_findings": len(findings),
        "total_risks": sum(
            1
            for finding in findings
            if str(
                finding.get("severity", "INFO")
            ).upper() != "INFO"
        ),
        "breakdown": breakdown_result,
    }


# ============================================================
# Risk Label
# ============================================================

def get_risk_label(score: float) -> str:
    """
    แปลงคะแนน CVSS เป็นข้อความสำหรับ Report
    """

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    severity = _score_to_severity(score)

    labels = {
        "CRITICAL": "CRITICAL RISK",
        "HIGH": "HIGH RISK",
        "MEDIUM": "MEDIUM RISK",
        "LOW": "LOW RISK",
        "INFO": "INFORMATIONAL",
    }

    return labels.get(
        severity,
        "INFORMATIONAL"
    )
