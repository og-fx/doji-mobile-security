
from datetime import datetime, timezone
from pathlib import Path
import json


REPORT_DIR = Path(__file__).resolve().parent / "reports"

STATUSES = {"PASS", "FAIL", "WARNING", "NOT_RUN"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}


def utc_now():
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def new_assessment(target_name, platform, device_id=""):
    """Create a structured Doji assessment report."""
    now = datetime.now(timezone.utc)

    return {
        "tool": "Doji Mobile Security Assessment",
        "tool_version": "0.2.0",
        "report_title": "Doji Mobile Security Assessment Report",
        "schema_version": "1.0",
        "assessment_id": now.strftime("DOJI-%Y%m%dT%H%M%S%fZ"),
        "created_utc": now.isoformat(),
        "target": {
            "name": target_name,
            "platform": platform,
            "device_id": device_id,
        },
        "summary": {
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "not_run": 0,
            "findings_total": 0,
            "severity_counts": {
                severity: 0 for severity in SEVERITIES
            },
        },
        "findings": [],
        "limitations": [
            "This report contains only checks that Doji actually attempted.",
            "A passing check does not prove that a device is uncompromised.",
            "Results depend on device permissions, Android version, and available diagnostic data.",
        ],
        "disclaimer": (
            "Defensive security assessment only. "
            "This tool does not conclusively determine whether a device "
            "is compromised or malware-free."
        ),
    }


def add_finding(
    report,
    check_name,
    status,
    details,
    severity=None,
    confidence="MEDIUM",
    evidence=None,
    remediation=None,
    limitations=None,
):
    """Record a check with evidence and actionable guidance."""
    status = str(status).upper()
    confidence = str(confidence).upper()

    if status not in STATUSES:
        raise ValueError(
            f"Status must be one of: {', '.join(sorted(STATUSES))}"
        )

    if severity is None:
        severity = {
            "PASS": "INFO",
            "FAIL": "MEDIUM",
            "WARNING": "LOW",
            "NOT_RUN": "INFO",
        }[status]

    severity = str(severity).upper()

    if severity not in SEVERITIES:
        raise ValueError(
            f"Severity must be one of: {', '.join(sorted(SEVERITIES))}"
        )

    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(
            "Confidence must be HIGH, MEDIUM, or LOW."
        )

    finding = {
        "finding_id": f"DOJI-F{len(report['findings']) + 1:03d}",
        "check": check_name,
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "details": str(details),
        "evidence": evidence if evidence is not None else str(details),
        "remediation": remediation or (
            "Review this result and consult the device manufacturer's "
            "security guidance where appropriate."
            if status in {"FAIL", "WARNING"}
            else "No action indicated by this check."
            if status == "PASS"
            else "Repeat this check when the required diagnostic data "
                 "or device access is available."
        ),
        "timestamp_utc": utc_now(),
    }

    if limitations:
        finding["limitations"] = (
            limitations if isinstance(limitations, list)
            else [str(limitations)]
        )
    else:
        finding["limitations"] = []

    report.setdefault("findings", []).append(finding)

    summary = report.setdefault("summary", {})
    status_key = {
        "PASS": "passed",
        "FAIL": "failed",
        "WARNING": "warnings",
        "NOT_RUN": "not_run",
    }[status]

    summary[status_key] = summary.get(status_key, 0) + 1
    summary["findings_total"] = len(report["findings"])

    severity_counts = summary.setdefault(
        "severity_counts",
        {item: 0 for item in SEVERITIES},
    )
    severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return finding


def save_report(report):
    """Save a structured JSON report with a Doji filename."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    assessment_id = report.get("assessment_id")
    if not assessment_id or not str(assessment_id).startswith("DOJI-"):
        raise ValueError("Report must have a valid DOJI assessment ID.")

    report_types = {
        "android_information": "Android-Information-Check",
        "android_permissions": "Android-Permission-Check",
        "android_device_malware": "Android-Device-Malware-Scan",
        "iphone_information": "iPhone-Information-Check",
    }

    report_type = report.get("report_type")
    label = report_types.get(report_type)

    filename = (
        f"DOJI-{label}-{str(assessment_id).removeprefix('DOJI-')}.json"
        if label else f"{assessment_id}.json"
    )

    path = REPORT_DIR / filename
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return path
