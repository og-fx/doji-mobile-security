"""Prepare saved forensic results for Doji's professional viewer."""

import json
from pathlib import Path


def prepare_forensic_report(metadata_path):
    metadata_path = Path(metadata_path)
    case_dir = metadata_path.parent

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    findings_path = case_dir / "doji_findings.json"

    findings_data = (
        json.loads(findings_path.read_text(encoding="utf-8"))
        if findings_path.is_file()
        else {}
    )

    if not isinstance(metadata, dict):
        raise ValueError("Invalid forensic metadata.")

    if not isinstance(findings_data, dict):
        raise ValueError("Invalid forensic findings.")

    findings = findings_data.get("findings") or []
    correlated = findings_data.get("correlated_findings") or []
    limitations = findings_data.get("limitations") or []

    if not isinstance(findings, list):
        raise ValueError("Invalid forensic findings list.")

    if not isinstance(correlated, list):
        raise ValueError("Invalid correlated findings list.")

    if not isinstance(limitations, list):
        raise ValueError("Invalid forensic limitations list.")

    return {
        "report_type": "android_forensic",
        "report_title": "Doji Android Advanced Forensic Report",
        "assessment_id": metadata.get("case_id"),
        "forensic_metadata": metadata,
        "findings": findings,
        "correlated_findings": correlated,
        "limitations": limitations,
        "target": {
            "platform": metadata.get("platform") or "Android",
        },
    }


def save_forensic_assessment(metadata_path):
    """Save a forensic investigation in Doji's standard JSON format."""
    from assessment import save_report

    report = prepare_forensic_report(metadata_path)
    metadata = report["forensic_metadata"]

    report["tool"] = "Doji Mobile Security Assessment"
    report["report_title"] = "Doji Android Advanced Forensic Report"
    report["created_utc"] = metadata.get("created_utc")
    report["schema_version"] = "1.0"

    findings = report["findings"]

    severity_counts = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = str(finding.get("severity") or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    report["summary"] = {
        "findings_total": len(findings),
        "severity_counts": severity_counts,
    }

    report["scan_status"] = metadata.get("status") or "UNKNOWN"
    report["assessment_coverage_status"] = (
        "COMPLETED"
        if metadata.get("status") == "COMPLETED"
        else "INCOMPLETE"
    )

    report["disclaimer"] = (
        "Forensic findings are evidence-based observations. "
        "A completed investigation does not guarantee "
        "that a device is free from malware or spyware."
    )

    return save_report(report)


def save_forensic_assessment(metadata_path):
    """Save a forensic investigation in Doji's standard JSON format."""
    from assessment import save_report

    report = prepare_forensic_report(metadata_path)
    metadata = report["forensic_metadata"]

    report["tool"] = "Doji Mobile Security Assessment"
    report["report_title"] = "Doji Android Advanced Forensic Report"
    report["created_utc"] = metadata.get("created_utc")
    report["schema_version"] = "1.0"

    findings = report["findings"]

    severity_counts = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = str(finding.get("severity") or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    report["summary"] = {
        "findings_total": len(findings),
        "severity_counts": severity_counts,
    }

    report["scan_status"] = metadata.get("status") or "UNKNOWN"
    report["assessment_coverage_status"] = (
        "COMPLETED"
        if metadata.get("status") == "COMPLETED"
        else "INCOMPLETE"
    )

    report["disclaimer"] = (
        "Forensic findings are evidence-based observations. "
        "A completed investigation does not guarantee "
        "that a device is free from malware or spyware."
    )

    return save_report(report)
