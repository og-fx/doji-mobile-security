#!/usr/bin/env python3
"""Connect verified iPhone backups to Doji's MVT investigation engine."""

import json
from pathlib import Path

from forensic_engine import RESULTS_DIR, run_investigation
from findings_engine import build_findings
from iphone_evidence_discovery import verify_iphone_backup_owner


def analyze_iphone_backup(backup_path, device_id,
                          progress_callback=None, timeout_seconds=600):
    """Analyze an existing backup belonging to the selected iPhone."""

    def progress(message):
        if progress_callback:
            progress_callback(message)

    backup_path = Path(backup_path).expanduser().resolve(strict=True)

    if not verify_iphone_backup_owner(backup_path, device_id):
        raise ValueError(
            "Backup ownership could not be verified for this iPhone."
        )

    progress("Starting MVT iPhone forensic analysis...")

    case_directories = []

    exit_code = run_investigation(
        "ios-backup",
        backup_path,
        timeout_seconds,
        case_callback=case_directories.append,
    )

    if len(case_directories) != 1:
        raise RuntimeError(
            "MVT did not provide exactly one investigation directory."
        )

    case_dir = case_directories[0]
    summary_path = case_dir / "run_summary.json"

    if not summary_path.is_file():
        raise RuntimeError("MVT investigation summary is missing.")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    result = {
        "case_id": summary.get("case_id"),
        "status": summary.get("status"),
        "evidence_integrity": summary.get("evidence_integrity"),
        "exit_code": exit_code,
        "case_directory": str(case_dir),
        "findings_generated": False,
        "ioc_match_count": None,
    }

    if (
        exit_code != 0
        or summary.get("status") != "COMPLETED"
        or summary.get("evidence_integrity") != "UNCHANGED"
    ):
        progress("MVT investigation did not complete successfully.")
        return result

    alerts_path = case_dir / "mvt-output" / "alerts.json"

    if not alerts_path.is_file():
        progress("MVT alert output is missing; findings not verified.")
        result["findings_status"] = "UNAVAILABLE"
        result["findings_error"] = (
            "MVT did not produce alerts.json. "
            "IOC matching results cannot be confirmed."
        )
        return result

    try:
        alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result["findings_status"] = "INVALID"
        result["findings_error"] = (
            f"Could not read MVT alerts: {type(exc).__name__}"
        )
        return result

    if not isinstance(alerts, list) or any(
        not isinstance(alert, dict) for alert in alerts
    ):
        result["findings_status"] = "INVALID"
        result["findings_error"] = (
            "MVT alerts must be a list of JSON objects."
        )
        return result


    progress("Classifying MVT forensic findings...")

    build_findings(case_dir)

    findings_path = case_dir / "doji_findings.json"

    if not findings_path.is_file():
        raise RuntimeError("Doji forensic findings report is missing.")

    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    counts = findings.get("classification_counts", {})

    result["findings_generated"] = True
    result["ioc_match_count"] = counts.get("IOC_MATCH", 0)
    result["findings_path"] = str(findings_path)

    progress("MVT forensic analysis and findings completed.")

    return result
