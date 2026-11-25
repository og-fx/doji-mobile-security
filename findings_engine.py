#!/usr/bin/env python3
"""Doji Advanced Mobile Forensics - Findings Engine."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_DIR / "forensic" / "results"
ENGINE_VERSION = "0.1.0"

# No historical activity is pre-confirmed.
USER_CONFIRMED_UNINSTALLS = set()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def validate_case(case_path):
    if case_path.is_symlink():
        raise ValueError("Case directory cannot be a symbolic link.")

    case_path = case_path.resolve(strict=True)
    results_root = RESULTS_DIR.resolve(strict=True)

    if not case_path.is_relative_to(results_root):
        raise ValueError("Case must be inside forensic/results.")

    if not case_path.is_dir():
        raise ValueError("Case path is not a directory.")

    if case_path.name.startswith("DOJI-FORENSIC-") is False:
        raise ValueError("Invalid Doji case directory name.")

    metadata_path = case_path / "case_metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError("case_metadata.json was not found.")

    output_dir = case_path / "mvt-output"
    alerts_path = output_dir / "alerts.json"

    if not output_dir.is_dir() or not alerts_path.is_file():
        raise FileNotFoundError("MVT output or alerts.json was not found.")

    return case_path, metadata_path, alerts_path


def classify_alert(alert, index):
    event = alert.get("event") or {}
    module = str(alert.get("module") or "unknown")
    message = str(alert.get("message") or "")
    matched_indicator = alert.get("matched_indicator")

    package = (
        event.get("package")
        or event.get("package_name")
        or event.get("packageName")
    )

    permission = event.get("permission")

    # Some MVT AppOps alerts store the permission in the message.
    if not permission and "risky permission '" in message:
        permission = (
            message.split("risky permission '", 1)[1]
            .split("'", 1)[0]
        )
    elif not permission and "permission '" in message:
        permission = (
            message.split("permission '", 1)[1]
            .split("'", 1)[0]
        )
    event_time = alert.get("event_time")

    finding = {
        "finding_id": f"DOJI-F-{index:04d}",
        "source": "MVT",
        "source_module": module,
        "source_record": index,
        "original_mvt_level": alert.get("level"),
        "original_message": message,
        "event_time": event_time,
        "matched_indicator": matched_indicator,
        "package": package,
        "permission": permission,
        "raw_event": event,
    }

    # A real indicator match must be explicitly present.
    if matched_indicator:
        finding.update({
            "classification": "IOC_MATCH",
            "severity": "HIGH",
            "confidence": "HIGH",
            "title": "Threat indicator match",
            "explanation": (
                "The source analysis reported a matched indicator. "
                "Review the indicator and supporting evidence."
            ),
            "recommendation": (
                "Verify the indicator, affected artifact and surrounding "
                "evidence before drawing a conclusion."
            ),
        })
        return finding

    # User-confirmed uninstall activity.
    if (
        module == "dumpsys_battery_daily"
        and event.get("action") == "uninstall"
        and package in USER_CONFIRMED_UNINSTALLS
    ):
        finding.update({
            "classification": "USER_CONFIRMED_HISTORICAL_ACTIVITY",
            "severity": "INFORMATIONAL",
            "confidence": "HIGH",
            "user_confirmed": True,
            "confirmation_source": "user_confirmation_in_chat",
            "confirmation_date": None,
            "title": "User-confirmed application uninstall",
            "explanation": (
                "The user confirmed this application was intentionally "
                "uninstalled. This is historical "
                "activity, not a spyware detection."
            ),
            "recommendation": (
                "Retain the original evidence and confirmation in the "
                "investigation record."
            ),
        })
        return finding

    # Accessibility information gap.
    if module == "dumpsys_accessibility":
        finding.update({
            "classification": "INFORMATION_GAP",
            "severity": "LOW",
            "confidence": "HIGH",
            "title": "Accessibility service details unavailable",
            "explanation": (
                "The source record reports installed services but does "
                "not provide their component names. This does not prove "
                "that any service is malicious."
            ),
            "recommendation": (
                "Review enabled accessibility services on the device "
                "and obtain a more detailed acquisition if possible."
            ),
        })
        return finding

    # AppOps permission history.
    if module == "dumpsys_appops" and permission == "REQUEST_INSTALL_PACKAGES":
        finding.update({
            "classification": "HISTORICAL_PERMISSION_ACTIVITY",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "title": "Package installation permission activity",
            "explanation": (
                "The record contains an access or rejection event for "
                "the package installation permission. This does not "
                "prove that an APK was successfully installed."
            ),
            "recommendation": (
                "Review the application's installation source and "
                "installation history if available."
            ),
        })
        return finding

    # Android shell permission discrepancy.
    if module == "dumpsys_appops" and package == "com.android.shell":
        finding.update({
            "classification": "CONFIGURATION_DISCREPANCY",
            "severity": "INFORMATIONAL",
            "confidence": "MEDIUM",
            "title": "Android shell AppOps record requires review",
            "explanation": (
                "The source message reports an unknown permission state, "
                "while the event contains an allow mode. These fields "
                "should not be treated as equivalent."
            ),
            "recommendation": (
                "Compare the original AppOps record with a fresh device "
                "state before interpreting this permission."
            ),
        })
        return finding

    # Preserve alerts that do not match a specific rule.
    finding.update({
        "classification": "UNCLASSIFIED_OBSERVATION",
        "severity": "REVIEW",
        "confidence": "LOW",
        "title": "Observation requires manual review",
        "explanation": (
            "The source generated an alert, but Doji has not assigned "
            "a more specific interpretation."
        ),
        "recommendation": "Review the original source record.",
    })

    return finding

def correlate_findings(findings):
    """Group repeated permission observations without deleting findings."""

    groups = {}

    for finding in findings:
        if finding.get("classification") != "HISTORICAL_PERMISSION_ACTIVITY":
            continue

        package = finding.get("package")
        permission = finding.get("permission")

        if not package or not permission:
            continue

        key = (package, permission)

        if key not in groups:
            groups[key] = {
                "correlation_id": f"DOJI-CORR-{len(groups) + 1:04d}",
                "classification": "CORRELATED_PERMISSION_ACTIVITY",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "package": package,
                "permission": permission,
                "event_count": 0,
                "event_times": [],
                "source_finding_ids": [],
                "source_modules": [],
                "interpretation": (
                    "Repeated historical permission observations "
                    "were recorded for this application. These events "
                    "do not prove successful APK installation or spyware."
                ),
                "recommendation": (
                    "Review the application's installation history "
                    "and verify whether the permission was expected."
                ),
            }

        group = groups[key]
        group["event_count"] += 1

        event_time = finding.get("event_time")
        if event_time:
            group["event_times"].append(event_time)

        finding_id = finding.get("finding_id")
        if finding_id:
            group["source_finding_ids"].append(finding_id)

        module = finding.get("source_module")
        if module and module not in group["source_modules"]:
            group["source_modules"].append(module)

    correlated = [
        group
        for group in groups.values()
        if group["event_count"] >= 2
    ]

    for group in correlated:
        group["event_times"] = sorted(group["event_times"])

    return correlated


def build_findings(case_path):
    case_path, metadata_path, alerts_path = validate_case(case_path)

    metadata = load_json(metadata_path)
    alerts = load_json(alerts_path)

    if not isinstance(alerts, list):
        raise ValueError("alerts.json must contain a JSON list.")

    findings = [
        classify_alert(alert, index + 1)
        for index, alert in enumerate(alerts)
        if isinstance(alert, dict)
    ]

    correlated_findings = correlate_findings(findings)

    counts = {}
    for finding in findings:
        category = finding["classification"]
        counts[category] = counts.get(category, 0) + 1

    result = {
        "product": "Doji Advanced Mobile Forensics",
        "engine": "Doji Findings Engine",
        "engine_version": ENGINE_VERSION,
        "generated_utc": utc_now(),
        "case_id": metadata.get("case_id"),
        "source_analysis_status": metadata.get("status"),
        "evidence_sha256": (
            metadata.get("evidence", {}).get("sha256")
        ),
        "source_alert_count": len(alerts),
        "finding_count": len(findings),
        "classification_counts": counts,
        "findings": findings,
        "correlated_finding_count": len(correlated_findings),
        "correlated_findings": correlated_findings,
        "limitations": [
            "Doji classifications are interpretations of available evidence.",
            "An alert is not automatically proof of spyware.",
            "No IOC match does not prove a device is safe.",
            "User confirmations are not independent forensic verification.",
        ],
    }

    output_path = case_path / "doji_findings.json"
    save_json(output_path, result)

    print("\n=== Doji Findings Engine ===")
    print(f"Case: {result['case_id']}")
    print(f"Source alerts: {len(alerts)}")
    print(f"Doji findings: {len(findings)}")
    print(f"Output: {output_path}")
    print("\nClassification summary:")

    for category, count in sorted(counts.items()):
        print(f"  {category}: {count}")

    print("\nOriginal MVT results were not modified.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate independent Doji forensic findings."
    )
    parser.add_argument(
        "--case",
        required=True,
        help="Path to a Doji forensic case directory.",
    )
    args = parser.parse_args()

    try:
        build_findings(Path(args.case))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[Doji] Error: {exc}")


if __name__ == "__main__":
    main()
