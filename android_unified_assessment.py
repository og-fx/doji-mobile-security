#!/usr/bin/env python3
"""Build consolidated Doji Android security assessment reports."""

from android_device_report import build_device_malware_report
from assessment import add_finding, save_report


def build_unified_report(malware_result, configuration, monitoring):
    """Combine existing evidence without changing the source reports."""

    report = build_device_malware_report(malware_result)

    report["report_type"] = "android_unified_security"
    report["scan_mode"] = malware_result.get("scan_mode", "full")
    report["report_title"] = (
        "Doji Android Quick Security Assessment"
        if report["scan_mode"] == "quick"
        else "Doji Android Full Security Assessment"
    )

    if report["scan_mode"] == "quick":
        report["limitations"].append(
            "Quick Scan excludes Quark behavioral analysis "
            "and provides reduced coverage compared with Full Scan."
        )

    malware_status = report["assessment_coverage_status"]

    report["malware_assessment_coverage_status"] = malware_status
    report["security_configuration"] = configuration
    report["live_monitoring"] = monitoring

    stage_status = {
        "malware_analysis": malware_status,
        "security_configuration": "COMPLETED",
        "live_monitoring": "NOT_COMPLETED",
    }

    expected_checks = (
        ("accessibility", "Accessibility services"),
        ("device_administrators", "Device administrators"),
    )

    checks = (
        configuration.get("checks", {})
        if isinstance(configuration, dict) else {}
    )

    if not all(
        isinstance(checks.get(name), dict)
        and checks[name].get("status") in ("PASS", "REVIEW REQUIRED")
        for name, _ in expected_checks
    ):
        stage_status["security_configuration"] = "PARTIAL"

    for name, label in expected_checks:
        result = checks.get(name, {})
        if not isinstance(result, dict):
            result = {}

        status = result.get("status", "NOT AVAILABLE")

        finding_status = {
            "PASS": "PASS",
            "REVIEW REQUIRED": "WARNING",
        }.get(status, "NOT_RUN")

        add_finding(
            report,
            check_name=f"Security configuration: {label}",
            status=finding_status,
            details=result.get(
                "details",
                "Configuration evidence unavailable.",
            ),
            severity="LOW" if finding_status == "WARNING" else "INFO",
            confidence="MEDIUM",
            evidence=result,
        )

    if isinstance(monitoring, dict):
        if monitoring.get("cancelled") is True:
            stage_status["live_monitoring"] = "CANCELLED"
        elif monitoring.get("error"):
            stage_status["live_monitoring"] = "FAILED"
        elif monitoring.get("completed") is True:
            stage_status["live_monitoring"] = "COMPLETED"
        else:
            stage_status["live_monitoring"] = "PARTIAL"

        for event in monitoring.get("events", []):
            if not isinstance(event, dict):
                continue

            event_type = event.get("type", "UNKNOWN_EVENT")

            add_finding(
                report,
                check_name=f"Live monitoring: {event_type}",
                status="WARNING",
                details=(
                    "A change was observed during monitoring. "
                    "Review the recorded evidence."
                ),
                severity="LOW",
                confidence="MEDIUM",
                evidence=event,
            )

    if stage_status["live_monitoring"] != "COMPLETED":
        add_finding(
            report,
            check_name="Live monitoring coverage",
            status="NOT_RUN",
            details="Live monitoring did not complete successfully.",
            evidence={
                "stage_status": stage_status["live_monitoring"]
            },
        )

    if malware_status == "CANCELLED":
        if not checks:
            stage_status["security_configuration"] = "NOT_STARTED"

    if (
        isinstance(monitoring, dict)
        and monitoring.get("cancelled") is True
        and monitoring.get("completed") is False
        and not monitoring.get("events")
        and not monitoring.get("started_utc")
    ):
        stage_status["live_monitoring"] = "NOT_STARTED"

    report["stage_status"] = stage_status

    if (
        "CANCELLED" in stage_status.values()
        or (
            isinstance(monitoring, dict)
            and monitoring.get("cancelled") is True
        )
    ):
        overall = "CANCELLED"
    elif (
        malware_status == "INTERRUPTED"
        or malware_result.get("connection_interrupted", False)
    ):
        overall = "INTERRUPTED"
    elif all(
        status == "COMPLETED"
        for status in stage_status.values()
    ):
        overall = "COMPLETED"
    elif any(
        status in ("COMPLETED", "PARTIAL")
        for status in stage_status.values()
    ):
        overall = "PARTIAL"
    else:
        overall = "NOT_COMPLETED"

    report["assessment_coverage_status"] = overall

    report["limitations"].append(
        "Live monitoring detects sampled changes, not all spyware activity."
    )

    return report


def save_unified_report(malware_result, configuration, monitoring):
    report = build_unified_report(
        malware_result,
        configuration,
        monitoring,
    )
    return save_report(report)
