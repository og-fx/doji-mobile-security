#!/usr/bin/env python3
"""Build evidence-based Android device malware assessment reports."""

from assessment import new_assessment, add_finding, save_report


def build_device_malware_report(scan_result):
    """Convert device application scan results into a Doji report."""

    serial = scan_result["device_serial"]

    model = scan_result.get("device_model")
    if not isinstance(model, str) or not model.strip():
        model = "Unknown Android Device"

    report = new_assessment(
        target_name=model,
        platform="Android",
        device_id=serial,
    )

    report["target"]["model"] = model

    report["report_type"] = "android_device_malware"
    report["report_title"] = "Doji Android Device Malware Assessment"

    report["cancelled"] = bool(scan_result.get("cancelled", False))

    if report["cancelled"]:
        report["limitations"].append(
            "Assessment cancelled by the user. Results cover only "
            "applications processed before cancellation."
        )

    coverage_fields = (
        "packages_discovered",
        "packages_selected",
        "packages_assessed",
        "packages_completed",
        "packages_partial",
        "packages_failed",
        "packages_not_run",
        "packages_not_selected",
    )

    report["coverage"] = {
        key: scan_result.get(key, 0)
        for key in coverage_fields
    }

    coverage = report["coverage"]

    if report["cancelled"]:
        coverage_status = "CANCELLED"
    elif scan_result.get("connection_interrupted"):
        coverage_status = "INTERRUPTED"
    elif (
        coverage["packages_completed"] == 0
        and coverage["packages_partial"] == 0
    ):
        coverage_status = "NOT_COMPLETED"
    elif (
        coverage["packages_partial"] > 0
        or coverage["packages_failed"] > 0
        or coverage["packages_not_run"] > 0
        or coverage["packages_not_selected"] > 0
        or coverage["packages_completed"] != coverage["packages_selected"]
    ):
        coverage_status = "PARTIAL"
    else:
        coverage_status = "COMPLETED"

    report["scan_status"] = scan_result.get(
        "scan_status", coverage_status
    )
    report["connection_interrupted"] = bool(
        scan_result.get("connection_interrupted", False)
    )
    report["assessment_coverage_status"] = coverage_status

    report["collection_budget"] = scan_result.get(
        "collection_budget", {}
    )

    report["applications"] = scan_result.get("applications", [])

    report["limitations"].extend(
        scan_result.get("limitations", [])
    )

    report["limitations"].extend(
        scan_result.get("errors", [])
    )

    for application in report["applications"]:
        package = application.get("package", "Unknown")
        status = application.get("analysis_status", "NOT_RUN")
        verdict = application.get("verdict") or "UNKNOWN"
        findings = application.get("findings") or []

        if verdict == "SUSPICIOUS":
            finding_status = "WARNING"
            severity = "HIGH"
        elif verdict == "REVIEW REQUIRED":
            finding_status = "WARNING"
            severity = "LOW"
        elif (
            status == "COMPLETED"
            and verdict == "NO KNOWN THREAT DETECTED"
        ):
            finding_status = "PASS"
            severity = "INFO"
        elif status == "NOT_RUN":
            finding_status = "NOT_RUN"
            severity = "INFO"
        else:
            finding_status = "WARNING"
            severity = "LOW"

        details = (
            f"Application: {package}. "
            f"Analysis status: {status}. "
            f"Verdict: {verdict}. "
            f"Recorded indicators: {len(findings)}."
        )

        add_finding(
            report,
            check_name=f"Application malware assessment: {package}",
            status=finding_status,
            details=details,
            severity=severity,
            confidence="LOW",
            evidence={
                "package": package,
                "analysis_status": status,
                "verdict": verdict,
                "findings": findings,
                "collection": application.get("collection"),
                "report_path": application.get("report_path"),
            },
            limitations=application.get("limitations", []),
        )

    if report["coverage"]["packages_not_selected"] > 0:
        add_finding(
            report,
            check_name="Application selection coverage",
            status="NOT_RUN",
            details=(
                f"{report['coverage']['packages_not_selected']} "
                "discovered applications were not selected "
                "for assessment."
            ),
            confidence="HIGH",
        )

    return report


def save_device_malware_report(scan_result):
    """Build and save a device malware assessment report."""
    report = build_device_malware_report(scan_result)
    return save_report(report)
