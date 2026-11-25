#!/usr/bin/env python3
"""Doji iPhone Full Security Scan engine.

Read-only checks. Backup-dependent forensic analysis
will be integrated separately.
"""

import shutil
import json
import plistlib
from pathlib import Path
import subprocess

from assessment import new_assessment, add_finding, save_report
from iphone_evidence_discovery import discover_iphone_evidence, verify_iphone_backup_owner
from iphone_mvt_integration import analyze_iphone_backup
from forensic_engine import run_investigation


def run_iphone_security_scan(device_id, device_name="iPhone",
                             progress_callback=None):
    """Perform available iPhone checks and record coverage."""

    def progress(message):
        if progress_callback:
            progress_callback(message)

    report = new_assessment(device_name, "Apple", device_id)
    report["report_type"] = "iphone_full_security"
    report["report_title"] = "Doji iPhone Full Security Scan"

    report["limitations"] = [
        "Device information checks use accessible iPhone metadata.",
        "MVT forensic analysis runs only when a verified, accessible backup is available.",
        "Unperformed forensic checks are marked NOT_RUN.",
        "A completed assessment or zero IOC matches does not establish that the iPhone is malware-free.",
    ]

    progress("Checking iPhone connection...")

    if not shutil.which("ideviceinfo"):
        raise RuntimeError("ideviceinfo is not installed.")

    checks = [
        ("Device name", "DeviceName"),
        ("iOS version", "ProductVersion"),
        ("Device model", "ProductType"),
        ("Build version", "BuildVersion"),
    ]

    for label, key in checks:
        progress(f"Checking {label.lower()}...")

        try:
            result = subprocess.run(
                ["ideviceinfo", "-u", device_id, "-k", key],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            value = result.stdout.strip()

            if result.returncode == 0 and value:
                add_finding(
                    report,
                    f"Read {label.lower()}",
                    "PASS",
                    f"Retrieved value: {value}",
                )
            else:
                add_finding(
                    report,
                    f"Read {label.lower()}",
                    "WARNING",
                    "Device information could not be retrieved.",
                )

        except (OSError, subprocess.TimeoutExpired):
            add_finding(
                report,
                f"Read {label.lower()}",
                "WARNING",
                "Device information check could not complete.",
            )


    # Collect accessible hardware diagnostics without storing identifiers.
    progress("Collecting iPhone hardware diagnostics...")

    try:
        diagnostic_result = subprocess.run(
            ["idevicediagnostics", "-u", device_id, "diagnostics", "All"],
            capture_output=True,
            timeout=30,
            check=False,
        )

        if diagnostic_result.returncode != 0:
            raise RuntimeError("Diagnostic service returned an error.")

        diagnostic_data = plistlib.loads(diagnostic_result.stdout)

        if not isinstance(diagnostic_data, dict):
            raise ValueError("Unexpected diagnostic response.")

        categories = sorted(
            key for key in diagnostic_data
            if key in {"GasGauge", "HDMI", "NAND", "WiFi"}
        )

        report["hardware_diagnostics"] = {
            "status": "COMPLETED",
            "categories": categories,
        }

        add_finding(
            report,
            "iPhone hardware diagnostic collection",
            "PASS",
            "Successfully retrieved diagnostic categories: "
            + ", ".join(categories),
        )

    except (OSError, ValueError, RuntimeError,
            subprocess.TimeoutExpired) as exc:
        report["hardware_diagnostics"] = {
            "status": "UNAVAILABLE",
        }

        add_finding(
            report,
            "iPhone hardware diagnostic collection",
            "WARNING",
            "Diagnostic collection could not complete: "
            + type(exc).__name__,
        )

    progress("Discovering existing iPhone forensic evidence...")

    discovered = discover_iphone_evidence()
    verified = []

    for evidence in discovered:
        if evidence["workflow"] == "ios-backup":
            if verify_iphone_backup_owner(
                evidence["path"], device_id
            ):
                verified.append(evidence)

    report["forensic_evidence"] = {
        "discovered_count": len(discovered),
        "verified_backup_count": len(verified),
        "verified_backups": verified,
        "analysis_started": False,
    }

    forensic_result = None
    completed_checks = set()

    if verified:
        progress("Running MVT spyware analysis on verified backup...")
        report["forensic_evidence"]["analysis_started"] = True

        try:
            forensic_result = analyze_iphone_backup(
                verified[0]["path"],
                device_id,
                progress_callback=progress,
                timeout_seconds=600,
            )

            report["forensic_analysis"] = forensic_result

            if (
                forensic_result.get("status") == "COMPLETED"
                and forensic_result.get("evidence_integrity") == "UNCHANGED"
                and forensic_result.get("exit_code") == 0
                and forensic_result.get("findings_generated") is True
                and isinstance(forensic_result.get("ioc_match_count"), int)
                and not isinstance(forensic_result.get("ioc_match_count"), bool)
                and forensic_result.get("ioc_match_count") >= 0
            ):
                matches = forensic_result.get("ioc_match_count")

                add_finding(
                    report,
                    "MVT spyware analysis",
                    "PASS",
                    "Analysis completed on available backup evidence. "
                    "This does not establish that the iPhone is malware-free.",
                )
                completed_checks.add("MVT spyware analysis")

                add_finding(
                    report,
                    "Known spyware IOC matching",
                    "WARNING" if matches else "PASS",
                    f"MVT reported {matches} IOC matches in the "
                    "analyzed evidence. Zero matches does not prove "
                    "the iPhone is malware-free.",
                )
                completed_checks.add("Known spyware IOC matching")

            else:
                add_finding(
                    report,
                    "MVT spyware analysis",
                    "WARNING",
                    "MVT analysis or findings were incomplete.",
                )
                completed_checks.add("MVT spyware analysis")

        except Exception as exc:
            report["forensic_analysis"] = {
                "status": "ERROR",
                "error": str(exc),
            }

            add_finding(
                report,
                "MVT spyware analysis",
                "WARNING",
                "MVT analysis could not complete: "
                + str(exc),
            )
            completed_checks.add("MVT spyware analysis")


    # Automatically analyze discovered sysdiagnose evidence.
    sysdiagnose_items = [
        item for item in discovered
        if item["workflow"] == "ios-sysdiagnose"
    ]

    if sysdiagnose_items:
        progress("Running MVT sysdiagnose forensic analysis...")

        case_directories = []

        try:
            exit_code = run_investigation(
                "ios-sysdiagnose",
                Path(sysdiagnose_items[0]["path"]),
                600,
                case_callback=case_directories.append,
            )

            if len(case_directories) != 1:
                raise RuntimeError("Investigation directory unavailable.")

            summary_path = case_directories[0] / "run_summary.json"
            summary = json.loads(summary_path.read_text())

            successful = (
                exit_code == 0
                and summary.get("status") == "COMPLETED"
                and summary.get("evidence_integrity") == "UNCHANGED"
            )

            add_finding(
                report,
                "Sysdiagnose forensic analysis",
                "PASS" if successful else "WARNING",
                "MVT sysdiagnose investigation completed."
                if successful else
                "MVT sysdiagnose investigation was incomplete.",
            )

            report["sysdiagnose_analysis"] = {
                "status": summary.get("status"),
                "exit_code": exit_code,
                "case_directory": str(case_directories[0]),
            }

        except Exception as exc:
            add_finding(
                report,
                "Sysdiagnose forensic analysis",
                "WARNING",
                f"Sysdiagnose investigation failed: {exc}",
            )

        completed_checks.add("Sysdiagnose forensic analysis")

    unavailable_checks = [
        "MVT spyware analysis",
        "Known spyware IOC matching",
        "Encrypted backup forensic analysis",
        "Sysdiagnose forensic analysis",
        "Filesystem forensic analysis",
        "Application security analysis",
        "Configuration profile inspection",
        "Network indicator analysis",
        "Persistence indicator analysis",
        "Forensic timeline correlation",
    ]

    for check in unavailable_checks:
        if check in completed_checks:
            continue

        add_finding(
            report,
            check,
            "NOT_RUN",
            "This check requires additional implementation, "
            "accessible forensic evidence, or both.",
        )

    progress("Saving iPhone security assessment...")
    report_path = save_report(report)

    return report, report_path
