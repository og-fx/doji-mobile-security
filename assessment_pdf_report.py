#!/usr/bin/env python3
"""Generate PDF reports for Doji's general security assessments."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

from pdf_report import (
    REPORT_DIR,
    safe,
    format_timestamp,
    make_styles,
    make_table,
)


SUPPORTED_TYPES = {
    "android_unified_security",
    "android_device_malware",
    "android_information",
    "android_permissions",
    "iphone_information",
}


def generate_assessment_pdf(json_path):
    json_path = Path(json_path).expanduser()

    if json_path.is_symlink():
        raise ValueError("Symbolic-link reports are not accepted.")

    json_path = json_path.resolve()

    if json_path.parent != REPORT_DIR.resolve():
        raise ValueError("Report must be in Doji's reports directory.")

    report = json.loads(json_path.read_text(encoding="utf-8"))

    if not isinstance(report, dict):
        raise ValueError("Invalid report format.")

    report_type = report.get("report_type")

    if report_type not in SUPPORTED_TYPES:
        if report_type is not None:
            raise ValueError(f"Unsupported report type: {report_type}")

        if not all(
            key in report
            for key in ("summary", "target", "findings")
        ):
            raise ValueError("Unsupported legacy report structure.")

    summary = report.get("summary") or {}
    target = report.get("target") or {}
    findings = report.get("findings") or []
    limitations = report.get("limitations") or []

    if not isinstance(summary, dict) or not isinstance(target, dict):
        raise ValueError("Invalid assessment summary or target.")

    if not isinstance(findings, list):
        raise ValueError("Invalid findings structure.")

    if not isinstance(limitations, list):
        limitations = [limitations]

    styles = make_styles()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    output = REPORT_DIR / f"{json_path.stem}.pdf"

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="Doji Security Assessment Report",
        author="Doji Mobile Security Assessment",
    )

    story = []

    def heading(value):
        story.append(Paragraph(safe(value), styles["SectionHeading"]))

    def body(value):
        story.append(Paragraph(safe(value), styles["DojiBody"]))
        story.append(Spacer(1, 2 * mm))

    def table(rows):
        formatted = [
            [Paragraph(safe(cell), styles["DojiSmall"]) for cell in row]
            for row in rows
        ]
        story.append(make_table(formatted, [48 * mm, 128 * mm]))

    story.append(Paragraph("DOJI", styles["DojiTitle"]))
    story.append(Paragraph(
        "MOBILE SECURITY ASSESSMENT<br/>SECURITY ASSESSMENT REPORT",
        styles["DojiSubtitle"],
    ))

    heading("Assessment Summary")

    rows = [
        ["Field", "Value"],
        ["Assessment ID", report.get("assessment_id")],
        ["Report type", report_type or "Legacy assessment"],
        ["Scan date and time", format_timestamp(report.get("created_utc"))],
        ["PDF generated", format_timestamp(datetime.now(timezone.utc).isoformat())],
        ["Target", target.get("name")],
        ["Platform", target.get("platform")],
        ["Passed checks", summary.get("passed")],
        ["Failed checks", summary.get("failed")],
        ["Warnings", summary.get("warnings")],
        ["Not run", summary.get("not_run")],
        ["Findings", summary.get("findings_total")],
    ]

    table(rows)

    if report_type in ("android_device_malware", "android_unified_security"):
        coverage = report.get("coverage") or {}

        if not isinstance(coverage, dict):
          raise ValueError("Invalid Android scan coverage.")

        cancelled = report.get("cancelled") is True

        heading("Android Device Scan Coverage")

        coverage_rows = [
          ["Field", "Value"],
          [
            "Assessment status",
            report.get(
                "assessment_coverage_status",
                "CANCELLED" if cancelled else "UNKNOWN",
            ),
          ],
          [
            "Applications discovered",
            coverage.get("packages_discovered"),
          ],
          [
            "Applications selected",
            coverage.get("packages_selected"),
          ],
          [
            "Applications assessed",
            coverage.get("packages_assessed"),
          ],
          [
            "Applications completed",
            coverage.get("packages_completed"),
          ],
          [
            "Applications partially assessed",
            coverage.get("packages_partial"),
          ],
          [
            "Applications failed",
            coverage.get("packages_failed"),
          ],
          [
            "Applications not scanned",
            coverage.get("packages_not_run"),
          ],
          [
            "Applications not selected",
            coverage.get("packages_not_selected"),
          ],
        ]

        table(coverage_rows)

        if cancelled:
          body(
            "ASSESSMENT CANCELLED: The user stopped this "
            "assessment before all selected applications "
            "were processed. Results represent only the "
            "applications assessed before cancellation."
          )

    heading("Assessment Findings")

    if not findings:
        body("No findings were recorded in this assessment.")

    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue

        heading(f"Finding {index}")

        for label, key in (
            ("Check", "check"),
            ("Status", "status"),
            ("Severity", "severity"),
            ("Confidence", "confidence"),
            ("Details", "details"),
            ("Evidence", "evidence"),
            ("Remediation", "remediation"),
        ):
            value = finding.get(key)

            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2, ensure_ascii=True)

            body(f"{label}: {value if value is not None else 'Not available'}")

    if report_type in ("android_unified_security", "android_device_malware"):
        applications = report.get("applications") or []

        if isinstance(applications, list):
            flagged = [
                app for app in applications
                if isinstance(app, dict)
                and (
                    app.get("verdict") in ("SUSPICIOUS", "REVIEW REQUIRED")
                    or any(
                        isinstance(f, dict)
                        and f.get("type") == "yara_rule_match"
                        for f in (app.get("findings") or [])
                    )
                )
            ]

            heading("Malware Investigation Evidence")

            if not flagged:
                body("No flagged applications were recorded in this assessment.")

            for app in flagged:
                package = app.get("package") or "Unknown package"
                heading(f"Application: {package}")
                body(f"Verdict: {app.get('verdict') or 'Not available'}")
                body(f"Analysis status: {app.get('analysis_status') or 'Unknown'}")

                collection = app.get("collection") or {}
                if isinstance(collection, dict):
                    for item in collection.get("collected") or []:
                        if not isinstance(item, dict):
                            continue
                        body(f"APK component: {item.get('component') or 'Unknown'}")
                        body(f"Original Android path: {item.get('device_path') or 'Not recorded'}")
                        body(f"Evidence copy: {item.get('local_path') or 'Not recorded'}")
                        body(f"SHA-256: {item.get('sha256') or 'Not recorded'}")

                for finding in app.get("findings") or []:
                    if not isinstance(finding, dict):
                        continue
                    if finding.get("type") != "yara_rule_match":
                        continue

                    evidence = finding.get("evidence") or {}
                    if not isinstance(evidence, dict):
                        evidence = {}

                    body(f"YARA rule: {finding.get('rule') or 'Unknown'}")
                    body(f"Severity: {finding.get('severity') or 'Unknown'}")
                    files = evidence.get("matched_files") or []
                    if isinstance(files, list):
                        body(f"Detected internal files: {', '.join(map(str, files)) or 'Not recorded'}")

                analysis = app.get("apk_analysis") or {}
                if isinstance(analysis, dict) and analysis:
                    checks = analysis.get("checks") or {}
                    if not isinstance(checks, dict):
                        checks = {}

                    vt = checks.get("virustotal") or {}
                    if isinstance(vt, dict):
                        body(
                            f"VirusTotal status: "
                            f"{vt.get('status') or 'Not available'}"
                        )
                        stats = vt.get("analysis_stats") or {}
                        if isinstance(stats, dict) and stats:
                            body(
                                "VirusTotal detections: "
                                f"{stats.get('malicious', 0)} malicious, "
                                f"{stats.get('suspicious', 0)} suspicious"
                            )

                    signature = checks.get("signature") or {}
                    if isinstance(signature, dict):
                        body(
                            f"APK signature verification: "
                            f"{signature.get('status') or 'Not available'}"
                        )
                        body(
                            f"Signer certificate: "
                            f"{signature.get('signer_certificate_dn') or 'Not recorded'}"
                        )
                        body(
                            f"Signer certificate SHA-256: "
                            f"{signature.get('signer_certificate_sha256') or 'Not recorded'}"
                        )

                    completeness = analysis.get("scan_completeness") or {}
                    if isinstance(completeness, dict):
                        body(
                            f"APK scan completeness: "
                            f"{completeness.get('status') or 'Not available'}"
                        )
                else:
                    body(
                        "Detailed VirusTotal, signature, and scan "
                        "completeness data were not embedded in this report."
                    )

                body(
                    "YARA matches are static indicators and do not by "
                    "themselves confirm active malware execution. "
                    "A valid APK signature does not establish publisher trust."
                )

    heading("Assessment Limitations")

    if limitations:
        for limitation in limitations:
            body(limitation)
    else:
        body("No additional limitations were recorded.")

    disclaimer = report.get("disclaimer")

    if disclaimer:
        heading("Disclaimer")
        body(disclaimer)

    doc.build(story)

    return output


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 assessment_pdf_report.py reports/REPORT.json")
        raise SystemExit(2)

    try:
        output = generate_assessment_pdf(sys.argv[1])
    except Exception as exc:
        print(f"PDF generation failed: {exc}")
        raise SystemExit(1)

    print("PASS: Assessment PDF generated.")
    print(output)


if __name__ == "__main__":
    main()
