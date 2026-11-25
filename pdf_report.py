import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

NAVY = colors.HexColor("#10151F")
PANEL = colors.HexColor("#192231")
ACCENT = colors.HexColor("#159A78")
MUTED = colors.HexColor("#536176")
LIGHT = colors.HexColor("#F3F6FA")
BORDER = colors.HexColor("#D9E1EB")


def safe(value):
    """Escape report data before placing it in a PDF paragraph."""
    if value is None:
        return "Not available"
    return escape(str(value))


def display_bytes(value):
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "Not available"

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024

    return "Not available"


def format_timestamp(value):
    if not value:
        return "Not available"

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        local_time = parsed.astimezone()
        date_text = local_time.strftime("%d %B %Y")
        time_text = local_time.strftime("%I:%M:%S %p")
        zone_text = local_time.strftime("%Z")
        offset_text = local_time.strftime("%z")

        if offset_text:
            offset_text = (
                f"UTC{offset_text[:3]}:{offset_text[3:]}"
            )

        return (
            f"{date_text}, {time_text} "
            f"({zone_text}, {offset_text})"
        )
    except ValueError:
        return str(value)


def make_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="DojiTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=28,
        textColor=NAVY,
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    ))

    styles.add(ParagraphStyle(
        name="DojiSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=15,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceAfter=7 * mm,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=NAVY,
        spaceBefore=5 * mm,
        spaceAfter=3 * mm,
    ))

    styles.add(ParagraphStyle(
        name="DojiBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=12,
        textColor=NAVY,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="DojiSmall",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        textColor=MUTED,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="DojiVerdict",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=ACCENT,
        alignment=TA_CENTER,
    ))

    return styles


def make_table(rows, widths, header=True):
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ])
        for row in rows[1:]:
            commands.append(
                ("BACKGROUND", (0, rows.index(row)), (-1, rows.index(row)),
                 LIGHT)
            )

    table.setStyle(TableStyle(commands))
    return table


def generate_pdf(json_path):
    json_path = Path(json_path).expanduser().resolve()

    if not json_path.is_file():
        raise FileNotFoundError(f"JSON report not found: {json_path}")

    report = json.loads(json_path.read_text(encoding="utf-8"))

    target = report.get("target") or {}
    checks = report.get("checks") or {}
    vt = checks.get("virustotal") or {}
    yara = checks.get("yara") or {}
    quark = checks.get("quark") or {}
    stats = vt.get("analysis_stats") or {}
    permissions = target.get("requested_permissions") or []
    findings = [
        item for item in (report.get("findings") or [])
        if not isinstance(item, dict)
        or item.get("type") != "quark_behavior_match"
    ]
    limitations = report.get("limitations") or []
    errors = report.get("errors") or []
    suspicious_reasons = report.get("suspicious_reasons") or []

    output_path = REPORT_DIR / f"{json_path.stem}.pdf"
    styles = make_styles()

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="Doji APK Security Assessment",
        author="Doji Mobile Security Assessment",
        subject="APK malware analysis report",
    )

    story = []

    story.append(Paragraph("DOJI", styles["DojiTitle"]))
    story.append(Paragraph(
        "MOBILE SECURITY ASSESSMENT<br/>APK MALWARE ANALYSIS REPORT",
        styles["DojiSubtitle"],
    ))

    verdict = str(report.get("verdict") or "UNKNOWN")
    story.append(Paragraph(f"VERDICT: {safe(verdict)}", styles["DojiVerdict"]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("Assessment Summary", styles["SectionHeading"]))
    summary_rows = [
        ["Field", "Value"],
        ["Assessment ID", safe(report.get("assessment_id"))],
        ["Report generated (UTC)", safe(format_timestamp(
            report.get("created_utc")
        ))],
        ["PDF generated (UTC)", safe(datetime.now(timezone.utc).isoformat())],
        ["Tool", safe(report.get("tool"))],
        ["Tool version", safe(report.get("tool_version"))],
        ["Report type", safe(report.get("report_type"))],
    ]

    completeness = report.get("scan_completeness") or {}

    if completeness:
        summary_rows.append([
            "Scan completeness",
            safe(completeness.get("status", "UNKNOWN")),
        ])

        incomplete_checks = completeness.get("incomplete_checks") or []

        if incomplete_checks:
            names = [
                str(item.get("check", "Unknown"))
                for item in incomplete_checks
                if isinstance(item, dict)
            ]

            summary_rows.append([
                "Incomplete checks",
                safe(", ".join(names) or "Unknown"),
            ])

    incomplete_reason = report.get("incomplete_reason")

    if incomplete_reason:
        summary_rows.append([
            "Incomplete reason",
            safe(incomplete_reason),
        ])

    story.append(make_table(summary_rows, [48 * mm, 128 * mm]))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("APK Details", styles["SectionHeading"]))
    apk_rows = [
        ["Field", "Value"],
        ["Filename", safe(target.get("file_name"))],
        ["Package", safe(target.get("package_name"))],
        ["Version", safe(target.get("version_name"))],
        ["Platform", safe(target.get("platform"))],
        ["File size", safe(display_bytes(target.get("size_bytes")))],
        ["Target SDK", safe(target.get("target_sdk"))],
        ["SHA-256", safe((checks.get("sha256") or {}).get("value")
                         if isinstance(checks.get("sha256"), dict)
                         else checks.get("sha256"))],
    ]
    story.append(make_table(apk_rows, [48 * mm, 128 * mm]))

    story.append(Paragraph("Analysis Checks", styles["SectionHeading"]))
    check_rows = [["Check", "Result / Details"]]

    for name in ("metadata", "permissions", "signature", "yara", "virustotal"):
        value = checks.get(name, {})

        if isinstance(value, dict):
            status = value.get("status", value.get("result", "Recorded"))
            details = str(value.get("details", "") or "")
            lower_details = details.lower()

            if name == "signature" and status == "FAIL":
                text = (
                    "Not verified. The APK format or signature could not "
                    "be validated. This alone does not prove malware."
                )
            elif (
                name in ("metadata", "permissions")
                and "no androidmanifest.xml found" in lower_details
            ):
                text = (
                    "Not available — AndroidManifest.xml is missing or "
                    "invalid, so this check could not be completed."
                )
            else:
                text = str(status)
                if details:
                    text += f" — {details}"
        else:
            text = str(value)

        check_rows.append([
            safe(name.replace("_", " ").title()),
            safe(text),
        ])

    story.append(make_table(check_rows, [40 * mm, 136 * mm]))
    # YARA static malware analysis results
    story.append(Paragraph(
        "YARA Static Analysis",
        styles["SectionHeading"],
    ))

    yara_matches = yara.get("matches") or []
    yara_status = yara.get("status", "NOT_RECORDED")

    yara_rows = [
        ["Metric", "Result"],
        ["Scan status", safe(yara_status)],
        ["Matched rule count", safe(
            yara.get("match_count", len(yara_matches))
        )],
    ]

    story.append(make_table(yara_rows, [48 * mm, 128 * mm]))

    if yara_matches:
        rule_rows = [["Matched YARA Rule", "Evidence"]]

        for match in yara_matches:
            if isinstance(match, dict):
                rule_name = match.get("rule", "Unknown rule")
                evidence = match.get("evidence") or (
                    "Rule matched; individual strings were not recorded."
                )
            else:
                rule_name = str(match)
                evidence = "Evidence details not available."

            rule_rows.append([
                safe(rule_name),
                safe(evidence),
            ])

        story.append(make_table(rule_rows, [65 * mm, 111 * mm]))

    elif yara_status == "COMPLETED":
        story.append(Paragraph(
            "No configured YARA rules matched this APK. "
            "This does not prove that the APK is safe.",
            styles["DojiBody"],
        ))
    else:
        story.append(Paragraph(
            "YARA analysis did not complete successfully. "
            "See Analysis Checks and Analysis Errors for details.",
            styles["DojiBody"],
        ))

    story.append(Spacer(1, 3 * mm))

    # Quark Engine — Android behavioral analysis
    story.append(Paragraph(
        "Quark Android Behavioral Analysis",
        styles["SectionHeading"],
    ))

    quark_status = quark.get("engine_status", "NOT_RECORDED")
    quark_findings = quark.get("findings") or []

    quark_summary = [
        ["Metric", "Result"],
        ["Engine", safe(quark.get("engine", "Quark-Engine"))],
        ["Engine status", safe(quark_status)],
        ["Original risk classification",
         safe(quark.get("original_threat_level"))],
        ["Original total score",
         safe(quark.get("original_total_score"))],
        ["Original weight sum",
         safe(quark.get("original_weight_sum"))],
        ["Available rules",
         safe(quark.get("rules_available"))],
        ["Behavior records",
         safe(quark.get("behavior_count", len(quark_findings)))],
        ["Evidence integrity",
         safe(quark.get("evidence_integrity"))],
        ["APK SHA-256",
         safe(quark.get("apk_sha256"))],
    ]

    story.append(make_table(
        quark_summary,
        [48 * mm, 128 * mm],
    ))

    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph(
        "Quark Behavioral Findings",
        styles["SectionHeading"],
    ))

    story.append(Paragraph(
        "The following records represent static behavioral patterns "
        "identified by Quark. Confidence measures rule-matching "
        "confidence, not the probability that an APK is malicious. "
        "Individual matches must be interpreted in context.",
        styles["DojiBody"],
    ))

    if quark_status == "COMPLETED" and quark_findings:

        behavior_rows = [[
            "Rule",
            "Behavior",
            "Confidence",
            "Score",
            "Labels",
            "API / Permissions",
        ]]

        # Summarize Quark findings by behavioral labels.
        # Preserve complete original evidence in the JSON report.
        from collections import Counter

        category_counts = Counter()
        valid_findings = 0

        for item in quark_findings:
            if not isinstance(item, dict):
                continue

            valid_findings += 1
            evidence = item.get("evidence") or item

            labels = evidence.get("labels") or []
            if not isinstance(labels, list):
                labels = [labels]

            normalized_labels = {
                str(label).strip().lower()
                for label in labels
                if str(label).strip()
            }

            if not normalized_labels:
                normalized_labels = {"uncategorized"}

            category_counts.update(normalized_labels)

        behavior_rows = [[
            "Behavior category",
            "Rule matches",
        ]]

        for category, count in category_counts.most_common():
            behavior_rows.append([
                Paragraph(safe(category.replace("_", " ").title()),
                          styles["DojiSmall"]),
                Paragraph(safe(count), styles["DojiSmall"]),
            ])

        story.append(Paragraph(
            f"Total behavioral rule matches: {valid_findings}. "
            "Categories may overlap because one rule can have "
            "multiple labels. Complete evidence is retained "
            "in the JSON report.",
            styles["DojiBody"],
        ))

        story.append(make_table(
            behavior_rows,
            [120 * mm, 56 * mm],
        ))

        story.append(Spacer(1, 3 * mm))

    elif quark_status == "COMPLETED":
        story.append(Paragraph(
            "Quark completed but no behavioral findings were recorded.",
            styles["DojiBody"],
        ))

    else:
        story.append(Paragraph(
            "Quark analysis was unavailable or did not complete. "
            "See engine errors and limitations in the JSON report.",
            styles["DojiBody"],
        ))

    for limitation in quark.get("limitations") or []:
        story.append(Paragraph(
            "• " + safe(limitation),
            styles["DojiSmall"],
        ))

    story.append(Paragraph(
        "Quark findings are static behavioral indicators. "
        "They do not independently establish active malware execution "
        "or malicious intent. The original Quark classification and "
        "numerical score are reproduced without recalculation.",
        styles["DojiSmall"],
    ))


    story.append(Paragraph("VirusTotal Reputation", styles["SectionHeading"]))
    vt_rows = [
        ["Metric", "Result"],
        ["Lookup status", safe(vt.get("status"))],
        ["Malicious detections", safe(stats.get("malicious", "Not available"))],
        ["Suspicious detections", safe(stats.get("suspicious", "Not available"))],
        ["Undetected", safe(stats.get("undetected", "Not available"))],
        ["Timed out", safe(stats.get("timeout", "Not available"))],
        ["Reputation", safe(vt.get("reputation", "Not available"))],
        ["Last analysis timestamp", safe(vt.get("last_analysis_date", "Not available"))],
        ["Report URL", safe(vt.get("permalink", "Not available"))],
    ]
    story.append(make_table(vt_rows, [48 * mm, 128 * mm]))

    story.append(Paragraph("Requested Android Permissions", styles["SectionHeading"]))
    story.append(Paragraph(
        f"Total permissions recorded: {len(permissions)}",
        styles["DojiBody"],
    ))
    if permissions:
        permission_rows = [["#", "Permission"]]
        for index, permission in enumerate(permissions, 1):
            permission_rows.append([str(index), safe(permission)])
        story.append(make_table(permission_rows, [12 * mm, 164 * mm]))
    else:
        story.append(Paragraph(
            "No requested permissions were recorded in this report.",
            styles["DojiBody"],
        ))

    story.append(Paragraph("Findings", styles["SectionHeading"]))
    if findings:
        for index, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                story.append(Paragraph(
                    f"{index}. {safe(finding)}", styles["DojiBody"]
                ))
                continue

            finding_type = str(finding.get("type") or "security_finding")
            rule_name = finding.get("rule") or finding.get("name")
            severity = str(finding.get("severity") or "UNSPECIFIED").upper()
            evidence = finding.get("evidence") or {}
            details = finding.get("details") or finding.get("description") or ""

            if finding_type == "yara_rule_match":
                title = rule_name or "YARA rule match"
            elif finding_type == "signature_verification_failure":
                title = "APK signature verification failed"
            else:
                title = finding.get("title") or finding.get("name") or finding_type.replace("_", " ").title()

            story.append(Paragraph(
                f"{index}. {safe(title)}", styles["DojiBody"]
            ))

            finding_rows = [
                ["Field", "Result"],
                ["Finding type", safe(finding_type.replace("_", " ").title())],
                ["Severity", safe(severity)],
            ]

            if rule_name:
                finding_rows.append(["Rule", safe(rule_name)])

            if isinstance(evidence, dict):
                matched_files = evidence.get("matched_files")
                evidence_text = evidence.get("evidence")
                if matched_files:
                    evidence_text = ", ".join(str(item) for item in matched_files)
                if evidence_text:
                    finding_rows.append(["Evidence", safe(evidence_text)])

                if evidence.get("verified") is False:
                    finding_rows.append([
                        "Signature status",
                        "Not verified; the APK format or signature could not be validated."
                    ])

            elif evidence:
                finding_rows.append(["Evidence", safe(evidence)])

            story.append(make_table(finding_rows, [48 * mm, 128 * mm]))

            if details:
                story.append(Paragraph(
                    f"<b>Details:</b> {safe(details)}",
                    styles["DojiBody"],
                ))

            if finding_type == "yara_rule_match":
                story.append(Paragraph(
                    "Interpretation: This is a heuristic indicator, not proof of malware.",
                    styles["DojiBody"],
                ))

            story.append(Spacer(1, 3 * mm))
    else:
        story.append(Paragraph(
            "No finding entries were recorded. This does not independently "
            "prove that the APK is safe.",
            styles["DojiBody"],
        ))

    if suspicious_reasons:
        story.append(Paragraph(
            "Suspicious Reasons", styles["SectionHeading"]
        ))
        for reason in suspicious_reasons:
            story.append(Paragraph(
                f"• {safe(reason)}", styles["DojiBody"]
            ))
            story.append(Spacer(1, 1 * mm))

    story.append(Paragraph("Assessment Limitations", styles["SectionHeading"]))
    story.append(Paragraph(
        "A verdict of NO KNOWN THREAT DETECTED is not a guarantee of safety. "
        "Reputation services may miss threats, and analysis results can be "
        "incomplete. APK permissions and signatures provide context, not "
        "proof of malicious or benign behavior. This report covers only the "
        "file and checks represented in the source JSON report.",
        styles["DojiBody"],
    ))

    if limitations:
        for limitation in limitations:
            story.append(Paragraph(
                f"• {safe(limitation)}", styles["DojiSmall"]
            ))
            story.append(Spacer(1, 1 * mm))

    if errors:
        story.append(Paragraph("Analysis Notes", styles["SectionHeading"]))
        for error in errors:
            error_text = str(error)
            lower_error = error_text.lower()

            if "no androidmanifest.xml found" in lower_error:
                display_error = (
                    "APK metadata could not be extracted because "
                    "AndroidManifest.xml is missing. This can happen when "
                    "the input is not a complete, valid APK file."
                )
            else:
                display_error = error_text

            story.append(Paragraph(
                f"• {safe(display_error)}", styles["DojiBody"]
            ))
            story.append(Spacer(1, 1 * mm))

    def draw_page(canvas, document):
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0, height - 5 * mm, width, 5 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(BORDER)
        canvas.line(
            document.leftMargin,
            13 * mm,
            width - document.rightMargin,
            13 * mm,
        )
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(
            document.leftMargin,
            8 * mm,
            "DOJI • APK SECURITY ASSESSMENT • CONFIDENTIALITY DEPENDS ON HANDLING",
        )
        canvas.drawRightString(
            width - document.rightMargin,
            8 * mm,
            f"Page {document.page}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return output_path


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 pdf_report.py reports/DOJI-APK-report.json")
        raise SystemExit(2)

    try:
        output = generate_pdf(sys.argv[1])
    except Exception as exc:
        print(f"PDF generation failed: {exc}")
        raise SystemExit(1)

    print("Doji PDF report generated:")
    print(output)


if __name__ == "__main__":
    main()
