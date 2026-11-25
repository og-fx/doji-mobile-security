#!/usr/bin/env python3
"""Generate read-only PDF summaries of Doji forensic investigations."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)

from pdf_report import (
    REPORT_DIR,
    safe,
    format_timestamp,
    make_styles,
    make_table,
)


BASE_DIR = Path(__file__).resolve().parent
FORENSIC_RESULTS = BASE_DIR / "forensic" / "results"


def generate_forensic_pdf(metadata_path):
    """Generate a PDF without modifying forensic case evidence."""

    metadata_path = Path(metadata_path).expanduser()

    if metadata_path.is_symlink():
        raise ValueError("Symbolic-link metadata is not accepted.")

    metadata_path = metadata_path.resolve()
    case_dir = metadata_path.parent

    if (
        metadata_path.name != "case_metadata.json"
        or case_dir.is_symlink()
        or case_dir.parent != FORENSIC_RESULTS.resolve()
        or not case_dir.name.startswith("DOJI-FORENSIC-")
    ):
        raise ValueError("Invalid forensic case location.")

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    if not isinstance(metadata, dict):
        raise ValueError("Invalid forensic metadata format.")

    findings_path = case_dir / "doji_findings.json"
    findings_data = {}

    if findings_path.is_symlink():
        raise ValueError("Symbolic-link findings are not accepted.")

    if findings_path.is_file():
        findings_data = json.loads(
            findings_path.read_text(encoding="utf-8")
        )
        if not isinstance(findings_data, dict):
            raise ValueError("Invalid forensic findings format.")

    findings = findings_data.get("findings") or []
    correlated = findings_data.get("correlated_findings") or []
    limitations = findings_data.get("limitations") or []

    if not isinstance(findings, list):
        findings = []
    if not isinstance(correlated, list):
        correlated = []
    if not isinstance(limitations, list):
        limitations = []

    integrity = metadata.get("evidence_integrity") or {}
    if not isinstance(integrity, dict):
        integrity = {}

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIR / f"{case_dir.name}.pdf"

    styles = make_styles()

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="Doji Forensic Investigation Report",
        author="Doji Mobile Security Assessment",
    )

    story = []

    def heading(value):
        story.append(
            Paragraph(value, styles["SectionHeading"])
        )

    def body(value):
        story.append(
            Paragraph(safe(value), styles["DojiBody"])
        )
        story.append(Spacer(1, 2 * mm))

    story.append(
        Paragraph("DOJI", styles["DojiTitle"])
    )

    story.append(
        Paragraph(
            "MOBILE SECURITY ASSESSMENT<br/>"
            "FORENSIC INVESTIGATION REPORT",
            styles["DojiSubtitle"],
        )
    )

    status = str(metadata.get("status") or "UNKNOWN")

    story.append(
        Paragraph(
            f"INVESTIGATION STATUS: {safe(status)}",
            styles["DojiVerdict"],
        )
    )

    heading("Investigation Summary")

    rows = [
        ["Field", "Value"],
        ["Case ID", safe(metadata.get("case_id"))],
        ["Platform", safe(metadata.get("platform"))],
        ["Workflow", safe(metadata.get("workflow"))],
        ["Status", safe(status)],
        ["Started", safe(format_timestamp(
            metadata.get("created_utc")
        ))],
        ["Finished", safe(format_timestamp(
            metadata.get("finished_utc")
        ))],
        ["Return code", safe(metadata.get("return_code"))],
        ["PDF generated UTC", safe(
            datetime.now(timezone.utc).isoformat()
        )],
    ]

    story.append(
        make_table(rows, [48 * mm, 128 * mm])
    )

    heading("Evidence Integrity")

    integrity_rows = [
        ["Field", "Value"],
        ["Integrity status", safe(integrity.get("status"))],
        ["Content unchanged", safe(
            integrity.get("content_unchanged")
        )],
        ["SHA-256 before", safe(
            integrity.get("before_sha256")
        )],
        ["SHA-256 after", safe(
            integrity.get("after_sha256")
        )],
    ]

    story.append(
        make_table(integrity_rows, [48 * mm, 128 * mm])
    )

    if status != "COMPLETED":
        heading("Investigation Warning")
        body(
            "This investigation did not complete successfully. "
            "Its status does not establish whether malware "
            "is present or absent."
        )

    heading("Forensic Assessment Overview")

    overview_rows = [
        ["Field", "Result"],
        ["Investigation status", safe(status)],
        ["Evidence integrity", safe(integrity.get("status"))],
        ["Individual findings", str(len(findings))],
        ["Correlated findings", str(len(correlated))],
    ]

    story.append(
        make_table(overview_rows, [48 * mm, 128 * mm])
    )

    body(
        "Forensic findings are evidence-based observations. "
        "They do not automatically indicate confirmed malware "
        "or spyware infections. A completed investigation does "
        "not guarantee that a device is free from compromise."
    )

    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue

        title = finding.get("title") or f"Finding {index}"
        heading(f"Finding {index}: {title}")

        finding_rows = [
            [
                Paragraph("Field", styles["DojiSmall"]),
                Paragraph("Result", styles["DojiSmall"]),
            ],
        ]

        for label, key in (
            ("Finding ID", "finding_id"),
            ("Classification", "classification"),
            ("Severity", "severity"),
            ("Confidence", "confidence"),
            ("Source module", "source_module"),
            ("Application package", "package"),
            ("Event time", "event_time"),
            ("Original MVT observation", "original_message"),
            ("Explanation", "explanation"),
            ("Recommendation", "recommendation"),
        ):
            value = finding.get(key)

            if value is not None and value != "":
                finding_rows.append([
                    Paragraph(safe(label), styles["DojiSmall"]),
                    Paragraph(safe(value), styles["DojiBody"]),
                ])

        story.append(
            make_table(finding_rows, [48 * mm, 128 * mm])
        )

        story.append(Spacer(1, 4 * mm))

    for index, finding in enumerate(correlated, 1):
        if not isinstance(finding, dict):
            continue

        heading(f"Correlated Finding {index}")

        for label, key in (
            ("Classification", "classification"),
            ("Package", "package"),
            ("Permission", "permission"),
            ("Event count", "event_count"),
            ("Severity", "severity"),
            ("Confidence", "confidence"),
            ("Interpretation", "interpretation"),
            ("Recommendation", "recommendation"),
        ):
            body(
                f"{label}: {finding.get(key, 'Not available')}"
            )

    if limitations:
        heading("Assessment Limitations")
        for item in limitations:
            body(item)

    doc.build(story)

    return output_path


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python3 forensic_pdf_report.py "
            "forensic/results/CASE/case_metadata.json"
        )
        raise SystemExit(2)

    try:
        output = generate_forensic_pdf(sys.argv[1])
    except Exception as exc:
        print(f"Forensic PDF generation failed: {exc}")
        raise SystemExit(1)

    print("PASS: Forensic PDF generated.")
    print(output)


if __name__ == "__main__":
    main()
