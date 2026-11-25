"""Professional report viewer for Doji Mobile Security."""

import tkinter as tk
from pathlib import Path
from tkinter import ttk

BG = "#10151f"
PANEL = "#192231"
TEXT = "#e7edf7"
MUTED = "#9eacc0"
ACCENT = "#56d6b0"


class ProfessionalReportViewer(tk.Toplevel):
    """Scrollable security assessment report window."""

    def __init__(self, parent, report, report_name):
        super().__init__(parent)

        self.report = report
        self.report_name = report_name

        self.title(f"Doji Security Report | {report_name}")
        self.geometry("950x720")
        self.minsize(750, 550)
        self.configure(bg=BG)

        self.build_interface()

        if self.report.get("report_type") == "android_forensic":
            self.add_forensic_pdf_controls()


    def add_analysis_sections(self):
        if self.report.get("report_type") == "android_unified_security":
            from collections import Counter

            apps = self.report.get("applications") or []

            tk.Label(
                self.content,
                text="Application Security Analysis",
                font=("Arial", 17, "bold"),
                bg=BG, fg=TEXT,
            ).pack(anchor="w", pady=(18, 12))

            engines = [
                ("YARA Malware Detection", "yara"),
                ("Quark Behavioral Analysis", "quark"),
                ("VirusTotal Reputation", "virustotal"),
                ("APK Digital Signature", "signature"),
                ("Permission Analysis", "permissions"),
            ]

            for title, key in engines:
                counts = Counter()

                for app in apps:
                    analysis = app.get("apk_analysis") or {}
                    checks = analysis.get("checks") or {}
                    check = checks.get(key) or {}

                    status = str(
                        check.get("engine_status")
                        or check.get("status")
                        or "NOT RECORDED"
                    ).upper()

                    counts[status] += 1

                details = " | ".join(
                    f"{status}: {count}"
                    for status, count in sorted(counts.items())
                ) or "No application results recorded."

                panel = tk.Frame(
                    self.content, bg=PANEL, padx=18, pady=14
                )
                panel.pack(fill="x", pady=5)

                tk.Label(
                    panel, text=title,
                    font=("Arial", 12, "bold"),
                    bg=PANEL, fg=TEXT,
                ).pack(anchor="w")

                tk.Label(
                    panel,
                    text=f"Applications recorded: {len(apps)}",
                    font=("Arial", 10),
                    bg=PANEL, fg=MUTED,
                ).pack(anchor="w", pady=(6, 3))

                tk.Label(
                    panel, text=details,
                    font=("Arial", 10),
                    bg=PANEL, fg=TEXT,
                    wraplength=750, justify="left",
                ).pack(anchor="w")

            return

        if self.report.get("report_type") == "iphone_full_security":
            report = self.report
            forensic = report.get("forensic_analysis") or {}
            evidence = report.get("forensic_evidence") or {}

            if not isinstance(forensic, dict):
                forensic = {}
            if not isinstance(evidence, dict):
                evidence = {}

            matches = forensic.get("ioc_match_count")
            verified = (
                forensic.get("status") == "COMPLETED"
                and forensic.get("evidence_integrity") == "UNCHANGED"
                and forensic.get("exit_code") == 0
                and forensic.get("findings_generated") is True
                and isinstance(matches, int)
                and not isinstance(matches, bool)
                and matches >= 0
            )

            tk.Label(
                self.content,
                text="iPhone Forensic Analysis",
                font=("Arial", 17, "bold"),
                bg=BG, fg=TEXT,
            ).pack(anchor="w", pady=(18, 12))

            if verified:
                mvt_status = "COMPLETED"
                mvt_details = "MVT analysis completed with verified findings."
                ioc_status = "MATCHES REPORTED" if matches else "NO MATCHES REPORTED"
                ioc_details = (
                    f"{matches} IOC matches in analyzed evidence. "
                    "This does not establish that the device is malware-free."
                )
            elif forensic:
                mvt_status = "INCOMPLETE"
                mvt_details = "Forensic analysis did not produce verified findings."
                ioc_status = "NOT VERIFIED"
                ioc_details = "No verified IOC result is available."
            else:
                mvt_status = "NOT RUN"
                mvt_details = "No verified iPhone forensic analysis was performed."
                ioc_status = "NOT RUN"
                ioc_details = "IOC matching requires supported forensic evidence."

            panels = [
                ("MVT Spyware Analysis", mvt_status, mvt_details),
                ("Known Spyware IOC Matching", ioc_status, ioc_details),
                (
                    "Verified iPhone Backups",
                    str(evidence.get("verified_backup_count", 0)),
                    "Existing backups verified as belonging to this device.",
                ),
            ]

            for title, status, details in panels:
                panel = tk.Frame(
                    self.content, bg=PANEL, padx=18, pady=14
                )
                panel.pack(fill="x", pady=5)

                tk.Label(
                    panel, text=title,
                    font=("Arial", 12, "bold"),
                    bg=PANEL, fg=TEXT,
                ).pack(anchor="w")

                tk.Label(
                    panel, text=f"Status: {status}",
                    font=("Arial", 10, "bold"),
                    bg=PANEL,
                    fg=ACCENT if status == "COMPLETED" else "#f0c674",
                ).pack(anchor="w", pady=(6, 3))

                tk.Label(
                    panel, text=details,
                    font=("Arial", 10),
                    bg=PANEL, fg=MUTED,
                    wraplength=750, justify="left",
                ).pack(anchor="w")

            return

        """Display the actual APK analysis check results."""
        report = self.report
        checks = report.get("checks") or {}

        heading = tk.Label(
            self.content,
            text="Security Analysis Checks",
            font=("Arial", 17, "bold"),
            bg=BG, fg=TEXT,
        )
        heading.pack(anchor="w", pady=(18, 12))

        check_names = [
            ("YARA Malware Detection", "yara"),
            ("VirusTotal Reputation", "virustotal"),
            ("APK Digital Signature", "signature"),
            ("Permission Analysis", "permissions"),
        ]

        for title, key in check_names:
            check = checks.get(key)

            if not isinstance(check, dict):
                status = "NOT AVAILABLE"
                details = "No structured result recorded."
            else:
                status = str(check.get("status", "UNKNOWN"))
                details = ""

                if key == "yara":
                    count = check.get("match_count")
                    if count is not None:
                        details = f"YARA rule matches: {count}"
                elif key == "virustotal":
                    stats = check.get("analysis_stats") or {}
                    if isinstance(stats, dict):
                        details = (
                            f"Malicious: {stats.get('malicious', 0)}  |  "
                            f"Suspicious: {stats.get('suspicious', 0)}"
                        )
                elif key == "signature":
                    verified = check.get("verified")
                    if verified is not None:
                        details = (
                            "Signature verified"
                            if verified else
                            "Signature not verified"
                        )

                if not details:
                    details = str(
                        check.get("details")
                        or "Refer to the full assessment report."
                    )

            panel = tk.Frame(
                self.content, bg=PANEL, padx=18, pady=14
            )
            panel.pack(fill="x", pady=5)

            tk.Label(
                panel,
                text=title,
                font=("Arial", 12, "bold"),
                bg=PANEL, fg=TEXT,
            ).pack(anchor="w")

            tk.Label(
                panel,
                text=f"Status: {status}",
                font=("Arial", 10, "bold"),
                bg=PANEL,
                fg=(
                    ACCENT if status in ("PASS", "COMPLETED", "FOUND")
                    else "#f0c674"
                ),
            ).pack(anchor="w", pady=(6, 3))

            tk.Label(
                panel,
                text=details,
                font=("Arial", 10),
                bg=PANEL, fg=MUTED,
                wraplength=750, justify="left",
            ).pack(anchor="w")


    def show_finding_details(self, finding, number):
        """Present recorded security evidence in accessible language."""
        import json

        window = tk.Toplevel(self)
        window.title(f"Doji - Finding {number}")
        window.geometry("820x680")
        window.configure(bg=BG)

        outer = tk.Frame(window, bg=BG, padx=20, pady=18)
        outer.pack(fill="both", expand=True)

        tk.Label(
            outer,
            text=f"Security Finding {number}",
            font=("Arial", 19, "bold"),
            bg=BG,
            fg=TEXT,
        ).pack(anchor="w", pady=(0, 12))

        text = tk.Text(
            outer, bg=PANEL, fg=TEXT,
            font=("Arial", 11), wrap="word",
            padx=18, pady=16, relief="flat",
        )
        text.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            outer, orient="vertical", command=text.yview
        )
        scrollbar.pack(side="right", fill="y")
        text.configure(yscrollcommand=scrollbar.set)

        text.tag_configure(
            "heading", foreground=ACCENT,
            font=("Arial", 12, "bold"),
            spacing1=12, spacing3=6,
        )

        def add(title, body):
            text.insert("end", title + "\n", "heading")
            text.insert("end", str(body) + "\n\n")

        if self.report.get("report_type") == "android_forensic":
            add("Finding", finding.get("title") or "Forensic observation")
            add("Classification", finding.get("classification") or "Unknown")
            add("Severity", finding.get("severity") or "Not recorded")
            add("Confidence", finding.get("confidence") or "Not recorded")
            add("What Doji Found", finding.get("explanation") or "No explanation recorded.")
            add("Recommended Action", finding.get("recommendation") or "Review the evidence.")

            technical_data = json.dumps(finding, indent=2, default=str)
            text.mark_set("technical_start", "end")
            text.configure(state="disabled")

            show_technical = tk.BooleanVar(value=False)

            def toggle_forensic_evidence():
                text.configure(state="normal")
                text.delete("technical_start", "end")
                if show_technical.get():
                    add("Original Finding Data", technical_data)
                text.configure(state="disabled")

            tk.Checkbutton(
                window,
                text="Show technical evidence (advanced users)",
                variable=show_technical,
                command=toggle_forensic_evidence,
                bg=BG, fg=TEXT, selectcolor=PANEL,
                activebackground=BG, activeforeground=TEXT,
            ).pack(anchor="w", padx=20, pady=(0, 14))
            return

        status = str(finding.get("status") or "UNKNOWN").upper()
        severity = finding.get("severity") or "Not recorded"
        confidence = finding.get("confidence") or "Not recorded"
        check = finding.get("check") or finding.get("type") or "Security check"

        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {"recorded_evidence": evidence}

        indicators = evidence.get("findings") or []
        if not isinstance(indicators, list):
            indicators = []

        add("Security Check", check)
        add(
            "Assessment",
            f"Status: {status}\nSeverity: {severity}\n"
            f"Confidence: {confidence}"
        )

        if status == "PASS":
            add(
                "What Doji Found",
                finding.get("details") or
                "This particular check passed."
            )
            add(
                "What This Means",
                "No problem was identified by this specific check. "
                "This does not guarantee the entire phone is safe."
            )
            add(
                "What You Should Do",
                finding.get("remediation") or
                "No action indicated by this check."
            )
        else:
            observations = []
            actions = []

            for item in indicators:
                if not isinstance(item, dict):
                    continue

                kind = item.get("type")
                rule = str(item.get("rule") or "")
                recorded = item.get("evidence")

                if kind == "sensitive_permission_review":
                    permissions = recorded if isinstance(recorded, list) else []
                    for permission in permissions:
                        observations.append(
                            "The application declares the permission "
                            + str(permission) + "."
                        )
                    actions.append(
                        "Check the application's permissions and special "
                        "access in Android Settings. A declared permission "
                        "does not prove it has been granted."
                    )

                elif kind in ("yara_rule_match", "split_apk_yara_match"):
                    if "Overlay" in rule:
                        observations.append(
                            "Doji found code patterns associated with "
                            "displaying content over other apps."
                        )
                        actions.append(
                            "Review permission to display over other apps "
                            "and investigate unexpected pop-ups."
                        )
                    elif "SMS" in rule:
                        observations.append(
                            "Doji found code patterns associated with "
                            "SMS-related functions."
                        )
                        actions.append(
                            "Review SMS access and investigate unexpected "
                            "messages or charges."
                        )
                    elif "Command_Execution" in rule:
                        observations.append(
                            "Doji found code patterns associated with "
                            "executing system commands."
                        )
                        actions.append(
                            "Verify the application's source and investigate "
                            "unusual behavior."
                        )
                    else:
                        observations.append(
                            "A malware-detection rule matched code in "
                            "this application."
                        )

            add(
                "What Doji Found",
                "\n\n".join(dict.fromkeys(observations))
                if observations else
                finding.get("details") or
                "A security observation was recorded."
            )

            add(
                "What This Means",
                "These observations require review, but they do not "
                "confirm that the application is malware. Legitimate "
                "applications can contain similar permissions or code."
            )

            if not actions:
                actions.append(
                    finding.get("remediation") or
                    "Review the application and its source."
                )

            add(
                "What You Should Do",
                "\n\n".join(
                    f"{i}. {action}"
                    for i, action in enumerate(dict.fromkeys(actions), 1)
                )
            )

        limitations = finding.get("limitations") or []
        if limitations:
            add(
                "What This Scan Could Not Verify",
                "\n".join(map(str, limitations))
            )

        technical_data = json.dumps(
            {
                "finding_id": finding.get("finding_id"),
                "check": check,
                "status": status,
                "severity": severity,
                "confidence": confidence,
                "evidence": evidence,
            },
            indent=2,
            default=str,
        )

        text.mark_set("technical_start", "end")
        text.configure(state="disabled")

        show_technical = tk.BooleanVar(value=False)

        def toggle_technical():
            text.configure(state="normal")
            text.delete("technical_start", "end")
            if show_technical.get():
                add("Technical Evidence", technical_data)
            text.configure(state="disabled")

        tk.Checkbutton(
            window,
            text="Show technical evidence (advanced users)",
            variable=show_technical,
            command=toggle_technical,
            bg=BG, fg=TEXT, selectcolor=PANEL,
            activebackground=BG, activeforeground=TEXT,
        ).pack(anchor="w", padx=20, pady=(0, 14))

    def add_findings_sections(self):
        """Display individually accessible security findings."""
        report = self.report

        self.findings_anchor = tk.Frame(
            self.content, bg=BG, height=1
        )
        self.findings_anchor.pack(fill="x")

        tk.Label(
            self.content,
            text="Security Findings",
            font=("Arial", 17, "bold"),
            bg=BG,
            fg=TEXT,
        ).pack(anchor="w", pady=(22, 12))

        findings = report.get("findings") or []

        if not findings:
            tk.Label(
                self.content,
                text="No security findings recorded.",
                bg=BG,
                fg=MUTED,
            ).pack(anchor="w")

        for index, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue

            status = str(finding.get("status") or "UNKNOWN").upper()
            severity = str(finding.get("severity") or "UNKNOWN").upper()
            check = finding.get("check") or finding.get("type") or "Security observation"

            if report.get("report_type") == "android_forensic":
                status = str(
                    finding.get("classification") or "OBSERVATION"
                ).upper()
                check = (
                    finding.get("title")
                    or "Forensic observation"
                )

            color = (
                "#ff7777" if severity in ("HIGH", "CRITICAL")
                else "#f0c674" if status == "WARNING"
                else ACCENT if status == "PASS"
                else TEXT
            )

            button = tk.Button(
                self.content,
                text=(
                    f"Finding {index} | {status} | {severity}\n"
                    f"{check}\n"
                    "Click to view evidence and precautions"
                ),
                command=lambda f=finding, n=index:
                    self.show_finding_details(f, n),
                bg=PANEL,
                fg=color,
                activebackground=PANEL,
                activeforeground=TEXT,
                font=("Arial", 11),
                justify="left",
                anchor="w",
                wraplength=700,
                relief="flat",
                cursor="hand2",
                padx=18,
                pady=14,
            )
            button.pack(fill="x", pady=5)

        limitations = report.get("limitations") or []

        if limitations:
            notes_panel = tk.Frame(self.content, bg=BG)
            notes_panel.pack(fill="x", pady=(22, 12))

            notes_content = tk.Frame(notes_panel, bg=BG)

            def toggle_notes():
                if notes_content.winfo_manager():
                    notes_content.pack_forget()
                    notes_button.configure(
                        text="Scan Coverage & Important Notes  +"
                    )
                else:
                    notes_content.pack(fill="x", pady=(8, 0))
                    notes_button.configure(
                        text="Scan Coverage & Important Notes  −"
                    )

            notes_button = tk.Button(
                notes_panel,
                text="Scan Coverage & Important Notes  +",
                command=toggle_notes,
                font=("Arial", 13, "bold"),
                bg=PANEL,
                fg=TEXT,
                activebackground=PANEL,
                activeforeground=ACCENT,
                relief="flat",
                cursor="hand2",
                anchor="w",
                padx=16,
                pady=14,
            )
            notes_button.pack(fill="x")

            for limitation in limitations:
                tk.Label(
                    notes_content,
                    text=str(limitation),
                    bg=PANEL,
                    fg=MUTED,
                    wraplength=700,
                    justify="left",
                    anchor="w",
                    padx=16,
                    pady=10,
                ).pack(fill="x", pady=3)

        errors = report.get("errors") or []

        if errors:
            tk.Label(
                self.content,
                text="Analysis Errors",
                font=("Arial", 17, "bold"),
                bg=BG,
                fg=TEXT,
            ).pack(anchor="w", pady=(22, 12))

            for error in errors:
                tk.Label(
                    self.content,
                    text=str(error),
                    bg=PANEL,
                    fg="#ff7777",
                    wraplength=720,
                    justify="left",
                    padx=16,
                    pady=12,
                ).pack(fill="x", pady=4)

        tk.Label(
            self.content,
            text=(
                "Doji reports evidence-based observations. "
                "A completed scan does not guarantee that a device "
                "is free from compromise."
            ),
            bg=BG,
            fg=MUTED,
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(22, 14))

    def jump_to_findings(self):
        """Scroll directly to the Security Findings section."""
        self.update_idletasks()

        anchor = getattr(self, "findings_anchor", None)
        canvas = getattr(self, "report_canvas", None)

        if anchor is None or canvas is None:
            return

        region = canvas.bbox("all")
        if not region:
            return

        total_height = region[3] - region[1]
        visible_height = canvas.winfo_height()
        scrollable_height = max(
            total_height - visible_height, 0
        )

        if scrollable_height <= 0:
            return

        position = (
            anchor.winfo_rooty()
            - self.content.winfo_rooty()
        )

        canvas.yview_moveto(
            max(0.0, min(1.0, position / scrollable_height))
        )


    def add_forensic_pdf_controls(self):
        """Provide PDF actions for the selected forensic case."""
        import shutil
        import subprocess
        from tkinter import filedialog, messagebox

        if self.report.get("report_type") != "android_forensic":
            return

        case_id = self.report.get("assessment_id")
        if (
            not isinstance(case_id, str)
            or not case_id.startswith("DOJI-FORENSIC-")
            or not all(c.isalnum() or c == "-" for c in case_id)
        ):
            return

        pdf_path = (
            Path(__file__).resolve().parent.parent
            / "reports" / f"{case_id}.pdf"
        )

        toolbar = tk.Frame(self, bg=BG, padx=20, pady=12)
        toolbar.pack(side="bottom", fill="x")

        def view_pdf():
            if not pdf_path.is_file() or pdf_path.is_symlink():
                messagebox.showerror(
                    "PDF unavailable",
                    "No PDF report exists for this investigation.",
                    parent=self,
                )
                return
            try:
                subprocess.Popen(["xdg-open", str(pdf_path)])
            except OSError as exc:
                messagebox.showerror(
                    "PDF error", str(exc), parent=self
                )

        def export_pdf():
            if not pdf_path.is_file() or pdf_path.is_symlink():
                messagebox.showerror(
                    "PDF unavailable",
                    "No PDF report exists for this investigation.",
                    parent=self,
                )
                return

            destination = filedialog.asksaveasfilename(
                parent=self,
                title="Export forensic PDF",
                initialfile=pdf_path.name,
                defaultextension=".pdf",
                filetypes=[("PDF report", "*.pdf")],
            )
            if not destination:
                return

            try:
                if Path(destination).resolve() == pdf_path.resolve():
                    return
                shutil.copyfile(pdf_path, destination)
                messagebox.showinfo(
                    "PDF exported",
                    "Forensic PDF exported successfully.",
                    parent=self,
                )
            except OSError as exc:
                messagebox.showerror(
                    "Export failed", str(exc), parent=self
                )

        for label, command in (
            ("View PDF", view_pdf),
            ("Export PDF", export_pdf),
            ("Close Report", self.destroy),
        ):
            tk.Button(
                toolbar,
                text=label,
                command=command,
                bg=PANEL,
                fg=TEXT,
                activebackground="#30445a",
                activeforeground=TEXT,
                relief="flat",
                padx=16,
                pady=10,
            ).pack(side="left", padx=6)

    def build_interface(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=28, pady=(24, 16))

        tk.Label(
            header,
            text="DOJI",
            font=("Arial", 26, "bold"),
            bg=BG,
            fg=ACCENT,
        ).pack(anchor="w")

        tk.Label(
            header,
            text=(
                "ANDROID ADVANCED FORENSIC REPORT"
                if self.report.get("report_type") == "android_forensic"
                else "MOBILE SECURITY ASSESSMENT REPORT"
            ),
            font=("Arial", 11, "bold"),
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w", pady=(2, 0))

        separator = tk.Frame(
            self, bg="#2b394b", height=1
        )
        separator.pack(fill="x", padx=28)

        container = tk.Frame(self, bg=BG)
        container.pack(
            fill="both", expand=True,
            padx=28, pady=18
        )

        canvas = tk.Canvas(
            container,
            bg=BG,
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=canvas.yview,
        )

        content = tk.Frame(canvas, bg=BG)

        content.bind(
            "<Configure>",
            lambda event: canvas.configure(
                scrollregion=canvas.bbox("all")
            ),
        )

        canvas_window = canvas.create_window(
            (0, 0),
            window=content,
            anchor="nw",
        )

        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(
                canvas_window,
                width=event.width,
            ),
        )

        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self.report_canvas = canvas
        self.content = content

        # Mouse-wheel scrolling for Windows and Linux/X11.
        def scroll_report(event):
            if event.num == 4:
                canvas.yview_scroll(-3, "units")
            elif event.num == 5:
                canvas.yview_scroll(3, "units")
            elif event.delta:
                direction = -1 if event.delta > 0 else 1
                canvas.yview_scroll(direction * 3, "units")

        def bind_report_scroll(widget):
            widget.bind("<MouseWheel>", scroll_report, add="+")
            widget.bind("<Button-4>", scroll_report, add="+")
            widget.bind("<Button-5>", scroll_report, add="+")

            for child in widget.winfo_children():
                bind_report_scroll(child)

        def refresh_scroll_bindings():
            bind_report_scroll(content)

        self.after_idle(refresh_scroll_bindings)
        bind_report_scroll(canvas)

        tk.Label(
            content,
            text="Security Assessment Overview",
            font=("Arial", 19, "bold"),
            bg=BG,
            fg=TEXT,
        ).pack(anchor="w", pady=(8, 16))

        report = self.report
        target = report.get("target") or {}
        completeness = report.get("scan_completeness") or {}
        findings = report.get("findings") or []

        verdict = str(report.get("verdict") or "NOT ASSESSED")

        if report.get("report_type") == "android_unified_security":
            summary = report.get("summary") or {}
            coverage_status = str(
                report.get("assessment_coverage_status") or "UNKNOWN"
            ).upper()

            warnings = sum(
                1 for item in findings
                if isinstance(item, dict)
                and str(item.get("status") or "").upper() == "WARNING"
            )

            high_risk_warnings = any(
                isinstance(item, dict)
                and str(item.get("status") or "").upper() == "WARNING"
                and str(item.get("severity") or "").upper()
                in ("HIGH", "CRITICAL")
                for item in findings
            )

            if coverage_status != "COMPLETED":
                verdict = "ASSESSMENT INCOMPLETE"
            elif high_risk_warnings:
                verdict = "SUSPICIOUS"
            elif warnings:
                verdict = "REVIEW REQUIRED"
            else:
                verdict = "ASSESSMENT COMPLETED"

        coverage = str(
            completeness.get("status")
            or report.get("assessment_coverage_status")
            or "UNKNOWN"
        )

        panel_heading = "THREAT ASSESSMENT"
        panel_note = (
            "A static assessment does not guarantee device "
            "or application safety."
        )

        if report.get("report_type") == "iphone_full_security":
            panel_heading = "IPHONE FORENSIC ASSESSMENT"
            panel_note = (
                "Results cover only accessible evidence. "
                "No assessment guarantees an iPhone is malware-free."
            )

            forensic = report.get("forensic_analysis") or {}
            if not isinstance(forensic, dict):
                forensic = {}

            matches = forensic.get("ioc_match_count")
            verified = (
                forensic.get("status") == "COMPLETED"
                and forensic.get("evidence_integrity") == "UNCHANGED"
                and forensic.get("exit_code") == 0
                and forensic.get("findings_generated") is True
                and isinstance(matches, int)
                and not isinstance(matches, bool)
                and matches >= 0
            )

            if verified and matches > 0:
                verdict = "IOC MATCHES REPORTED"
            elif verified:
                verdict = "FORENSIC ANALYSIS COMPLETED"
            elif forensic:
                verdict = "FORENSIC ANALYSIS INCOMPLETE"
            else:
                verdict = "DEVICE INFORMATION ONLY"

        if report.get("report_type") == "android_forensic":
            metadata = report.get("forensic_metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}

            integrity = metadata.get("evidence_integrity") or {}
            if not isinstance(integrity, dict):
                integrity = {}

            panel_heading = "ANDROID FORENSIC INVESTIGATION"
            panel_note = (
                "Results reflect only the evidence analyzed. "
                "A completed investigation does not guarantee "
                "the absence of malware or spyware."
            )

            if (
                metadata.get("status") == "COMPLETED"
                and integrity.get("status") == "UNCHANGED"
            ):
                verdict = "FORENSIC INVESTIGATION COMPLETED"
            else:
                verdict = "FORENSIC INVESTIGATION INCOMPLETE"

        if verdict == "NO KNOWN THREAT DETECTED":
            verdict_color = ACCENT
        elif verdict in (
            "SUSPICIOUS",
            "MALICIOUS",
            "IOC MATCHES REPORTED",
        ):
            verdict_color = "#ff7777"
        else:
            verdict_color = "#f0c674"

        verdict_panel = tk.Frame(
            content, bg=PANEL, padx=22, pady=20
        )
        verdict_panel.pack(fill="x", pady=(0, 18))

        tk.Label(
            verdict_panel,
            text=panel_heading,
            font=("Arial", 10, "bold"),
            bg=PANEL, fg=MUTED,
        ).pack(anchor="w")

        tk.Label(
            verdict_panel,
            text=verdict,
            font=("Arial", 18, "bold"),
            bg=PANEL, fg=verdict_color,
            wraplength=750, justify="left",
        ).pack(anchor="w", pady=(8, 6))

        tk.Label(
            verdict_panel,
            text=panel_note,
            font=("Arial", 10),
            bg=PANEL, fg=MUTED,
            wraplength=750, justify="left",
        ).pack(anchor="w")

        overview = tk.Frame(content, bg=BG)
        overview.pack(fill="x", pady=(0, 18))

        if report.get("report_type") == "android_unified_security":
            apps = report.get("applications") or []

            details = [
                ("APPLICATIONS RECORDED", str(len(apps))),
                ("ASSESSMENT TYPE",
                 "Android Quick Security Scan"
                 if report.get("scan_mode") == "quick"
                 else "Android Full Security Scan"),
                ("SCAN COMPLETENESS", coverage),
                ("SECURITY FINDINGS", str(len(findings))),
            ]

        elif report.get("report_type") == "iphone_full_security":
            summary = report.get("summary") or {}
            forensic = report.get("forensic_analysis") or {}

            if not isinstance(summary, dict):
                summary = {}
            if not isinstance(forensic, dict):
                forensic = {}

            matches = forensic.get("ioc_match_count")
            verified = (
                forensic.get("status") == "COMPLETED"
                and forensic.get("evidence_integrity") == "UNCHANGED"
                and forensic.get("exit_code") == 0
                and forensic.get("findings_generated") is True
                and isinstance(matches, int)
                and not isinstance(matches, bool)
                and matches >= 0
            )

            details = [
                ("DEVICE", target.get("name") or "Unknown iPhone"),
                ("PLATFORM", target.get("platform") or "Apple"),
                (
                    "SECURITY CHECKS",
                    f"{summary.get('passed', 0)} passed | "
                    f"{summary.get('warnings', 0)} warnings | "
                    f"{summary.get('not_run', 0)} not run",
                ),
                (
                    "MVT / IOC ANALYSIS",
                    (
                        f"{matches} IOC matches"
                        if verified
                        else "Not verified"
                    ),
                ),
            ]
        elif report.get("report_type") == "android_forensic":
            metadata = report.get("forensic_metadata") or {}
            integrity = metadata.get("evidence_integrity") or {}

            if not isinstance(metadata, dict):
                metadata = {}
            if not isinstance(integrity, dict):
                integrity = {}

            details = [
                ("CASE ID", metadata.get("case_id") or "Unknown"),
                ("INVESTIGATION STATUS", metadata.get("status") or "Unknown"),
                ("EVIDENCE INTEGRITY", integrity.get("status") or "Unknown"),
                ("FORENSIC FINDINGS", str(len(findings))),
            ]
        else:
            details = [
                ("APPLICATION", target.get("file_name") or "Not specified"),
                ("PACKAGE", target.get("package_name") or "Not specified"),
                ("SCAN COMPLETENESS", coverage),
                ("SECURITY FINDINGS", str(len(findings))),
            ]

        for index, (heading, value) in enumerate(details):
            card = tk.Frame(
                overview, bg=PANEL, padx=16, pady=14
            )
            card.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=5, pady=5,
            )

            tk.Label(
                card, text=heading,
                font=("Arial", 9, "bold"),
                bg=PANEL, fg=MUTED,
            ).pack(anchor="w")

            tk.Label(
                card, text=str(value),
                font=("Arial", 12, "bold"),
                bg=PANEL, fg=TEXT,
                wraplength=330, justify="left",
            ).pack(anchor="w", pady=(6, 0))

        overview.columnconfigure(0, weight=1)
        overview.columnconfigure(1, weight=1)

        tk.Label(
            content,
            text=f"Report: {self.report_name}",
            font=("Arial", 9),
            bg=BG, fg=MUTED,
            wraplength=750, justify="left",
        ).pack(anchor="w", pady=(4, 12))

        self.add_analysis_sections()
        self.add_findings_sections()

