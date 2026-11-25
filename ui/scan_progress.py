#!/usr/bin/env python3
"""Reusable progress window for Doji security assessments."""

import tkinter as tk
from tkinter import ttk


class ScanProgressWindow:
    """Display assessment progress without claiming false percentages."""

    def __init__(self, parent, title):
        self.window = tk.Toplevel(parent)
        self.window.title("Doji | Assessment Progress")
        self.window.geometry("560x310")
        self.window.resizable(False, False)
        self.window.configure(bg="#10151f")

        self.window.protocol("WM_DELETE_WINDOW", self.hide)

        self.title_label = tk.Label(
            self.window,
            text=title,
            font=("Arial", 16, "bold"),
            bg="#10151f",
            fg="#e7edf7",
            wraplength=460,
        )
        self.title_label.pack(pady=(24, 14))

        self.status_label = tk.Label(
            self.window,
            text="Preparing assessment...",
            font=("Arial", 11),
            bg="#10151f",
            fg="#56d6b0",
            wraplength=460,
        )
        self.status_label.pack(pady=(0, 18))

        self.progress = ttk.Progressbar(
            self.window,
            mode="indeterminate",
            length=430,
        )
        self.progress.pack(pady=(0, 18))
        self.progress.start(12)

        self.details_label = tk.Label(
            self.window,
            text="Doji is working. Please wait.",
            font=("Arial", 10),
            bg="#10151f",
            fg="#9eacc0",
            wraplength=460,
        )
        self.details_label.pack()

        # Current assessment stage.
        self.stage_label = tk.Label(
            self.window,
            text="CURRENT STAGE: INITIALIZING",
            font=("Arial", 10, "bold"),
            bg="#10151f",
            fg="#56d6b0",
            anchor="w",
        )
        self.stage_label.pack(
            fill="x",
            padx=24,
            pady=(8, 6),
        )

        # Live assessment activity log.
        self.window.geometry("600x520")

        # Keep the progress window centered over the Doji dashboard.
        parent.update_idletasks()
        self.window.update_idletasks()

        width, height = 600, 520
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2

        self.window.geometry(
            f"{width}x{height}+{max(0, x)}+{max(0, y)}"
        )
        self.window.transient(parent)

        activity_frame = tk.Frame(
            self.window,
            bg="#192231",
            padx=12,
            pady=10,
        )
        activity_frame.pack(
            fill="both",
            expand=True,
            padx=24,
            pady=(0, 12),
        )

        tk.Label(
            activity_frame,
            text="LIVE SCAN ACTIVITY",
            font=("Arial", 10, "bold"),
            bg="#192231",
            fg="#56d6b0",
        ).pack(anchor="w", pady=(0, 8))

        self.activity_log = tk.Text(
            activity_frame,
            height=5,
            bg="#10151f",
            fg="#e7edf7",
            font=("Arial", 13),
            relief="flat",
            bd=0,
            wrap="word",
            state="disabled",
            padx=10,
            pady=10,
        )
        self.activity_log.pack(fill="both", expand=True)

        self.cancel_callback = None

        self.cancel_button = tk.Button(
            self.window,
            text="Cancel Scan",
            command=self.request_cancel,
            state="disabled",
            bg="#9b3944",
            fg="#ffffff",
            padx=16,
            pady=6,
        )
        self.cancel_button.pack(side="bottom", pady=(8, 16))

        self.close_button = tk.Button(
            self.window,
            text="Close",
            command=self.window.destroy,
            bg="#26384d",
            fg="#ffffff",
            padx=20,
            pady=6,
        )
        self.close_button.pack(
            side="bottom",
            pady=(8, 0),
        )
        self.close_button.pack_forget()

    def enable_cancel(self, callback):
        """Enable cancellation for supported assessments."""
        if not callable(callback):
            raise TypeError("Cancellation callback must be callable.")

        self.cancel_callback = callback
        self.cancel_button.configure(state="normal")

    def request_cancel(self):
        """Request cancellation without terminating the GUI."""
        if self.cancel_callback is None:
            return

        callback = self.cancel_callback
        self.cancel_callback = None

        self.cancel_button.configure(state="disabled")
        self.status_label.configure(
            text="Cancellation requested..."
        )
        self.details_label.configure(
            text="Finishing the current operation safely."
        )

        callback()

    def detect_stage(self, message):
        """Identify the current stage from a real scanner message."""
        text = str(message).lower()

        if any(word in text for word in (
            "monitoring", "security changes", "live activity"
        )):
            return "LIVE SECURITY MONITORING"

        if any(word in text for word in (
            "security configuration", "security patch",
            "encryption", "usb debugging"
        )):
            return "DEVICE SECURITY CONFIGURATION"

        if any(word in text for word in (
            "yara", "dex file", "malware indicator"
        )):
            return "YARA MALWARE ANALYSIS"

        if any(word in text for word in (
            "virustotal", "hash reputation"
        )):
            return "THREAT REPUTATION CHECK"

        if any(word in text for word in (
            "saving", "report", "cleanup", "removing local"
        )):
            return "REPORTING & CLEANUP"

        if any(word in text for word in (
            "apk", "metadata", "application", "package",
            "permission", "collecting"
        )):
            return "APPLICATION ANALYSIS"

        if any(word in text for word in (
            "evidence", "forensic", "investigation", "mvt"
        )):
            return "FORENSIC INVESTIGATION"

        return "ASSESSMENT IN PROGRESS"

    def update_status(self, message):
        """Update status and record activity on the Tkinter main thread."""
        message = str(message)
        self.status_label.configure(text=message)
        self.stage_label.configure(
            text="CURRENT STAGE: " + self.detect_stage(message)
        )

        self.activity_log.configure(state="normal")
        self.activity_log.insert("end", message + "\n")
        self.activity_log.see("end")
        self.activity_log.configure(state="disabled")

    def disable_cancel(self):
        """Disable cancellation and display Close after an assessment."""
        self.cancel_callback = None
        self.cancel_button.pack_forget()
        self.close_button.pack(
            side="bottom",
            pady=(8, 16),
        )

    def cancelled(self, message="Assessment cancelled."):
        """Display a cancelled assessment without claiming completion."""
        self.disable_cancel()
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.status_label.configure(text=message)
        self.details_label.configure(
            text="Assessment stopped. Available results may be reviewed."
        )

    def complete(self, message="Assessment completed."):
        """Mark the assessment as finished."""
        self.disable_cancel()
        self.progress.stop()
        self.progress.configure(mode="determinate", value=100)
        self.status_label.configure(text=message)
        self.details_label.configure(
            text="The assessment has finished. Review the results."
        )

    def fail(self, message="Assessment failed."):
        """Mark the assessment as failed."""
        self.disable_cancel()
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.status_label.configure(text=message)
        self.details_label.configure(
            text="The assessment could not be completed."
        )

    def hide(self):
        """Hide the window without interrupting the assessment."""
        self.window.withdraw()
