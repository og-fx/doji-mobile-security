
import json
import threading
import queue
import tkinter as tk
import shutil
import subprocess
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from device_manager import discover_devices, run_command
from ui.device_authorization import authorization_guidance
from ui.secure_disconnect import finish_android_session
from assessment import new_assessment, add_finding, save_report, REPORT_DIR
from malware_scanner import scan_apk
from android_permission_parser import parse_package_permissions
from android_scan_validation import validate_android_scan_target
from android_device_scanner import assess_android_device
from android_device_report import save_device_malware_report
from android_compromise_checker import assess_configuration
from android_live_monitor import monitor_device
from android_unified_assessment import save_unified_report
from ui.scan_progress import ScanProgressWindow
from ui.apk_file_browser import select_apk


BG = "#10151f"
PANEL = "#192231"
TEXT = "#e7edf7"
MUTED = "#9eacc0"
ACCENT = "#56d6b0"


class DojiDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Doji | Mobile Security Assessment")
        self.root.geometry("1100x720")
        self.root.minsize(850, 580)
        self.root.configure(bg=BG)

        # Set Doji's custom application and taskbar icon.
        icon_path = Path(__file__).resolve().parent.parent / "assets" / "doji-icon.png"
        try:
            self.doji_icon = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, self.doji_icon)
        except tk.TclError as exc:
            print(f"Doji icon could not be loaded: {exc}")

        self.devices = []
        self.current_report = None
        self.discovery_running = False
        self.discovery_paused = False
        self.authorization_notified = set()
        self.device_scan_running = False
        self.assessment_running = False
        self.auto_refresh_ms = 5000

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=30,
        )
        style.configure(
            "Treeview.Heading",
            background="#243247",
            foreground=TEXT,
            padding=8,
        )
        style.map(
            "Treeview",
            background=[("selected", "#31546a")],
        )

        self.status = tk.Label(
            root, text="Ready.", bg="#0b1018", fg=ACCENT,
            anchor="w", padx=24, pady=10,
        )
        # Status updates remain available internally.
        # The scrolling welcome ticker is the visible footer.


        # Continuous security-awareness ticker above the status bar.
        self.ticker_canvas = tk.Canvas(
            root,
            height=30,
            bg="#14202d",
            highlightthickness=0,
            bd=0,
        )
        self.ticker_canvas.pack(side="bottom", fill="x")

        self.ticker_message = (
            "WELCOME TO DOJI  •  MOBILE SECURITY & DIGITAL FORENSICS"
            "     •     FOR EDUCATIONAL AND AUTHORIZED SECURITY "
            "RESEARCH PURPOSES ONLY"
            "     •     PROTECT PRIVACY AND OBTAIN AUTHORIZATION"
            "     •     ANALYZE RESPONSIBLY"
            "     •     DOJI MOBILE SECURITY"
            "     •     DEVELOPED BY ONWUTA ONYINYE"
            "     •     "
        )

        self.ticker_text = self.ticker_canvas.create_text(
            0, 15,
            text=self.ticker_message,
            fill=ACCENT,
            font=("DejaVu Sans", 10, "bold"),
            anchor="w",
        )
        self.ticker_positioned = False
        self.ticker_canvas.bind(
            "<Configure>", self.position_welcome_ticker
        )
        self.root.after(50, self.animate_welcome_ticker)

        self.shell = tk.Frame(root, bg=BG)
        self.shell.pack(fill="both", expand=True)

        sidebar = tk.Frame(self.shell, bg="#0b1018", width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar, text="DOJI", font=("Arial", 24, "bold"),
            bg="#0b1018", fg=ACCENT,
        ).pack(anchor="w", padx=20, pady=(24, 2))

        tk.Label(
            sidebar, text="MOBILE SECURITY",
            font=("Arial", 9, "bold"), bg="#0b1018", fg=TEXT,
        ).pack(anchor="w", padx=20, pady=(0, 24))

        self.page_container = tk.Frame(self.shell, bg=BG)
        self.page_container.pack(
            side="left", fill="both", expand=True, padx=20, pady=18
        )

        self.pages = {}
        page_names = [
            "Dashboard", "Devices", "Security Assessment",
            "Reports", "System Settings",
        ]

        self.nav_buttons = {}
        nav_icons = {
            "Dashboard": "⌂",
            "Devices": "▣",
            "Security Assessment": "◇",
            "Reports": "▤",
            "System Settings": "⚙",
        }

        for name in page_names:
            page = tk.Frame(self.page_container, bg=BG)
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = page

            button = tk.Button(
                sidebar,
                text=f"  {nav_icons[name]}   {name}",
                command=lambda selected=name: self.show_page(selected),
                font=("DejaVu Sans", 10),
                bg="#0b1018",
                fg="#a9bac9",
                activebackground="#153c36",
                activeforeground="#56d6b0",
                relief="flat",
                bd=0,
                highlightthickness=0,
                anchor="w",
                padx=14,
                pady=12,
                cursor="hand2",
            )
            button.pack(fill="x", padx=10, pady=3)
            self.nav_buttons[name] = button

        dashboard = self.pages["Dashboard"]
        tk.Label(
            dashboard, text="Dashboard", font=("Arial", 22, "bold"),
            bg=BG, fg=TEXT,
        ).pack(anchor="w", pady=(4, 12))

        tk.Label(
            dashboard,
            text="Welcome to Doji Mobile Security Assessment.",
            font=("Arial", 12), bg=BG, fg=MUTED,
        ).pack(anchor="w", pady=5)

        self.dashboard_device_count = tk.Label(
            dashboard, text="Connected devices: 0",
            font=("Arial", 14, "bold"), bg=PANEL, fg=ACCENT,
            anchor="w", justify="left",
            padx=18, pady=18,
        )
        self.dashboard_device_count.pack(anchor="w", fill="x", pady=12)

        tk.Label(
            dashboard,
            text="Security Capabilities",
            font=("Arial", 12, "bold"),
            bg=BG, fg=TEXT,
        ).pack(anchor="w", pady=(6, 8))

        tk.Label(
            dashboard,
            text=(
                "Android APK Analysis  |  YARA Threat Detection  |  "
                "VirusTotal Hash Checks  |  Android & iOS Forensics  |  "
                "Security Reports"
            ),
            font=("Arial", 10),
            bg=BG, fg=MUTED,
            justify="left",
            wraplength=650,
        ).pack(anchor="w", pady=(0, 12))

        devices_page = self.pages["Devices"]
        tk.Label(
            devices_page, text="Connected Devices",
            font=("Arial", 20, "bold"), bg=BG, fg=TEXT,
        ).pack(anchor="w", pady=(4, 10))

        self.add_button(
            devices_page, "Refresh Devices", self.refresh_devices,
            ACCENT, "#10151f",
        ).pack(anchor="w", pady=(0, 10))

        self.add_button(
            devices_page,
            "Finish & Secure Device",
            self.finish_secure_device,
            "#294052",
            TEXT,
        ).pack(anchor="w", pady=(0, 12))

        self.table = ttk.Treeview(
            devices_page,
            columns=("platform", "name", "model", "os", "state"),
            show="headings", height=9,
        )
        for column, heading, width in [
            ("platform", "Platform", 100),
            ("name", "Device Name", 160),
            ("model", "Model", 150),
            ("os", "OS Version", 120),
            ("state", "Connection State", 150),
        ]:
            self.table.heading(column, text=heading)
            self.table.column(column, width=width, anchor="w")

        self.table.pack(fill="x", pady=(0, 12))
        self.table.bind("<<TreeviewSelect>>", self.show_selected)

        tk.Label(
            devices_page, text="Device Details",
            font=("Arial", 12, "bold"), bg=BG, fg=ACCENT,
        ).pack(anchor="w")

        self.details = tk.Label(
            devices_page,
            text="Connect a supported device and select Refresh Devices.",
            bg=PANEL, fg=TEXT, justify="left", anchor="nw",
            padx=12, pady=7, wraplength=720,
        )
        self.details.pack(fill="both", expand=True, pady=(6, 0))

        # Doji Dark Professional — Security Assessment
        assessment_page = self.pages["Security Assessment"]

        surface = "#0b1420"
        panel = "#111f2c"
        emerald = "#27d6a0"
        purple = "#a77bff"
        border = "#294052"
        secondary = "#9aafbf"

        tk.Label(
            assessment_page,
            text="SECURITY ASSESSMENT",
            font=("DejaVu Sans", 21, "bold"),
            bg=BG, fg=TEXT,
        ).pack(anchor="w", pady=(4, 5))

        tk.Label(
            assessment_page,
            text="Mobile threat analysis and digital forensics",
            font=("DejaVu Sans", 10),
            bg=BG, fg=secondary,
        ).pack(anchor="w", pady=(0, 24))

        self.assessment_device_card = tk.Frame(
            assessment_page,
            bg=panel,
            highlightbackground=border,
            highlightthickness=1,
            padx=16, pady=14,
        )
        self.assessment_device_card.pack(
            fill="x", pady=(0, 16)
        )

        tk.Label(
            self.assessment_device_card,
            text="CONNECTED DEVICE",
            font=("DejaVu Sans", 9, "bold"),
            bg=panel, fg=emerald,
        ).pack(anchor="w", pady=(0, 10))

        device_row = tk.Frame(
            self.assessment_device_card, bg=panel
        )
        device_row.pack(fill="x")

        device_info = tk.Frame(device_row, bg=panel)
        device_info.pack(
            side="left", fill="both", expand=True
        )

        self.assessment_device_label = tk.Label(
            device_info,
            text="Checking connected devices...",
            font=("DejaVu Sans", 17, "bold"),
            bg=panel, fg=TEXT,
            anchor="w",
        )
        self.assessment_device_label.pack(fill="x")

        self.assessment_device_status = tk.Label(
            device_info,
            text="",
            font=("DejaVu Sans", 10),
            bg=panel, fg=secondary,
            anchor="w",
        )
        self.assessment_device_status.pack(
            fill="x", pady=(5, 0)
        )

        self.assessment_connection_badge = tk.Label(
            device_row,
            text="CHECKING",
            font=("DejaVu Sans", 9, "bold"),
            bg="#233342",
            fg=secondary,
            padx=10, pady=6,
        )
        self.assessment_connection_badge.pack(
            side="right", padx=(8, 0)
        )

        self.assessment_actions_frame = tk.Frame(
            assessment_page, bg=BG
        )


        scan_card = tk.Frame(
            self.assessment_actions_frame,
            bg=panel,
            highlightbackground="#196f61",
            highlightthickness=1,
            padx=16, pady=12,
        )
        scan_card.pack(
            side="left", fill="both", expand=True,
            padx=(0, 8)
        )

        tk.Label(
            scan_card,
            text="◈  FULL SECURITY SCAN",
            font=("DejaVu Sans", 11, "bold"),
            bg=panel, fg=emerald,
        ).pack(anchor="w", pady=(0, 12))

        tk.Label(
            scan_card,
            text=(
                "Analyze supported indicators of malware, "
                "spyware and device compromise."
            ),
            font=("DejaVu Sans", 10),
            bg=panel, fg=secondary,
            justify="left",
            wraplength=500,
        ).pack(anchor="w", fill="x", pady=(0, 10))

        self.full_security_scan_button = tk.Button(
            scan_card,
            text="Full Scan — Coming Soon",
            command=self.run_unified_security_scan,
            bg="#21463f",
            fg="#d5e9e2",
            disabledforeground="#b1c8c1",
            relief="flat",
            font=("DejaVu Sans", 10, "bold"),
            padx=12, pady=7,
            state="disabled",
        )
        self.full_security_scan_button.pack(
            fill="x", side="bottom"
        )

        forensic_card = tk.Frame(
            self.assessment_actions_frame,
            bg=panel,
            highlightbackground="#55407d",
            highlightthickness=1,
            padx=16, pady=12,
        )
        forensic_card.pack(
            side="left", fill="both", expand=True,
            padx=(8, 0)
        )

        tk.Label(
            forensic_card,
            text="◎  ADVANCED FORENSICS",
            font=("DejaVu Sans", 11, "bold"),
            bg=panel, fg=purple,
        ).pack(anchor="w", pady=(0, 12))

        tk.Label(
            forensic_card,
            text=(
                "Investigate supported forensic artifacts, "
                "system evidence and threat indicators."
            ),
            font=("DejaVu Sans", 10),
            bg=panel, fg=secondary,
            justify="left",
            wraplength=500,
        ).pack(anchor="w", fill="x", pady=(0, 10))

        self.advanced_forensics_button = tk.Button(
            forensic_card,
            text="Forensics — Coming Soon",
            command=self.run_unified_forensics,
            bg="#403456",
            fg="#e6ddfa",
            disabledforeground="#c4b7d9",
            relief="flat",
            font=("DejaVu Sans", 10, "bold"),
            padx=12, pady=7,
            state="disabled",
        )
        self.advanced_forensics_button.pack(
            fill="x", side="bottom"
        )

        self.assessment_scan_card = scan_card
        self.assessment_forensic_card = forensic_card
        self.assessment_layout_mode = None

        assessment_page.bind(
            "<Configure>",
            self.update_assessment_card_layout
        )

        self.update_assessment_device_view()

        # Doji Professional Forensic Workstation — Reports Center
        reports_page = self.pages["Reports"]

        tk.Label(
            reports_page,
            text="DOJI / REPORT CENTER",
            font=("Arial", 22, "bold"),
            bg=BG,
            fg=TEXT,
        ).pack(anchor="w", pady=(4, 4))

        tk.Label(
            reports_page,
            text="Digital Forensics  •  Evidence  •  Reporting",
            font=("Arial", 10),
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w", pady=(0, 18))

        workspace = tk.Frame(reports_page, bg=BG)
        workspace.pack(fill="both", expand=True)

        workspace.columnconfigure(0, weight=3, uniform="workspace")
        workspace.columnconfigure(1, weight=2, uniform="workspace")
        workspace.rowconfigure(0, weight=1)

        history_panel = tk.Frame(
            workspace,
            bg=PANEL,
            padx=16,
            pady=16,
        )
        history_panel.grid(
            row=0, column=0,
            sticky="nsew",
            padx=(0, 12),
        )

        tk.Label(
            history_panel,
            text="ASSESSMENT HISTORY",
            font=("Arial", 12, "bold"),
            bg=PANEL,
            fg=ACCENT,
        ).pack(anchor="w", pady=(0, 12))

        tk.Label(
            history_panel,
            text="Select a saved assessment to inspect its findings.",
            font=("Arial", 9),
            bg=PANEL,
            fg=MUTED,
            wraplength=380,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        history_list_frame = tk.Frame(history_panel, bg=PANEL)
        history_list_frame.pack(fill="both", expand=True)

        self.report_history = tk.Listbox(
            history_list_frame,
            height=12,
            bg="#202f40",
            fg=TEXT,
            selectbackground="#315c57",
            selectforeground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=("Arial", 10),
            activestyle="none",
        )

        history_scrollbar = ttk.Scrollbar(
            history_list_frame,
            orient="vertical",
            command=self.report_history.yview,
        )
        self.report_history.configure(
            yscrollcommand=history_scrollbar.set
        )

        history_scrollbar.pack(side="right", fill="y")
        self.report_history.pack(
            side="left", fill="both", expand=True
        )

        self.report_history.bind(
            "<<ListboxSelect>>",
            self.open_selected_history,
        )

        tools_panel = tk.Frame(
            workspace,
            bg=PANEL,
            padx=16,
            pady=16,
        )
        tools_panel.grid(
            row=0, column=1,
            sticky="nsew",
        )

        tk.Label(
            tools_panel,
            text="REPORT TOOLS",
            font=("Arial", 12, "bold"),
            bg=PANEL,
            fg=ACCENT,
        ).pack(anchor="w", pady=(0, 14))

        def workstation_button(label, command, danger=False):
            normal = "#39252d" if danger else "#26394a"
            hover = "#55313c" if danger else "#345168"
            foreground = "#ffb3b3" if danger else TEXT

            button = tk.Button(
                tools_panel,
                text=label,
                command=command,
                font=("Arial", 10, "bold"),
                bg=normal,
                fg=foreground,
                activebackground=hover,
                activeforeground=foreground,
                relief="flat",
                bd=0,
                padx=16,
                pady=12,
                anchor="w",
                cursor="hand2",
            )

            button.bind(
                "<Enter>",
                lambda event: button.configure(bg=hover),
            )
            button.bind(
                "<Leave>",
                lambda event: button.configure(bg=normal),
            )

            button.pack(fill="x", pady=5)
            return button

        workstation_button(
            "View Latest Report",
            self.view_latest_report,
        )
        workstation_button(
            "Export Report",
            self.export_report,
        )
        workstation_button(
            "Generate PDF Report",
            self.generate_pdf_report,
        )
        workstation_button(
            "Refresh Reports",
            self.refresh_history,
        )

        tk.Frame(
            tools_panel,
            bg="#344254",
            height=1,
        ).pack(fill="x", pady=16)

        workstation_button(
            "Delete Selected",
            self.delete_selected_report,
            danger=True,
        )
        workstation_button(
            "Clear History",
            self.clear_report_history,
            danger=True,
        )

        settings_page = self.pages["System Settings"]

        tk.Label(
            settings_page,
            text="System Settings",
            font=("Arial", 22, "bold"),
            bg=BG, fg=TEXT,
        ).pack(anchor="w", pady=(4, 8))

        tk.Label(
            settings_page,
            text="Application information, system status and device setup.",
            font=("Arial", 11),
            bg=BG, fg=MUTED,
        ).pack(anchor="w", pady=(0, 20))

        settings_options = [
            ("ⓘ", "About Doji",
             "Application overview, capabilities and disclaimer",
             self.show_about_doji),
            ("◉", "System Readiness",
             "Security tools, dependencies and device status",
             self.show_system_readiness),
            ("⇄", "Device Connection",
             "Android and iPhone connection instructions",
             self.show_connection_guide),
        ]

        for symbol, heading, description, callback in settings_options:
            card = tk.Frame(
                settings_page,
                bg=PANEL,
                highlightbackground="#344457",
                highlightthickness=1,
                cursor="hand2",
            )
            card.pack(fill="x", pady=7, ipady=9)

            icon_label = tk.Label(
                card,
                text=symbol,
                font=("DejaVu Sans", 23, "bold"),
                bg=PANEL, fg=ACCENT,
                width=3,
                cursor="hand2",
            )
            icon_label.pack(side="left", padx=(12, 6))

            details = tk.Frame(card, bg=PANEL, cursor="hand2")
            details.pack(side="left", fill="both", expand=True)

            heading_label = tk.Label(
                details,
                text=heading,
                font=("Arial", 13, "bold"),
                bg=PANEL, fg=TEXT,
                anchor="w",
                cursor="hand2",
            )
            heading_label.pack(fill="x", pady=(5, 3))

            description_label = tk.Label(
                details,
                text=description,
                font=("Arial", 10),
                bg=PANEL, fg=MUTED,
                anchor="w",
                cursor="hand2",
            )
            description_label.pack(fill="x", pady=(0, 5))

            arrow = tk.Label(
                card,
                text="›",
                font=("Arial", 24),
                bg=PANEL, fg=ACCENT,
                cursor="hand2",
            )
            arrow.pack(side="right", padx=18)

            for widget in (
                card, icon_label, details,
                heading_label, description_label, arrow,
            ):
                widget.bind(
                    "<Button-1>",
                    lambda event, action=callback: action(),
                )

        # Keep this label for the existing readiness updater.
        # It is intentionally hidden from the Settings page.
        self.readiness = tk.Label(
            settings_page,
            text="Checking system tools...",
            bg=PANEL, fg=TEXT,
        )

        self.refresh_history()
        self.refresh_readiness()
        self.show_page("Dashboard")
        self.refresh_devices()
        self.root.after(self.auto_refresh_ms, self.auto_refresh_devices)


    def position_welcome_ticker(self, event=None):
        """Position the scrolling text when the canvas is ready."""
        if not self.ticker_positioned:
            width = self.ticker_canvas.winfo_width()
            if width <= 1:
                return
            self.ticker_canvas.coords(
                self.ticker_text, width, 15
            )
            self.ticker_positioned = True

    def animate_welcome_ticker(self):
        """Move the welcome message continuously from right to left."""
        try:
            if not self.ticker_canvas.winfo_exists():
                return

            if not self.ticker_positioned:
                self.position_welcome_ticker()

            if self.ticker_positioned:
                self.ticker_canvas.move(self.ticker_text, -2, 0)

                bounds = self.ticker_canvas.bbox(self.ticker_text)
                if bounds and bounds[2] < 0:
                    self.ticker_canvas.coords(
                        self.ticker_text,
                        self.ticker_canvas.winfo_width(),
                        15,
                    )

            self.root.after(35, self.animate_welcome_ticker)

        except tk.TclError:
            return

    def show_system_readiness(self):
        """Display the latest system readiness information."""
        self.refresh_readiness()

        window = tk.Toplevel(self.root)
        window.title("Doji - System Readiness")
        window.geometry("650x350")
        window.configure(bg=BG)

        tk.Label(
            window,
            text="System Readiness",
            font=("Arial", 19, "bold"),
            bg=BG, fg=ACCENT,
        ).pack(anchor="w", padx=20, pady=(20, 12))

        details = tk.Label(
            window,
            text=self.readiness.cget("text"),
            bg=PANEL, fg=TEXT,
            justify="left", anchor="nw",
            padx=18, pady=18,
            wraplength=580,
        )
        details.pack(fill="x", padx=20, pady=8)

        def refresh_status():
            self.refresh_readiness()
            details.configure(text=self.readiness.cget("text"))

        self.add_button(
            window, "Refresh Status",
            refresh_status, "#31546a", TEXT,
        ).pack(anchor="w", padx=20, pady=12)

    def show_connection_guide(self):
        """Show device connection diagnostics and troubleshooting."""
        import shutil
        import threading
        from device_manager import discover_devices

        window = tk.Toplevel(self.root)
        window.title("Doji - Device Connection Assistant")
        window.geometry("760x650")
        window.configure(bg=BG)

        tk.Label(
            window,
            text="Device Connection Assistant",
            font=("Arial", 20, "bold"),
            bg=BG, fg=TEXT,
        ).pack(anchor="w", padx=24, pady=(20, 6))

        status_var = tk.StringVar(
            value="Checking connected devices..."
        )

        tk.Label(
            window,
            textvariable=status_var,
            font=("Arial", 11),
            bg=BG, fg=ACCENT,
            justify="left",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=(0, 12))

        results = tk.Text(
            window,
            height=13,
            bg=PANEL,
            fg=TEXT,
            font=("Arial", 10),
            wrap="word",
            padx=14,
            pady=12,
            state="disabled",
        )
        results.pack(fill="both", expand=True, padx=24)

        def display_result(message, details):
            if not window.winfo_exists():
                return

            status_var.set(message)
            results.configure(state="normal")
            results.delete("1.0", "end")
            results.insert("end", details)
            results.configure(state="disabled")
            retry_button.configure(state="normal")

        def check_devices():
            retry_button.configure(state="disabled")
            status_var.set("Checking Android and Apple connections...")

            def worker():
                adb_available = bool(shutil.which("adb"))
                apple_available = bool(shutil.which("idevice_id"))

                try:
                    devices = discover_devices()
                    lines = []

                    if devices:
                        for device in devices:
                            platform = device.get("platform", "Unknown")
                            name = device.get("name", "Unknown device")
                            state = device.get("state", "Unknown")

                            lines.append(
                                f"{platform}: {name}\\n"
                                f"Status: {state}\\n"
                            )

                            if state == "Unauthorized":
                                lines.append(
                                    "Unlock the Android phone, enable USB "
                                    "debugging, and approve this computer.\\n"
                                )
                            elif state == "Offline":
                                lines.append(
                                    "Reconnect the USB cable and retry. "
                                    "Check the ADB connection.\\n"
                                )
                            elif state == "Permission issue":
                                lines.append(
                                    "Check Linux USB permissions and "
                                    "udev rules.\\n"
                                )
                            elif state == "Detected; details unavailable":
                                lines.append(
                                    "Unlock the Apple device, approve Trust, "
                                    "and check pairing tools.\\n"
                                )

                            lines.append("\\n")
                    else:
                        lines.append(
                            "No devices were discovered.\\n\\n"
                            "1. Use a USB cable that supports data.\\n"
                            "2. Unlock the phone.\\n"
                            "3. For Android ADB scans, enable USB debugging "
                            "and authorize this computer.\\n"
                            "4. If using VMware, connect the USB device "
                            "to the Kali virtual machine.\\n"
                            "5. Retry detection after reconnecting.\\n"
                        )

                    if not adb_available:
                        lines.append(
                            "\\nADB is unavailable. Install Android "
                            "platform tools for Android detection.\\n"
                        )

                    if not apple_available:
                        lines.append(
                            "\\nApple device tools are unavailable. "
                            "Install libimobiledevice utilities for "
                            "supported iPhone detection.\\n"
                        )

                    message = (
                        f"{len(devices)} device(s) discovered."
                        if devices else "No supported devices detected."
                    )
                    details = "".join(lines)

                except Exception as exc:
                    message = "Device discovery encountered an error."
                    details = str(exc)

                try:
                    window.after(
                        0,
                        lambda: display_result(message, details)
                    )
                except RuntimeError:
                    pass

            threading.Thread(
                target=worker, daemon=True
            ).start()

        retry_button = tk.Button(
            window,
            text="Retry Device Detection",
            command=check_devices,
            bg=ACCENT,
            fg="#10151f",
            font=("Arial", 11, "bold"),
            padx=16,
            pady=8,
        )
        retry_button.pack(pady=14)

        tk.Label(
            window,
            text=(
                "Android full-device scanning requires authorized ADB "
                "access. Offline APK analysis does not require a phone. "
                "Device detection alone does not confirm device security."
            ),
            font=("Arial", 10),
            bg=BG, fg=MUTED,
            wraplength=700,
            justify="left",
        ).pack(padx=24, pady=(0, 18))

        check_devices()

    def show_about_doji(self):
        """Display Doji capabilities and assessment limitations."""
        window = tk.Toplevel(self.root)
        window.title("About Doji Advanced Edition")
        window.geometry("760x600")
        window.configure(bg=BG)

        text_box = tk.Text(
            window,
            wrap="word",
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            padx=20,
            pady=20,
            font=("Arial", 11),
        )
        text_box.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=14,
        )

        content = """DOJI
Mobile Security & Digital Forensics
Created & Developed by Onwuta Onyinye

ABOUT DOJI

Doji is a mobile security assessment and digital forensic
analysis application designed to help security professionals,
researchers, and individuals investigate potential threats
affecting mobile devices and applications.

By combining static malware analysis, threat-indicator
detection, application security assessment, and forensic
examination, Doji provides structured insights into
suspicious activity and potential indicators of compromise.

CORE CAPABILITIES

Malware Analysis
Examines Android application packages for suspicious
characteristics and potential threats.

YARA Threat Detection
Identifies patterns associated with known threats and
suspicious application behavior.

Application Security Assessment
Reviews application permissions, signatures, and
relevant security indicators.

Device Security Assessment
Examines accessible device information and applications
through supported connections.

Digital Forensics
Analyzes supported Android and iOS forensic evidence
to assist security investigations.

Threat Intelligence
Integrates available hash-based reputation checks
to support security assessments.

Security Reporting
Produces structured findings and reports to support
investigation, documentation, and review.

DISCLAIMER

Doji is intended for authorized security assessment,
digital forensic investigation, and research purposes.
Its findings are based on available evidence, detection
rules, and supported analysis methods.

Results should be interpreted in context and independently
verified where appropriate. The absence of detected threats
does not guarantee that a device or application is free
from compromise.

Users are responsible for obtaining appropriate authorization
and complying with applicable laws and regulations.
"""

        text_box.insert("1.0", content)
        text_box.configure(state="disabled")

    def update_assessment_card_layout(self, event=None):
        """Adapt security cards to the available window width."""
        frame = self.assessment_actions_frame

        if not frame.winfo_ismapped():
            return

        width = self.pages["Security Assessment"].winfo_width()

        if width <= 1:
            return

        mode = "columns" if width >= 1000 else "stacked"

        if mode == self.assessment_layout_mode:
            return

        self.assessment_layout_mode = mode

        scan = self.assessment_scan_card
        forensic = self.assessment_forensic_card

        scan.pack_forget()
        forensic.pack_forget()

        if mode == "columns":
            scan.pack(
                side="left", fill="both", expand=True,
                padx=(0, 8)
            )
            forensic.pack(
                side="left", fill="both", expand=True,
                padx=(8, 0)
            )
        else:
            scan.pack(
                side="top", fill="x",
                padx=0, pady=(0, 12)
            )
            forensic.pack(
                side="top", fill="x",
                padx=0
            )

    def update_assessment_device_view(self):
        """Display the currently detected assessment device."""
        devices = getattr(self, "devices", [])

        eligible = [
            device for device in devices
            if (
                device.get("platform") == "Android"
                and device.get("state") == "Authorized"
            )
            or (
                device.get("platform") == "Apple"
                and device.get("state") == "Detected; details readable"
            )
        ]

        self.assessment_actions_frame.pack_forget()

        if len(eligible) == 1:
            device = eligible[0]
            platform = device.get("platform")
            name = device.get("name", "Mobile Device")
            model = device.get("model", "Unknown")

            self.assessment_device_label.configure(
                text=name
            )

            if platform == "Android":
                status = f"Android | {model} | Authorized"
            else:
                status = f"iPhone / iOS | {model} | Detected"

            self.assessment_device_status.configure(
                text=status
            )
            self.assessment_connection_badge.configure(
                text="AUTHORIZED" if platform == "Android"
                else "DETECTED",
                bg="#173b37",
                fg="#27d6a0",
            )

            self.assessment_actions_frame.pack(
                fill="x", pady=(0, 12)
            )

            # Enable verified Android and initial iPhone workflows.
            android_ready = (
                platform == "Android"
                and device.get("state") == "Authorized"
            )
            iphone_ready = (
                platform == "Apple"
                and device.get("state") == "Detected; details readable"
            )
            scan_ready = (
                (android_ready or iphone_ready)
                and not self.assessment_running
                and not self.device_scan_running
            )

            if android_ready:
                button_text = "Full Scan"
            elif iphone_ready:
                button_text = "iPhone Security Checks (Initial)"
            else:
                button_text = "Full Scan — Unavailable"

            self.full_security_scan_button.configure(
                state="normal" if scan_ready else "disabled",
                text=button_text,
            )

            # Enable the platform-specific forensic launcher.
            forensic_ready = (
                (android_ready or iphone_ready)
                and not self.assessment_running
                and not self.device_scan_running
            )

            if android_ready:
                forensic_text = "Android Advanced Forensics"
            elif iphone_ready:
                forensic_text = "Open iPhone Advanced Forensics"
            else:
                forensic_text = "Forensics — Unavailable"

            self.advanced_forensics_button.configure(
                state="normal" if forensic_ready else "disabled",
                text=forensic_text,
            )

        else:
            self.assessment_device_label.configure(
                text=(
                    "No Device Connected"
                    if not devices else
                    "No Authorized Device Available"
                )
            )
            self.assessment_device_status.configure(
                text=(
                    "Connect and authorize a mobile device."
                    if len(eligible) == 0 else
                    "Multiple devices detected."
                )
            )
            self.assessment_connection_badge.configure(
                text="NOT READY",
                bg="#233342",
                fg="#9aafbf",
            )

    def run_unified_security_scan(self):
        """Launch the appropriate mobile security assessment."""
        device = self.detect_assessment_device()

        if device is None:
            messagebox.showwarning(
                "Device Selection Required",
                "Connect and authorize one supported mobile device.",
            )
            return

        platform = device.get("platform")

        if platform == "Android":
            self.run_android_device_malware_scan()
            return

        if platform == "Apple":
            self.run_iphone_full_security_scan(device)
            return

        messagebox.showerror(
            "Unsupported Device",
            "Doji does not support this device platform.",
        )

    def run_iphone_full_security_scan(self, device):
        """Run available iPhone checks without blocking the GUI."""
        if self.assessment_is_busy():
            return

        from iphone_security_scanner import run_iphone_security_scan

        device_id = device.get("id", "")
        if not device_id:
            messagebox.showerror(
                "iPhone Scan Error",
                "The connected iPhone has no device identifier.",
            )
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(
                self.root, "iPhone Security Assessment"
            )
            progress_window.update_status(
                "Preparing iPhone security checks..."
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror(
                "Progress Window Error", str(exc)
            )
            return

        progress_queue = queue.Queue()
        running = {"active": True}

        def process_progress():
            try:
                while True:
                    progress_window.update_status(
                        progress_queue.get_nowait()
                    )
            except queue.Empty:
                pass

            if running["active"]:
                self.root.after(150, process_progress)

        def worker():
            try:
                report, report_path = run_iphone_security_scan(
                    device_id=device_id,
                    device_name=device.get("name", "iPhone"),
                    progress_callback=progress_queue.put,
                )

                def show_results():
                    running["active"] = False
                    self.assessment_running = False
                    self.current_report = report
                    self.refresh_history()

                    progress_window.complete(
                        "Available iPhone checks completed."
                    )

                    self.status.configure(
                        text=f"iPhone report: {report_path.name}"
                    )

                    summary = report["summary"]

                    forensic = report.get("forensic_analysis", {})
                    evidence = report.get("forensic_evidence", {})

                    mvt_status = forensic.get("status", "NOT_RUN")
                    matches = forensic.get("ioc_match_count")

                    verified = (
                        mvt_status == "COMPLETED"
                        and forensic.get("evidence_integrity") == "UNCHANGED"
                        and forensic.get("exit_code") == 0
                        and forensic.get("findings_generated") is True
                        and isinstance(matches, int)
                        and not isinstance(matches, bool)
                        and matches >= 0
                    )

                    ioc_text = str(matches) if verified else "Not verified"

                    messagebox.showinfo(
                        "iPhone Security Assessment",
                        f"Report saved: {report_path}\n\n"
                        f"Passed: {summary['passed']}\n"
                        f"Warnings: {summary['warnings']}\n"
                        f"Not run: {summary['not_run']}\n\n"
                        f"Verified backups: "
                        f"{evidence.get('verified_backup_count', 0)}\n"
                        f"MVT status: {mvt_status}\n"
                        f"Verified IOC matches: {ioc_text}\n\n"
                        "Results cover only the checks and evidence "
                        "actually analyzed. This assessment does not "
                        "prove that the iPhone is malware-free.",
                    )

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "iPhone assessment failed."
                    )
                    messagebox.showerror(
                        "iPhone Security Assessment Error",
                        error_message,
                    )

                self.root.after(0, show_error)

        self.root.after(150, process_progress)

        try:
            threading.Thread(
                target=worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "iPhone assessment could not start."
            )
            messagebox.showerror(
                "iPhone Startup Error", str(exc)
            )

    def run_android_forensic_analysis(self):
        """Analyze an existing Android bug report using MVT."""
        if self.assessment_is_busy():
            return

        from forensic_engine import (
            WORKFLOWS,
            run_investigation,
            validate_evidence,
        )
        from findings_engine import build_findings
        from forensic_pdf_report import generate_forensic_pdf

        workflow_name = "android-bugreport"
        title = "Android Bug Report Forensic Analysis"

        from ui.forensic_evidence_browser import select_forensic_evidence

        evidence = select_forensic_evidence(self.root)

        if not evidence:
            return

        evidence_path = Path(evidence)

        try:
            validate_evidence(
                evidence_path,
                WORKFLOWS[workflow_name]["input_type"],
                workflow_name,
            )
        except (ValueError, FileNotFoundError, OSError) as exc:
            messagebox.showerror("Invalid forensic evidence", str(exc))
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(self.root, title)
            progress_window.update_status(
                "Preparing Android forensic investigation..."
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror("Progress Window Error", str(exc))
            return

        progress_queue = queue.Queue()
        running = {"active": True}

        def process_progress():
            try:
                while True:
                    progress_window.update_status(
                        progress_queue.get_nowait()
                    )
            except queue.Empty:
                pass

            if running["active"]:
                self.root.after(200, process_progress)

        def worker():
            try:
                progress_queue.put(
                    "Validating Android evidence and calculating SHA-256..."
                )

                case_holder = {}

                def capture_case(case_dir):
                    case_holder["path"] = Path(case_dir)

                progress_queue.put(
                    "Running MVT forensic investigation..."
                )

                result = run_investigation(
                    workflow_name,
                    evidence_path,
                    7200,
                    case_callback=capture_case,
                )

                if result != 0:
                    raise RuntimeError(
                        "Android forensic investigation failed. "
                        "Review case metadata and logs under forensic/results."
                    )

                case_dir = case_holder.get("path")
                if case_dir is None:
                    raise RuntimeError(
                        "Investigation completed without a case directory."
                    )

                progress_queue.put(
                    "Classifying forensic findings..."
                )
                build_findings(case_dir)

                progress_queue.put(
                    "Generating forensic PDF report..."
                )
                pdf_path = generate_forensic_pdf(
                    case_dir / "case_metadata.json"
                )

                if not Path(pdf_path).is_file():
                    raise RuntimeError(
                        "Forensic PDF report was not created."
                    )

                progress_queue.put(
                    "Saving standard Doji forensic JSON report..."
                )
                from ui.forensic_report_adapter import save_forensic_assessment

                json_path = save_forensic_assessment(
                    case_dir / "case_metadata.json"
                )

                if not Path(json_path).is_file():
                    raise RuntimeError(
                        "Forensic JSON report was not created."
                    )

                def show_results():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.complete(
                        "Android forensic investigation completed."
                    )
                    self.status.configure(
                        text="Android Advanced Forensics: Completed"
                    )
                    messagebox.showinfo(
                        title,
                        "Investigation and reporting completed.\\n\\n"
                        f"Case: {case_dir.name}\\n\\n"
                        f"PDF report: {pdf_path}\\n\\n"
                        "A completed investigation does not guarantee "
                        "the absence of spyware.",
                    )

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "Android forensic investigation failed."
                    )
                    messagebox.showerror(title, error_message)

                self.root.after(0, show_error)

        self.root.after(200, process_progress)

        try:
            threading.Thread(
                target=worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "Android forensic investigation could not start."
            )
            messagebox.showerror(
                "Investigation Startup Error", str(exc)
            )

    def run_unified_forensics(self):
        """Launch supported forensic analysis for the selected platform."""
        if self.assessment_is_busy():
            return

        device = self.detect_assessment_device()

        if device is None:
            # Existing Android evidence can be analyzed offline.
            self.run_android_forensic_analysis()
            return

        if device.get("platform") == "Android":
            self.run_android_forensic_analysis()
            return

        if device.get("platform") == "Apple":
            self.run_iphone_full_security_scan(device)
            return

        messagebox.showerror(
            "Unsupported Device",
            "No supported forensic workflow is available.",
        )

    def detect_assessment_device(self):
        """Return an authorized device only when selection is unambiguous."""
        from device_manager import discover_devices

        devices = discover_devices()

        eligible = [
            device for device in devices
            if (
                device.get("platform") == "Android"
                and device.get("state") == "Authorized"
            )
            or (
                device.get("platform") == "Apple"
                and device.get("state") == "Detected; details readable"
            )
        ]

        if len(eligible) == 1:
            return eligible[0]

        return None

    def show_assessment_platform(self, platform):
        """Show the selected platform's assessment tools."""
        frames = {
            "Android": self.android_assessment_frame,
            "iPhone": self.iphone_assessment_frame,
        }

        if platform not in frames:
            raise ValueError("Unsupported assessment platform.")

        self.assessment_selection_frame.pack_forget()
        self.android_assessment_frame.pack_forget()
        self.iphone_assessment_frame.pack_forget()

        frames[platform].pack(fill="both", expand=True)
        self.status.configure(
            text=f"Security Assessment: {platform}"
        )

    def show_assessment_selection(self):
        """Return to Android/iPhone platform selection."""
        self.android_assessment_frame.pack_forget()
        self.iphone_assessment_frame.pack_forget()
        self.assessment_selection_frame.pack(
            fill="both", expand=True
        )
        self.status.configure(
            text="Security Assessment: Select a platform"
        )

    def show_page(self, page_name):
        page = self.pages.get(page_name)

        if page_name == "Security Assessment":
            self.update_assessment_device_view()

        print(f"DEBUG: Switching to page: {page_name}")
        if page is not None:
            page.lift()
            self.status.configure(text=f"Page: {page_name}")

            for name, button in self.nav_buttons.items():
                selected = name == page_name
                button.configure(
                    bg="#153c36" if selected else "#0b1018",
                    fg="#56d6b0" if selected else "#a9bac9",
                    font=(
                        "DejaVu Sans", 10,
                        "bold" if selected else "normal"
                    ),
                )

            self.root.update_idletasks()

            if page_name == "Security Assessment":
                self.assessment_layout_mode = None
                self.update_assessment_card_layout()

            if page_name == "Security Assessment":
                self.assessment_layout_mode = None
                self.update_assessment_card_layout()


    @staticmethod
    def add_button(parent, text, command, background, foreground):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=background,
            fg=foreground,
            activebackground=background,
            activeforeground=foreground,
            relief="flat",
            padx=12,
            pady=9,
            cursor="hand2",
        )
    
    def refresh_readiness(self):
        """Display basic checks for mobile-device testing prerequisites."""
        checks = []

        # Android debugging tools
        adb_path = shutil.which("adb")
        if adb_path:
            checks.append("Android ADB: Installed")
        else:
            checks.append("Android ADB: Not installed")

        # Apple device tools
        apple_tools = all(
            shutil.which(tool)
            for tool in ("idevice_id", "ideviceinfo")
        )
        if apple_tools:
            checks.append("Apple tools: Installed")
        else:
            checks.append("Apple tools: Missing one or more tools")

        # Apple USB communication service
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "usbmuxd"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            service_state = result.stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            service_state = "unavailable"

        checks.append(f"Apple USB service (usbmuxd): {service_state}")

        # Device detection status
        if self.devices:
            checks.append(f"Devices detected: {len(self.devices)}")
        else:
            checks.append("Devices detected: None")

        self.readiness.configure(text="\n".join(checks))

    def refresh_devices(self):
        if self.discovery_running:
            return

        self.discovery_paused = False
        self.discovery_running = True
        self.status.configure(text="Checking for connected devices...")
        threading.Thread(
            target=self.discovery_worker, daemon=True
        ).start()

    def auto_refresh_devices(self):
        if not self.discovery_paused:
            self.refresh_devices()

        self.root.after(
            self.auto_refresh_ms, self.auto_refresh_devices
        )

    def discovery_worker(self):
        try:
            devices = discover_devices()
            error = None
        except Exception as exc:
            devices = []
            error = str(exc)

        try:
            self.root.after(
                0, lambda: self.update_devices(devices, error)
            )
        except tk.TclError:
            pass

    def update_devices(self, devices, error=None):
        previous_id = None
        selection = self.table.selection()
        if selection:
            try:
                previous_id = self.devices[int(selection[0])].get("id")
            except (IndexError, ValueError):
                pass
        self.discovery_running = False

        # Avoid rebuilding the device table when nothing has changed.
        if devices == self.devices and error is None:
            return

        self.devices = devices

        # Notify once per connected device and authorization state.
        # Clear notifications when a device disappears or becomes ready.
        active_keys = {
            (str(device.get("id")), str(device.get("state")))
            for device in devices
            if isinstance(device, dict)
        }

        self.authorization_notified.intersection_update(active_keys)

        for device in devices:
            guidance = authorization_guidance(device)

            if not guidance:
                continue

            if guidance["status"] == "READY":
                continue

            key = (
                str(device.get("id")),
                str(device.get("state")),
            )

            if key in self.authorization_notified:
                continue

            self.authorization_notified.add(key)

            self.root.after(
                100,
                lambda info=guidance: messagebox.showinfo(
                    info["title"],
                    info["message"],
                    parent=self.root,
                ),
            )
            break

        if hasattr(self, "update_assessment_device_view"):
            self.update_assessment_device_view()

        if hasattr(self, "dashboard_device_count"):
            self.dashboard_device_count.configure(
                text=f"Connected devices: {len(devices)}"
            )

        for item in self.table.get_children():
            self.table.delete(item)

        for index, device in enumerate(devices):
            self.table.insert(
                "", "end", iid=str(index),
                values=(
                    device["platform"],
                    device["name"],
                    device["model"],
                    device["os"],
                    device["state"],
                                ),
            )

        for index, device in enumerate(devices):
            if device.get("id") == previous_id and previous_id:
                self.table.selection_set(str(index))
                self.table.focus(str(index))
                self.show_selected()
                break

        if error:
            self.status.configure(text=f"Discovery error: {error}")

        elif devices:
            self.status.configure(
                text=f"Discovery complete: {len(devices)} device(s) reported."
            )
        else:
            self.status.configure(
                text=(
                    "No devices detected. Android: enable USB debugging "
                    "and authorize this computer. Apple: unlock the device, "
                    "trust the computer, and check usbmuxd/libimobiledevice. "
                    "No security scan has been performed."
                )
            )
            self.details.configure(
                text=(
                    "No phone is currently visible to the discovery tools.\n"
                    "1. Connect the phone using a data-capable USB cable.\n"
                    "2. In VMware, connect the USB device to Kali Linux.\n"
                    "3. Android: enable USB debugging and accept the "
                    "authorization prompt.\n"
                    "4. iPhone/iPad: unlock it and accept Trust if prompted.\n"
                    "5. Click Refresh devices again."
                )
            )

    def finish_secure_device(self):
        """End the local ADB session after explicit confirmation."""
        if self.assessment_running or self.device_scan_running:
            messagebox.showwarning(
                "Security Assessment Running",
                "Please wait until the current assessment finishes "
                "before ending the ADB session.",
                parent=self.root,
            )
            return

        if self.discovery_running:
            messagebox.showwarning(
                "Device Discovery Running",
                "Please wait for device discovery to finish, "
                "then select Finish & Secure Device again.",
                parent=self.root,
            )
            return

        confirmed = messagebox.askyesno(
            "Finish & Secure Device",
            "Do you want to stop the local ADB server?\\n\\n"
            "This may disconnect other applications using ADB.\\n"
            "It will NOT disable USB debugging or revoke "
            "computer authorization on your phone.",
            parent=self.root,
        )

        if not confirmed:
            return

        result = finish_android_session()

        message = (
            result["message"]
            + "\\n\\n"
            + result["instructions"]
        )

        if result["success"]:
            self.discovery_paused = True
            messagebox.showinfo(
                "Finish & Secure Device",
                message + (
                    "\n\nAutomatic device discovery is paused. "
                    "Click Refresh Devices to reconnect."
                ),
                parent=self.root,
            )
        else:
            messagebox.showwarning(
                "Finish & Secure Device",
                message,
                parent=self.root,
            )

        if result["success"]:
            # Clear cached discovery results so the interface does not
            # continue displaying a previously authorized connection.
            self.devices = []

            for item in self.table.get_children():
                self.table.delete(item)

            if hasattr(self, "dashboard_device_count"):
                self.dashboard_device_count.configure(
                    text="Connected devices: Not currently checked"
                )

            if hasattr(self, "update_assessment_device_view"):
                self.update_assessment_device_view()

            self.details.configure(
                text=(
                    "Doji's local ADB session has ended.\n"
                    "Automatic device discovery is paused.\n\n"
                    "Disable USB debugging and revoke USB debugging "
                    "authorizations on your phone if appropriate.\n"
                    "Click Refresh Devices when you want to reconnect."
                )
            )

            self.status.configure(
                text="ADB session ended. Automatic discovery paused."
            )

    def show_selected(self, _event=None):
        selection = self.table.selection()
        if not selection:
            return

        device = self.devices[int(selection[0])]
        self.details.configure(
            text=(
                f'{device["platform"]} | {device["name"]}\n'
                f'Model: {device["model"]} | OS: {device["os"]}\n'
                f'ID: {device["id"]} | {device["transport"]}\n'
                f'State: {device["state"]}'
            )
        )

    def run_demo_assessment(self):
        report = new_assessment(
            "Doji demonstration (no phone scanned)",
            "Not connected",
        )
        add_finding(
            report,
            "Physical device connection",
            "NOT_RUN",
            "No physical phone was connected for this demonstration.",
        )
        add_finding(
            report,
            "Mobile security checks",
            "NOT_RUN",
            "Device security checks have not yet been implemented.",
        )

        try:
            path = save_report(report)
        except (OSError, ValueError) as exc:
            messagebox.showerror(
                "Report error", f"Could not save report:\n{exc}"
            )
            return

        self.current_report = report
        self.refresh_history()
        self.status.configure(
            text=f"Demo report saved: {path.name}"
        )
 
        messagebox.showinfo(
            "Demo assessment saved",
            f"Report saved successfully:\n{path}\n\n"
            "This is a demonstration record, not a phone scan."
        )

    def run_device_info_assessment(self):
        """Read iPhone information without blocking the GUI."""
        if self.assessment_is_busy():
            return

        selection = self.table.selection()
        if not selection:
            messagebox.showinfo(
                "Select a device",
                "Select your iPhone on the Devices page first.",
            )
            self.show_page("Devices")
            return

        try:
            device = self.devices[int(selection[0])].copy()
        except (IndexError, ValueError):
            messagebox.showerror(
                "Device selection error",
                "Please select your iPhone again.",
            )
            return

        if device.get("platform") != "Apple":
            messagebox.showinfo(
                "iPhone required",
                "Select your connected iPhone on the Devices page.",
            )
            return

        device_id = device.get("id", "")
        if not device_id:
            messagebox.showerror(
                "Device ID missing",
                "Doji could not identify the selected iPhone.",
            )
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(
                self.root, "iPhone Information Check"
            )
            progress_window.update_status(
                "Preparing read-only iPhone information check..."
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror(
                "Progress Window Error", str(exc)
            )
            return

        progress_queue = queue.Queue()
        running = {"active": True}

        def process_progress():
            try:
                while True:
                    progress_window.update_status(
                        progress_queue.get_nowait()
                    )
            except queue.Empty:
                pass

            if running["active"]:
                self.root.after(150, process_progress)

        def worker():
            try:
                progress_queue.put(
                    "Reading iPhone information using ideviceinfo..."
                )

                report = new_assessment(
                    device.get("name", "iPhone"),
                    device.get("platform", "Apple"),
                    device_id,
                )
                report["report_type"] = "iphone_information"

                output, error = run_command(
                    ["ideviceinfo", "-u", device_id]
                )

                if not output:
                    add_finding(
                        report,
                        "Read iPhone device information",
                        "WARNING",
                        error or (
                            "No information returned. Check the USB "
                            "connection and Trust authorization."
                        ),
                    )
                else:
                    values = {}
                    for line in output.splitlines():
                        key, separator, value = line.partition(":")
                        if separator:
                            values[key.strip()] = value.strip()

                    checks = [
                        ("Device name", "DeviceName"),
                        ("Product type", "ProductType"),
                        ("iOS version", "ProductVersion"),
                    ]

                    for label, key in checks:
                        progress_queue.put(
                            f"Checking {label.lower()}..."
                        )
                        value = values.get(key, "")
                        add_finding(
                            report,
                            f"Read {label.lower()}",
                            "PASS" if value else "WARNING",
                            f"Retrieved value: {value}" if value
                            else "This value was not available.",
                        )

                report["limitations"].append(
                    "This assessment reads available Apple device "
                    "information using libimobiledevice. It does not "
                    "perform malware detection, spyware analysis, "
                    "a vulnerability audit, or a complete iOS "
                    "security assessment."
                )

                progress_queue.put("Saving iPhone information report...")
                report_path = save_report(report)

                def show_results():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.complete(
                        "iPhone information check completed."
                    )
                    self.current_report = report
                    self.refresh_history()
                    self.status.configure(
                        text=f"iPhone report saved: {report_path.name}"
                    )
                    messagebox.showinfo(
                        "iPhone Information Check",
                        f"Report saved to:\n{report_path}\n\n"
                        "Read-only information checks completed. "
                        "This is not a malware or spyware scan.",
                    )

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "iPhone information check failed."
                    )
                    messagebox.showerror(
                        "iPhone Information Check Error",
                        error_message,
                    )

                self.root.after(0, show_error)

        self.root.after(150, process_progress)

        try:
            threading.Thread(
                target=worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "iPhone information check could not start."
            )
            messagebox.showerror(
                "iPhone Startup Error", str(exc)
            )

    def run_ios_backup_analysis(self):
        """Launch iOS backup forensic analysis."""
        self.run_ios_forensic_analysis("ios-backup")

    def run_ios_forensic_analysis(self, workflow_name):
        """Analyze existing iOS evidence without blocking the GUI."""
        if self.assessment_is_busy():
            return

        from pathlib import Path
        from forensic_engine import WORKFLOWS, run_investigation, validate_evidence

        titles = {
            "ios-backup": "iOS Backup Forensic Analysis",
            "ios-filesystem": "iOS Filesystem Forensic Analysis",
            "ios-sysdiagnose": "iOS Sysdiagnose Analysis",
        }

        if workflow_name not in titles:
            messagebox.showerror(
                "Unsupported workflow",
                "The selected iOS workflow is not supported.",
            )
            return

        title = titles[workflow_name]
        evidence_type = WORKFLOWS[workflow_name]["input_type"]

        guidance = {
            "ios-backup": (
                "Select an existing iPhone backup folder containing "
                "Manifest.db and Info.plist.\n\n"
                "Do not select the Doji project folder."
            ),
            "ios-filesystem": (
                "Select an existing iOS filesystem extraction directory.\n\n"
                "This does not extract files from a connected iPhone."
            ),
            "ios-sysdiagnose": (
                "Select an existing iOS sysdiagnose archive or "
                "extracted diagnostic directory."
            ),
        }

        messagebox.showinfo(
            "Select forensic evidence",
            guidance[workflow_name],
        )

        if evidence_type == "directory":
            evidence = filedialog.askdirectory(
                title=f"{title}: Select evidence directory"
            )
        else:
            choose_file = messagebox.askyesno(
                title,
                "Is your sysdiagnose evidence a file?\n\n"
                "Yes: Select an archive file.\n"
                "No: Select an extracted directory.",
            )
            if choose_file:
                evidence = filedialog.askopenfilename(
                    title="Select iOS sysdiagnose archive"
                )
            else:
                evidence = filedialog.askdirectory(
                    title="Select extracted sysdiagnose directory"
                )

        if not evidence:
            return

        evidence_path = Path(evidence)

        if evidence_path.is_symlink() or not evidence_path.exists():
            messagebox.showerror(
                "Invalid evidence",
                "Select existing evidence that is not a symbolic link.",
            )
            return

        if evidence_type == "directory" and not evidence_path.is_dir():
            messagebox.showerror(
                "Invalid evidence",
                "This workflow requires an evidence directory.",
            )
            return

        try:
            validate_evidence(
                evidence_path,
                evidence_type,
                workflow_name,
            )
        except (ValueError, FileNotFoundError, OSError) as exc:
            messagebox.showerror(
                "Invalid forensic evidence",
                str(exc),
            )
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(self.root, title)
            progress_window.update_status(
                "Preparing read-only forensic investigation..."
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror("Progress Window Error", str(exc))
            return

        progress_queue = queue.Queue()
        running = {"active": True}

        def process_progress():
            try:
                while True:
                    progress_window.update_status(
                        progress_queue.get_nowait()
                    )
            except queue.Empty:
                pass

            if running["active"]:
                self.root.after(200, process_progress)

        def worker():
            try:
                progress_queue.put(
                    "Validating evidence and calculating its hash..."
                )

                result = run_investigation(
                    workflow_name,
                    evidence_path,
                    7200,
                )

                if result != 0:
                    raise RuntimeError(
                        "The investigation did not complete successfully. "
                        "Review the latest forensic case metadata and logs "
                        "under forensic/results."
                    )

                def show_results():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.complete(
                        "Forensic investigation completed."
                    )
                    self.status.configure(
                        text=f"{title}: Completed"
                    )
                    messagebox.showinfo(
                        title,
                        "Investigation completed.\n\n"
                        "Evidence analysis results and case metadata "
                        "are saved under forensic/results.\n\n"
                        "A completed investigation does not guarantee "
                        "the absence of spyware.",
                    )

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "Forensic investigation failed."
                    )
                    messagebox.showerror(title, error_message)

                self.root.after(0, show_error)

        self.root.after(200, process_progress)

        try:
            threading.Thread(
                target=worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "Forensic investigation could not start."
            )
            messagebox.showerror(
                "Investigation Startup Error", str(exc)
            )

    def assessment_is_busy(self):
        """Prevent overlapping security assessments."""
        if self.assessment_running:
            messagebox.showwarning(
                "Assessment already running",
                "Another Doji security assessment is currently running. "
                "Please wait for it to finish before starting another.",
            )
            return True
        return False

    def run_android_device_malware_scan(self):
        """Assess selected Android device applications in background."""
        if self.assessment_is_busy():
            return
        if self.device_scan_running:
            messagebox.showwarning(
                "Scan already running",
                "An Android device malware scan is already running.",
            )
            return

        # Discover Android devices at scan time.
        try:
            from device_manager import discover_devices
            connected = discover_devices()
        except Exception as exc:
            messagebox.showerror(
                "Device Detection Error",
                f"Doji could not check connected devices: {exc}",
            )
            return

        android_devices = [
            device for device in connected
            if device.get("platform") == "Android"
        ]
        authorized = [
            device for device in android_devices
            if device.get("state") == "Authorized"
        ]

        if not authorized:
            if android_devices:
                states = ", ".join(
                    sorted({
                        str(device.get("state", "Unknown"))
                        for device in android_devices
                    })
                )
                messagebox.showwarning(
                    "Android Authorization Required",
                    "Android device detected, but none is authorized.\\n\\n"
                    f"Connection status: {states}\\n\\n"
                    "For ADB scanning, enable USB debugging and "
                    "authorize this computer on your phone.",
                )
                return

            open_apk = messagebox.askyesno(
                "No Android Device Connected",
                "Doji could not detect an authorized Android phone.\\n\\n"
                "Connect your phone and retry the Malware Scan.\\n\\n"
                "Would you like to scan a saved APK file instead?",
            )
            if open_apk:
                self.run_apk_malware_scan()
            return

        if len(authorized) == 1:
            device = authorized[0]
        else:
            from tkinter import simpledialog

            choices = "\\n".join(
                f"{index + 1}. {item.get('name', 'Android')} "
                f"({item.get('id', 'Unknown')})"
                for index, item in enumerate(authorized)
            )

            selected = simpledialog.askinteger(
                "Choose Android Device",
                "Multiple authorized Android devices detected.\\n\\n"
                f"{choices}\\n\\n"
                "Enter the number of the device to scan:",
                parent=self.root,
                minvalue=1,
                maxvalue=len(authorized),
            )

            if selected is None:
                return

            device = authorized[selected - 1]

        try:
            serial = validate_android_scan_target(device)
        except ValueError as exc:
            messagebox.showerror(
                "Android Device Validation",
                str(exc),
            )
            return

        from tkinter import BooleanVar, StringVar, simpledialog, ttk

        class AndroidScanOptions(simpledialog.Dialog):
            def body(self, parent):
                self.scan_mode = StringVar(master=self, value="quick")

                ttk.Label(
                    parent, text="Select Security Scan Mode"
                ).pack(anchor="w", pady=(0, 8))

                ttk.Radiobutton(
                    parent,
                    text="Quick Scan (Recommended)",
                    variable=self.scan_mode,
                    value="quick",
                ).pack(anchor="w")

                ttk.Radiobutton(
                    parent,
                    text="Full Security Scan",
                    variable=self.scan_mode,
                    value="full",
                ).pack(anchor="w", pady=(4, 12))

                ttk.Label(
                    parent,
                    text=(
                        "Quick Scan excludes Quark behavioral analysis. "
                        "Full Scan analyzes every selected base APK "
                        "with Quark. Quick Scan has reduced coverage."
                    ),
                    wraplength=380,
                    justify="left",
                ).pack(anchor="w", pady=(0, 10))

                self.retain_apks = BooleanVar(master=self, value=False)
                ttk.Label(
                    parent,
                    text=(
                        "Doji attempts to analyze all ADB-visible third-party "
                        "applications, subject to APK size, collection, and "
                        "access limits. Up to 1 GiB of APK data may be collected "
                        "during an assessment. Routine scans remove local APK "
                        "copies after reports are saved."
                    ),
                    wraplength=380,
                    justify="left",
                ).pack(anchor="w", pady=(0, 10))
                checkbox = ttk.Checkbutton(
                    parent,
                    text="Retain APK copies for forensic review",
                    variable=self.retain_apks,
                )
                checkbox.pack(anchor="w")

                self.force_rescan = BooleanVar(master=self, value=False)
                ttk.Checkbutton(
                    parent,
                    text="Force fresh malware analysis",
                    variable=self.force_rescan,
                ).pack(anchor="w", pady=(8, 0))

                ttk.Label(
                    parent,
                    text="Standard scans reuse valid cached Quark analysis.",
                    wraplength=380,
                ).pack(anchor="w", pady=(4, 0))

                return checkbox

            def apply(self):
                self.result = (
                    self.retain_apks.get(),
                    self.force_rescan.get(),
                    self.scan_mode.get(),
                )

        options = AndroidScanOptions(self.root, "Android Malware Assessment")
        if options.result is None:
            return
        retain_apks, force_rescan, scan_mode = options.result
        quick_scan = scan_mode == "quick"
        quark_timeout = 15 if quick_scan else 120

        self.assessment_running = True
        self.device_scan_running = True
        self.status.configure(
            text="Android device malware assessment running..."
        )

        try:
            progress_window = ScanProgressWindow(
                self.root,
                "Android Quick Security Scan"
                if quick_scan else "Android Full Security Assessment",
            )
        except Exception as exc:
            self.assessment_running = False
            self.device_scan_running = False
            messagebox.showerror(
                "Progress Window Error",
                f"Could not open the assessment window: {exc}",
            )
            return
        progress_window.update_status(
            "Discovering and analyzing Android applications..."
        )

        progress_queue = queue.Queue()

        cancel_event = threading.Event()
        progress_window.enable_cancel(cancel_event.set)

        def process_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    progress_window.update_status(message)
            except queue.Empty:
                pass

            if self.device_scan_running:
                self.root.after(150, process_progress)

        self.root.after(150, process_progress)

        def scan_worker():
            destination = None
            report_saved = False
            try:
                from datetime import datetime, timezone
                from shutil import rmtree

                timestamp = datetime.now(timezone.utc).strftime(
                    "%Y%m%dT%H%M%S%fZ"
                )

                destination = (
                    REPORT_DIR.parent
                    / "forensic"
                    / "device_apks"
                    / f"DOJI-DEVICE-{timestamp}"
                )

                destination.mkdir(parents=True, exist_ok=False)

                try:
                    result = assess_android_device(
                        serial,
                        destination,
                        max_packages=None,
                        third_party_only=True,
                        progress_callback=progress_queue.put,
                        cancel_event=cancel_event,
                        force_rescan=force_rescan,
                        retain_apks=retain_apks,
                        quick_scan=quick_scan,
                        quark_timeout=quark_timeout,
                    )

                except Exception as exc:
                    progress_queue.put(
                        "Malware assessment failed. Continuing independent "
                        "security checks..."
                    )

                    result = {
                        "device_serial": serial,
                        "device_model": "Unknown Android Device",
                        "packages_discovered": 0,
                        "packages_selected": 0,
                        "packages_assessed": 0,
                        "packages_completed": 0,
                        "packages_partial": 0,
                        "packages_failed": 0,
                        "packages_not_run": 0,
                        "packages_not_selected": 0,
                        "applications": [],
                        "cancelled": cancel_event.is_set(),
                        "errors": [
                            f"Malware engine failure: "
                            f"{type(exc).__name__}: {exc}"
                        ],
                        "limitations": [
                            "Application malware analysis did not complete. "
                            "No malware-free conclusion can be drawn."
                        ],
                    }

                result["limitations"].append(
                    "APK copies retained for forensic review."
                    if retain_apks else
                    "Routine scans attempt to remove APK copies after each "
                    "application assessment. Local APK paths are historical "
                    "collection paths; cleanup results are recorded."
                )
                if cancel_event.is_set():
                    progress_queue.put(
                        "Malware assessment cancelled. "
                        "Saving available results..."
                    )
                else:
                    progress_queue.put(
                        "Malware assessment complete. Continuing unified scan..."
                    )
                malware_report_path = None

                configuration = {"checks": {}}
                monitoring = {
                    "completed": False,
                    "cancelled": cancel_event.is_set(),
                    "events": [],
                }

                if not cancel_event.is_set():
                    progress_queue.put(
                        "Stage 2/3: Checking Android security configuration..."
                    )
                    try:
                        configuration = assess_configuration(serial)
                    except Exception as exc:
                        configuration = {
                            "checks": {},
                            "error": f"{type(exc).__name__}: {exc}",
                        }

                if not cancel_event.is_set():
                    progress_queue.put(
                        "Stage 3/3: Monitoring Android security changes "
                        "for 30 seconds..."
                    )
                    try:
                        monitoring_started_utc = datetime.now(
                            timezone.utc
                        ).isoformat()
                        monitoring = monitor_device(
                            serial,
                            duration=30,
                            interval=5,
                            cancel_event=cancel_event,
                        )
                    except Exception as exc:
                        monitoring = {
                            "completed": False,
                            "cancelled": cancel_event.is_set(),
                            "events": [],
                            "error": f"{type(exc).__name__}: {exc}",
                            "started_utc": monitoring_started_utc,
                        }

                if cancel_event.is_set():
                    monitoring["cancelled"] = True

                progress_queue.put("Saving unified security assessment...")
                result["scan_mode"] = scan_mode
                report_path = save_unified_report(
                    result,
                    configuration,
                    monitoring,
                )

                report_saved = True

                if retain_apks:
                    apk_storage = f"APK copies retained at: {destination}"
                else:
                    progress_queue.put("Removing local APK copies...")
                    try:
                        rmtree(destination)
                    except OSError as exc:
                        apk_storage = (
                            f"APK cleanup could not finish. Check {destination}. "
                            f"Error: {exc}"
                        )
                    else:
                        apk_storage = "Local APK copies removed."

                with Path(report_path).open(
                    "r", encoding="utf-8"
                ) as saved_file:
                    unified_report = json.load(saved_file)

                coverage_status = unified_report[
                    "assessment_coverage_status"
                ]
                stage_status = unified_report["stage_status"]
                cancelled = coverage_status == "CANCELLED"

                def show_results():

                    progress_window.cancel_callback = None
                    progress_window.cancel_button.configure(
                        state="disabled"
                    )

                    if coverage_status == "CANCELLED":
                        progress_window.cancelled(
                            "Android full security assessment cancelled."
                        )
                        progress_window.details_label.configure(
                            text="Available results have been saved."
                        )
                    elif coverage_status == "COMPLETED":
                        progress_window.complete(
                            "Android full security assessment completed."
                        )
                    elif coverage_status == "PARTIAL":
                        progress_window.complete(
                            "Android full security assessment partially completed."
                        )
                    elif coverage_status == "INTERRUPTED":
                        progress_window.fail(
                            "Android connection lost. Scan interrupted. "
                            "Available results have been saved."
                        )
                        progress_window.details_label.configure(
                            text=(
                                "The device disconnected before scanning finished. "
                                "Completed findings are saved in report history. "
                                "Reconnect the device to start another assessment."
                            )
                        )
                    else:
                        progress_window.fail(
                            "Android full security assessment could not be completed."
                        )

                    self.device_scan_running = False
                    self.assessment_running = False
                    self.refresh_history()

                    coverage = result
                    summary = (
                        f"Assessment coverage: {coverage_status}\n"
                        f"Malware analysis: {stage_status['malware_analysis']}\n"
                        f"Security configuration: "
                        f"{stage_status['security_configuration']}\n"
                        f"Live monitoring: {stage_status['live_monitoring']}\n\n"
                        f"Assessment: {coverage_status}\n\n"
                        f"Discovered: {coverage['packages_discovered']}\n"
                        f"Selected: {coverage['packages_selected']}\n"
                        f"Completed: {coverage['packages_completed']}\n"
                        f"Partial: {coverage['packages_partial']}\n"
                        f"Failed: {coverage['packages_failed']}\n"
                        f"Not run: {coverage['packages_not_run']}\n"
                        f"Not selected: {coverage['packages_not_selected']}\n\n"
                        f"Report: {report_path}\n"
                        f"{apk_storage}\n\n"
                        "No known detections do not guarantee device safety."
                    )

                    self.status.configure(
                        text=(
                            "Android full security assessment cancelled."
                            if cancelled else
                            "Android connection interrupted. Results saved."
                            if coverage_status == "INTERRUPTED" else
                            "Android full security assessment finished."
                        )
                    )
                    if coverage_status == "COMPLETED":
                        notice = "Scan Completed"
                    elif coverage_status == "PARTIAL":
                        notice = "Scan Partially Completed"
                    elif coverage_status == "CANCELLED":
                        notice = "Scan Cancelled"
                    else:
                        notice = (
                            "Connection Interrupted"
                            if coverage_status == "INTERRUPTED"
                            else "Scan Failed"
                        )

                    messagebox.showinfo(
                        "Doji Mobile Security",
                        notice,
                    )

                    # Reports remain saved in history.
                    # Opening a report requires user selection.

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                if (
                    not retain_apks
                    and report_saved
                    and destination is not None
                    and destination.is_dir()
                ):
                    try:
                        from shutil import rmtree
                        rmtree(destination)
                    except OSError as cleanup_exc:
                        error_message += (
                            f"\nAPK cleanup failed: {cleanup_exc}"
                        )

                elif destination is not None and destination.is_dir():
                    error_message += (
                        f"\nAPK evidence preserved at: {destination}"
                    )

                def show_error():
                    progress_window.cancel_callback = None
                    progress_window.cancel_button.configure(
                        state="disabled"
                    )
                    progress_window.fail(
                        "Android device malware assessment failed."
                    )
                    self.device_scan_running = False
                    self.assessment_running = False
                    self.status.configure(
                        text="Android device malware assessment failed."
                    )
                    messagebox.showerror(
                        "Android Device Scan Error",
                        error_message,
                    )

                self.root.after(0, show_error)

        try:
            threading.Thread(
                target=scan_worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            self.device_scan_running = False
            self.assessment_running = False
            progress_window.fail(
                "Android device malware assessment could not start."
            )
            messagebox.showerror(
                "Scan Startup Error",
                f"Could not start the background scan: {exc}",
            )

    def run_apk_malware_scan(self):
        if self.assessment_is_busy():
            return

        apk_path = select_apk(self.root)

        if not apk_path:
            return

        force_rescan = messagebox.askyesnocancel(
            "APK Scan Options",
            "Force fresh malware analysis?\n\n"
            "Yes: Run fresh Quark analysis.\n"
            "No: Reuse valid cached analysis (recommended).\n"
            "Cancel: Return without scanning.",
            default="no",
            parent=self.root,
        )

        if force_rescan is None:
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(
                self.root,
                "Android APK Malware Analysis",
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror(
                "Progress Window Error",
                f"Could not open the assessment window: {exc}",
            )
            return
        progress_window.update_status(
            "Analyzing the selected APK for security indicators..."
        )

        progress_queue = queue.Queue()
        scan_running = {"active": True}

        cancel_event = threading.Event()
        progress_window.enable_cancel(cancel_event.set)

        def process_apk_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    progress_window.update_status(message)
            except queue.Empty:
                pass

            if scan_running["active"]:
                self.root.after(150, process_apk_progress)

        self.root.after(150, process_apk_progress)

        def scan_in_background():
            try:
                report_path = scan_apk(
                    apk_path,
                    progress_callback=progress_queue.put,
                    cancel_event=cancel_event,
                    force_rescan=force_rescan,
                )

                with open(report_path, "r", encoding="utf-8") as report_file:
                    report = json.load(report_file)

                verdict = report.get("verdict", "Unknown")
                completeness = report.get("scan_completeness") or {}
                completeness_status = completeness.get("status", "UNKNOWN")
                incomplete_checks = completeness.get("incomplete_checks") or []
                incomplete_names = ", ".join(
                    str(item.get("check", "Unknown"))
                    for item in incomplete_checks
                    if isinstance(item, dict)
                ) or "None"
                finding_count = len(report.get("findings") or [])
                incomplete_reason = report.get("incomplete_reason") or ""
                target = report.get("target", {})
                package_name = target.get("package_name") or "Unknown"

                checks = report.get("checks", {})
                vt = checks.get("virustotal", {})
                stats = vt.get("analysis_stats") or {}

                malicious = stats.get("malicious", "N/A")
                suspicious = stats.get("suspicious", "N/A")
                undetected = stats.get("undetected", "N/A")
                timed_out = stats.get("timeout", "N/A")
                vt_status = vt.get("status", "Unknown")
                vt_details = vt.get("details", "No additional details.")
                vt_link = vt.get("permalink")

                result_message = (
                    f"Doji APK Malware Analysis\n\n"
                    f"Verdict: {verdict}\n"
                    f"Scan completeness: {completeness_status}\n"
                    f"Incomplete checks: {incomplete_names}\n"
                    f"Security findings: {finding_count}\n"
                    f"{'Analysis warning: ' + incomplete_reason + chr(10) if incomplete_reason else ''}"
                    f"Package: {package_name}\n\n"
                    f"VirusTotal status: {vt_status}\n"
                    f"Malicious detections: {malicious}\n"
                    f"Suspicious detections: {suspicious}\n"
                    f"Undetected engines: {undetected}\n"
                    f"Timed-out engines: {timed_out}\n\n"
                    f"Details: {vt_details}\n\n"
                    f"Report saved to:\n{report_path}"
                )

                if vt_link:
                    result_message += f"\n\nVirusTotal report:\n{vt_link}"

                result_message += (
                    "\n\nImportant: No known detections do not guarantee "
                    "that an APK is safe. Review the report and other "
                    "available evidence."
                )

                def show_results():
                    # Display pending scanner messages before completion.
                    while True:
                        try:
                            message = progress_queue.get_nowait()
                        except queue.Empty:
                            break
                        progress_window.update_status(message)

                    scan_running["active"] = False
                    self.assessment_running = False
                    if report.get("cancelled"):
                        progress_window.cancelled(
                            "APK analysis cancelled. Partial report saved."
                        )
                    else:
                        progress_window.complete(
                            "APK malware analysis completed."
                        )
                        progress_window.stage_label.configure(
                            text="CURRENT STAGE: ASSESSMENT COMPLETED"
                        )
                    warning_needed = (
                        verdict in (
                            "SUSPICIOUS",
                            "REVIEW REQUIRED",
                            "SCAN INCOMPLETE",
                        )
                        or completeness_status == "INCOMPLETE"
                        or (isinstance(malicious, int) and malicious > 0)
                        or (isinstance(suspicious, int) and suspicious > 0)
                    )

                    if warning_needed:
                        messagebox.showwarning(
                            "Doji APK Scan Results",
                            result_message,
                        )
                    else:
                        messagebox.showinfo(
                            "Doji APK Scan Results",
                            result_message,
                        )

                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)
                def show_scan_error():
                    scan_running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "APK malware analysis failed."
                    )
                    messagebox.showerror(
                        "APK Scan Error",
                        f"Doji could not complete the scan:\n{error_message}",
                    )

                self.root.after(0, show_scan_error)

        try:
            threading.Thread(
                target=scan_in_background,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            scan_running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "APK malware analysis could not start."
            )
            messagebox.showerror(
                "APK Scan Startup Error",
                f"Could not start the background scan: {exc}",
            )

    def run_android_info_assessment(self):
        if self.assessment_is_busy():
            return

        selection = self.table.selection()

        if not selection:
            messagebox.showinfo(
                "Select a device",
                "Select your Android phone on the Devices page first.",
            )
            self.show_page("Devices")
            return

        device = self.devices[int(selection[0])]

        if device.get("platform") != "Android":
            messagebox.showinfo(
                "Android required",
                "Select your connected Android phone on the Devices page.",
            )
            return

        device_id = device.get("id", "")
        if not device_id:
            messagebox.showerror(
                "Device ID missing",
                "Doji could not find the selected device ID.",
            )
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(
                self.root,
                "Android Information Check",
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror(
                "Progress Window Error",
                f"Could not open the assessment window: {exc}",
            )
            return
        progress_window.update_status(
            "Preparing Android information assessment..."
        )

        progress_queue = queue.Queue()
        scan_running = {"active": True}

        def process_info_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    progress_window.update_status(message)
            except queue.Empty:
                pass

            if scan_running["active"]:
                self.root.after(150, process_info_progress)

        self.root.after(150, process_info_progress)

        def android_info_worker():
            try:
                report = new_assessment(
                    device.get("name", "Android device"),
                    "Android",
                    device_id,
                )

                report["report_type"] = "android_information"

                def adb_read(args):
                    output, error = run_command(
                        ["adb", "-s", device_id, *args]
                    )
                    return output.strip(), error.strip()

                progress_queue.put("Reading Android system properties...")
                # Collect basic device metadata.
                properties = [
                    ("Manufacturer", "ro.product.manufacturer"),
                    ("Device model", "ro.product.model"),
                    ("Android version", "ro.build.version.release"),
                    ("Android SDK version", "ro.build.version.sdk"),
                    ("Android security patch level",
                     "ro.build.version.security_patch"),
                ]

                patch_level = ""
                for label, prop in properties:
                    value, error = adb_read(["shell", "getprop", prop])

                    if prop == "ro.build.version.security_patch":
                        patch_level = value

                    add_finding(
                        report,
                        f"Read {label.lower()}",
                        "PASS" if value else "WARNING",
                        f"{label}: {value}" if value else
                        f"Could not retrieve {label.lower()}: "
                        f"{error or 'No value returned.'}",
                        severity="INFO" if value else "LOW",
                        confidence="HIGH" if value else "LOW",
                        evidence={"property": prop, "value": value or None,
                                  "error": error or None},
                        remediation=(
                            "No action indicated by this metadata check."
                            if value else
                            "Reconnect the authorized device and retry. "
                            "Some Android builds restrict diagnostic access."
                        ),
                    )

                progress_queue.put("Evaluating Android security patch age...")
                # Evaluate patch age only when Android provides a valid date.
                from datetime import date

                if patch_level:
                    try:
                        patch_date = date.fromisoformat(patch_level)
                        age_days = (date.today() - patch_date).days

                        if age_days < 0:
                            patch_status = "WARNING"
                            patch_details = (
                                f"Reported patch date {patch_level} is in the "
                                "future relative to the assessment system date."
                            )
                            patch_severity = "LOW"
                        elif age_days > 180:
                            patch_status = "WARNING"
                            patch_details = (
                                f"Reported security patch level is {patch_level}, "
                                f"approximately {age_days} days old. This exceeds "
                                "Doji's 180-day review threshold; it does not by "
                                "itself prove that the device is vulnerable."
                            )
                            patch_severity = "MEDIUM"
                        else:
                            patch_status = "PASS"
                            patch_details = (
                                f"Reported security patch level is {patch_level}, "
                                f"approximately {age_days} days old. It is within "
                                "Doji's 180-day review threshold."
                            )
                            patch_severity = "INFO"

                        add_finding(
                            report,
                            "Review Android security patch age",
                            patch_status,
                            patch_details,
                            severity=patch_severity,
                            confidence="MEDIUM",
                            evidence={
                                "reported_patch_level": patch_level,
                                "age_days": age_days,
                                "review_threshold_days": 180,
                            },
                            remediation=(
                                "Check for and install the latest official system "
                                "update from the device manufacturer."
                                if patch_status != "PASS" else
                                "Continue checking for official security updates."
                            ),
                            limitations=[
                                "The 180-day threshold is a Doji review heuristic, "
                                "not an official vulnerability determination.",
                                "Patch availability varies by manufacturer and model.",
                            ],
                        )
                    except ValueError:
                        add_finding(
                            report,
                            "Review Android security patch age",
                            "WARNING",
                            f"Android returned an unrecognized patch date: "
                            f"{patch_level}",
                            severity="LOW",
                            confidence="LOW",
                            evidence={"reported_patch_level": patch_level},
                            remediation=(
                                "Verify the security patch date in Android "
                                "Settings and check for official system updates."
                            ),
                        )
                else:
                    add_finding(
                        report,
                        "Review Android security patch age",
                        "NOT_RUN",
                        "The device did not provide a security patch date.",
                        severity="INFO",
                        confidence="LOW",
                        evidence={"reported_patch_level": None},
                        remediation=(
                            "Check Android Settings for the security patch level "
                            "and retry if the device exposes this property."
                        ),
                    )

                progress_queue.put("Checking device encryption...")
                # Check Android-reported encryption state and type.
                encryption, state_error = adb_read([
                    "shell", "getprop", "ro.crypto.state"
                ])
                crypto_type, type_error = adb_read([
                    "shell", "getprop", "ro.crypto.type"
                ])

                encryption_value = encryption.strip().lower()
                crypto_type_value = crypto_type.strip().lower()

                encryption_types = {
                    "file": "file-based encryption (FBE)",
                    "block": "full-disk encryption (FDE)",
                }

                if encryption_value == "encrypted":
                    status = "PASS"
                    severity = "INFO"

                    if crypto_type_value in encryption_types:
                        details = (
                            "Android reports encryption enabled using "
                            f"{encryption_types[crypto_type_value]}."
                        )
                    else:
                        details = (
                            "Android reports encryption enabled, but the "
                            "encryption type could not be identified."
                        )

                elif encryption_value == "unencrypted":
                    status = "FAIL"
                    severity = "HIGH"
                    details = (
                        "Android reports device encryption as disabled. "
                        "Verify this in the device security settings."
                    )

                else:
                    status = "WARNING"
                    severity = "LOW"
                    details = (
                        "Could not confirm Android encryption state. "
                        f"Reported value: {encryption or 'Not available'}."
                    )

                add_finding(
                    report,
                    "Check reported device encryption state",
                    status,
                    details,
                    severity=severity,
                    confidence=(
                        "MEDIUM"
                        if encryption_value in {"encrypted", "unencrypted"}
                        else "LOW"
                    ),
                    evidence={
                        "ro.crypto.state": encryption_value or None,
                        "ro.crypto.type": crypto_type_value or None,
                        "state_error": state_error or None,
                        "type_error": type_error or None,
                    },
                    remediation=(
                        "Review device security settings and official "
                        "manufacturer guidance about encryption."
                        if status == "FAIL" else
                        "Verify encryption in Android Settings."
                        if status == "WARNING" else
                        "No action indicated by this metadata check."
                    ),
                    limitations=[
                        "These values are Android-reported system properties.",
                        "They do not independently verify encryption keys, "
                        "data protection, or resistance to compromise.",
                        "An unavailable encryption type does not establish "
                        "that encryption is disabled.",
                    ],
                )

                progress_queue.put("Checking USB debugging status...")
                # Check USB debugging.
                adb_enabled, error = adb_read([
                    "shell", "settings", "get", "global", "adb_enabled"
                ])

                if adb_enabled == "1":
                    status = "WARNING"
                    severity = "LOW"
                    details = "USB debugging is enabled."
                    remediation = (
                        "Disable USB debugging when it is not required, and "
                        "revoke unused debugging authorizations."
                    )
                elif adb_enabled == "0":
                    status = "PASS"
                    severity = "INFO"
                    details = "USB debugging is reported as disabled."
                    remediation = "No action indicated by this check."
                else:
                    status = "WARNING"
                    severity = "LOW"
                    details = (
                        "Could not confirm USB debugging state. "
                        f"Returned value: {adb_enabled or error or 'No value'}"
                    )
                    remediation = (
                        "Check Developer options on the device to verify "
                        "the USB debugging setting."
                    )

                add_finding(
                    report,
                    "Check USB debugging setting",
                    status,
                    details,
                    severity=severity,
                    confidence="HIGH" if adb_enabled in {"0", "1"} else "LOW",
                    evidence={"adb_enabled": adb_enabled or None,
                              "error": error or None},
                    remediation=remediation,
                )

                progress_queue.put("Checking ADB authorization...")
                # Record the current ADB authorization state.
                adb_state = device.get("state", "")
                authorized = adb_state == "Authorized"

                add_finding(
                    report,
                    "Check ADB connection authorization",
                    "PASS" if authorized else "WARNING",
                    f"Doji reports the ADB connection state as "
                    f"{adb_state or 'Unknown'}.",
                    severity="INFO" if authorized else "LOW",
                    confidence="HIGH" if adb_state else "LOW",
                    evidence={"connection_state": adb_state or None},
                    remediation=(
                        "Disconnect debugging access when testing is complete."
                        if authorized else
                        "Unlock the device and approve the debugging prompt "
                        "only if you trust this computer."
                    ),
                )

                progress_queue.put("Collecting third-party application metadata...")
                # Collect third-party package identifiers as metadata only.
                packages, package_error = adb_read([
                    "shell", "pm", "list", "packages", "-3"
                ])

                if packages and not package_error:
                    package_names = sorted(
                        line.strip().removeprefix("package:")
                        for line in packages.splitlines()
                        if line.strip().startswith("package:")
                    )
                    add_finding(
                        report,
                        "Inventory third-party application package names",
                        "PASS",
                        f"Retrieved {len(package_names)} third-party package "
                        "identifier(s). Package names alone do not establish "
                        "whether an application is malicious.",
                        severity="INFO",
                        confidence="MEDIUM",
                        evidence={
                            "package_count": len(package_names),
                            "packages": package_names,
                        },
                        remediation=(
                            "Review unfamiliar applications on the device and "
                            "verify their publishers through trusted sources."
                        ),
                        limitations=[
                            "This inventory does not inspect application code, "
                            "permissions, runtime behavior, or reputation.",
                            "Some packages may be hidden or omitted by the OS.",
                        ],
                    )
                else:
                    add_finding(
                        report,
                        "Inventory third-party application package names",
                        "NOT_RUN",
                        "Doji could not retrieve third-party package metadata.",
                        severity="INFO",
                        confidence="LOW",
                        evidence={"error": package_error or None},
                        remediation=(
                            "Reconnect the authorized Android device and retry."
                        ),
                    )

                report["limitations"].append(
                    "Doji performed read-only checks using available ADB "
                    "diagnostics. The patch-age threshold is a review heuristic. "
                    "Application package names are metadata, not malware verdicts."
                )
                report["limitations"].append(
                    "This is not a full vulnerability audit or malware scan. "
                    "A passing result does not prove the device is uncompromised."
                )

                progress_queue.put("Saving Android information report...")
                path = save_report(report)


                def show_results():
                    scan_running["active"] = False
                    self.assessment_running = False
                    progress_window.complete(
                        "Android information assessment completed."
                    )
                    self.current_report = report
                    self.refresh_history()
                    self.status.configure(
                        text=f"Doji Android report saved: {path.name}"
                    )
                    messagebox.showinfo(
                        "Doji Android assessment complete",
                        f"Doji report saved to:\n{path}\n\n"
                        "Read-only checks completed. This is not a malware verdict."
                    )



                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    scan_running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "Android information assessment failed."
                    )
                    messagebox.showerror(
                        "Android Information Check Error",
                        error_message,
                    )

                self.root.after(0, show_error)

        try:
            threading.Thread(
                target=android_info_worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            scan_running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "Android information assessment could not start."
            )
            messagebox.showerror(
                "Android Information Startup Error",
                f"Could not start the background assessment: {exc}",
            )

    def run_android_permission_assessment(self):
        """Read Android app permission metadata using ADB."""
        if self.assessment_is_busy():
            return
        selection = self.table.selection()

        if not selection:
            messagebox.showinfo(
                "Select a device",
                "Select your Android phone on the Devices page first.",
            )
            self.show_page("Devices")
            return

        device = self.devices[int(selection[0])]

        if device.get("platform") != "Android":
            messagebox.showinfo(
                "Android required",
                "Select your connected Android phone on the Devices page.",
            )
            return

        device_id = device.get("id", "")
        if not device_id:
            messagebox.showerror(
                "Device ID missing",
                "Doji could not find the selected device ID.",
            )
            return

        self.assessment_running = True

        try:
            progress_window = ScanProgressWindow(
                self.root,
                "Android Application Permission Check",
            )
        except Exception as exc:
            self.assessment_running = False
            messagebox.showerror(
                "Progress Window Error",
                f"Could not open the assessment window: {exc}",
            )
            return
        progress_window.update_status(
            "Preparing Android permission assessment..."
        )

        progress_queue = queue.Queue()
        scan_running = {"active": True}

        def process_permission_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    progress_window.update_status(message)
            except queue.Empty:
                pass

            if scan_running["active"]:
                self.root.after(150, process_permission_progress)

        self.root.after(150, process_permission_progress)

        def permission_worker():
            try:
                report = new_assessment(
                    device.get("name", "Android device"),
                    "Android",
                    device_id,
                )

                report["report_type"] = "android_permissions"

                def adb_read(args):
                    output, error = run_command(
                        ["adb", "-s", device_id, *args]
                    )
                    return output.strip(), error.strip()

                progress_queue.put("Discovering third-party Android applications...")
                output, error = adb_read(["shell", "pm", "list", "packages", "-3"])

                if error or not output:
                    add_finding(
                        report,
                        "Retrieve installed third-party applications",
                        "NOT_RUN",
                        "Doji could not retrieve the third-party package list.",
                        severity="INFO",
                        confidence="LOW",
                        evidence={"error": error or "No package list returned"},
                        remediation=(
                            "Reconnect the Android phone, ensure ADB debugging "
                            "is authorized, and retry."
                        ),
                    )
                    package_names = []
                else:
                    package_names = sorted({
                        line.strip().removeprefix("package:")
                        for line in output.splitlines()
                        if line.strip().startswith("package:")
                    })

                    add_finding(
                        report,
                        "Retrieve installed third-party applications",
                        "PASS",
                        f"Retrieved {len(package_names)} third-party package names.",
                        severity="INFO",
                        confidence="HIGH",
                        evidence={"package_count": len(package_names)},
                        limitations=[
                            "Package inventory alone does not identify malware."
                        ],
                    )

                app_results = []
                app_errors = []

                # Inspect a limited number of apps to keep the check responsive.
                selected_packages = package_names[:100]

                for index, package in enumerate(selected_packages, start=1):
                    progress_queue.put(
                        f"Checking permissions: application {index} "
                        f"of {len(selected_packages)} - {package}"
                    )
                    details, detail_error = adb_read([
                        "shell", "dumpsys", "package", package
                    ])

                    if detail_error or not details:
                        app_errors.append({
                            "package": package,
                            "error": detail_error or "No package details returned",
                        })
                        continue

                    parsed = parse_package_permissions(details)

                    if not (
                        parsed["requested_permissions"]
                        or parsed["install_permissions"]
                        or parsed["runtime_permissions_by_user"]
                    ):
                        app_errors.append({
                            "package": package,
                            "error": "No recognizable permission metadata returned",
                        })
                        continue

                    install = parsed["install_permissions"]
                    runtime = parsed["runtime_permissions_by_user"]

                    granted = {
                        permission
                        for permission, state in install.items()
                        if state is True
                    }
                    denied = {
                        permission
                        for permission, state in install.items()
                        if state is False
                    }

                    for user_permissions in runtime.values():
                        for permission, state in user_permissions.items():
                            if state is True:
                                granted.add(permission)
                            elif state is False:
                                denied.add(permission)

                    app_results.append({
                        "package": package,
                        "requested_permissions": parsed["requested_permissions"],
                        "install_permissions": install,
                        "runtime_permissions_by_user": runtime,
                        "granted_permissions_reported": sorted(granted),
                        "denied_permissions_reported": sorted(denied),
                    })

                if app_results:
                    requested_total = sum(
                        len(app["requested_permissions"]) for app in app_results
                    )
                    granted_total = sum(
                        len(app["granted_permissions_reported"])
                        for app in app_results
                    )
                    denied_total = sum(
                        len(app["denied_permissions_reported"])
                        for app in app_results
                    )

                    add_finding(
                        report,
                        "Inventory application permission metadata",
                        (
                            "WARNING"
                            if app_errors or len(package_names) > 100
                            else "PASS"
                        ),
                        (
                            f"Read permission metadata for {len(app_results)} "
                            f"application(s). Recorded {requested_total} requested, "
                            f"{granted_total} reported granted, and "
                            f"{denied_total} reported denied permission entries. "
                            f"Failed applications: {len(app_errors)}. "
                            f"Not inspected due to limit: "
                            f"{max(0, len(package_names) - 100)}."
                        ),
                        severity="INFO",
                        confidence="MEDIUM",
                        evidence={
                            "applications_inspected": len(app_results),
                            "applications": app_results,
                            "applications_with_errors": app_errors,
                        },
                        remediation=(
                            "Review sensitive permissions against each app's "
                            "purpose. Revoke unnecessary permissions in Android "
                            "Settings where appropriate."
                        ),
                        limitations=[
                            "Requested permissions are not necessarily granted.",
                            "Android versions and package-manager output vary.",
                            "Some permission grants may not be represented in the "
                            "parsed sections; this report is not a complete "
                            "permission-state guarantee.",
                            "Permission metadata alone does not establish malicious "
                            "behavior or a vulnerability.",
                        ],
                    )
                else:
                    add_finding(
                        report,
                        "Inventory application permission metadata",
                        "NOT_RUN",
                        "Doji could not parse permission metadata for any app.",
                        severity="INFO",
                        confidence="LOW",
                        evidence={"application_errors": app_errors},
                        remediation=(
                            "Check ADB authorization and Android package-manager "
                            "output, then retry."
                        ),
                    )

                report["limitations"].append(
                    "This assessment reads package-manager metadata only. "
                    "It does not install, modify, or remove applications or "
                    "permissions and does not constitute a full security audit."
                )

                progress_queue.put("Saving Android permission report...")
                path = save_report(report)


                def show_results():
                    scan_running["active"] = False
                    self.assessment_running = False
                    progress_window.complete(
                        "Android permission assessment completed."
                    )
                    self.current_report = report
                    self.refresh_history()
                    self.status.configure(
                        text=f"Doji permission report saved: {path.name}"
                    )
                    messagebox.showinfo(
                        "Doji permission assessment complete",
                        f"Doji report saved to:\n{path}\n\n"
                        f"Applications inspected: {len(app_results)}\n"
                        "Review the report's limitations before interpreting results.",
                    )


                self.root.after(0, show_results)

            except Exception as exc:
                error_message = str(exc)

                def show_error():
                    scan_running["active"] = False
                    self.assessment_running = False
                    progress_window.fail(
                        "Android permission assessment failed."
                    )
                    messagebox.showerror(
                        "Android Permission Check Error",
                        error_message,
                    )

                self.root.after(0, show_error)

        try:
            threading.Thread(
                target=permission_worker,
                daemon=True,
            ).start()
        except RuntimeError as exc:
            scan_running["active"] = False
            self.assessment_running = False
            progress_window.fail(
                "Android permission assessment could not start."
            )
            messagebox.showerror(
                "Android Permission Startup Error",
                f"Could not start the background assessment: {exc}",
            )

    def refresh_history(self):
        self.report_history.delete(0, tk.END)

        # Forensic investigations are indexed separately from
        # ordinary JSON reports to protect existing report actions.
        forensic_results = (
            Path(__file__).resolve().parent.parent
            / "forensic" / "results"
        )

        self.forensic_history_paths = []

        if forensic_results.is_dir():
            for case_dir in forensic_results.glob(
                "DOJI-FORENSIC-*"
            ):
                if (
                    not case_dir.is_dir()
                    or case_dir.is_symlink()
                ):
                    continue

                metadata_path = (
                    case_dir / "case_metadata.json"
                )

                if (
                    metadata_path.is_file()
                    and not metadata_path.is_symlink()
                ):
                    self.forensic_history_paths.append(
                        metadata_path
                    )

            self.forensic_history_paths.sort(
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        forensic_case_ids = {
            metadata_path.parent.name
            for metadata_path in self.forensic_history_paths
        }

        self.history_paths = sorted(
            (
                path for path in REPORT_DIR.glob("*.json")
                if not (
                    path.stem.startswith("DOJI-FORENSIC-")
                    and path.stem in forensic_case_ids
                )
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        for path in self.history_paths:
            try:
                data = json.loads(
                    path.read_text(encoding="utf-8")
                )

                if not isinstance(data, dict):
                    raise ValueError("Invalid report format")

                target = data.get("target") or {}
                summary = data.get("summary") or {}

                if not isinstance(target, dict):
                    target = {}
                if not isinstance(summary, dict):
                    summary = {}

                name = str(target.get("name") or "Unknown device")
                platform = str(
                    target.get("platform") or "Unknown"
                )

                passed = summary.get("passed", 0)
                warnings = summary.get("warnings", 0)
                not_run = summary.get("not_run", 0)

                forensic = data.get("forensic_analysis") or {}
                if not isinstance(forensic, dict):
                    forensic = {}

                case_id = str(forensic.get("case_id") or "")
                is_simulated = "SIMULATED" in case_id.upper()

                prefix = (
                    "[TEST / SIMULATED] "
                    if is_simulated else ""
                )

                from datetime import datetime, timezone

                created = data.get("created_utc")
                scan_time = "Date unavailable"

                if isinstance(created, str):
                    try:
                        parsed = datetime.fromisoformat(
                            created.replace("Z", "+00:00")
                        )
                        if parsed.tzinfo is None:
                            parsed = parsed.replace(tzinfo=timezone.utc)
                        local_time = parsed.astimezone()
                        scan_time = local_time.strftime(
                            "%d %b %Y, %I:%M %p"
                        )
                    except ValueError:
                        pass

                scan_type = str(
                    data.get("report_type") or "Security Assessment"
                ).replace("_", " ").title()

                label = (
                    f"{prefix}{name}  |  "
                    f"{scan_time}  |  "
                    f"{scan_type}"
                )

            except (OSError, ValueError, TypeError):
                label = f"[REPORT] {path.name}"

            self.report_history.insert(tk.END, label)

        valid_forensic_paths = []
        for metadata_path in self.forensic_history_paths:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue

            if not isinstance(metadata, dict):
                continue

            platform = metadata.get("platform", "Unknown")
            status = metadata.get("status", "UNKNOWN")
            case_id = metadata.get("case_id", metadata_path.parent.name)
            from datetime import datetime, timezone

            created = metadata.get("created_utc")
            scan_time = "Date unavailable"

            if isinstance(created, str):
                try:
                    parsed = datetime.fromisoformat(
                        created.replace("Z", "+00:00")
                    )
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    scan_time = parsed.astimezone(
                        timezone.utc
                    ).strftime("%d %b %Y, %H:%M UTC")
                except ValueError:
                    pass

            self.report_history.insert(
                tk.END,
                f"{scan_time} | [FORENSIC] {platform} | "
                f"{status} | {case_id}"
            )
            valid_forensic_paths.append(metadata_path)

        self.forensic_history_paths = valid_forensic_paths

        # Unified chronological history index.
        # Existing report functions remain unchanged until
        # their selection logic is migrated together.
        self.unified_history = []

        for index, report_path in enumerate(self.history_paths):
            self.unified_history.append({
                "type": "report",
                "path": report_path,
                "original_index": index,
            })

        for index, metadata_path in enumerate(self.forensic_history_paths):
            self.unified_history.append({
                "type": "forensic",
                "path": metadata_path,
                "original_index": index,
            })

        self.unified_history.sort(
            key=lambda entry: entry["path"].stat().st_mtime,
            reverse=True,
        )

        # Preserve the current list order until Open, Delete,
        # and PDF actions are migrated to unified_history.
        # This avoids mismatched selections during migration.

    def get_selected_history_entry(self):
        """Return the selected entry from the unified history index."""
        selection = self.report_history.curselection()

        if not selection:
            return None

        index = selection[0]
        entries = getattr(self, "unified_history", [])

        if not 0 <= index < len(entries):
            return None

        return entries[index]

    def delete_selected_forensic_case(self, case_index):
        from shutil import rmtree

        try:
            metadata_path = self.forensic_history_paths[case_index]
            case_dir = metadata_path.parent
            forensic_dir = Path(__file__).resolve().parent.parent / "forensic"
            results_dir = forensic_dir / "results"
            if (
                forensic_dir.is_symlink()
                or results_dir.is_symlink()
                or case_dir.parent != results_dir
                or not case_dir.name.startswith("DOJI-FORENSIC-")
                or case_dir.is_symlink()
                or not case_dir.is_dir()
                or metadata_path.name != "case_metadata.json"
                or metadata_path.is_symlink()
            ):
                raise ValueError("The selected folder is not a valid local forensic case.")

            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("The case metadata is invalid.")
            evidence = metadata.get("evidence")
            source_path = evidence.get("source_path") if isinstance(evidence, dict) else None
            if not isinstance(source_path, str) or not Path(source_path).is_absolute():
                raise ValueError("The original evidence location could not be verified.")
            evidence_path = Path(source_path)
            if (
                evidence_path.is_relative_to(case_dir)
                or evidence_path.resolve().is_relative_to(case_dir.resolve())
            ):
                raise ValueError("The original evidence is inside this case folder.")
        except (IndexError, OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Case deletion blocked", str(exc))
            return

        if not messagebox.askyesno(
            "Delete forensic case results",
            f"Permanently delete the generated results in this folder?\n\n{case_dir}",
        ):
            return

        try:
            rmtree(case_dir)
        except OSError as exc:
            messagebox.showerror(
                "Case deletion failed",
                f"Could not finish deleting {case_dir}:\n{exc}",
            )
            return

        self.current_report = None
        self.refresh_history()
        self.status.configure(text=f"Deleted forensic case {case_dir.name}.")

    def delete_selected_report(self):
        selection = self.report_history.curselection()
        if selection and selection[0] >= len(self.history_paths):
            forensic_index = selection[0] - len(self.history_paths)

            try:
                metadata_path = self.forensic_history_paths[forensic_index]
                case_id = metadata_path.parent.name

                if not (
                    case_id.startswith("DOJI-FORENSIC-")
                    and metadata_path.name == "case_metadata.json"
                    and metadata_path.is_file()
                    and not metadata_path.is_symlink()
                ):
                    raise ValueError("Invalid forensic case selection.")

                report_dir = REPORT_DIR.resolve()
                json_path = REPORT_DIR / f"{case_id}.json"
                pdf_path = REPORT_DIR / f"{case_id}.pdf"

                for report_path in (json_path, pdf_path):
                    if (
                        report_path.parent.resolve() != report_dir
                        or report_path.is_symlink()
                    ):
                        raise ValueError("Unsafe report path.")

            except (IndexError, OSError, ValueError) as exc:
                messagebox.showerror("Deletion blocked", str(exc))
                return

            existing = [
                report_path
                for report_path in (json_path, pdf_path)
                if report_path.is_file()
            ]

            if not existing:
                messagebox.showinfo(
                    "No generated reports",
                    "No generated JSON or PDF reports exist for this case. "
                    "The forensic investigation remains protected."
                )
                return

            if not messagebox.askyesno(
                "Delete forensic reports",
                "Delete the generated JSON and PDF reports for "
                f"{case_id}?\n\n"
                "The original forensic investigation and evidence "
                "will be preserved."
            ):
                return

            try:
                for report_path in existing:
                    report_path.unlink()
            except OSError as exc:
                messagebox.showerror("Deletion failed", str(exc))
                self.refresh_history()
                return

            self.current_report = None
            self.refresh_history()
            self.status.configure(
                text=f"Deleted generated reports for {case_id}."
            )
            messagebox.showinfo(
                "Reports deleted",
                "Generated forensic reports deleted. "
                "The investigation case remains available."
            )
            return

        if not selection:
            messagebox.showinfo(
                "Select a report",
                "Please select a report from the history list first.",
            )
            return

        report_path = self.history_paths[selection[0]]
        report_dir = REPORT_DIR.resolve()

        if (
            report_path.parent.resolve() != report_dir
            or report_path.suffix.lower() != ".json"
            or report_path.is_symlink()
        ):
            messagebox.showerror(
                "Deletion blocked",
                "The selected file is not a valid local Doji report.",
            )
            return

        pdf_path = report_path.with_suffix(".pdf")

        if not messagebox.askyesno(
            "Delete report",
            f"Delete this report and its matching PDF, if present?\n\n"
            f"{report_path.name}\n\n"
            "This action cannot be undone.",
        ):
            return

        try:
            report_path.unlink()
            if pdf_path.is_file() and not pdf_path.is_symlink():
                pdf_path.unlink()
        except OSError as exc:
            messagebox.showerror(
                "Deletion failed",
                f"Could not delete the report:\n{exc}",
            )
            self.refresh_history()
            return

        self.current_report = None
        self.refresh_history()
        self.status.configure(
            text=f"Deleted report: {report_path.name}"
        )

        messagebox.showinfo(
            "Report deleted",
            "The selected report was deleted successfully.",
        )

    def clear_report_history(self):
        report_dir = REPORT_DIR.resolve()

        json_reports = [
            path for path in REPORT_DIR.glob("*.json")
            if path.parent.resolve() == report_dir
            and not path.is_symlink()
            and not path.name.startswith("DOJI-FORENSIC-")
        ]

        if not json_reports:
            messagebox.showinfo(
                "History empty",
                "There are no reports to clear.",
            )
            return

        if not messagebox.askyesno(
            "Clear report history",
            f"Delete {len(json_reports)} JSON reports and their "
            "matching PDF files?\\n\\n"
            "This cannot be undone. Original forensic evidence "
            "and collected APKs will not be deleted.",
        ):
            return

        deleted = 0
        errors = []

        for report_path in json_reports:
            pdf_path = report_path.with_suffix(".pdf")

            try:
                report_path.unlink()
                deleted += 1

                if pdf_path.is_file() and not pdf_path.is_symlink():
                    pdf_path.unlink()

            except OSError as exc:
                errors.append(f"{report_path.name}: {exc}")

        self.current_report = None
        self.refresh_history()

        self.status.configure(
            text=f"Cleared {deleted} reports from history."
        )

        if errors:
            messagebox.showwarning(
                "History partially cleared",
                f"Deleted {deleted} reports.\\n\\n"
                + "\\n".join(errors[:5]),
            )
        else:
            messagebox.showinfo(
                "History cleared",
                f"Successfully deleted {deleted} reports.",
            )

    def view_latest_report(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        paths = sorted(
            REPORT_DIR.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not paths:
            messagebox.showinfo(
                "No reports", "Run a security assessment first."
            )
            return

        self.display_report(paths[0])

    def open_selected_history(self, _event=None):
        selection = self.report_history.curselection()

        if not selection:
            return

        index = selection[0]

        if index < len(self.history_paths):
            self.display_report(self.history_paths[index])
            return

        forensic_index = index - len(self.history_paths)

        if forensic_index >= len(self.forensic_history_paths):
            messagebox.showerror(
                "History error",
                "The selected forensic case could not be found. "
                "Refresh the Reports page.",
            )
            return

        metadata_path = self.forensic_history_paths[
            forensic_index
        ]

        self.display_forensic_case(metadata_path)

    def display_forensic_case(self, metadata_path):
        """Display saved forensic case details without modifying evidence."""
        from ui.forensic_report_adapter import prepare_forensic_report
        from ui.professional_report import ProfessionalReportViewer

        try:
            report = prepare_forensic_report(metadata_path)
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror(
                "Forensic report error",
                f"Could not prepare forensic report:\n{exc}",
            )
            return

        ProfessionalReportViewer(
            self.root,
            report,
            Path(metadata_path).parent.name,
        )

        self.status.configure(
            text=f"Viewing forensic investigation: {Path(metadata_path).parent.name}"
        )
        return

        try:
            metadata_path = Path(metadata_path)

            results_dir = (
                Path(__file__).resolve().parent.parent
                / "forensic" / "results"
            ).resolve()

            case_dir = metadata_path.parent

            if (
                case_dir.parent.resolve() != results_dir
                or case_dir.is_symlink()
                or metadata_path.is_symlink()
                or metadata_path.name != "case_metadata.json"
            ):
                raise ValueError("Invalid forensic case location.")

            metadata = json.loads(
                metadata_path.read_text(encoding="utf-8")
            )

            if not isinstance(metadata, dict):
                raise ValueError("Invalid forensic case metadata.")

            findings_path = case_dir / "doji_findings.json"
            findings_data = {}

            if (
                findings_path.is_file()
                and not findings_path.is_symlink()
            ):
                findings_data = json.loads(
                    findings_path.read_text(encoding="utf-8")
                )

                if not isinstance(findings_data, dict):
                    raise ValueError("Invalid forensic findings format.")

        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror(
                "Forensic report error",
                f"Could not load investigation details:\\n{exc}",
            )
            return

        integrity = metadata.get("evidence_integrity") or {}
        if not isinstance(integrity, dict):
            integrity = {}

        lines = [
            "DOJI FORENSIC INVESTIGATION",
            "=" * 55,
            "",
            f"Case ID: {metadata.get('case_id', 'Unknown')}",
            f"Platform: {metadata.get('platform', 'Unknown')}",
            f"Workflow: {metadata.get('workflow', 'Unknown')}",
            f"Status: {metadata.get('status', 'Unknown')}",
            f"Started: {metadata.get('created_utc', 'Unknown')}",
            f"Finished: {metadata.get('finished_utc', 'Unknown')}",
            f"Return code: {metadata.get('return_code', 'Unknown')}",
            "",
            "EVIDENCE INTEGRITY",
            "-" * 55,
            f"Status: {integrity.get('status', 'Unknown')}",
            f"Content unchanged: {integrity.get('content_unchanged', 'Unknown')}",
            "",
        ]

        if metadata.get("status") != "COMPLETED":
            lines.extend([
                "INVESTIGATION NOTICE",
                "-" * 55,
                "This investigation did not complete successfully.",
                "Its status is not evidence of malware infection.",
                "",
            ])

        findings = findings_data.get("findings", [])
        correlated = findings_data.get("correlated_findings", [])

        if not isinstance(findings, list):
            findings = []

        if not isinstance(correlated, list):
            correlated = []

        lines.extend([
            "FINDINGS SUMMARY",
            "-" * 55,
            f"Individual findings: {len(findings)}",
            f"Correlated findings: {len(correlated)}",
            "",
            "Findings are observations, not automatically",
            "confirmed malware detections.",
            "",
        ])

        for index, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue

            lines.extend([
                f"FINDING {index}",
                "-" * 55,
                f"Title: {finding.get('title', 'Unknown')}",
                f"Classification: {finding.get('classification', 'Unknown')}",
                f"Severity: {finding.get('severity', 'Unknown')}",
                f"Confidence: {finding.get('confidence', 'Unknown')}",
                f"Explanation: {finding.get('explanation', '')}",
                f"Recommendation: {finding.get('recommendation', '')}",
                "",
            ])

        for index, finding in enumerate(correlated, 1):
            if not isinstance(finding, dict):
                continue

            lines.extend([
                f"CORRELATED FINDING {index}",
                "-" * 55,
                f"Classification: {finding.get('classification', 'Unknown')}",
                f"Package: {finding.get('package', 'Unknown')}",
                f"Permission: {finding.get('permission', 'Unknown')}",
                f"Events: {finding.get('event_count', 0)}",
                f"Severity: {finding.get('severity', 'Unknown')}",
                f"Confidence: {finding.get('confidence', 'Unknown')}",
                f"Interpretation: {finding.get('interpretation', '')}",
                f"Recommendation: {finding.get('recommendation', '')}",
                "",
            ])

        window = tk.Toplevel(self.root)
        window.title(
            f"Doji Forensic Investigation — {case_dir.name}"
        )
        window.geometry("850x620")
        window.configure(bg=BG)

        text_box = tk.Text(
            window,
            wrap="word",
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            padx=16,
            pady=16,
        )
        text_box.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=12,
        )

        text_box.insert("1.0", "\n".join(lines))
        text_box.configure(state="disabled")

        self.status.configure(
            text=f"Viewing forensic investigation: {case_dir.name}"
        )

    def display_report(self, path):
        """Open the professional Doji assessment report viewer."""
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            messagebox.showerror(
                "Report Error",
                f"Could not read report:\n{exc}",
            )
            return

        if not isinstance(report, dict):
            messagebox.showerror(
                "Report Error",
                "The report must contain a JSON object.",
            )
            return

        from ui.professional_report import ProfessionalReportViewer

        self.current_report = report

        ProfessionalReportViewer(
            self.root,
            report,
            path.name,
        )

        self.status.configure(
            text=f"Viewing security report: {path.name}"
        )

    def export_report(self):
        if self.current_report is None:
            messagebox.showinfo(
                "Select a report",
                "Run a security assessment or select a report from history first.",
            )
            return

        destination = filedialog.asksaveasfilename(
            title="Export Doji JSON report",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            initialfile=(
                next(
                    (
                        report_path.name
                        for report_path in self.history_paths
                        if report_path.is_file()
                        and report_path.stem.endswith(
                            self.current_report.get("assessment_id", "").removeprefix("DOJI-")
                        )
                    ),
                    f'{self.current_report.get("assessment_id", "doji-report")}.json',
                )
            ),
        )

        if not destination:
            return

        try:
            Path(destination).write_text(
                json.dumps(self.current_report, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror(
                "Export error", f"Could not export report:\n{exc}"
            )
            return

        self.status.configure(text=f"Exported report to {destination}")
        messagebox.showinfo(
            "Export complete", f"Report exported to:\n{destination}"
        )


    def generate_pdf_report(self):
        from tkinter import filedialog
        from pdf_report import generate_pdf

        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        selected = self.report_history.curselection()

        if selected and selected[0] >= len(self.history_paths):
            from forensic_pdf_report import generate_forensic_pdf

            forensic_index = selected[0] - len(self.history_paths)

            if not 0 <= forensic_index < len(self.forensic_history_paths):
                messagebox.showerror(
                    "Forensic PDF",
                    "The selected forensic investigation was not found.",
                )
                return

            metadata_path = self.forensic_history_paths[forensic_index]

            try:
                pdf_path = generate_forensic_pdf(metadata_path)
            except Exception as exc:
                messagebox.showerror(
                    "Forensic PDF generation failed",
                    f"Could not generate the forensic PDF report:\n{exc}",
                )
                return

            self.status.configure(
                text=f"Doji forensic PDF saved: {Path(pdf_path).name}"
            )

            messagebox.showinfo(
                "Forensic PDF generated",
                f"Doji forensic PDF saved successfully:\n\n{pdf_path}",
            )
            return

        if selected:
            json_path = self.history_paths[selected[0]]
        else:
            json_path = filedialog.askopenfilename(
                title="Select a Doji JSON report",
                initialdir=str(REPORT_DIR),
                filetypes=[("JSON reports", "*.json")],
            )

        if not json_path:
            return

        try:
            import json
            from assessment_pdf_report import (
                generate_assessment_pdf,
                SUPPORTED_TYPES,
            )

            report_path = Path(json_path).expanduser().resolve()

            with report_path.open("r", encoding="utf-8") as file:
                report_data = json.load(file)

            if not isinstance(report_data, dict):
                raise ValueError("Invalid JSON report structure.")

            report_type = report_data.get("report_type")

            if report_type == "local_apk_analysis":
                pdf_path = generate_pdf(report_path)

            elif report_type in SUPPORTED_TYPES or (
                report_type is None
                and all(
                    key in report_data
                    for key in ("summary", "target", "findings")
                )
            ):
                pdf_path = generate_assessment_pdf(report_path)

            else:
                raise ValueError(
                    f"Unsupported PDF report type: {report_type}"
                )

        except Exception as exc:
            messagebox.showerror(
                "PDF generation failed",
                f"Could not generate the PDF report:\n{exc}",
            )
            return

        self.status.configure(
            text=f"Doji PDF report saved: {Path(pdf_path).name}"
        )

        messagebox.showinfo(
            "PDF report generated",
            f"Doji PDF report saved successfully:\n\n{pdf_path}",
        )


def main():
    root = tk.Tk()
    DojiDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
