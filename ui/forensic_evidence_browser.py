"""User-friendly Android forensic evidence selection."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "forensic/evidence/android/bugreports"


def select_forensic_evidence(parent):
    """Return selected evidence path, or None if cancelled."""

    selected = {"path": None}

    window = tk.Toplevel(parent)
    window.title("Doji | Select Forensic Evidence")
    window.geometry("900x560")
    window.minsize(600, 400)
    window.configure(bg="#10151f")
    window.transient(parent)
    window.grab_set()

    tk.Label(
        window,
        text="Android Forensic Evidence",
        font=("DejaVu Sans", 17, "bold"),
        bg="#10151f",
        fg="#e7edf7",
    ).pack(anchor="w", padx=24, pady=(22, 5))

    tk.Label(
        window,
        text="Select a saved bug report or browse for another ZIP file.",
        font=("DejaVu Sans", 10),
        bg="#10151f",
        fg="#9eacc0",
    ).pack(anchor="w", padx=24, pady=(0, 18))

    frame = tk.Frame(window, bg="#10151f")
    frame.pack(fill="both", expand=True, padx=24)

    columns = ("filename", "date", "size")

    tree = ttk.Treeview(
        frame,
        columns=columns,
        show="headings",
        selectmode="browse",
    )

    tree.heading("filename", text="Evidence File")
    tree.heading("date", text="Modified")
    tree.heading("size", text="Size")

    tree.column("filename", width=400)
    tree.column("date", width=145)
    tree.column("size", width=90, anchor="e")

    scrollbar = ttk.Scrollbar(
        frame, orient="vertical", command=tree.yview
    )
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    paths = {}

    def refresh():
        tree.delete(*tree.get_children())
        paths.clear()

        if not EVIDENCE_DIR.is_dir():
            return

        files = sorted(
            EVIDENCE_DIR.glob("*.zip"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        for path in files:
            if not path.is_file():
                continue

            stat = path.stat()
            modified = datetime.fromtimestamp(
                stat.st_mtime
            ).strftime("%d %b %Y %H:%M")

            size = f"{stat.st_size / 1048576:.2f} MB"

            display_name = path.name

            if display_name.startswith("bugreport-"):
                display_name = display_name.replace(
                    "bugreport-", "Android Bug Report - ", 1
                )

            if len(display_name) > 38:
                display_name = display_name[:35] + "..."

            item = tree.insert(
                "",
                "end",
                values=(display_name, modified, size),
            )
            paths[item] = path

        if tree.get_children():
            first = tree.get_children()[0]
            tree.selection_set(first)
            tree.focus(first)

    def choose():
        selection = tree.selection()

        if not selection:
            messagebox.showwarning(
                "Select Evidence",
                "Please select a forensic ZIP file.",
                parent=window,
            )
            return

        selected["path"] = paths[selection[0]]
        window.destroy()

    def browse():
        path = filedialog.askopenfilename(
            parent=window,
            title="Browse for Android Bug Report",
            initialdir=str(
                EVIDENCE_DIR
                if EVIDENCE_DIR.is_dir()
                else PROJECT_DIR
            ),
            filetypes=[
                ("ZIP archives", "*.zip"),
                ("All files", "*.*"),
            ],
        )

        if path:
            selected["path"] = Path(path)
            window.destroy()

    buttons = tk.Frame(window, bg="#10151f")
    buttons.pack(fill="x", padx=24, pady=20)

    actions = (
        ("Start Investigation", choose, "#176b56"),
        ("Browse Files", browse, "#243247"),
        ("Refresh", refresh, "#243247"),
        ("Cancel", window.destroy, "#403447"),
    )

    for label, command, color in actions:
        tk.Button(
            buttons,
            text=label,
            command=command,
            bg=color,
            fg="#ffffff",
            activebackground="#31546a",
            activeforeground="#ffffff",
            relief="flat",
            font=("DejaVu Sans", 10, "bold"),
            padx=16,
            pady=10,
            cursor="hand2",
        ).pack(side="left", padx=(0, 10))

    tree.bind("<Double-1>", lambda event: choose())
    window.protocol("WM_DELETE_WINDOW", window.destroy)

    refresh()
    parent.wait_window(window)

    return selected["path"]
