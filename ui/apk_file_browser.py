"""APK file browser with visible folder navigation."""

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


BG = "#10151f"
PANEL = "#192231"
TEXT = "#e7edf7"
ACCENT = "#56d6b0"


def select_apk(parent):
    """Return a selected APK path, or None if cancelled."""

    project_dir = Path(__file__).resolve().parent.parent
    samples_dir = project_dir / "samples"

    current = samples_dir if samples_dir.is_dir() else project_dir
    history = []
    selected = {"path": None}

    window = tk.Toplevel(parent)
    window.title("Doji | Select Android APK")
    window.geometry("700x500")
    window.minsize(550, 380)
    window.configure(bg=BG)
    window.transient(parent)
    window.grab_set()

    header = tk.Frame(window, bg=BG)
    header.pack(fill="x", padx=16, pady=12)

    path_label = tk.Label(
        window,
        bg=BG,
        fg=TEXT,
        anchor="w",
        wraplength=650,
    )
    path_label.pack(fill="x", padx=16, pady=(0, 10))

    file_list = ttk.Treeview(
        window,
        columns=("type",),
        show="tree headings",
        selectmode="browse",
    )
    file_list.heading("#0", text="Name")
    file_list.heading("type", text="Type")
    file_list.column("#0", width=460)
    file_list.column("type", width=100)
    file_list.pack(
        fill="both",
        expand=True,
        padx=16,
        pady=8,
    )

    def refresh():
        path_label.configure(text=str(current))

        for item in file_list.get_children():
            file_list.delete(item)

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError as exc:
            messagebox.showerror(
                "Folder Error",
                str(exc),
                parent=window,
            )
            return

        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue

            if not is_dir and entry.suffix.lower() != ".apk":
                continue

            file_list.insert(
                "",
                "end",
                iid=str(entry),
                text=("📁 " if is_dir else "📦 ") + entry.name,
                values=("Folder" if is_dir else "APK",),
            )

    def navigate(destination):
        nonlocal current

        if not destination.is_dir():
            return

        history.append(current)
        current = destination
        refresh()

    def go_back():
        nonlocal current

        if history:
            current = history.pop()
            refresh()

    def go_parent():
        if current.parent != current:
            navigate(current.parent)

    def open_selected(_event=None):
        item = file_list.focus()

        if not item:
            return

        path = Path(item)

        if path.is_dir():
            navigate(path)
        elif path.is_file() and path.suffix.lower() == ".apk":
            selected["path"] = str(path)
            window.destroy()

    def cancel():
        window.destroy()

    tk.Button(
        header,
        text="← Back",
        command=go_back,
        bg=PANEL,
        fg=TEXT,
        relief="flat",
        padx=12,
        pady=7,
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        header,
        text="↑ Parent Folder",
        command=go_parent,
        bg=PANEL,
        fg=TEXT,
        relief="flat",
        padx=12,
        pady=7,
    ).pack(side="left")

    tk.Button(
        header,
        text="Cancel",
        command=cancel,
        bg=PANEL,
        fg=TEXT,
        relief="flat",
        padx=12,
        pady=7,
    ).pack(side="right")

    file_list.bind("<Double-1>", open_selected)
    file_list.bind("<Return>", open_selected)

    tk.Button(
        window,
        text="Open Selected APK / Folder",
        command=open_selected,
        bg=ACCENT,
        fg=BG,
        relief="flat",
        padx=16,
        pady=10,
    ).pack(pady=12)

    window.protocol("WM_DELETE_WINDOW", cancel)

    refresh()
    parent.wait_window(window)

    return selected["path"]
