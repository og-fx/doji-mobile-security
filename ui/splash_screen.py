"""Doji Mobile Security startup splash screen."""

import tkinter as tk


BG = "#10151f"
PANEL = "#192231"
TEXT = "#e7edf7"
MUTED = "#9eacc0"
ACCENT = "#56d6b0"


def show_splash(duration_ms=3000):
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.configure(bg=BG)

    width = 760
    height = 420

    screen_width = splash.winfo_screenwidth()
    screen_height = splash.winfo_screenheight()

    x = (screen_width - width) // 2
    y = (screen_height - height) // 2

    splash.geometry(f"{width}x{height}+{x}+{y}")

    container = tk.Frame(
        splash,
        bg=BG,
        highlightbackground=ACCENT,
        highlightthickness=2,
    )
    container.pack(fill="both", expand=True)

    tk.Label(
        container,
        text="◆",
        font=("Arial", 48, "bold"),
        bg=BG,
        fg=ACCENT,
    ).pack(pady=(45, 12))

    tk.Label(
        container,
        text="DOJI MOBILE SECURITY",
        font=("Arial", 27, "bold"),
        bg=BG,
        fg=TEXT,
    ).pack()

    tk.Label(
        container,
        text="ADVANCED MOBILE FORENSICS & MALWARE DETECTION",
        font=("Arial", 11, "bold"),
        bg=BG,
        fg=ACCENT,
    ).pack(pady=(10, 32))

    status = tk.Label(
        container,
        text="Initializing security environment...",
        font=("Arial", 10),
        bg=BG,
        fg=MUTED,
    )
    status.pack()

    progress_canvas = tk.Canvas(
        container,
        width=450,
        height=6,
        bg="#26394a",
        highlightthickness=0,
    )
    progress_canvas.pack(pady=(14, 0))

    progress = progress_canvas.create_rectangle(
        0, 0, 0, 6,
        fill=ACCENT,
        outline="",
    )

    footer = tk.Frame(container, bg=BG)
    footer.pack(side="bottom", fill="x", padx=22, pady=18)

    tk.Label(
        footer,
        text="By Onwuta Onyinye Gift",
        font=("Arial", 10, "bold"),
        bg=BG,
        fg=MUTED,
    ).pack(side="right")

    steps = 60
    interval = max(1, duration_ms // steps)

    def animate(step=0):
        if step > steps:
            splash.destroy()
            return

        progress_canvas.coords(
            progress,
            0, 0,
            450 * step / steps,
            6,
        )

        splash.after(
            interval,
            lambda: animate(step + 1),
        )

    splash.after(0, animate)
    splash.mainloop()


if __name__ == "__main__":
    show_splash()
