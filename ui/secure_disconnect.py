"""Safe, user-requested Android ADB session cleanup."""

import shutil
import subprocess


SECURITY_INSTRUCTIONS = (
    "To secure your Android phone after scanning:\n\n"
    "1. Open Settings on the phone.\n"
    "2. Find Developer options.\n"
    "3. Turn OFF USB debugging.\n"
    "4. If available, select 'Revoke USB debugging authorizations'.\n"
    "5. Disconnect the USB cable when finished.\n\n"
    "Menu names may differ by phone manufacturer."
)


def finish_android_session(run=None):
    """Stop the local ADB server without changing phone settings.

    Stopping the server may affect other local ADB applications.
    """
    if run is None:
        run = subprocess.run

    if not shutil.which("adb"):
        return {
            "success": False,
            "message": "ADB is not installed or not on PATH.",
            "instructions": SECURITY_INSTRUCTIONS,
        }

    try:
        result = run(
            ["adb", "kill-server"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "success": False,
            "message": f"Could not stop the local ADB server: {exc}",
            "instructions": SECURITY_INSTRUCTIONS,
        }

    success = result.returncode == 0

    return {
        "success": success,
        "message": (
            "Local ADB server stopped successfully."
            if success
            else (
                "ADB server shutdown failed: "
                + (result.stderr.strip() or "Unknown error")
            )
        ),
        "instructions": SECURITY_INSTRUCTIONS,
    }
