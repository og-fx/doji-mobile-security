"""User-controlled Android device authorization guidance.

This module never enables USB debugging or grants ADB access.
"""


def authorization_guidance(device):
    """Return safe connection guidance for a detected device."""
    if not isinstance(device, dict):
        return None

    if device.get("platform") != "Android":
        return None

    state = str(device.get("state") or "").strip().lower()

    if state == "authorized":
        return {
            "status": "READY",
            "title": "Android Device Ready",
            "message": (
                "This Android device has authorized ADB access. "
                "You can select a supported security assessment."
            ),
        }

    if state == "unauthorized":
        return {
            "status": "AUTHORIZATION_REQUIRED",
            "title": "USB Debugging Authorization Required",
            "message": (
                "Doji detected your Android device, but this "
                "computer has not been authorized.\n\n"
                "1. Unlock your phone.\n"
                "2. Look for the 'Allow USB debugging?' prompt.\n"
                "3. Verify that you trust this computer.\n"
                "4. Tap Allow on the phone.\n\n"
                "Doji will automatically check the connection again."
            ),
        }

    if "usb detected" in state:
        return {
            "status": "DEBUGGING_REQUIRED",
            "title": "Android Connection Setup",
            "message": (
                "Your phone is visible over USB, but ADB access "
                "has not been established.\n\n"
                "1. Unlock the phone.\n"
                "2. Open Settings and locate Developer options.\n"
                "3. Enable USB debugging if you consent.\n"
                "4. Approve the computer on your phone.\n\n"
                "Menu locations vary by Android manufacturer."
            ),
        }

    if state == "offline":
        return {
            "status": "CONNECTION_OFFLINE",
            "title": "Android Connection Offline",
            "message": (
                "Doji can see the device, but ADB reports it offline.\n\n"
                "Unlock the phone, check the USB cable, "
                "and reconnect if necessary."
            ),
        }

    return None
