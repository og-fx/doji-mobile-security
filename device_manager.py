
import shutil
import subprocess


def run_command(args):
    """Run a system command safely and return stdout and stderr."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", str(exc)



def discover_usb_phone_candidates():
    """Find possible phones visible through USB, without assuming ADB access."""
    import re

    if not shutil.which("lsusb"):
        return []

    output, error = run_command(["lsusb"])
    if error and not output:
        return []

    candidates = []
    pattern = re.compile(
        r"^Bus\s+(\d+)\s+Device\s+(\d+):\s+"
        r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)$"
    )

    phone_terms = (
        "android", "samsung", "infinix", "tecno",
        "xiaomi", "redmi", "oppo", "vivo", "oneplus",
        "motorola", "google pixel", "huawei",
        "honor", "realme", "nokia", "sony xperia",
    )

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue

        bus, number, vendor, product, description = match.groups()
        description = description.strip()

        if not any(term in description.lower() for term in phone_terms):
            continue

        candidates.append({
            "bus": bus,
            "device_number": number,
            "vendor_id": vendor.lower(),
            "product_id": product.lower(),
            "description": description,
            "state": "USB detected; ADB access not confirmed",
        })

    return candidates

def discover_devices():
    """
    Discover devices visible to ADB or libimobiledevice.

    Detection does not prove a device is connected by USB
    or that a security assessment has been performed.
    """
    devices = []

    # Android devices visible to ADB.
    if shutil.which("adb"):
        output, error = run_command(["adb", "devices", "-l"])

        for line in output.splitlines()[1:]:
            line = line.strip()

            if not line or line.startswith("*"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial, adb_state = parts[0], parts[1]
            details = {}

            for item in parts[2:]:
                if ":" in item:
                    key, value = item.split(":", 1)
                    details[key] = value

            state_labels = {
                "device": "Authorized",
                "unauthorized": "Unauthorized",
                "offline": "Offline",
                "no permissions": "Permission issue",
            }
            display_state = state_labels.get(
                adb_state, f"ADB state: {adb_state}"
            )

            model = details.get("model", "Unknown")
            name = model.replace("_", " ") if model != "Unknown" else "Android device"

            devices.append({
                "platform": "Android",
                "name": name,
                "model": model,
                "os": "Not queried",
                "transport": "ADB; connection type not verified",
                "state": display_state,
                "id": serial,
            })

    # Show USB phone candidates when ADB has not identified a phone.
    # USB detection alone does not authorize security scanning.
    usb_candidates = discover_usb_phone_candidates()

    adb_android_devices = [
        device for device in devices
        if device.get("platform") == "Android"
    ]

    if not adb_android_devices:
        for candidate in usb_candidates:
            devices.append({
                "platform": "Android",
                "name": candidate["description"],
                "model": "Unconfirmed",
                "os": "Not queried",
                "transport": "USB; ADB access not confirmed",
                "state": "USB detected; authorization not confirmed",
                "id": (
                    "usb:"
                    + candidate["bus"]
                    + ":"
                    + candidate["device_number"]
                ),
            })

    # Apple devices visible to libimobiledevice.
    if shutil.which("idevice_id"):
        output, error = run_command(["idevice_id", "-l"])

        for udid in output.splitlines():
            udid = udid.strip()
            if not udid:
                continue

            name, name_error = run_command([
                "ideviceinfo", "-u", udid, "-k", "DeviceName"
            ])
            model, model_error = run_command([
                "ideviceinfo", "-u", udid, "-k", "ProductType"
            ])
            version, version_error = run_command([
                "ideviceinfo", "-u", udid, "-k", "ProductVersion"
            ])

            details_read = bool(name or model or version)

            devices.append({
                "platform": "Apple",
                "name": name or "iPhone/iPad (name unavailable)",
                "model": model or "Unknown",
                "os": version or "Not available",
                "transport": "libimobiledevice; connection type not verified",
                "state": (
                    "Detected; details readable"
                    if details_read
                    else "Detected; details unavailable"
                ),
                "id": udid,
            })

    return devices



def check_android_connection(serial):
    """Check the ADB state of one specific Android device."""
    if not isinstance(serial, str) or not serial.strip():
        raise ValueError("A valid Android device serial is required.")

    if not shutil.which("adb"):
        return "ERROR"

    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "ERROR"

    if result.returncode != 0:
        return "ERROR"

    for line in result.stdout.splitlines()[1:]:
        parts = line.split()

        if len(parts) < 2 or parts[0] != serial:
            continue

        state = parts[1].lower()

        if state == "device":
            return "CONNECTED"
        if state == "offline":
            return "OFFLINE"
        if state == "unauthorized":
            return "UNAUTHORIZED"

        return "ERROR"

    return "DISCONNECTED"



def wait_for_android_connection(
    serial, timeout=60, interval=2,
    cancel_event=None, progress_callback=None,
):
    """Wait for the same authorized Android device to return."""
    import time

    deadline = time.monotonic() + timeout
    last_state = None

    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError(
                "Connection recovery cancelled by user."
            )

        state = check_android_connection(serial)

        if state == "CONNECTED":
            return True

        if state == "UNAUTHORIZED":
            if state != last_state and progress_callback:
                progress_callback(
                    "Android authorization required. "
                    "Unlock the phone and approve USB debugging "
                    "for this computer."
                )
            last_state = state

        if state != last_state and progress_callback:
            progress_callback(
                f"Android connection: {state}. "
                "Waiting for reconnection..."
            )

        last_state = state

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return False

        wait_seconds = min(interval, remaining)

        if cancel_event is not None:
            if cancel_event.wait(wait_seconds):
                raise InterruptedError(
                    "Connection recovery cancelled by user."
                )
        else:
            time.sleep(wait_seconds)
