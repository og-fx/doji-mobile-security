#!/usr/bin/env python3
"""Validate Android device selection before malware assessment."""


def validate_android_scan_target(device):
    """Return the authorized Android serial or raise ValueError."""

    if not isinstance(device, dict):
        raise ValueError("Select an Android device first.")

    if device.get("platform") != "Android":
        raise ValueError(
            "Android malware scanning requires an Android device."
        )

    if device.get("state") != "Authorized":
        raise ValueError(
            "Android device is not authorized for ADB access."
        )

    serial = device.get("id")

    if not isinstance(serial, str) or not serial.strip():
        raise ValueError(
            "Android device serial number is unavailable."
        )

    serial = serial.strip()

    from device_manager import discover_devices

    try:
        current_devices = discover_devices()
    except Exception as exc:
        raise ValueError(
            "Could not verify the live Android connection. "
            "Check ADB and try again."
        ) from exc

    matching_devices = [
        item for item in current_devices
        if item.get("platform") == "Android"
        and item.get("id") == serial
    ]

    if not matching_devices:
        raise ValueError(
            "The selected Android device is no longer connected. "
            "Reconnect it and refresh the Devices page."
        )

    if matching_devices[0].get("state") != "Authorized":
        raise ValueError(
            "The Android device is connected but is not authorized "
            "for ADB scanning. Check the phone and authorize access."
        )

    return serial
