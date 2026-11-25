#!/usr/bin/env python3
"""Doji Android security configuration checks (read-only)."""

import json
import re
import subprocess
from datetime import datetime, timezone


def run_adb(serial, *args):
    if not serial:
        raise ValueError("An Android device serial is required.")

    result = subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "ADB command failed."
        )

    return result.stdout.strip()


def check_accessibility(serial):
    output = run_adb(
        serial, "shell", "settings", "get",
        "secure", "enabled_accessibility_services"
    )

    if output.lower() in ("null", ""):
        return {
            "status": "PASS",
            "enabled_services": [],
            "details": "No enabled accessibility services reported.",
        }

    services = [
        service.strip()
        for service in output.split(":")
        if service.strip()
    ]

    return {
        "status": "REVIEW REQUIRED",
        "enabled_services": services,
        "details": (
            "Enabled accessibility services require contextual review. "
            "Their presence alone does not prove spyware."
        ),
    }


def check_device_admins(serial):
    output = run_adb(
        serial, "shell", "dumpsys", "device_policy"
    )

    match = re.search(
        r"Enabled Device Admins \(User 0[^)]*\):(.*?)(?:\n\s*Constants:|\n\s*Stats:)",
        output,
        re.DOTALL,
    )

    if not match:
        return {
            "status": "NOT AVAILABLE",
            "details": "Could not reliably locate device administrator section.",
        }

    section = match.group(1)

    admins = re.findall(
        r"(?:ComponentInfo\{[^}]+\}|admin=[^\s]+)",
        section,
        re.IGNORECASE,
    )

    if admins:
        return {
            "status": "REVIEW REQUIRED",
            "administrators": admins,
            "details": (
                "Device administrators were reported. "
                "Review their legitimacy and permissions."
            ),
        }

    return {
        "status": "PASS",
        "administrators": [],
        "details": "No active device administrators identified for User 0.",
    }


def assess_configuration(serial):
    report = {
        "tool": "Doji Android Security Configuration Checker",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "checks": {},
        "limitations": [
            "Only ADB-accessible device configuration is examined.",
            "Checks do not establish that a device is malware-free.",
            "Device administrator inspection currently targets User 0.",
        ],
    }

    for name, checker in (
        ("accessibility", check_accessibility),
        ("device_administrators", check_device_admins),
    ):
        try:
            report["checks"][name] = checker(serial)
        except (OSError, RuntimeError, ValueError,
                subprocess.TimeoutExpired) as exc:
            report["checks"][name] = {
                "status": "ERROR",
                "details": f"{type(exc).__name__}: {exc}",
            }

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()

    print(json.dumps(
        assess_configuration(args.serial),
        indent=2,
    ))
