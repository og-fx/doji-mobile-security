#!/usr/bin/env python3
"""Doji Android live application change monitor.

Read-only monitoring of ADB-visible third-party applications.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from android_device_scanner import list_installed_packages
from android_compromise_checker import assess_configuration


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def monitor_device(serial, duration=30, interval=5, cancel_event=None):
    if not serial:
        raise ValueError("An authorized Android device is required.")

    if duration <= 0 or interval <= 0:
        raise ValueError("Duration and interval must be positive.")

    print("Doji Android Live Threat Monitor")
    print("Collecting initial application snapshot...", flush=True)

    previous = set(
        list_installed_packages(serial, third_party_only=True)
    )

    print("Collecting initial security configuration...", flush=True)
    initial_security = assess_configuration(serial)

    def security_items(snapshot, check_name, field):
        check = snapshot.get("checks", {}).get(check_name, {})
        if check.get("status") not in ("PASS", "REVIEW REQUIRED"):
            return None
        values = check.get(field)
        return set(values) if isinstance(values, list) else None

    previous_accessibility = security_items(
        initial_security, "accessibility", "enabled_services"
    )
    previous_admins = security_items(
        initial_security, "device_administrators", "administrators"
    )

    report = {
        "tool": "Doji Android Live Threat Monitor",
        "started_utc": utc_now(),
        "duration_seconds_requested": duration,
        "interval_seconds": interval,
        "initial_application_count": len(previous),
        "initial_security_configuration": initial_security,
        "events": [],
        "limitations": [
            "Only ADB-visible third-party applications are monitored.",
            "Application changes between snapshots may be missed.",
            "An installation or removal is not proof of malware.",
            "This version does not monitor processes or network traffic.",
            "Security configuration changes between snapshots may be missed.",
            "Device administrator checks currently cover User 0.",
        ],
    }

    deadline = time.monotonic() + duration
    completed = False
    cancelled = False

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                completed = True
                break

            wait_seconds = min(interval, remaining)

            if cancel_event is not None:
                if cancel_event.wait(wait_seconds):
                    cancelled = True
                    break
            else:
                time.sleep(wait_seconds)

            current = set(
                list_installed_packages(serial, third_party_only=True)
            )

            for package in sorted(current - previous):
                event = {
                    "timestamp_utc": utc_now(),
                    "type": "APPLICATION_INSTALLED",
                    "package": package,
                    "severity": "INFO",
                }
                report["events"].append(event)
                print(f"[NEW APP] {package}", flush=True)

            for package in sorted(previous - current):
                event = {
                    "timestamp_utc": utc_now(),
                    "type": "APPLICATION_REMOVED",
                    "package": package,
                    "severity": "INFO",
                }
                report["events"].append(event)
                print(f"[REMOVED APP] {package}", flush=True)

            previous = current

            security = assess_configuration(serial)

            for check_name, field, event_type, label in (
                (
                    "accessibility", "enabled_services",
                    "ACCESSIBILITY_SERVICE_CHANGE", "Accessibility services",
                ),
                (
                    "device_administrators", "administrators",
                    "DEVICE_ADMINISTRATOR_CHANGE", "Device administrators",
                ),
            ):
                current_items = security_items(security, check_name, field)
                previous_items = (
                    previous_accessibility
                    if check_name == "accessibility"
                    else previous_admins
                )

                if current_items is None:
                    print(f"[CHECK UNAVAILABLE] {label}", flush=True)
                    continue

                if previous_items is not None and current_items != previous_items:
                    event = {
                        "timestamp_utc": utc_now(),
                        "type": event_type,
                        "added": sorted(current_items - previous_items),
                        "removed": sorted(previous_items - current_items),
                        "severity": "REVIEW",
                    }
                    report["events"].append(event)
                    print(f"[SECURITY CHANGE] {label}", flush=True)

                if check_name == "accessibility":
                    previous_accessibility = current_items
                else:
                    previous_admins = current_items

            report["latest_security_configuration"] = security

            print(
                f"Monitoring... {len(current)} third-party apps visible.",
                flush=True,
            )

    except KeyboardInterrupt:
        print("Monitoring stopped by user.", flush=True)

    except (OSError, RuntimeError, ValueError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        print(f"Monitoring error: {exc}", flush=True)

    report["finished_utc"] = utc_now()
    report["final_application_count"] = len(previous)
    report["completed"] = completed
    report["cancelled"] = cancelled
    report["event_count"] = len(report["events"])

    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    report = monitor_device(
        args.serial,
        duration=args.duration,
        interval=args.interval,
    )

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = (
        "DOJI-LIVE-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ".json"
    )

    output_path = output_dir / filename
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nEvents detected: {report['event_count']}")
    print(f"Report saved: {output_path}")

    if report.get("error"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
