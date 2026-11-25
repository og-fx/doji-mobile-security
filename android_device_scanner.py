#!/usr/bin/env python3
"""Doji Android device assessment — read-only discovery."""

import subprocess
import time
import json
import hashlib
import re
from pathlib import Path

from device_manager import discover_devices


# APK collection safety limits (bytes unless stated otherwise).
MAX_APK_COMPONENT_BYTES = 250 * 1024 * 1024
MAX_SCAN_COLLECTION_BYTES = 1024 * 1024 * 1024
MAX_APK_COMPONENTS_PER_APP = 64



def run_adb_with_recovery(
    command, serial, timeout=30,
    cancel_event=None, progress_callback=None,
):
    """Retry an ADB command once after a recoverable connection failure."""
    from device_manager import (
        check_android_connection,
        wait_for_android_connection,
    )

    connection_errors = (
        "device offline",
        "device not found",
        "no devices/emulators found",
        "device disconnected",
        "closed",
        "transport error",
    )

    for attempt in range(2):
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("ADB operation cancelled.")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = None

        if result is not None and result.returncode == 0:
            return result

        message = (
            (result.stderr or "").lower()
            if result is not None else "adb command timed out"
        )

        state = check_android_connection(serial)

        recoverable = (
            state in ("OFFLINE", "DISCONNECTED", "ERROR")
            or any(error in message for error in connection_errors)
            or (
                "adb: device " in message
                and " not found" in message
            )
            or result is None
        )

        if not recoverable or attempt == 1:
            raise RuntimeError(
                (result.stderr.strip() if result is not None else "")
                or "ADB command failed or timed out."
            )

        if progress_callback:
            progress_callback(
                "ADB connection interrupted. Waiting for recovery..."
            )

        recovered = wait_for_android_connection(
            serial,
            timeout=60,
            interval=2,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
        )

        if not recovered:
            raise RuntimeError(
                "Android device did not reconnect or requires authorization."
            )

    raise RuntimeError("ADB operation failed after recovery.")

def list_installed_packages(
    serial, third_party_only=False,
    cancel_event=None, progress_callback=None,
):
    """Return ADB-visible packages with connection recovery."""
    command = [
        "adb", "-s", serial, "shell", "pm", "list", "packages"
    ]

    if third_party_only:
        command.append("-3")

    result = run_adb_with_recovery(
        command,
        serial,
        timeout=30,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )

    packages = []

    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            package = line.removeprefix("package:").strip()
            if package:
                packages.append(package)

    return sorted(set(packages))



def get_package_apk_paths(
    serial, package_name,
    cancel_event=None, progress_callback=None,
):
    """Discover installed APK components with ADB recovery."""
    result = run_adb_with_recovery(
        ["adb", "-s", serial, "shell", "pm", "path", package_name],
        serial,
        timeout=30,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )

    paths = [
        line.removeprefix("package:").strip()
        for line in result.stdout.splitlines()
        if line.startswith("package:")
    ]

    if not paths:
        raise RuntimeError(
            f"No accessible APK paths returned for {package_name}."
        )

    return paths



def get_remote_apk_size(
    serial, remote_path, cancel_event=None,
    progress_callback=None,
):
    """Retrieve remote APK size with ADB recovery and cancellation."""
    if cancel_event is not None and cancel_event.is_set():
        raise InterruptedError("APK size lookup cancelled.")

    result = run_adb_with_recovery(
        ["adb", "-s", serial, "shell", "stat", "-c", "%s", remote_path],
        serial,
        timeout=30,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )

    output = result.stdout.strip()

    if not output.isdecimal():
        raise ValueError("Invalid remote APK size returned by ADB.")

    return int(output)



def stream_apk_bounded(
    serial, remote_path, local_path, expected_size, max_bytes,
    cancel_event=None,
):
    """Collect an APK with cancellation, size limits and SHA-256 verification."""
    import os
    import tempfile

    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or expected_size < 0
        or max_bytes < 0
        or expected_size > max_bytes
    ):
        raise ValueError("Invalid APK collection size limits.")

    local_path = Path(local_path)

    if local_path.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing file: {local_path}"
        )

    if cancel_event is not None and cancel_event.is_set():
        raise InterruptedError("APK collection cancelled before download.")

    temp_path = None
    process = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix=".doji-apk-",
            suffix=".tmp",
            dir=local_path.parent,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)

        process = subprocess.Popen(
            ["adb", "-s", serial, "pull", remote_path, str(temp_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        started = time.monotonic()

        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

                raise InterruptedError(
                    "ADB APK collection cancelled by user."
                )

            if time.monotonic() - started >= 180:
                process.kill()
                process.wait()
                raise TimeoutError("ADB APK collection exceeded 180 seconds.")

            time.sleep(0.25)

        if process.returncode != 0:
            raise RuntimeError(
                f"ADB APK collection failed with exit code "
                f"{process.returncode}."
            )

        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("APK collection cancelled after download.")

        downloaded_size = temp_path.stat().st_size

        if downloaded_size != expected_size:
            raise RuntimeError(
                f"APK size mismatch: expected {expected_size} bytes, "
                f"received {downloaded_size} bytes."
            )

        if downloaded_size > max_bytes:
            raise RuntimeError(
                "APK collection exceeded the permitted byte limit."
            )

        digest = hashlib.sha256()

        with temp_path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(65536), b""):
                digest.update(chunk)

        os.link(temp_path, local_path)
        temp_path.unlink()
        temp_path = None

        return {
            "size_bytes": downloaded_size,
            "sha256": digest.hexdigest(),
        }

    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()

        if temp_path is not None:
            temp_path.unlink(missing_ok=True)



def stream_apk_with_recovery(
    serial, remote_path, local_path, expected_size, max_bytes,
    cancel_event=None, progress_callback=None,
):
    """Retry an interrupted APK transfer after ADB reconnection."""
    from device_manager import (
        check_android_connection,
        wait_for_android_connection,
    )

    for attempt in range(2):
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("APK transfer cancelled.")

        try:
            return stream_apk_bounded(
                serial,
                remote_path,
                local_path,
                expected_size,
                max_bytes,
                cancel_event=cancel_event,
            )

        except InterruptedError:
            raise

        except (RuntimeError, TimeoutError, OSError) as exc:
            if attempt == 1:
                raise

            state = check_android_connection(serial)

            message = str(exc).lower()

            transfer_error = (
                "adb apk collection failed with exit code" in message
                or "adb apk collection exceeded 180 seconds" in message
            )

            if state == "CONNECTED" and not transfer_error:
                raise

            if progress_callback:
                progress_callback(
                    "APK transfer interrupted. "
                    "Waiting for Android reconnection..."
                )

            recovered = wait_for_android_connection(
                serial,
                timeout=60,
                interval=2,
                cancel_event=cancel_event,
                progress_callback=progress_callback,
            )

            if not recovered:
                raise RuntimeError(
                    "Android device did not reconnect. "
                    "APK collection remains incomplete."
                ) from exc

            if progress_callback:
                progress_callback(
                    "Android reconnected. Retrying APK transfer..."
                )

    raise RuntimeError("APK transfer recovery failed.")

def collect_package_apks(
    serial, package_name, destination, collection_budget=None,
    cancel_event=None, progress_callback=None,
):
    """Collect accessible APK components without modifying the device."""
    if collection_budget is not None:
        if not isinstance(collection_budget, dict):
            raise ValueError("Collection budget must be a dictionary.")

        if not isinstance(collection_budget.get("remaining_bytes"), int):
            raise ValueError("Collection budget requires remaining_bytes.")

        if collection_budget["remaining_bytes"] < 0:
            raise ValueError("Collection budget cannot be negative.")
    if not re.fullmatch(r"[A-Za-z0-9_.]+", package_name):
        raise ValueError("Invalid Android package name.")

    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)

    apk_paths = get_package_apk_paths(
        serial, package_name,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )
    collected = []
    errors = []

    if len(apk_paths) > MAX_APK_COMPONENTS_PER_APP:
        skipped = len(apk_paths) - MAX_APK_COMPONENTS_PER_APP
        errors.append(
            f"Collection limit: {skipped} APK components skipped "
            f"(maximum {MAX_APK_COMPONENTS_PER_APP} per application)."
        )

    cancelled = False

    for index, remote_path in enumerate(
        apk_paths[:MAX_APK_COMPONENTS_PER_APP]
    ):
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            break

        filename = Path(remote_path).name

        if not filename.endswith(".apk"):
            errors.append(f"Unexpected APK path: {remote_path}")
            continue

        local_path = destination / f"{index:03d}_{filename}"

        try:
            remote_size = get_remote_apk_size(
                serial, remote_path,
                cancel_event=cancel_event,
                progress_callback=progress_callback,
            )

            if remote_size > MAX_APK_COMPONENT_BYTES:
                errors.append(
                    f"{filename}: skipped because APK size "
                    f"{remote_size} bytes exceeds the "
                    f"{MAX_APK_COMPONENT_BYTES} byte limit."
                )
                continue

            if (
                collection_budget is not None
                and remote_size > collection_budget["remaining_bytes"]
            ):
                errors.append(
                    f"{filename}: skipped because {remote_size} bytes "
                    f"exceeds the remaining collection budget of "
                    f"{collection_budget['remaining_bytes']} bytes."
                )
                continue

            transfer = stream_apk_with_recovery(
                serial,
                remote_path,
                local_path,
                expected_size=remote_size,
                max_bytes=min(
                    MAX_APK_COMPONENT_BYTES,
                    collection_budget["remaining_bytes"]
                    if collection_budget is not None
                    else MAX_APK_COMPONENT_BYTES,
                ),
                cancel_event=cancel_event,
                progress_callback=progress_callback,
            )

            downloaded_size = transfer["size_bytes"]

            collected.append({
                "component": filename,
                "device_path": remote_path,
                "local_path": str(local_path),
                "sha256": transfer["sha256"],
                "size_bytes": downloaded_size,
            })

            if collection_budget is not None:
                collection_budget["remaining_bytes"] -= downloaded_size

        except InterruptedError as exc:
            cancelled = True
            errors.append(f"{filename}: {exc}")
            break

        except (
            OSError, ValueError, TimeoutError,
            subprocess.TimeoutExpired, RuntimeError
        ) as exc:
            errors.append(f"{filename}: {exc}")

            from device_manager import check_android_connection

            connection_state = check_android_connection(serial)

            if connection_state != "CONNECTED":
                errors.append(
                  "APK collection stopped because Android "
                  f"connection state is {connection_state}."
                )
                break

    return {
        "package": package_name,
        "expected_components": len(apk_paths),
        "collected": collected,
        "errors": errors,
        "cancelled": cancelled,
        "complete": (
            len(collected) == len(apk_paths)
            and not errors
            and not cancelled
        ),
    }



def assess_installed_application(
    serial, package_name, destination, collection_budget=None,
    progress_callback=None, cancel_event=None,
    force_rescan=False,
    quark_timeout=120,
    quick_scan=False,
):
    """Collect an installed application and analyze its APK components."""
    from malware_scanner import scan_apk, yara_scan_apk

    if progress_callback is not None:
        progress_callback("Collecting APK components...")

    collection = collect_package_apks(
        serial, package_name, destination,
        collection_budget=collection_budget,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )

    result = {
        "package": package_name,
        "collection": collection,
        "analysis_status": "NOT_RUN",
        "verdict": None,
        "findings": [],
        "report_path": None,
        "limitations": [],
    }

    if not collection["complete"]:
        result["limitations"].append(
            "APK collection was incomplete."
        )

    base_apks = [
        item for item in collection["collected"]
        if item["component"] == "base.apk"
    ]

    if len(base_apks) != 1:
        result["limitations"].append(
            "Exactly one base APK is required for full APK analysis."
        )
        result["verdict"] = "SCAN INCOMPLETE"
    else:
        try:
            report = scan_apk(
                base_apks[0]["local_path"],
                progress_callback=progress_callback,
                save_to_disk=False,
                cancel_event=cancel_event,
                force_rescan=force_rescan,
                quark_timeout=quark_timeout,
                quick_scan=quick_scan,
            )

            result["analysis_status"] = (
                "COMPLETED"
                if report.get("scan_completeness", {}).get("status")
                == "COMPLETE"
                else "PARTIAL"
            )
            result["verdict"] = report.get("verdict")
            result["findings"] = report.get("findings", [])
            result["apk_analysis"] = report
            result["report_path"] = None

        except (OSError, ValueError, RuntimeError) as exc:
            result["analysis_status"] = "ERROR"
            result["verdict"] = "SCAN INCOMPLETE"
            result["limitations"].append(
                f"Base APK analysis failed: {exc}"
            )

            if progress_callback is not None:
                progress_callback(
                    "Main APK analysis failed. Running independent YARA..."
                )

            try:
                fallback_yara = yara_scan_apk(
                    base_apks[0]["local_path"],
                    cancel_event=cancel_event,
                )
            except (OSError, ValueError, RuntimeError) as yara_exc:
                fallback_yara = {
                    "status": "ERROR",
                    "matches": [],
                    "details": str(yara_exc),
                }

            result["fallback_yara"] = fallback_yara

            for match in fallback_yara.get("matches", []):
                result["findings"].append({
                    "type": "base_apk_yara_fallback_match",
                    "rule": match.get("rule", "Unknown"),
                    "severity": str(
                        match.get("severity", "UNKNOWN")
                    ).upper(),
                    "classification": match.get(
                        "classification", "unclassified"
                    ),
                    "evidence": match,
                    "details": (
                        "Independent YARA scan detected an indicator "
                        "after the main APK analysis failed. "
                        "This is not proof of malware."
                    ),
                })

            if fallback_yara.get("status") != "COMPLETED":
                result["limitations"].append(
                    "Independent base APK YARA analysis did not complete."
                )
            else:
                result["analysis_status"] = "PARTIAL"

    split_results = []

    for item in collection["collected"]:
        if cancel_event is not None and cancel_event.is_set():
            result["analysis_status"] = "PARTIAL"
            result["verdict"] = "SCAN INCOMPLETE"
            result["limitations"].append(
                "Split APK analysis interrupted by user cancellation."
            )
            break

        if item["component"] == "base.apk":
            continue

        if progress_callback is not None:
            progress_callback(f"Running YARA on split APK {item['component']}...")

        try:
            yara_result = yara_scan_apk(
                item["local_path"], cancel_event=cancel_event
            )
        except (OSError, ValueError, RuntimeError) as exc:
            yara_result = {
                "status": "ERROR",
                "matches": [],
                "details": f"YARA execution failed: {exc}",
            }

        split_results.append({
            "component": item["component"],
            "sha256": item["sha256"],
            "yara": yara_result,
        })

        for match in yara_result.get("matches", []):
            result["findings"].append({
                "type": "split_apk_yara_match",
                "component": item["component"],
                "rule": match.get("rule", "Unknown"),
                "severity": match.get(
                    "severity", "UNKNOWN"
                ).upper(),
                "classification": match.get(
                    "classification", "unclassified"
                ),
                "evidence": match,
                "details": (
                    "YARA indicator found in a split APK component. "
                    "This is not proof of malware."
                ),
            })

        if yara_result.get("status") != "COMPLETED":
            result["limitations"].append(
                f"Split APK {item['component']} YARA status: "
                f"{yara_result.get('status', 'UNKNOWN')}. "
                f"{yara_result.get('details', '')}"
            )

    result["split_analysis"] = split_results

    if split_results:
        result["limitations"].append(
            "Split APK components received YARA static analysis "
            "only; full APK metadata, permission, and signature "
            "checks were not performed on these components."
        )

    split_findings = [
        finding for finding in result["findings"]
        if finding.get("type") == "split_apk_yara_match"
    ]

    high_severity_split = any(
        finding.get("severity") in ("HIGH", "CRITICAL")
        and finding.get("classification") != "capability"
        for finding in split_findings
    )

    review_split_findings = [
        finding for finding in split_findings
        if finding.get("classification") != "capability"
    ]

    incomplete_split = any(
        item["yara"].get("status") != "COMPLETED"
        for item in split_results
    )

    if result["analysis_status"] == "COMPLETED":
        if incomplete_split or not collection["complete"]:
            result["analysis_status"] = "PARTIAL"
        elif result["verdict"] == "SCAN INCOMPLETE":
            result["analysis_status"] = "PARTIAL"

    elif result["analysis_status"] == "NOT_RUN":
        completed_splits = any(
            item["yara"].get("status") == "COMPLETED"
            for item in split_results
        )

        if completed_splits:
            result["analysis_status"] = "PARTIAL"

    if high_severity_split:
        result["verdict"] = "SUSPICIOUS"
    elif incomplete_split or not collection["complete"]:
        if result["verdict"] != "SUSPICIOUS":
            result["verdict"] = "SCAN INCOMPLETE"
    elif review_split_findings:
        if result["verdict"] == "NO KNOWN THREAT DETECTED":
            result["verdict"] = "REVIEW REQUIRED"

    if cancel_event is not None and cancel_event.is_set():
        result["cancelled"] = True
        result["analysis_status"] = "PARTIAL"
        result["verdict"] = "SCAN INCOMPLETE"
        result["limitations"].append(
            "Application assessment interrupted by user cancellation. "
            "Existing security findings are preserved."
        )

    return result



def cleanup_collected_apks(assessment, package_destination):
    """Remove current application APK copies and report recovered bytes."""
    root = Path(package_destination)
    released = 0
    errors = []

    for item in assessment.get("collection", {}).get("collected", []):
        try:
            path = Path(item["local_path"])

            if (
                root.is_symlink()
                or path.is_symlink()
                or path.resolve().parent != root.resolve()
                or path.suffix.lower() != ".apk"
                or not path.is_file()
            ):
                raise ValueError("Unsafe APK cleanup path.")

            size = path.stat().st_size

            if size != item["size_bytes"]:
                raise ValueError("Collected APK size changed.")

            path.unlink()
            released += size
            item["storage_status"] = "REMOVED"

        except (OSError, ValueError, KeyError) as exc:
            item["storage_status"] = "CLEANUP_FAILED"
            errors.append(str(exc))

    return {
        "released_bytes": released,
        "errors": errors,
    }


def assess_android_device(
    serial, destination, max_packages=3, third_party_only=False,
    progress_callback=None, cancel_event=None,
    force_rescan=False, retain_apks=True,
    quark_timeout=120,
    quick_scan=False,
):
    """Assess a bounded number of installed Android applications."""
    if max_packages is not None and (
        isinstance(max_packages, bool)
        or not isinstance(max_packages, int)
        or max_packages < 1
    ):
        raise ValueError("max_packages must be a positive integer or None.")

    destination = Path(destination)
    if progress_callback:
        progress_callback("Discovering installed Android applications...")

    packages = list_installed_packages(
        serial,
        third_party_only=third_party_only,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )
    selected = packages if max_packages is None else packages[:max_packages]

    collection_budget = {
        "remaining_bytes": MAX_SCAN_COLLECTION_BYTES,
    }

    from device_manager import run_command

    model, model_error = run_command([
        "adb", "-s", serial, "shell", "getprop", "ro.product.model"
    ])

    model = model.strip() if model else ""

    if not model or model.lower() in ("unknown", "null"):
        model = "Unknown Android Device"

    result = {
        "device_serial": serial,
        "device_model": model,
        "packages_discovered": len(packages),
        "packages_selected": len(selected),
        "packages_assessed": 0,
        "packages_completed": 0,
        "packages_partial": 0,
        "packages_failed": 0,
        "packages_not_run": 0,
        "packages_not_selected": len(packages) - len(selected),
        "applications": [],
        "errors": [],
        "limitations": [
            "Only ADB-visible installed packages can be assessed.",
            "Static APK analysis cannot prove a device is malware-free.",
        ],
    }

    result["cancelled"] = False

    for index, package_name in enumerate(selected, start=1):
        if cancel_event is not None and cancel_event.is_set():
            result["cancelled"] = True
            result["limitations"].append(
                "Assessment cancelled by the user before all selected "
                "applications were processed."
            )
            if progress_callback:
                progress_callback(
                    "Cancellation acknowledged. Preparing partial results..."
                )
            break

        app_progress = None
        if progress_callback is not None:
            app_label = f"App {index} of {len(selected)} · {package_name}"

            def app_progress(message, label=app_label):
                progress_callback(f"{label} · {message}")

        print(
            f"[{index}/{len(selected)}] Assessing {package_name}",
            flush=True,
        )

        package_destination = destination / package_name

        try:
            if not retain_apks:
                if destination.is_symlink():
                    raise ValueError("Unsafe scan destination.")

                if not re.fullmatch(
                    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+",
                    package_name,
                ):
                    raise ValueError("Invalid package name.")

                package_destination.mkdir(
                    parents=False, exist_ok=False
                )

            assessment = assess_installed_application(
                serial, package_name, package_destination,
                collection_budget=collection_budget,
                progress_callback=app_progress,
                cancel_event=cancel_event,
                force_rescan=force_rescan,
                quark_timeout=quark_timeout,
                quick_scan=quick_scan,
            )
        except (OSError, ValueError, RuntimeError,
                subprocess.TimeoutExpired) as exc:
            assessment = {
                "package": package_name,
                "analysis_status": "ERROR",
                "verdict": "SCAN INCOMPLETE",
                "findings": [],
                "limitations": [
                    f"Application assessment failed: {exc}"
                ],
            }
            result["errors"].append(
                f"{package_name}: {type(exc).__name__}: {exc}"
            )

        if cancel_event is not None and cancel_event.is_set():
            result["cancelled"] = True
            assessment["cancelled"] = True
            assessment["analysis_status"] = "PARTIAL"
            assessment["verdict"] = "SCAN INCOMPLETE"

        if not retain_apks:
            cleanup = cleanup_collected_apks(
                assessment, package_destination
            )

            collection_budget["remaining_bytes"] += (
                cleanup["released_bytes"]
            )

            assessment["apk_cleanup"] = cleanup

            if cleanup["errors"]:
                result["errors"].extend(
                    f"APK cleanup {package_name}: {error}"
                    for error in cleanup["errors"]
                )

            if app_progress:
                app_progress(
                    f"Released {cleanup['released_bytes'] / 1048576:.2f} MiB "
                    "of temporary APK storage."
                )

        result["applications"].append(assessment)
        result["packages_assessed"] += 1

        status = assessment.get("analysis_status", "NOT_RUN")

        if status == "COMPLETED":
            result["packages_completed"] += 1
        elif status == "PARTIAL":
            result["packages_partial"] += 1
        elif status == "ERROR":
            result["packages_failed"] += 1
        else:
            result["packages_not_run"] += 1

        from device_manager import check_android_connection

        connection_state = check_android_connection(serial)

        if connection_state in (
            "DISCONNECTED", "OFFLINE", "UNAUTHORIZED", "ERROR"
        ):
            from device_manager import wait_for_android_connection

            if progress_callback:
                progress_callback(
                    "Android connection interrupted. "
                    "Waiting up to 60 seconds for reconnection..."
                )

            try:
                recovered = wait_for_android_connection(
                    serial,
                    timeout=60,
                    interval=2,
                    cancel_event=cancel_event,
                    progress_callback=progress_callback,
                )
            except InterruptedError:
                result["cancelled"] = True
                result["limitations"].append(
                    "Assessment cancelled during connection recovery."
                )
                if progress_callback:
                    progress_callback(
                        "Scan cancelled. Preserving completed results..."
                    )
                break

            if recovered:
                if progress_callback:
                    progress_callback(
                        "Android reconnected. Continuing security scan..."
                    )
                continue

            result["connection_interrupted"] = True
            result["connection_state"] = connection_state

            result["limitations"].append(
                "Android connection was lost during assessment. "
                "Remaining applications were not scanned."
            )

            if progress_callback:
                progress_callback(
                    "Android connection lost. "
                    "Preserving completed scan results..."
                )

            break


    if result["cancelled"] or result.get("connection_interrupted"):
        result["packages_not_run"] += (
            len(selected) - result["packages_assessed"]
        )

    if progress_callback:
        progress_callback(
            f"Application assessment {'cancelled' if result['cancelled'] else 'finished'}: "
            f"{result['packages_assessed']} of {len(selected)} processed."
        )

    if len(selected) < len(packages):
        result["limitations"].append(
            f"Assessment limited to {len(selected)} of "
            f"{len(packages)} discovered packages."
        )

    result["scan_status"] = (
        "CANCELLED"
        if result["cancelled"]
        else "INTERRUPTED"
        if result.get("connection_interrupted")
        else "COMPLETE"
        if result["packages_completed"] == len(selected)
        else "PARTIAL"
    )

    if result["scan_status"] != "COMPLETE":
        result["limitations"].append(
            "The device assessment did not complete all selected "
            "application security checks."
        )

    released_bytes = sum(
        app.get("apk_cleanup", {}).get("released_bytes", 0)
        for app in result["applications"]
    )

    retained_bytes = (
        MAX_SCAN_COLLECTION_BYTES
        - collection_budget["remaining_bytes"]
    )

    result["collection_budget"] = {
        "limit_bytes": MAX_SCAN_COLLECTION_BYTES,
        "collected_bytes": retained_bytes + released_bytes,
        "released_bytes": released_bytes,
        "retained_bytes": retained_bytes,
        "remaining_bytes": collection_budget["remaining_bytes"],
        "retention_enabled": retain_apks,
    }

    return result


def discover_android_targets():
    """Return authorized Android devices."""
    return [
        device
        for device in discover_devices()
        if device["platform"] == "Android"
        and device["state"] == "Authorized"
    ]


if __name__ == "__main__":
    devices = discover_android_targets()

    if not devices:
        print("No authorized Android device detected.")
    else:
        for device in devices:
            print(f"\nDevice: {device['name']}")
            print(f"Serial: {device['id']}")

            try:
                packages = list_installed_packages(device["id"])
                print(f"Visible installed packages: {len(packages)}")

                for package in packages:
                    print(f"  {package}")

            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                print(f"Package discovery error: {exc}")
