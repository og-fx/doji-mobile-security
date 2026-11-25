#!/usr/bin/env python3
"""Safe Quark-Engine adapter for Doji Mobile Security."""

import hashlib
import json
import shutil
import sys
import subprocess
import tempfile

from pathlib import Path


DEFAULT_RULES = (
    Path.home() / ".quark-engine" / "quark-rules" / "rules"
)

DEFAULT_TIMEOUT = 1800


def sha256_file(path):
    """Calculate a file's SHA-256 without modifying it."""
    digest = hashlib.sha256()

    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def analyze_apk(
    apk_path,
    rules_dir=DEFAULT_RULES,
    timeout=DEFAULT_TIMEOUT,
    executable=None,
    cancel_event=None,
    force_rescan=False,
    core_library="dextrace",
):
    """Run Quark and return structured, independently verifiable results."""

    if core_library not in ("androguard", "dextrace"):
        raise ValueError("Unsupported Quark analysis backend.")

    apk = Path(apk_path).expanduser()

    result = {
        "engine": "Quark-Engine",
        "core_library": core_library,
        "engine_status": "NOT_RUN",
        "apk_path": str(apk),
        "apk_sha256": None,
        "evidence_integrity": "NOT_VERIFIED",
        "original_threat_level": None,
        "original_total_score": None,
        "original_weight_sum": None,
        "behavior_count": 0,
        "findings": [],
        "limitations": [],
        "errors": [],
    }

    try:
        if apk.is_symlink():
            raise ValueError("Symbolic-link APKs are not accepted.")

        apk = apk.resolve(strict=True)

        if not apk.is_file():
            raise ValueError("APK path is not a regular file.")

        if apk.suffix.lower() != ".apk":
            raise ValueError("Input must be an APK file.")

        rules = Path(rules_dir).expanduser().resolve(strict=True)

        if not rules.is_dir():
            raise ValueError("Quark rules path is not a directory.")

        rule_files = list(rules.glob("*.json"))

        if not rule_files:
            raise ValueError("No Quark JSON rules were found.")

        quark = executable or shutil.which("quark")

        if not quark:
            environment_quark = (
                Path(sys.prefix) / "bin" / "quark"
            )

            if environment_quark.is_file():
                quark = str(environment_quark)

        if not quark:
            raise RuntimeError(
                "Quark executable was not found in the active environment."
            )

        before_hash = sha256_file(apk)
        result["apk_sha256"] = before_hash
        result["rules_available"] = len(rule_files)

        from engines.quark_cache import (
            rules_fingerprint,
            engine_fingerprint,
            build_cache_key,
            load_cached_result,
            save_cached_result,
        )

        cache_key = None
        result["cache_status"] = "MISS"

        if cancel_event is not None and cancel_event.is_set():
            result["engine_status"] = "CANCELLED"
            return result

        try:
            cache_key = build_cache_key(
                before_hash,
                rules_fingerprint(rules),
                engine_fingerprint(quark),
                core_library=core_library,
            )

            if not force_rescan:
                cached = load_cached_result(cache_key, before_hash)

                if (
                    cached is not None
                    and sha256_file(apk) == before_hash
                    and not (
                        cancel_event is not None
                        and cancel_event.is_set()
                    )
                ):
                    cached["apk_path"] = str(apk)
                    cached["cache_status"] = "HIT"
                    return cached

            else:
                result["cache_status"] = "BYPASSED"

        except Exception:
            cache_key = None
            result["cache_status"] = "UNAVAILABLE"

        with tempfile.TemporaryDirectory(
            prefix="doji-quark-"
        ) as temporary_directory:

            output = Path(temporary_directory) / "quark.json"

            command = [
                str(quark),
                "--apk", str(apk),
                "--rule", str(rules),
                "--output", str(output),
                "--core-library", core_library,
            ]

            if cancel_event is not None and cancel_event.is_set():
                result["engine_status"] = "CANCELLED"
                result["limitations"].append(
                    "Quark analysis cancelled before execution."
                )
                return result

            import os
            import signal
            import time


            prlimit = shutil.which("prlimit")
            if prlimit:
                command = [
                    prlimit,
                    "--as=5368709120",
                    "--",
                    *command,
                ]
                result["memory_limit_bytes"] = 5368709120
            else:
                result["memory_limit_bytes"] = None
                result["limitations"].append(
                    "Quark memory limit unavailable: prlimit not installed."
                )

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

            started = time.monotonic()

            def stop_quark():
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()

            while True:
                if cancel_event is not None and cancel_event.is_set():
                    stop_quark()
                    result["engine_status"] = "CANCELLED"
                    result["limitations"].append(
                        "Quark analysis cancelled by the user."
                    )
                    return result

                remaining = timeout - (time.monotonic() - started)

                if remaining <= 0:
                    stop_quark()
                    result["engine_status"] = "TIMEOUT"
                    result["errors"].append(
                        f"Quark exceeded the {timeout}-second timeout."
                    )
                    return result

                try:
                    stdout, stderr = process.communicate(
                        timeout=min(0.25, remaining)
                    )
                    break
                except subprocess.TimeoutExpired:
                    continue

            result["return_code"] = process.returncode

            if process.returncode != 0:
                result["engine_status"] = "ERROR"

                if process.returncode == -signal.SIGKILL:
                    result["error_category"] = "POSSIBLE_RESOURCE_EXHAUSTION"
                    result["errors"].append(
                        "Quark was forcibly terminated (SIGKILL). "
                        "Possible insufficient RAM or system resource limits."
                    )
                    result["limitations"].append(
                        "Close unnecessary applications, increase available "
                        "memory where possible, and retry the analysis. "
                        "Check system logs to confirm memory exhaustion."
                    )

                elif stderr and (
                    "MemoryError" in stderr
                    or "Cannot allocate memory" in stderr
                ):
                    result["error_category"] = "RESOURCE_LIMIT_EXCEEDED"
                    result["errors"].append(
                        "Quark could not complete analysis because "
                        "its memory allocation failed."
                    )
                    result["limitations"].append(
                        "Quark behavioral analysis is incomplete. "
                        "This is not evidence that the APK is malicious "
                        "or malware-free."
                    )

                elif process.returncode == -signal.SIGTERM:
                    result["error_category"] = "PROCESS_TERMINATED"
                    result["errors"].append(
                        "Quark was terminated by an external signal."
                    )

                else:
                    result["error_category"] = "ENGINE_EXECUTION_FAILURE"
                    result["errors"].append(
                        f"Quark exited with code {process.returncode}."
                    )

                if stderr and stderr.strip():
                    result["errors"].append(stderr[-4000:])

                return result

            if not output.is_file():
                result["engine_status"] = "ERROR"
                result["errors"].append(
                    "Quark did not create its JSON report."
                )
                return result

            report = json.loads(
                output.read_text(encoding="utf-8")
            )

        if not isinstance(report, dict):
            raise ValueError("Quark returned an invalid report structure.")

        crimes = report.get("crimes")

        if not isinstance(crimes, list):
            raise ValueError("Quark report has no valid crimes list.")

        after_hash = sha256_file(apk)

        result["evidence_integrity"] = (
            "UNCHANGED" if before_hash == after_hash else "CHANGED"
        )

        if before_hash != after_hash:
            result["engine_status"] = "INTEGRITY_FAILURE"
            result["errors"].append(
                "APK SHA-256 changed during analysis."
            )
            return result

        result["original_threat_level"] = report.get(
            "threat_level"
        )
        result["original_total_score"] = report.get(
            "total_score"
        )

        result["original_weight_sum"] = sum(
            float(item.get("weight", 0))
            for item in crimes
            if isinstance(item, dict)
        )

        for item in crimes:
            if not isinstance(item, dict):
                result["limitations"].append(
                    "A malformed Quark behavior record was skipped."
                )
                continue

            result["findings"].append({
                "rule": item.get("rule"),
                "behavior": item.get("crime"),
                "labels": item.get("label", []),
                "confidence": item.get("confidence"),
                "score": item.get("score"),
                "weight": item.get("weight"),
                "permissions": item.get("permissions", []),
                "native_api": item.get("native_api", []),
                "combination": item.get("combination", []),
                "sequence": item.get("sequence", []),
                "register": item.get("register", []),
            })

        result["behavior_count"] = len(result["findings"])
        result["engine_status"] = "COMPLETED"

        result["limitations"].append(
            "Quark behavioral rule matches are static indicators, "
            "not proof of active malware execution."
        )

        result["limitations"].append(
            "Quark's original risk classification is preserved "
            "without treating it as an independently verified verdict."
        )

        result["limitations"].append(
            "VirusTotal reputation and Android runtime behavior "
            "are outside this adapter's scope."
        )

        if cache_key is not None:
            try:
                current_key = build_cache_key(
                    sha256_file(apk),
                    rules_fingerprint(rules),
                    engine_fingerprint(quark),
                    core_library=core_library,
                )

                if current_key == cache_key:
                    result["cache_saved"] = save_cached_result(
                        cache_key, before_hash, result
                    )
            except Exception:
                result["cache_saved"] = False

    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result["engine_status"] = "ERROR"
        result["errors"].append(str(exc))

    return result
