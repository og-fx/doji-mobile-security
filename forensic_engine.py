#!/usr/bin/env python3
"""Doji Advanced Forensics Engine.

Runs supported, evidence-based MVT analysis workflows.
Original evidence is read only and is never modified by this script.
"""

import zipfile
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
FORENSIC_DIR = PROJECT_DIR / "forensic"
IOC_DIR = FORENSIC_DIR / "iocs" / "mvt-public"
RESULTS_DIR = FORENSIC_DIR / "results"

MVT_ANDROID = shutil.which("mvt-android") or str(Path.home() / ".local/bin/mvt-android")
MVT_IOS = shutil.which("mvt-ios") or str(Path.home() / ".local/bin/mvt-ios")

WORKFLOWS = {
    "android-bugreport": {
        "platform": "Android",
        "executable": MVT_ANDROID,
        "command": "check-bugreport",
        "input_type": "file",
    },
    "android-androidqf": {
        "platform": "Android",
        "executable": MVT_ANDROID,
        "command": "check-androidqf",
        "input_type": "directory",
    },
    "android-backup": {
        "platform": "Android",
        "executable": MVT_ANDROID,
        "command": "check-backup",
        "input_type": "directory",
    },
    "ios-backup": {
        "platform": "iOS",
        "executable": MVT_IOS,
        "command": "check-backup",
        "input_type": "directory",
    },
    "ios-filesystem": {
        "platform": "iOS",
        "executable": MVT_IOS,
        "command": "check-fs",
        "input_type": "directory",
    },
    "ios-sysdiagnose": {
        "platform": "iOS",
        "executable": MVT_IOS,
        "command": "check-sysdiagnose",
        "input_type": "either",
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def hash_evidence(path):
    """Hash a file or create a deterministic hash for a directory tree."""

    if path.is_symlink():
        raise ValueError("Evidence path must not be a symbolic link.")

    if path.is_file():
        return {
            "type": "file",
            "sha256": sha256_file(path),
            "file_count": 1,
        }

    if not path.is_dir():
        raise ValueError("Evidence must be a regular file or directory.")

    digest = hashlib.sha256()
    file_count = 0

    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise ValueError(
                f"Evidence contains a symbolic link: {item}"
            )

        if not item.is_file():
            continue

        relative_name = item.relative_to(path).as_posix().encode("utf-8")
        file_hash = sha256_file(item)

        digest.update(len(relative_name).to_bytes(8, "big"))
        digest.update(relative_name)
        digest.update(bytes.fromhex(file_hash))
        file_count += 1

    if file_count == 0:
        raise ValueError("Evidence directory contains no regular files.")

    return {
        "type": "directory",
        "sha256": digest.hexdigest(),
        "file_count": file_count,
    }


def load_ioc_files():
    """Verify every IOC against the SHA-256 manifest before use."""

    manifest = FORENSIC_DIR / "iocs" / "sha256-manifest.txt"

    if not manifest.is_file():
        raise FileNotFoundError(f"IOC manifest not found: {manifest}")

    expected = {}

    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue

        parts = line.split(maxsplit=1)

        if len(parts) != 2:
            raise ValueError(
                f"Invalid IOC manifest entry on line {line_number}."
            )

        expected_hash, relative_path = parts

        if len(expected_hash) != 64 or any(
            char not in "0123456789abcdefABCDEF"
            for char in expected_hash
        ):
            raise ValueError(
                f"Invalid SHA-256 value on manifest line {line_number}."
            )

        candidate = PROJECT_DIR / relative_path

        if candidate.is_symlink():
            raise ValueError(f"IOC symbolic link rejected: {candidate}")

        candidate = candidate.resolve(strict=True)

        try:
            candidate.relative_to(IOC_DIR.resolve())
        except ValueError:
            raise ValueError(
                f"IOC path is outside the approved directory: {candidate}"
            )

        if candidate in expected:
            raise ValueError(f"Duplicate IOC manifest entry: {candidate}")

        if not candidate.is_file() or candidate.suffix != ".stix2":
            raise ValueError(f"Invalid IOC file: {candidate}")

        actual_hash = sha256_file(candidate)

        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(
                f"IOC integrity verification failed: {candidate.name}"
            )

        expected[candidate] = expected_hash.lower()

    actual_files = list(IOC_DIR.glob("*.stix2"))

    if any(item.is_symlink() for item in actual_files):
        raise ValueError("IOC directory contains a symbolic link.")

    actual_paths = {item.resolve() for item in actual_files}

    if actual_paths != set(expected):
        raise ValueError(
            "IOC manifest and IOC directory do not contain the same files."
        )

    if not expected:
        raise ValueError("No verified STIX2 indicators are available.")

    print(f"[Doji] Verified {len(expected)} IOC files against manifest.")
    return sorted(expected)


def write_json(path, data):
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def create_case_directory():
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_id = f"DOJI-FORENSIC-{timestamp}"
    case_dir = RESULTS_DIR / case_id

    suffix = 1
    while case_dir.exists():
        case_dir = RESULTS_DIR / f"{case_id}-{suffix:02d}"
        suffix += 1

    case_dir.mkdir(parents=True)
    (case_dir / "mvt-output").mkdir()
    (case_dir / "logs").mkdir()

    return case_dir


def validate_evidence(path, expected_type, workflow_name):
    if not path.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {path}")

    if path.is_symlink():
        raise ValueError("Symbolic-link evidence paths are not accepted.")

    # Prevent evidence and investigation output from overlapping.
    evidence = path.resolve()
    project = PROJECT_DIR.resolve()
    results = RESULTS_DIR.resolve()

    if evidence == project:
        raise ValueError(
            "The Doji project directory cannot be used as forensic evidence."
        )

    if evidence.is_dir() and (
        evidence == results or evidence in results.parents
    ):
        raise ValueError(
            "The selected evidence directory contains Doji's forensic "
            "results directory. Choose an independent evidence folder."
        )

    if workflow_name == "ios-backup":
        if not evidence.is_dir():
            raise ValueError(
                "iOS backup analysis requires an existing backup directory."
            )

        required_files = ("Manifest.db", "Info.plist")
        missing = [
            name for name in required_files
            if not (evidence / name).is_file()
        ]

        if missing:
            raise ValueError(
                "Invalid iPhone backup directory. Missing: "
                + ", ".join(missing)
                + ". Select the actual iPhone backup folder."
            )

    if expected_type == "file" and not path.is_file():
        raise ValueError("This workflow requires an evidence file.")

    if workflow_name == "android-bugreport":
        if not zipfile.is_zipfile(path):
            raise ValueError(
                "Invalid Android bug report: expected a valid ZIP archive."
            )

    if expected_type == "directory" and not path.is_dir():
        raise ValueError("This workflow requires an evidence directory.")

    if expected_type == "either" and not (path.is_file() or path.is_dir()):
        raise ValueError("Evidence must be a regular file or directory.")


def run_investigation(workflow_name, evidence_path, timeout_seconds, case_callback=None):
    workflow = WORKFLOWS[workflow_name]

    evidence_path = evidence_path.expanduser()

    if evidence_path.is_symlink():
        raise ValueError("Original evidence path must not be a symbolic link.")

    evidence_path = evidence_path.resolve(strict=True)

    validate_evidence(evidence_path, workflow["input_type"], workflow_name)

    executable = workflow["executable"]
    if not Path(executable).is_file():
        raise FileNotFoundError(
            f"Required analysis command was not found: {executable}"
        )

    ioc_files = load_ioc_files()

    print("[Doji] Calculating original evidence hash...")
    evidence_hash = hash_evidence(evidence_path)

    case_dir = create_case_directory()

    if case_callback is not None:
        case_callback(case_dir)

    output_dir = case_dir / "mvt-output"
    log_dir = case_dir / "logs"

    command = [
        executable,
        workflow["command"],
        "-o",
        str(output_dir),
    ]

    for ioc_file in ioc_files:
        command.extend(["-i", str(ioc_file)])

    command.append(str(evidence_path))

    metadata = {
        "product": "Doji Advanced Mobile Forensics",
        "case_id": case_dir.name,
        "created_utc": utc_now(),
        "platform": workflow["platform"],
        "workflow": workflow_name,
        "analysis_tool": "MVT",
        "analysis_command": workflow["command"],
        "evidence": {
            "source_path": str(evidence_path),
            **evidence_hash,
        },
        "indicators": {
            "directory": str(IOC_DIR),
            "files_used": [item.name for item in ioc_files],
            "count": len(ioc_files),
        },
        "output_directory": str(output_dir),
        "evidence_integrity": {
            "status": "PENDING_POST_ANALYSIS",
            "before_sha256": evidence_hash["sha256"],
            "after_sha256": None,
        },
        "status": "PREPARING",
    }

    write_json(case_dir / "case_metadata.json", metadata)

    command_log = log_dir / "command.txt"
    stdout_log = log_dir / "stdout.txt"
    stderr_log = log_dir / "stderr.txt"

    command_log.write_text(
        "Command arguments:\n"
        + json.dumps(command, indent=2)
        + "\n\nThe command was executed without a shell.\n",
        encoding="utf-8",
    )

    print(f"[Doji] Case: {case_dir.name}")
    print(f"[Doji] Evidence SHA-256: {evidence_hash['sha256']}")
    print(f"[Doji] IOC files supplied: {len(ioc_files)}")
    print("[Doji] Starting evidence analysis...")

    started = time.monotonic()
    status = "ERROR"
    return_code = None
    error_message = None

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        return_code = result.returncode
        stdout_log.write_text(result.stdout or "", encoding="utf-8")
        stderr_log.write_text(result.stderr or "", encoding="utf-8")

        status = "COMPLETED" if return_code == 0 else "FAILED"

    except subprocess.TimeoutExpired as exc:
        status = "TIMEOUT"
        error_message = (
            f"Analysis exceeded the {timeout_seconds}-second timeout."
        )
        stdout_log.write_text(
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            encoding="utf-8",
        )
        stderr_log.write_text(
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            encoding="utf-8",
        )

    except OSError as exc:
        error_message = str(exc)
        stderr_log.write_text(error_message + "\n", encoding="utf-8")

    print("[Doji] Rechecking original evidence integrity...")

    after_hash = None
    integrity_status = "CHECK_FAILED"

    try:
        after_hash = hash_evidence(evidence_path)

        integrity_status = (
            "UNCHANGED"
            if after_hash["sha256"] == evidence_hash["sha256"]
            else "CHANGED"
        )

    except (OSError, ValueError) as exc:
        integrity_error = f"Post-analysis integrity check failed: {exc}"

        if error_message:
            error_message += " | " + integrity_error
        else:
            error_message = integrity_error

    if status == "COMPLETED" and integrity_status == "CHANGED":
        status = "INTEGRITY_WARNING"
    elif status == "COMPLETED" and integrity_status == "CHECK_FAILED":
        status = "INTEGRITY_UNVERIFIED"

    metadata["evidence_integrity"] = {
        "status": integrity_status,
        "before_sha256": evidence_hash["sha256"],
        "after_sha256": (
            after_hash["sha256"] if after_hash else None
        ),
        "content_unchanged": integrity_status == "UNCHANGED",
    }

    duration = round(time.monotonic() - started, 2)

    metadata.update({
        "finished_utc": utc_now(),
        "duration_seconds": duration,
        "status": status,
        "return_code": return_code,
        "error": error_message,
    })

    write_json(case_dir / "case_metadata.json", metadata)

    run_summary = {
        "case_id": case_dir.name,
        "status": status,
        "return_code": return_code,
        "duration_seconds": duration,
        "error": error_message,
        "evidence_integrity": integrity_status,
        "output_directory": str(output_dir),
        "logs_directory": str(log_dir),
    }
    write_json(case_dir / "run_summary.json", run_summary)

    print()
    print(f"[Doji] Investigation status: {status}")
    print(f"[Doji] Evidence integrity: {integrity_status}")
    print(f"[Doji] Case directory: {case_dir}")
    print(f"[Doji] Results: {output_dir}")
    print(f"[Doji] Logs: {log_dir}")

    if error_message:
        print(f"[Doji] Error: {error_message}")

    if return_code not in (None, 0):
        print(f"[Doji] MVT returned exit code: {return_code}")

    print(
        "[Doji] Important: a completed analysis is not proof "
        "that a device is free of spyware."
    )

    return (
        0
        if status == "COMPLETED" and integrity_status == "UNCHANGED"
        else 1
    )


def main():
    parser = argparse.ArgumentParser(
        description="Doji Advanced Mobile Forensics Engine"
    )

    parser.add_argument(
        "--workflow",
        required=True,
        choices=sorted(WORKFLOWS),
        help="Evidence analysis workflow to run.",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="Path to an existing evidence file or directory.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="Maximum analysis time in seconds (default: 7200).",
    )

    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be greater than zero.")

    try:
        return run_investigation(
            args.workflow,
            args.evidence,
            args.timeout,
        )
    except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        print(f"[Doji] Cannot start investigation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
