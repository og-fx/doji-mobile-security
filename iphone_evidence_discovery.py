#!/usr/bin/env python3
"""Discover existing iPhone forensic evidence for Doji."""

from pathlib import Path

from forensic_engine import validate_evidence, WORKFLOWS

PROJECT_DIR = Path(__file__).resolve().parent

EVIDENCE_ROOTS = [
    PROJECT_DIR / "forensic" / "ios",
    PROJECT_DIR / "forensic" / "evidence" / "ios",
]


def discover_iphone_evidence():
    """Return validated existing iPhone forensic evidence."""
    discovered = []
    seen = set()

    for root in EVIDENCE_ROOTS:
        if not root.is_dir() or root.is_symlink():
            continue

        candidates = [root]

        # Keep discovery bounded and avoid traversing arbitrary files.
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                candidates.append(child)

        for candidate in candidates:
            if candidate.is_symlink():
                continue

            if (
                (candidate / "Manifest.db").is_file()
                and (candidate / "Info.plist").is_file()
            ):
                workflow = "ios-backup"

                try:
                    validate_evidence(
                        candidate,
                        WORKFLOWS[workflow]["input_type"],
                        workflow,
                    )
                except (ValueError, FileNotFoundError, OSError):
                    continue

                key = (workflow, str(candidate.resolve()))

                if key not in seen:
                    discovered.append({
                        "workflow": workflow,
                        "path": str(candidate.resolve()),
                    })
                    seen.add(key)

            if candidate.is_dir():
                for item in candidate.iterdir():
                    if (
                        item.is_file()
                        and not item.is_symlink()
                        and "sysdiagnose" in item.name.lower()
                        and item.suffix.lower() in {".tar", ".gz", ".zip"}
                    ):
                        key = ("ios-sysdiagnose", str(item.resolve()))

                        if key not in seen:
                            discovered.append({
                                "workflow": "ios-sysdiagnose",
                                "path": str(item.resolve()),
                            })
                            seen.add(key)

    return discovered


if __name__ == "__main__":
    for evidence in discover_iphone_evidence():
        print(evidence)


def verify_iphone_backup_owner(backup_path, device_id):
    """Check whether an iPhone backup belongs to the selected device."""
    import plistlib

    backup_path = Path(backup_path)
    info_path = backup_path / "Info.plist"

    if info_path.is_symlink() or not info_path.is_file():
        return False

    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)

        backup_device_id = info.get("Target Identifier")

        if not isinstance(backup_device_id, str):
            return False

        return backup_device_id.strip().lower() == device_id.strip().lower()

    except (OSError, ValueError, TypeError, OverflowError):
        return False
