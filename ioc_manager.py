
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
IOC_DIR = BASE_DIR / "forensic" / "iocs"
INDICATOR_DIR = IOC_DIR / "mvt-public"
MANIFEST = IOC_DIR / "sha256-manifest.txt"
INVENTORY = IOC_DIR / "inventory.json"


def calculate_sha256(file_path):
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_manifest():
    results = {}

    if not MANIFEST.is_file():
        return results, "Manifest not found"

    with MANIFEST.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            expected_hash, relative_path = line.split(maxsplit=1)
            results[relative_path.lstrip("*")] = expected_hash

    return results, None


def build_inventory():
    expected_hashes, error = verify_manifest()

    if error:
        raise FileNotFoundError(error)

    if not INDICATOR_DIR.is_dir():
        raise FileNotFoundError(
            f"Indicator directory not found: {INDICATOR_DIR}"
        )

    indicators = []

    for file_path in sorted(INDICATOR_DIR.glob("*.stix2")):
        relative_path = file_path.relative_to(BASE_DIR).as_posix()
        digest = calculate_sha256(file_path)

        expected = expected_hashes.get(relative_path)

        if expected is None:
            integrity = "NOT_IN_MANIFEST"
        elif digest == expected:
            integrity = "VERIFIED"
        else:
            integrity = "MISMATCH"

        stat = file_path.stat()

        indicators.append({
            "filename": file_path.name,
            "path": relative_path,
            "source": "MVT public threat intelligence",
            "format": "STIX2",
            "size_bytes": stat.st_size,
            "modified_utc": datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat(),
            "sha256": digest,
            "integrity": integrity,
        })

    manifest_entries = len(expected_hashes)
    verified_count = sum(
        item["integrity"] == "VERIFIED" for item in indicators
    )

    inventory = {
        "tool": "Doji IOC Manager",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "collection": "MVT public indicators",
        "indicator_count": len(indicators),
        "manifest_entry_count": manifest_entries,
        "verified_count": verified_count,
        "indicators": indicators,
    }

    INVENTORY.write_text(
        json.dumps(inventory, indent=2),
        encoding="utf-8",
    )

    return inventory


def main():
    try:
        inventory = build_inventory()

        print("\n=== Doji IOC Manager ===")
        print(f"Indicators found: {inventory['indicator_count']}")
        print(f"Manifest entries: {inventory['manifest_entry_count']}")
        print(f"Verified: {inventory['verified_count']}")
        print(f"Inventory saved: {INVENTORY}")

        for item in inventory["indicators"]:
            print(f"[{item['integrity']}] {item['filename']}")

        if any(
            item["integrity"] != "VERIFIED"
            for item in inventory["indicators"]
        ):
            print("\nWARNING: Some indicators need integrity review.")

    except (OSError, ValueError) as exc:
        print(f"IOC inventory failed: {exc}")


if __name__ == "__main__":
    main()
