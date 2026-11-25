"""Local analysis cache support for Doji Mobile Security."""

import hashlib
import json
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "cache" / "quark"
CACHE_SCHEMA_VERSION = 1


def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rules_fingerprint(rules_dir):
    rules = Path(rules_dir)
    files = sorted(rules.glob("*.json"))

    if not files:
        raise ValueError("No Quark rules available.")

    manifest = [
        {
            "name": path.name,
            "sha256": hash_file(path),
        }
        for path in files
    ]

    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()
    ).hexdigest()


def build_cache_key(
    apk_sha256, rules_sha256, engine_signature,
    core_library="androguard"
):
    payload = {
        "schema": CACHE_SCHEMA_VERSION,
        "apk_sha256": apk_sha256,
        "rules_sha256": rules_sha256,
        "engine_signature": engine_signature,
        "core_library": core_library,
    }

    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()


def is_cacheable(result, apk_sha256):
    return (
        isinstance(result, dict)
        and result.get("engine_status") == "COMPLETED"
        and result.get("evidence_integrity") == "UNCHANGED"
        and result.get("apk_sha256") == apk_sha256
        and isinstance(result.get("findings"), list)
        and result.get("behavior_count") == len(result["findings"])
        and result.get("errors") == []
        and not any(
            "malformed" in str(item).lower()
            for item in result.get("limitations", [])
        )
    )


def load_cached_result(key, apk_sha256):
    try:
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            return None

        path = CACHE_DIR / f"{key}.json"

        if path.is_symlink():
            return None

        data = json.loads(path.read_text(encoding="utf-8"))

        if data.get("schema") != CACHE_SCHEMA_VERSION:
            return None

        if data.get("cache_key") != key:
            return None

        result = data.get("result")

        if is_cacheable(result, apk_sha256):
            return result

    except (OSError, ValueError, TypeError, AttributeError):
        pass

    return None


def save_cached_result(key, apk_sha256, result):
    import os
    import tempfile

    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        return False

    if not is_cacheable(result, apk_sha256):
        return False

    temporary_path = None

    try:
        CACHE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        payload = {
            "schema": CACHE_SCHEMA_VERSION,
            "cache_key": key,
            "result": result,
        }

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=CACHE_DIR,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())

        temporary_path.replace(CACHE_DIR / f"{key}.json")
        return True

    except (OSError, ValueError, TypeError):
        return False

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def engine_fingerprint(executable):
    import subprocess

    executable = Path(executable).resolve(strict=True)
    interpreter = executable.parent / "python"

    if not interpreter.is_file():
        raise RuntimeError("Quark Python environment not found.")

    dependencies = subprocess.check_output(
        [
            str(interpreter),
            "-c",
            "import importlib.metadata as m; "
            "print(sorted((d.metadata['Name'], d.version) "
            "for d in m.distributions()))",
        ],
        text=True,
        timeout=30,
    )

    payload = {
        "executable_sha256": hash_file(executable),
        "python_sha256": hash_file(interpreter),
        "dependencies": dependencies.strip(),
        "adapter_sha256": hash_file(
            Path(__file__).with_name("quark_adapter.py")
        ),
        "cache_module_sha256": hash_file(Path(__file__)),
    }

    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()
