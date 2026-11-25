#!/usr/bin/env python3
"""Parse Android dumpsys package permission information."""

import re


USER_PATTERN = re.compile(r"^User (\d+):")
PERMISSION_PATTERN = re.compile(
    r"^([\w.]+):\s+granted=(true|false)\b"
)


def parse_package_permissions(output):
    """Parse requested, install and per-user runtime permissions."""
    requested = set()
    install = {}
    runtime = {}

    section = None
    current_user = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        user_match = USER_PATTERN.match(line)
        if user_match:
            current_user = user_match.group(1)
            section = None
            continue

        if line == "requested permissions:":
            section = "requested"
            continue

        if line == "install permissions:":
            section = "install"
            continue

        if line == "runtime permissions:":
            section = "runtime" if current_user is not None else None
            continue

        if line.endswith(":"):
            section = None
            continue

        if section == "requested":
            if re.fullmatch(r"[\w.]+", line):
                requested.add(line)

        elif section in {"install", "runtime"}:
            match = PERMISSION_PATTERN.match(line)
            if not match:
                continue

            permission, state = match.groups()
            granted = state == "true"

            if section == "install":
                install[permission] = granted
            else:
                runtime.setdefault(current_user, {})[permission] = granted

    return {
        "requested_permissions": sorted(requested),
        "install_permissions": install,
        "runtime_permissions_by_user": runtime,
    }
