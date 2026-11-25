#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$(realpath "$0")")"

export PATH="$HOME/.local/bin:$PATH"

echo "Downloading public MVT indicators..."
mvt-android download-iocs

SOURCE="${XDG_DATA_HOME:-$HOME/.local/share}/mvt/indicators"
DEST="forensic/iocs/mvt-public"

mkdir -p "$DEST"

cp "$SOURCE"/*.stix2 "$DEST/"

sha256sum "$DEST"/*.stix2 \
    > forensic/iocs/sha256-manifest.txt

sha256sum -c forensic/iocs/sha256-manifest.txt

echo "IOC setup completed."
