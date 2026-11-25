#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$(realpath "$0")")"

echo "Installing Doji Mobile Security..."

sudo apt update

sudo apt install -y \
    python3 \
    python3-tk \
    python3-reportlab \
    python3-venv \
    pipx \
    adb \
    yara \
    aapt \
    apksigner \
    libimobiledevice-utils \
    usbmuxd \
    git

export PATH="$HOME/.local/bin:$PATH"

echo "Installing security engines..."

pipx install mvt==2026.10.26
pipx install quark-engine==26.11.1

pipx ensurepath

echo "Downloading Quark rules..."
freshquark

echo "Preparing local directories..."

mkdir -p reports cache/quark
mkdir -p forensic/evidence
mkdir -p forensic/results
mkdir -p forensic/device_apks
mkdir -p forensic/iocs/mvt-public
mkdir -p forensic/logs

chmod +x DOJI-START

echo "Checking required dependencies..."

python3 -c "import tkinter, reportlab"

for tool in adb yara aapt apksigner quark mvt-android
do
    command -v "$tool" >/dev/null
    echo "PASS: $tool"
done

./UPDATE-IOCS.sh

echo "Installation completed."
echo "Launch Doji using ./DOJI-START"
