#!/bin/bash
set -euo pipefail

INSTALL_URL="https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh"

if [ -n "${SIS_INSTALL_DIR:-}" ]; then
    curl -fsSL "$INSTALL_URL" | sh
    exit 0
fi

DEFAULT_DIR="$HOME/.local/bin"
export SIS_INSTALL_DIR="$DEFAULT_DIR"
mkdir -p "$SIS_INSTALL_DIR"
curl -fsSL "$INSTALL_URL" | sh
