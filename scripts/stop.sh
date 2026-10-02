#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

sudo ./build/apps/drvctl/ads_drvctl stop || true

sudo rm -f /dev/ads_drv_setup
sudo rm -f /dev/ads_sniff_mmap