#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if lsmod | grep -q '^ads_netfilter '; then
    sudo ./build/apps/drvctl/ads_drvctl stop || true
fi

sudo ./build/apps/drvctl/ads_drvctl start

[[ -c /dev/ads_drv_setup ]] || {
    echo "ERROR: /dev/ads_drv_setup is missing" >&2
    exit 1
}

[[ -c /dev/ads_sniff_mmap ]] || {
    echo "ERROR: /dev/ads_sniff_mmap is missing" >&2
    exit 1
}

sudo ./build/apps/ads/ads