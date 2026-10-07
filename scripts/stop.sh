#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
RUN_DIR="${ROOT_DIR}/run"

sudo env \
    KOHMAR_CONFIG_DIR="${RUN_DIR}/config" \
    KOHMAR_STATE_DIR="${RUN_DIR}/state" \
    KOHMAR_RUNTIME_DIR="${RUN_DIR}/runtime" \
    KOHMAR_MODULE_FILE="${ROOT_DIR}/kernel/ads_netfilter/ads_netfilter.ko" \
    "${BUILD_DIR}/apps/drvctl/ads_drvctl" stop || true