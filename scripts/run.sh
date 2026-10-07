#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
RUN_DIR="${ROOT_DIR}/run"
CONFIG_DIR="${RUN_DIR}/config"
STATE_DIR="${RUN_DIR}/state"
RUNTIME_DIR="${RUN_DIR}/runtime"
MODULE_FILE="${ROOT_DIR}/kernel/ads_netfilter/ads_netfilter.ko"

mkdir -p \
    "${CONFIG_DIR}" \
    "${STATE_DIR}/db" \
    "${STATE_DIR}/samples" \
    "${RUNTIME_DIR}"

[[ -f "${CONFIG_DIR}/ads.settings" ]] ||
    cp "${ROOT_DIR}/config/ads.settings.example" \
       "${CONFIG_DIR}/ads.settings"

[[ -f "${CONFIG_DIR}/readerd.conf" ]] ||
    cp "${ROOT_DIR}/config/readerd.conf.example" \
       "${CONFIG_DIR}/readerd.conf"

[[ -f "${CONFIG_DIR}/module.conf" ]] ||
    cp "${ROOT_DIR}/config/module.conf.example" \
       "${CONFIG_DIR}/module.conf"

[[ -f "${STATE_DIR}/db/db_firewall.sqlite" ]] ||
    cp "${ROOT_DIR}/data/seeds/common/db_firewall.sqlite" \
       "${STATE_DIR}/db/db_firewall.sqlite"

for sample in "${ROOT_DIR}"/data/samples/ads/*.samples; do
    target="${STATE_DIR}/samples/$(basename "${sample}")"

    if [[ ! -f "${target}" ]]; then
        cp "${sample}" "${target}"
    fi
done

run_with_paths() {
    sudo env \
        KOHMAR_CONFIG_DIR="${CONFIG_DIR}" \
        KOHMAR_STATE_DIR="${STATE_DIR}" \
        KOHMAR_RUNTIME_DIR="${RUNTIME_DIR}" \
        KOHMAR_MODULE_FILE="${MODULE_FILE}" \
        "$@"
}

if lsmod | grep -q '^ads_netfilter '; then
    run_with_paths \
        "${BUILD_DIR}/apps/drvctl/ads_drvctl" stop || true
fi

run_with_paths \
    "${BUILD_DIR}/apps/drvctl/ads_drvctl" start

[[ -c /dev/ads_drv_setup ]] || {
    echo "ERROR: /dev/ads_drv_setup is missing" >&2
    exit 1
}

[[ -c /dev/ads_sniff_mmap ]] || {
    echo "ERROR: /dev/ads_sniff_mmap is missing" >&2
    exit 1
}

run_with_paths "${BUILD_DIR}/apps/ads/ads"