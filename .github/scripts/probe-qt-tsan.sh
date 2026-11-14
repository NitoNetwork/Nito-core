#!/usr/bin/env bash
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8
set -euo pipefail

: "${NITO_TSAN_CXX:?NITO_TSAN_CXX is required}"
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
log_dir="${NITO_SANITIZER_LOG_DIR:-${source_dir}/sanitizer-logs}"
mkdir -p "${log_dir}"
"${NITO_TSAN_CXX}" --version | tee "${log_dir}/tsan-toolchain.log"

WARNING_CLEAN_LOG="${log_dir}/tsan-probe-build.log" \
    bash "${source_dir}/.github/scripts/warning-clean-run.sh" \
    "${NITO_TSAN_CXX}" -std=c++20 -O1 -g -Wall -Wextra -Wno-unused-parameter \
    -Werror -fsanitize=thread -fno-omit-frame-pointer -pthread \
    -I"${source_dir}/src" "${source_dir}/.github/tests/tsan-runtime.cpp" \
    "${source_dir}/src/scheduler.cpp" -o "${log_dir}/tsan-probe"

# GCC's TSan address layout needs deterministic mappings on modern Linux.
# Restrict this to the probe/test process; never change host-wide ASLR settings.
runner=(timeout --signal=ABRT 60 setarch "$(uname -m)" -R "${log_dir}/tsan-probe")
TSAN_OPTIONS=halt_on_error=1:exitcode=66 \
    WARNING_CLEAN_LOG="${log_dir}/tsan-probe-clean.log" \
    bash "${source_dir}/.github/scripts/warning-clean-run.sh" "${runner[@]}"

set +e
TSAN_OPTIONS=halt_on_error=1:exitcode=66 \
    "${runner[@]}" --race >"${log_dir}/tsan-probe-race.log" 2>&1
status=$?
set -e
cat "${log_dir}/tsan-probe-race.log"
if [[ "${status}" != 66 ]] || ! grep -q 'WARNING: ThreadSanitizer: data race' "${log_dir}/tsan-probe-race.log"; then
    echo "ERROR: TSan did not detect the deliberate race (exit ${status})." >&2
    exit 1
fi
echo "PASS: TSan accepts synchronized code and rejects the deliberate race"
