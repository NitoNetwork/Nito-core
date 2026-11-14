#!/usr/bin/env bash
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

set -euo pipefail

# Pick the first locale whose effective character map really is UTF-8.
# Linux CI containers (glibc >= 2.35) provide C.UTF-8 out of the box, while
# macOS runners have no C.UTF-8 and must use en_US.UTF-8. Setting an
# unavailable LC_ALL silently falls back to "C"/US-ASCII, which Qt tools
# reject, so every candidate is verified through 'locale charmap'.
nito_utf8_locale_candidates="${NITO_UTF8_LOCALES:-C.UTF-8 en_US.UTF-8}"
nito_pick_utf8_locale() {
    local candidate
    for candidate in ${nito_utf8_locale_candidates}; do
        if [[ "$(LC_ALL=${candidate} LANG=${candidate} locale charmap 2>/dev/null || true)" == "UTF-8" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}
if ! NITO_UTF8_LOCALE="$(nito_pick_utf8_locale)"; then
    echo "ERROR: no UTF-8 locale available. Candidates tried: ${nito_utf8_locale_candidates}" >&2
    echo "Locales reported by 'locale -a':" >&2
    locale -a >&2 || true
    exit 1
fi
export LC_ALL="${NITO_UTF8_LOCALE}"
export LANG="${NITO_UTF8_LOCALE}"
echo "Using UTF-8 locale: ${NITO_UTF8_LOCALE}"

: "${NITO_HOST:?NITO_HOST is required}"
: "${NITO_QT_PLATFORM:?NITO_QT_PLATFORM is required}"

SOURCE_DIR="$(pwd)"
DEPENDS_PREFIX="${SOURCE_DIR}/depends/${NITO_HOST}"
LOG_DIR="${SOURCE_DIR}/sanitizer-logs"
MAKEJOBS="${MAKEJOBS:-4}"
mkdir -p "${LOG_DIR}"

QT_BINDIR=""
for dir in \
    "${DEPENDS_PREFIX}/bin" \
    "${DEPENDS_PREFIX}/libexec" \
    "${DEPENDS_PREFIX}/native/bin"; do
    if [[ -x "${dir}/moc" || -x "${dir}/moc-qt6" || -x "${dir}/moc6" ]]; then
        QT_BINDIR="${dir}"
        break
    fi
done
if [[ -z "${QT_BINDIR}" ]]; then
    echo "No Depends Qt6 moc found below ${DEPENDS_PREFIX}" >&2
    find "${DEPENDS_PREFIX}" -type f \( -name moc -o -name moc-qt6 -o -name moc6 \) -print >&2
    exit 1
fi

QT_LINGUIST_BINDIR=""
for dir in \
    "${DEPENDS_PREFIX}/native/bin" \
    "${DEPENDS_PREFIX}/bin" \
    "${DEPENDS_PREFIX}/libexec" \
    "/usr/lib/qt6/bin" \
    "/usr/lib/qt6/libexec" \
    "/usr/lib/$(uname -m)-linux-gnu/qt6/bin"; do
    if [[ -x "${dir}/lrelease" || -x "${dir}/lrelease-qt6" || -x "${dir}/lrelease6" ]]; then
        QT_LINGUIST_BINDIR="${dir}"
        break
    fi
done
if [[ -z "${QT_LINGUIST_BINDIR}" ]]; then
    echo "No Qt6 lrelease found below ${DEPENDS_PREFIX}" >&2
    find "${DEPENDS_PREFIX}" -type f \( -name lrelease -o -name lrelease-qt6 -o -name lrelease6 \) -print >&2
    exit 1
fi
export PATH="${QT_BINDIR}:${QT_LINGUIST_BINDIR}:${PATH}"

chmod +x autogen.sh
WARNING_CLEAN_LOG="${LOG_DIR}/autogen.log" \
    bash .github/scripts/warning-clean-run.sh ./autogen.sh

configure_and_run() {
    local profile="$1"
    local sanitizers="$2"
    shift 2
    local -a sanitizer_symbols=("$@")
    local config_log="${LOG_DIR}/${profile}-configure.log"
    local build_log="${LOG_DIR}/${profile}-build.log"
    local symbols_log="${LOG_DIR}/${profile}-symbols.log"
    local app_log="${LOG_DIR}/${profile}-apptests.log"
    local wallet_log="${LOG_DIR}/${profile}-wallettests.log"

    if [[ -f Makefile ]]; then
        make distclean >"${LOG_DIR}/${profile}-preclean.log" 2>&1
    fi

    local -a configure_args=(
        --disable-shared
        --disable-hardening
        --with-gui=qt6
        --with-qrencode
        --with-sqlite=yes
        --with-bdb=yes
        --enable-reduce-exports
        --enable-tests
        --disable-bench
        --enable-werror
        "--with-sanitizers=${sanitizers}"
        "--with-qt-bindir=${QT_BINDIR}"
    )
    if [[ "${profile}" == tsan && "$(uname)" == Linux ]]; then
        # GCC 11/libtsan.so.0 does not intercept pthread_cond_clockwait.
        # Use the same compiler as the early runtime probe, without changing
        # the release/Depends or ASan toolchain and without suppressing reports.
        : "${NITO_TSAN_CC:?NITO_TSAN_CC is required}"
        : "${NITO_TSAN_CXX:?NITO_TSAN_CXX is required}"
        configure_args+=("CC=${NITO_TSAN_CC}" "CXX=${NITO_TSAN_CXX}")
    fi
    if [[ -n "${NITO_CONFIGURE_EXTRA:-}" ]]; then
        # NITO_CONFIGURE_EXTRA is a repository-controlled workflow value.
        # shellcheck disable=SC2206
        local extra_args=( ${NITO_CONFIGURE_EXTRA} )
        configure_args+=("${extra_args[@]}")
    fi

    CONFIG_SITE="${DEPENDS_PREFIX}/share/config.site" \
    CFLAGS="-O1 -g -fno-omit-frame-pointer" \
    CXXFLAGS="-O1 -g -fno-omit-frame-pointer" \
    WARNING_CLEAN_LOG="${config_log}" \
        bash .github/scripts/warning-clean-run.sh ./configure "${configure_args[@]}"

    WARNING_CLEAN_LOG="${build_log}" \
        bash .github/scripts/warning-clean-run.sh \
            make -C src -j"${MAKEJOBS}" qt/test/test_nito-qt

    nm -a src/qt/test/test_nito-qt >"${symbols_log}"
    for sanitizer_symbol in "${sanitizer_symbols[@]}"; do
        if ! grep -Eq "${sanitizer_symbol}" "${symbols_log}"; then
            echo "The ${profile} test binary does not expose ${sanitizer_symbol}; refusing an uninstrumented run." >&2
            exit 1
        fi
    done

    local -a runtime_env=(
        "QT_QPA_PLATFORM=${NITO_QT_PLATFORM}"
        "ASAN_OPTIONS=halt_on_error=1:strict_init_order=1"
        "LSAN_OPTIONS=suppressions=${SOURCE_DIR}/test/sanitizer_suppressions/lsan"
        "UBSAN_OPTIONS=suppressions=${SOURCE_DIR}/test/sanitizer_suppressions/ubsan:print_stacktrace=1:halt_on_error=1:report_error_type=1"
        "TSAN_OPTIONS=suppressions=${SOURCE_DIR}/test/sanitizer_suppressions/tsan:halt_on_error=1:second_deadlock_stack=1"
    )

    # External hang guard: on Linux, coreutils timeout(1) terminates the whole
    # instrumented suite if it wedges, so a genuine hang fails visibly instead
    # of burning the job-level timeout.
    local -a test_guard=()
    if [[ "$(uname)" == "Linux" ]]; then
        test_guard=(timeout --signal=ABRT "${NITO_TEST_TIMEOUT_SECONDS:-7200}")
        if [[ "${profile}" == tsan ]]; then
            test_guard+=(setarch "$(uname -m)" -R)
        fi
    fi

    env "${runtime_env[@]}" NITO_QT_TEST_SUITE=AppTests \
        WARNING_CLEAN_LOG="${app_log}" \
        "${test_guard[@]+${test_guard[@]}}" \
        bash .github/scripts/warning-clean-run.sh src/qt/test/test_nito-qt
    env "${runtime_env[@]}" NITO_QT_TEST_SUITE=WalletTests \
        WARNING_CLEAN_LOG="${wallet_log}" \
        "${test_guard[@]+${test_guard[@]}}" \
        bash .github/scripts/warning-clean-run.sh src/qt/test/test_nito-qt
}

configure_and_run asan-ubsan address,undefined \
    '__asan_init|___asan_init' \
    '__ubsan_handle_|___ubsan_handle_'

# macOS currently supplies ASan/UBSan evidence only; Linux also requires TSan.
if [[ "$(uname)" == "Darwin" ]]; then
    # The Qt/Cocoa TSan profile stalls during initialization on this runner.
    # macOS coverage is limited to ASan/UBSan; Linux must also pass TSan.
    echo "Skipping TSan profile on macOS: Qt/Cocoa TSan profile is not reliable on this GitHub macOS runner/toolchain."
else
    configure_and_run tsan thread '__tsan_init|___tsan_init'
fi
